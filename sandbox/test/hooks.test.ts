import assert from "node:assert/strict";
import { after, afterEach, before, describe, it } from "node:test";
import { Browser } from "puppeteer";
import { HookedPage, TestServer, launch_browser, matches_rust_types } from "./harness";
import * as types from "../src/types";
import { sanitize_ioc } from "../src/utils";

// Tests marked as `todo` describe the behaviour we want from a hook but do not have
// yet. They run and they are listed in the results, but they do not fail the suite.

const BYPASS = "evasion: the sample can avoid the hook this way";

let browser: Browser;
let server: TestServer;
let hooked: HookedPage | null = null;

async function open(options: Parameters<typeof HookedPage.open>[2] = {}): Promise<HookedPage> {
    hooked = await HookedPage.open(browser, server.origin, options);
    return hooked;
}

const FunctionCall = types.IoCType.FunctionCall;
const HttpRequest = types.IoCType.HttpRequest;
const SetCookie = types.IoCType.SetCookie;
const GetCookie = types.IoCType.GetCookie;
const AddEventListener = types.IoCType.AddEventListener;
const SetTimeoutIoC = types.IoCType.SetTimeout;
const NewNetworkElement = types.IoCType.NewNetworkHtmlElement;

function assert_rust_compatible(p: HookedPage) {
    assert.ok(p.iocs.length > 0, "expected at least one ioc");
    for (const ioc of p.iocs) {
        assert.ok(matches_rust_types(ioc.ioc_type, ioc.value), `not accepted by rust: ${JSON.stringify(ioc)}`);
    }
}

before(async () => {
    server = new TestServer();
    await server.start();
    browser = await launch_browser();
});

after(async () => {
    await browser.close();
    await server.stop();
});

afterEach(async () => {
    if (hooked) await hooked.close();
    hooked = null;
});

describe("hook placement", () => {
    it("leaves no place_hooks global behind", async () => {
        const p = await open();
        assert.equal(await p.run(`typeof place_hooks`), "undefined");
    });

    it("is active before the first script of the page", async () => {
        const p = await open({ path: "/inline-script" });
        await p.flush();
        assert.deepEqual(p.of_type(SetCookie), [{ cookie: "from_inline=1" }]);
    });

    it("survives navigation", async () => {
        const p = await open();
        await p.page.goto(server.origin + "/other");
        await p.run(`fetch("/after-navigation")`);
        assert.equal(p.of_type(HttpRequest)[0].url, "/after-navigation");
    });

    it("is active in same origin iframes", async () => {
        const p = await open({ path: "/same-origin-frame" });
        await p.wait_for(HttpRequest, v => v.url === "/from-frame");
    });

    it("is active in iframes created by the page", async () => {
        const p = await open();
        await p.run(`
            const f = document.createElement("iframe");
            document.body.appendChild(f);
            f.contentWindow.fetch("/through-new-frame").catch(() => {});
        `);
        await p.wait_for(HttpRequest, v => v.url === "/through-new-frame");
    });

    it("still places the other hooks on sandboxed iframes, where localStorage throws", async () => {
        const p = await open({ path: "/sandboxed-frame" });
        await p.wait_for(HttpRequest, v => v.url === "/from-sandboxed-frame");
    });

    it("works on about:blank", async () => {
        const p = await open();
        await p.page.goto("about:blank");
        await p.run(`fetch("http://127.0.0.1:1/x").catch(() => {})`);
        assert.equal(p.of_type(HttpRequest)[0].url, "http://127.0.0.1:1/x");
    });

    it("sets timestamp and executed_on on every ioc", async () => {
        const p = await open();
        const before_call = Date.now();
        await p.run(`localStorage.setItem("k", "v")`);
        const ioc = p.iocs[0];
        assert.ok(ioc.timestamp >= before_call - 5000 && ioc.timestamp <= Date.now() + 5000);
        assert.equal(ioc.executed_on, "");
    });

    for (const fn of [
        "window.fetch", "window.open", "window.eval", "document.write", "document.addEventListener",
        "window.setTimeout", "XMLHttpRequest.prototype.open", "XMLHttpRequest.prototype.send"
    ]) {
        it(`${fn} still looks native`, { todo: "evasion: the sample can detect the hook" }, async () => {
            const p = await open();
            assert.match(await p.run(`Function.prototype.toString.call(${fn})`), /\[native code\]/);
        });
    }
});

describe("localStorage.setItem", () => {
    it("reports key and value", async () => {
        const p = await open();
        await p.run(`localStorage.setItem("k", "v")`);
        assert.deepEqual(p.of_type(FunctionCall), [{ callee: "window.localStorage.setItem", arguments: ["k", "v"] }]);
    });

    it("really stores the value", async () => {
        const p = await open();
        assert.equal(await p.run(`localStorage.setItem("k", "v"); Storage.prototype.getItem.call(localStorage, "k")`), "v");
    });

    it("keeps working on another document of the same origin", async () => {
        const p = await open();
        await p.run(`localStorage.setItem("k", "v")`);
        await p.page.goto(server.origin + "/other");
        await p.run(`localStorage.setItem("k2", "v2")`);
        assert.deepEqual(p.of_type(FunctionCall), [{ callee: "window.localStorage.setItem", arguments: ["k2", "v2"] }]);
    });

    it("does not leave anything in the storage", async () => {
        const p = await open();
        assert.equal(await p.run(`localStorage.length`), 0);
    });

    it("reports non string values as strings", async () => {
        const p = await open();
        await p.run(`localStorage.setItem("k", 1)`);
        assert_rust_compatible(p);
    });

    it("reports calls through Storage.prototype", { todo: BYPASS }, async () => {
        const p = await open();
        await p.run(`Storage.prototype.setItem.call(localStorage, "k", "v")`);
        assert.equal(p.of_type(FunctionCall).length, 1);
    });

    it("reports property assignment", { todo: BYPASS }, async () => {
        const p = await open();
        await p.run(`localStorage.k = "v"`);
        assert.equal(p.of_type(FunctionCall).length, 1);
    });
});

describe("localStorage.getItem", () => {
    it("reports the key", async () => {
        const p = await open();
        await p.run(`localStorage.getItem("k")`);
        assert.deepEqual(p.of_type(FunctionCall), [{ callee: "window.localStorage.getItem", arguments: ["k"] }]);
    });

    it("returns the stored value", async () => {
        const p = await open();
        assert.equal(await p.run(`Storage.prototype.setItem.call(localStorage, "k", "v"); localStorage.getItem("k")`), "v");
    });

    it("returns null for a missing key", async () => {
        const p = await open();
        assert.equal(await p.run(`localStorage.getItem("missing")`), null);
    });

    it("reports calls through Storage.prototype", { todo: BYPASS }, async () => {
        const p = await open();
        await p.run(`Storage.prototype.getItem.call(localStorage, "k")`);
        assert.equal(p.of_type(FunctionCall).length, 1);
    });

    it("reports property access", { todo: BYPASS }, async () => {
        const p = await open();
        await p.run(`localStorage.k`);
        assert.equal(p.of_type(FunctionCall).length, 1);
    });
});

describe("document.write", () => {
    it("reports the written code", async () => {
        const p = await open();
        await p.run(`document.write("<b>x</b>")`);
        assert.deepEqual(p.of_type(FunctionCall), [{ callee: "document.write", arguments: ["<b>x</b>"] }]);
    });

    it("really writes to the document", async () => {
        const p = await open();
        assert.equal(await p.run(`document.write("<b id='w'>x</b>"); document.getElementById("w").textContent`), "x");
    });

    it("writes all the arguments", async () => {
        const p = await open();
        assert.equal(await p.run(`document.write("<b id='w'>", "x", "</b>"); document.getElementById("w").textContent`), "x");
    });

    it("works while the page is being parsed", async () => {
        const p = await open({ path: "/inline-write" });
        await p.flush();
        assert.equal(p.of_type(FunctionCall)[0].callee, "document.write");
        assert.equal(await p.run(`document.getElementById("written").textContent`), "x");
    });

    it("reports all the arguments", { todo: "only the first argument is reported" }, async () => {
        const p = await open();
        await p.run(`document.write("a", "b")`);
        assert.deepEqual(p.of_type(FunctionCall)[0].arguments, ["a", "b"]);
    });

    it("reports non string arguments as strings", async () => {
        const p = await open();
        await p.run(`document.write(1)`);
        assert_rust_compatible(p);
    });

    it("reports document.writeln", { todo: BYPASS }, async () => {
        const p = await open();
        await p.run(`document.writeln("<b>x</b>")`);
        assert.equal(p.of_type(FunctionCall).length, 1);
    });
});

describe("window.eval", () => {
    it("reports the code", async () => {
        const p = await open();
        await p.run(`window.eval("1 + 1")`);
        assert.deepEqual(p.of_type(FunctionCall), [{ callee: "window.eval", arguments: ["1 + 1"] }]);
    });

    it("reports a bare eval call", async () => {
        const p = await open();
        await p.run(`eval("1 + 1")`);
        assert.deepEqual(p.of_type(FunctionCall), [{ callee: "window.eval", arguments: ["1 + 1"] }]);
    });

    it("returns the result", async () => {
        const p = await open();
        assert.equal(await p.run(`window.eval("1 + 1")`), 2);
    });

    it("evaluates in the global scope", async () => {
        const p = await open();
        assert.equal(await p.run(`window.eval("var from_eval = 7"); window.from_eval`), 7);
    });

    it("reports and then rethrows syntax errors", async () => {
        const p = await open();
        assert.equal(await p.run(`try { window.eval("(("); "no error" } catch (e) { e.name }`), "SyntaxError");
        assert.equal(p.of_type(FunctionCall).length, 1);
    });

    it("returns non strings untouched", async () => {
        const p = await open();
        assert.equal(await p.run(`window.eval(42)`), 42);
    });

    it("reports non string arguments as strings", async () => {
        const p = await open();
        await p.run(`window.eval(42)`);
        assert_rust_compatible(p);
    });

    it("keeps the local scope of a direct eval", { todo: "code using a direct eval breaks, also on the bait website" }, async () => {
        const p = await open();
        assert.equal(await p.run(`(function () { var local = 1; return eval("local"); })()`), 1);
    });

    it("reports new Function", { todo: BYPASS }, async () => {
        const p = await open();
        await p.run(`new Function("return 1")()`);
        assert.equal(p.of_type(FunctionCall).length, 1);
    });
});

describe("window.execScript", () => {
    const IE_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko";
    const OLD_IE_USER_AGENT = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)";
    const WITH_EXEC_SCRIPT = `window.execScript = function (code) { window.exec_script_ran = code; };`;

    it("is left alone outside of Internet Explorer", async () => {
        const p = await open({ before_hooks: WITH_EXEC_SCRIPT });
        await p.run(`window.execScript("x")`);
        assert.equal(p.of_type(FunctionCall).length, 0);
        assert.equal(await p.run(`window.exec_script_ran`), "x");
    });

    it("leaves eval working on old Internet Explorer without execScript", async () => {
        const p = await open({ user_agent: OLD_IE_USER_AGENT });
        assert.equal(await p.run(`window.eval("1 + 1")`), 2);
        assert.equal(p.of_type(FunctionCall)[0].callee, "window.eval");
    });

    it("reports execScript on Internet Explorer", { todo: "the hook replaces window.eval instead of window.execScript" }, async () => {
        const p = await open({ user_agent: IE_USER_AGENT, before_hooks: WITH_EXEC_SCRIPT });
        await p.run(`window.execScript("x")`);
        assert.deepEqual(p.of_type(FunctionCall), [{ callee: "window.execScript", arguments: ["x"] }]);
    });

    it("runs the code given to execScript", async () => {
        const p = await open({ user_agent: IE_USER_AGENT, before_hooks: WITH_EXEC_SCRIPT });
        assert.equal(await p.run(`window.execScript("x"); window.exec_script_ran`), "x");
    });

    it("reports eval as eval on Internet Explorer", { todo: "the hook replaces window.eval instead of window.execScript" }, async () => {
        const p = await open({ user_agent: IE_USER_AGENT, before_hooks: WITH_EXEC_SCRIPT });
        await p.run(`window.eval("1 + 1")`);
        assert.equal(p.of_type(FunctionCall)[0].callee, "window.eval");
    });

    it("leaves eval working when the Trident user agent has no execScript", { todo: "operator precedence in the check: a && b || c" }, async () => {
        const p = await open({ user_agent: IE_USER_AGENT });
        assert.equal(await p.run(`window.eval("1 + 1")`), 2);
    });
});

describe("window.fetch", () => {
    it("reports the url", async () => {
        const p = await open();
        await p.run(`fetch("/echo")`);
        assert.deepEqual(p.of_type(HttpRequest), [{ url: "/echo", method: "GET", data: "" }]);
    });

    it("returns the real response", async () => {
        const p = await open();
        assert.equal((await p.run(`fetch("/echo").then(r => r.json())`)).method, "GET");
    });

    it("passes method and body to the server", async () => {
        const p = await open();
        const echo = await p.run(`fetch("/echo", { method: "POST", body: "stolen" }).then(r => r.json())`);
        assert.deepEqual([echo.method, echo.body], ["POST", "stolen"]);
    });

    it("rejects when the request fails", async () => {
        const p = await open();
        assert.equal(await p.run(`fetch("http://127.0.0.1:1/").then(() => "resolved", e => e.name)`), "TypeError");
    });

    it("reports URL objects as strings", async () => {
        const p = await open();
        await p.run(`fetch(new URL("/echo", location.href))`);
        assert.equal(p.of_type(HttpRequest)[0].url, server.origin + "/echo");
    });

    it("reports the real method", { todo: "the method is always reported as GET" }, async () => {
        const p = await open();
        await p.run(`fetch("/echo", { method: "POST", body: "stolen" })`);
        assert.equal(p.of_type(HttpRequest)[0].method, "POST");
    });

    it("reports the body", { todo: "exfiltrated data is never reported" }, async () => {
        const p = await open();
        await p.run(`fetch("/echo", { method: "POST", body: "stolen" })`);
        assert.equal(p.of_type(HttpRequest)[0].data, "stolen");
    });

    it("keeps the report valid with a Request object", async () => {
        const p = await open();
        await p.run(`fetch(new Request("/echo"))`);
        assert_rust_compatible(p);
    });

    it("reports the url of a Request object", { todo: "a Request reaches node as {}, only the hook can read its url" }, async () => {
        const p = await open();
        await p.run(`fetch(new Request("/echo"))`);
        assert.equal(p.of_type(HttpRequest)[0].url, server.origin + "/echo");
    });
});

describe("window.open", () => {
    it("reports the url", async () => {
        const p = await open();
        await p.run(`window.open("/other"); 0`);
        assert.deepEqual(p.of_type(HttpRequest), [{ url: "/other", method: "GET", data: "" }]);
    });

    it("really opens the window", async () => {
        const p = await open();
        assert.equal(await p.run(`window.open("/other") !== null`), true);
    });

    it("passes target and features", async () => {
        const p = await open();
        assert.equal(await p.run(`window.open("/other", "named_window", "width=100,height=100").name`), "named_window");
    });

    it("reports a call without url", async () => {
        const p = await open();
        await p.run(`window.open(); 0`);
        assert_rust_compatible(p);
    });
});

describe("XMLHttpRequest.open", () => {
    it("reports method and url", async () => {
        const p = await open();
        await p.run(`new XMLHttpRequest().open("POST", "/echo")`);
        assert.deepEqual(p.of_type(HttpRequest), [{ url: "/echo", method: "POST", data: "" }]);
    });

    it("passes the async flag", async () => {
        const p = await open();
        assert.equal(await p.run(`
            const xhr = new XMLHttpRequest();
            xhr.open("GET", "/echo", false);
            xhr.send();
            xhr.readyState
        `), 4);
    });

    it("reports URL objects as strings", async () => {
        const p = await open();
        await p.run(`new XMLHttpRequest().open("GET", new URL("/echo", location.href))`);
        assert_rust_compatible(p);
    });
});

describe("XMLHttpRequest.send", () => {
    const POST = (body: string) => `
        const xhr = new XMLHttpRequest();
        xhr.open("POST", "/echo", false);
        xhr.send(${body});
        xhr.responseText
    `;

    it("reports the body", async () => {
        const p = await open();
        await p.run(POST(`"stolen"`));
        assert.equal(p.of_type(HttpRequest)[1].data, `["stolen"]`);
    });

    it("reports an empty send", async () => {
        const p = await open();
        await p.run(POST(``));
        assert.equal(p.of_type(HttpRequest)[1].data, "[]");
    });

    it("really sends the body", async () => {
        const p = await open();
        assert.equal(JSON.parse(await p.run(POST(`"stolen"`))).body, "stolen");
    });

    it("fires the load event of async requests", async () => {
        const p = await open();
        assert.equal(await p.run(`new Promise(resolve => {
            const xhr = new XMLHttpRequest();
            xhr.onload = () => resolve(xhr.status);
            xhr.open("GET", "/echo");
            xhr.send();
        })`), 200);
    });

    it("reports the content of FormData", { todo: "exfiltrated data is reported as {}" }, async () => {
        const p = await open();
        await p.run(`
            const form = new FormData();
            form.append("password", "stolen");
            ${POST("form")}
        `);
        assert.match(p.of_type(HttpRequest)[1].data, /stolen/);
    });

    it("rethrows errors of the real send", { todo: "the hook swallows them, which the sample can detect" }, async () => {
        const p = await open();
        assert.equal(await p.run(`try { new XMLHttpRequest().send(); "no error" } catch (e) { e.name }`), "InvalidStateError");
    });
});

describe("document.cookie", () => {
    it("reports a set", async () => {
        const p = await open();
        await p.run(`document.cookie = "a=b"`);
        assert.deepEqual(p.of_type(SetCookie), [{ cookie: "a=b" }]);
    });

    it("reports the attributes of a set", async () => {
        const p = await open();
        await p.run(`document.cookie = "a=b; path=/; max-age=60"`);
        assert.deepEqual(p.of_type(SetCookie), [{ cookie: "a=b; path=/; max-age=60" }]);
    });

    it("really sets the cookie", async () => {
        const p = await open();
        await p.run(`document.cookie = "a=b"`);
        assert.equal((await p.run(`fetch("/echo").then(r => r.json())`)).cookie, "a=b");
    });

    it("reports a get with the real value", async () => {
        const p = await open();
        await p.page.setCookie({ name: "real", value: "1", url: server.origin });
        assert.equal(await p.run(`document.cookie`), "real=1");
        assert.deepEqual(p.of_type(GetCookie), [{ cookie: "real=1" }]);
    });

    it("applies expirations", async () => {
        const p = await open();
        await p.run(`document.cookie = "a=b"`);
        assert.equal(await p.run(`document.cookie = "a=; max-age=0"; document.cookie`), "");
    });

    it("does not expose HttpOnly cookies", async () => {
        const p = await open({ path: "/set-httponly" });
        assert.equal(await p.run(`document.cookie`), "");
    });

    it("reports non string values as strings", async () => {
        const p = await open();
        await p.run(`document.cookie = 1`);
        assert_rust_compatible(p);
    });

    it("reports reads through Document.prototype", { todo: BYPASS }, async () => {
        const p = await open();
        await p.run(`Object.getOwnPropertyDescriptor(Document.prototype, "cookie").get.call(document)`);
        assert.equal(p.of_type(GetCookie).length, 1);
    });

    it("reports writes through Document.prototype", { todo: BYPASS }, async () => {
        const p = await open();
        await p.run(`Object.getOwnPropertyDescriptor(Document.prototype, "cookie").set.call(document, "a=b")`);
        assert.equal(p.of_type(SetCookie).length, 1);
    });
});

describe("document.addEventListener", () => {
    const COUNT_CLICKS = (options: string) => `
        window.clicks = 0;
        document.addEventListener("click", () => window.clicks++, ${options});
        document.dispatchEvent(new Event("click"));
        document.dispatchEvent(new Event("click"));
        window.clicks
    `;

    it("reports the event name", async () => {
        const p = await open();
        await p.run(`document.addEventListener("keydown", () => {})`);
        assert.deepEqual(p.of_type(AddEventListener), [{ listener: "keydown" }]);
    });

    it("calls the listener", async () => {
        const p = await open();
        assert.equal(await p.run(COUNT_CLICKS("undefined")), 2);
    });

    it("passes the options", async () => {
        const p = await open();
        assert.equal(await p.run(COUNT_CLICKS("{ once: true }")), 1);
    });

    it("passes a useCapture flag", async () => {
        const p = await open();
        assert.equal(await p.run(`
            window.order = [];
            document.addEventListener("click", () => window.order.push("capture"), true);
            document.body.addEventListener("click", () => window.order.push("body"));
            document.body.click();
            window.order.join()
        `), "capture,body");
    });

    it("can be removed", async () => {
        const p = await open();
        assert.equal(await p.run(`
            window.clicks = 0;
            const listener = () => window.clicks++;
            document.addEventListener("click", listener);
            document.removeEventListener("click", listener);
            document.dispatchEvent(new Event("click"));
            window.clicks
        `), 0);
    });

    it("reports window.addEventListener", { todo: BYPASS }, async () => {
        const p = await open();
        await p.run(`window.addEventListener("keydown", () => {})`);
        assert.equal(p.of_type(AddEventListener).length, 1);
    });
});

describe("setTimeout", () => {
    it("reports the delay and the arguments", async () => {
        const p = await open();
        await p.run(`setTimeout(() => {}, 100, "a", 1); 0`);
        assert.deepEqual(p.of_type(SetTimeoutIoC), [{ delay: 100, arguments: ["a", "1"] }]);
    });

    it("reports a call without delay", async () => {
        const p = await open();
        await p.run(`setTimeout(() => {}); 0`);
        assert.deepEqual(p.of_type(SetTimeoutIoC), [{ delay: 0, arguments: [] }]);
    });

    it("runs the callback with its arguments", async () => {
        const p = await open();
        assert.equal(await p.run(`new Promise(resolve => setTimeout((a, b) => resolve(a + b), 1, "x", "y"))`), "xy");
    });

    it("runs string callbacks", async () => {
        const p = await open();
        assert.equal(await p.run(`new Promise(resolve => {
            window.resolve_timer = resolve;
            setTimeout("window.resolve_timer('ran')", 1);
        })`), "ran");
    });

    it("returns an id that clearTimeout accepts", async () => {
        const p = await open();
        assert.equal(await p.run(`new Promise(resolve => {
            window.fired = false;
            clearTimeout(setTimeout(() => { window.fired = true; }, 1));
            setTimeout(() => resolve(window.fired), 50);
        })`), false);
    });

    it("hooks window.setTimeout too", async () => {
        const p = await open();
        await p.run(`window.setTimeout(() => {}, 100); 0`);
        assert.equal(p.of_type(SetTimeoutIoC).length, 1);
    });

    it("works with arguments that cannot become strings", { todo: "the hook throws and the callback never runs" }, async () => {
        const p = await open();
        assert.equal(await p.run(`new Promise(resolve => setTimeout(resolve, 1, Object.create(null))).then(() => "ran")`), "ran");
    });

    it("reports setInterval", { todo: "the setInterval hook is commented out" }, async () => {
        const p = await open();
        await p.run(`clearInterval(setInterval(() => {}, 100)); 0`);
        assert.equal(p.of_type(SetTimeoutIoC).length, 1);
    });
});

describe("network html elements", () => {
    const ADD = (tag: string, attribute: string, value: string) => `
        const element = document.createElement("${tag}");
        element.setAttribute("${attribute}", "${value}");
        document.body.appendChild(element);
        0
    `;

    for (const [tag, attribute] of [
        ["form", "action"], ["img", "src"], ["audio", "src"], ["source", "src"], ["video", "src"], ["track", "src"],
        ["script", "src"], ["link", "href"], ["iframe", "src"], ["object", "src"], ["embed", "src"]
    ]) {
        it(`reports <${tag} ${attribute}>`, async () => {
            const p = await open();
            await p.run(ADD(tag, attribute, "/resource"));
            assert.deepEqual(p.of_type(NewNetworkElement), [{ elementType: tag, src: "/resource" }]);
        });

        it(`skips <${tag}> without ${attribute}`, async () => {
            const p = await open();
            await p.run(`document.body.appendChild(document.createElement("${tag}")); 0`);
            assert.deepEqual(p.of_type(NewNetworkElement), []);
        });
    }

    it("ignores elements that make no requests", async () => {
        const p = await open();
        await p.run(ADD("div", "src", "/resource"));
        assert.deepEqual(p.of_type(NewNetworkElement), []);
    });

    it("ignores text nodes", async () => {
        const p = await open();
        await p.run(`document.body.appendChild(document.createTextNode("x")); 0`);
        assert.deepEqual(p.of_type(NewNetworkElement), []);
    });

    it("ignores removed elements", async () => {
        const p = await open({ path: "/initial-markup" });
        await p.run(`document.querySelector("img").remove()`);
        assert.deepEqual(p.of_type(NewNetworkElement), []);
    });

    it("reports elements of the initial markup", async () => {
        const p = await open({ path: "/initial-markup" });
        await p.flush();
        assert.deepEqual(p.of_type(NewNetworkElement), [{ elementType: "img", src: "/initial.png" }]);
    });

    it("reports elements added with innerHTML", async () => {
        const p = await open();
        await p.run(`document.body.innerHTML = "<img src='/resource'>"; 0`);
        assert.deepEqual(p.of_type(NewNetworkElement), [{ elementType: "img", src: "/resource" }]);
    });

    it("reports an empty url as a string", async () => {
        const p = await open();
        await p.run(ADD("img", "src", ""));
        assert_rust_compatible(p);
    });

    it("reports elements nested in an added element", { todo: BYPASS }, async () => {
        const p = await open();
        await p.run(`document.body.innerHTML = "<div><img src='/resource'></div>"; 0`);
        assert.deepEqual(p.of_type(NewNetworkElement), [{ elementType: "img", src: "/resource" }]);
    });

    it("reports a url set after the element was added", { todo: BYPASS }, async () => {
        const p = await open();
        await p.run(`new Promise(resolve => {
            const image = document.createElement("img");
            document.body.appendChild(image);
            // the url is set after the observer has seen the element
            window.setTimeout(() => { image.src = "/resource"; resolve(); }, 20);
        })`);
        assert.equal(p.of_type(NewNetworkElement).length, 1);
    });

    it("reports images that are never added to the document", { todo: BYPASS }, async () => {
        const p = await open();
        await p.run(`new Image().src = "/resource"; 0`);
        assert.equal(p.of_type(NewNetworkElement).length, 1);
    });
});

describe("sanitize_ioc", () => {
    for (const garbage of [null, undefined, 1, "x", [], {}, { type: "unknown", value: {} }, { value: { cookie: "a" } }]) {
        it(`drops ${JSON.stringify(garbage)}`, () => {
            assert.equal(sanitize_ioc(garbage), null);
        });
    }

    it("keeps an ioc without a value valid", () => {
        const ioc = sanitize_ioc({ type: FunctionCall }) as types.IoC;
        assert.deepEqual(ioc.value, { callee: "", arguments: [] });
    });

    it("keeps strings untouched and converts everything else", () => {
        const ioc = sanitize_ioc({ type: FunctionCall, value: { callee: "c", arguments: ["a", 1, true, null, { x: 1 }] } }) as types.IoC;
        assert.deepEqual(ioc.value, { callee: "c", arguments: ["a", "1", "true", "null", `{"x":1}`] });
    });

    it("does not fail on arguments that are not a list", () => {
        const ioc = sanitize_ioc({ type: FunctionCall, value: { callee: "c", arguments: "a" } }) as types.IoC;
        assert.deepEqual(ioc.value, { callee: "c", arguments: [] });
    });

    it("removes fields that are not part of the ioc", () => {
        const ioc = sanitize_ioc({ type: SetCookie, extra: 1, value: { cookie: "a", extra: 1 } }) as any;
        assert.deepEqual(Object.keys(ioc).sort(), ["executed_on", "timestamp", "type", "value"]);
        assert.deepEqual(ioc.value, { cookie: "a" });
    });

    for (const timestamp of [undefined, "1", -1, 1.5, null]) {
        it(`replaces the timestamp ${JSON.stringify(timestamp)}`, () => {
            const ioc = sanitize_ioc({ type: SetCookie, timestamp, value: {} }) as types.IoC;
            assert.ok(Number.isSafeInteger(ioc.timestamp) && ioc.timestamp >= 0);
        });
    }

    for (const [delay, expected] of [["1000", 1000], [undefined, 0], ["x", 0], [null, 0], [250, 250]] as [unknown, number][]) {
        it(`turns the setTimeout delay ${JSON.stringify(delay)} into ${expected}`, () => {
            const ioc = sanitize_ioc({ type: SetTimeoutIoC, value: { delay } }) as types.IoC;
            assert.equal((ioc.value as types.IoCSetTimeout).delay, expected);
        });
    }
});
