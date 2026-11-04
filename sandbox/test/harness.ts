import http from "http";
import { AddressInfo } from "net";
import puppeteer, { Browser, BrowserContext, Page } from "puppeteer";
import { place_hooks } from "../src/hooks";
import * as types from "../src/types";
import { sanitize_ioc } from "../src/utils";

const REPORT_FN = "reportIoCForTests";
const FLUSH = "__flush__";

const html = (body: string) => `<!DOCTYPE html><html><head></head><body>${body}</body></html>`;

const pages: {[path: string]: string} = {
    "/": html("<p>blank</p>"),
    "/other": html("<p>other</p>"),
    "/inline-script": html(`<script>document.cookie = "from_inline=1";</script>`),
    "/inline-write": html(`<script>document.write("<b id='written'>x</b>");</script>`),
    "/initial-markup": html(`<img src="/initial.png">`),
    "/same-origin-frame": html(`<iframe src="/frame-child"></iframe>`),
    "/frame-child": html(`<script>fetch("/from-frame");</script>`),
    "/sandboxed-frame": html(`<iframe sandbox="allow-scripts" srcdoc="<script>fetch('/from-sandboxed-frame').catch(function(){})</script>"></iframe>`),
};

// local website the hooks are tested on. localStorage and cookies need a real origin
class TestServer {
    private server: http.Server;
    public origin = "";

    constructor() {
        this.server = http.createServer((req, res) => {
            const path = (req.url as string).split("?")[0];
            if (path === "/echo") {
                let body = "";
                req.on("data", chunk => body += chunk);
                req.on("end", () => {
                    res.setHeader("content-type", "application/json");
                    res.end(JSON.stringify({ method: req.method, body, cookie: req.headers.cookie || "" }));
                });
                return;
            }
            if (path === "/set-httponly") {
                res.setHeader("set-cookie", "secret=1; HttpOnly");
            }
            res.setHeader("content-type", "text/html");
            res.end(pages[path] || pages["/"]);
        });
    }

    async start() {
        await new Promise<void>(resolve => this.server.listen(0, "127.0.0.1", resolve));
        this.origin = `http://127.0.0.1:${(this.server.address() as AddressInfo).port}`;
    }

    async stop() {
        this.server.closeAllConnections();
        await new Promise(resolve => this.server.close(resolve));
    }
}

type SessionOptions = {
    path?: string,
    user_agent?: string,
    // code that runs in every new document before the hooks are placed
    before_hooks?: string
}

// a page with the hooks placed the same way app.ts places them
class HookedPage {
    public page!: Page;
    public iocs: types.IoC[] = [];
    private context!: BrowserContext;

    static async open(browser: Browser, origin: string, options: SessionOptions = {}): Promise<HookedPage> {
        const hooked = new HookedPage();
        hooked.context = await browser.createBrowserContext();
        hooked.page = await hooked.context.newPage();
        if (options.user_agent) await hooked.page.setUserAgent(options.user_agent);
        if (options.before_hooks) await hooked.page.evaluateOnNewDocument(options.before_hooks);
        await hooked.page.exposeFunction(REPORT_FN, (reported: any) => {
            if (reported?.type === FLUSH) return;
            const ioc = sanitize_ioc(reported);
            if (ioc !== null) hooked.iocs.push(ioc);
        });
        await hooked.page.evaluateOnNewDocument(place_hooks, REPORT_FN);
        await hooked.page.goto(origin + (options.path || "/"), { waitUntil: "load" });
        return hooked;
    }

    async close() {
        await this.context.close();
    }

    // reports reach node asynchronously but in order, so once this
    // call comes back every report made before it has been received
    async flush() {
        await this.page.evaluate(`window.${REPORT_FN}({ type: "${FLUSH}" })`);
    }

    // runs code in the page and returns its result, forgetting all iocs reported before it
    async run(code: string): Promise<any> {
        await this.flush();
        this.iocs.length = 0;
        const result = await this.page.evaluate(code);
        await this.flush();
        return result;
    }

    of_type(type: types.IoCType): any[] {
        return this.iocs.filter(i => i.ioc_type === type).map(i => i.value);
    }

    // for reports coming from places that a flush cannot follow, e.g. other frames
    async wait_for(type: types.IoCType, predicate: (value: any) => boolean = () => true, timeout = 3000): Promise<any> {
        const start = Date.now();
        while (Date.now() - start < timeout) {
            const found = this.of_type(type).find(predicate);
            if (found) return found;
            await new Promise(resolve => setTimeout(resolve, 20));
        }
        throw new Error(`no ${type} ioc was reported in ${timeout}ms, got: ${JSON.stringify(this.iocs)}`);
    }
}

// what the main application accepts (src/analysis/dast_ioc_types.rs). A report is parsed
// as a whole, so one ioc that does not match this makes it reject the entire report
function matches_rust_types(type: types.IoCType, value: any): boolean {
    const is_str = (v: any) => typeof v === "string";
    switch (type) {
        case types.IoCType.HttpRequest:
            return is_str(value.method) && is_str(value.url) && is_str(value.data);
        case types.IoCType.FunctionCall:
            return is_str(value.callee) && Array.isArray(value.arguments) && value.arguments.every(is_str);
        case types.IoCType.NewNetworkHtmlElement:
            return is_str(value.elementType) && is_str(value.src);
        case types.IoCType.SetCookie:
        case types.IoCType.GetCookie:
            return is_str(value.cookie);
        case types.IoCType.AddEventListener:
            return is_str(value.listener);
        default:
            return true;
    }
}

async function launch_browser(): Promise<Browser> {
    return puppeteer.launch({
        headless: true,
        args: ["--ignore-certificate-errors", "--disable-web-security", "--disable-gpu", "--no-sandbox"]
    });
}

export {
    HookedPage,
    TestServer,
    launch_browser,
    matches_rust_types
}
