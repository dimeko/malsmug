import puppeteer from "puppeteer";
import fs from "fs";
import path from "path";

const scriptFile = process.argv[2];

if (!scriptFile) {
    console.error("Error: No JavaScript file provided!");
    process.exit(1);
}

if (!fs.existsSync(scriptFile)) {
    console.error(`Error: File "${scriptFile}" not found!`);
    process.exit(1);
}

(async () => {
    console.log("[analysis-debug] Launching browser...");
    const browser = await puppeteer.launch({
        headless: true,
        dumpio: true,
        executablePath: "/js_dast/browsers/chrome/linux-134.0.6998.35/chrome-linux64/chrome",
        args: [
            "--ignore-certificate-errors",
            "--disable-setuid-sandbox",
            "--disable-web-security",
            "--disable-features=IsolateOrigins,site-per-process",
            "--disable-gpu",
            "--no-sandbox"]
    });
    console.log("[analysis-debug] Launched ...");
    const page = await browser.newPage();
    await page.goto('https://google.com');
    console.log("[analysis-debug] Hooking JavaScript APIs...");
    page
    .on('console', message =>
      console.log(`[target-console] ${message.text()}`))
    .on('pageerror', ({ message }) => console.log(`[target-pageerror] ${message}`))
    .on('response', response => {
            console.log(`[target-response] ${response.status()} ${response.url()}`)
            response.json().then((_r) => {
                console.log(`[target-response][success] ${_r}`)
            }).catch((_e) => {
                console.log(`[target-response][error] ${_e}`)
            })
        }
    )

    await page.evaluate(() => {
        const originalSetItem = window.localStorage.setItem;
        window.localStorage.setItem = function (key: string, value: string) {
            console.log(`[hook-debug][localStorage.setItem] localStorage.setItem(${key}, ${value})`);
            return originalSetItem.apply(this, [key, value] as [key: string, value: string]);
        };

        const originalGetItem = window.localStorage.getItem;
        window.localStorage.getItem = function (key: string) {
            console.log(`[hook-debug][localStorage.getItem] localStorage.getItem(${key})`);
            return originalGetItem.apply(this, [key] as [key: string]);
        };

        const originalFetch = window.fetch;
        window.fetch = function (...args) {
            console.log(`[hook-debug][window.fetch] fetch called with`, args);
            return originalFetch.apply(this, args);
        };

        const originalXHR = window.XMLHttpRequest.prototype.open;
        window.XMLHttpRequest.prototype.open = function(...args: any) {
            console.log(`[hook-debug][window.XMLHttpRequest.prototype.open] XMLHttpRequest called with`, ...args);
            return originalXHR.apply(this, args);
        };

        let originalCookies = document.cookie;
        Object.defineProperty(document, "cookie", {
            get: function () {
                console.log("[hook-debug][document.cookie][get]");
                return originalCookies;
            },
            set: function (value) {
                console.log(`[hook-debug][document.cookie][set]:${value}`);
                originalCookies += value + "; "; 
            }
        });

        const originalWindow: Window = window;

        window = new Proxy(originalWindow, {
            get(target: Window, prop: string, receiver) {
                console.log(`[hook-debug][window][get] ${prop}`);
                return Reflect.get(target, prop, receiver);
            },
            set(target: Window, prop: string, value: any, receiver) {
                console.log(`[hook-debug][window][set] ${prop}->${value}`);
                return Reflect.set(target, prop, value, receiver);
            }
        }) as Window & typeof globalThis;
    });

    console.log(`[analysis-debug] Executing script: ${scriptFile}`);
    
    const scriptCode = fs.readFileSync(scriptFile, "utf-8");
    // console.log("code: ", scriptCode);
    await page.evaluate(scriptCode);

    console.log("[analysis-debug] Closing browser...");
    await browser.close();
})();
