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
    console.log("[*] Launching browser...");
    const browser = await puppeteer.launch({
        headless: true,
        args: ["--disable-web-security", "--disable-features=IsolateOrigins,site-per-process", "--no-sandbox"]
    });

    const page = await browser.newPage();
    await page.goto('https://example.com');
    console.log("[*] Hooking JavaScript APIs...");
    page
    .on('console', message =>
      console.log(`[browser] ${message.type().substr(0, 3).toUpperCase()} ${message.text()}`))
    .on('pageerror', ({ message }) => console.log(`[browser] ${message}`))
    .on('response', response =>
      console.log(`[browser] ${response.status()} ${response.url()}`))

    await page.evaluate(() => {
        const originalSetItem = localStorage.setItem;
        localStorage.setItem = function (key: string, value: string) {
            console.log(`[Hook] localStorage.setItem(${key}, ${value})`);
            return originalSetItem.apply(this, [key, value] as [key: string, value: string]);
        };

        const originalGetItem = localStorage.getItem;
        localStorage.getItem = function (key: string) {
            console.log(`[Hook] localStorage.getItem(${key})`);
            return originalGetItem.apply(this, [key] as [key: string]);
        };

        const originalFetch = window.fetch;
        window.fetch = function (...args) {
            console.log(`[Hook] fetch called with`, args);
            return originalFetch.apply(this, args);
        };

        const originalXHR = window.XMLHttpRequest.prototype.open;
        window.XMLHttpRequest.prototype.open = (method: string, url: any , async?: boolean, username?: string, password?: string) => {
            console.log(`[Hook] XMLHttpRequest called with`, method, url, async, username, password);
            return originalXHR.apply(this, [
                method, url, async, username, password] as [
                    method: string,
                    url: string | URL,
                    async: boolean,
                    username?: string | null | undefined,
                    password?: string | null | undefined]);
        };
    });

    console.log(`[*] Executing script: ${scriptFile}`);
    
    const scriptCode = fs.readFileSync(scriptFile, "utf-8");
    // console.log("code: ", scriptCode);
    await page.evaluate(scriptCode);

    console.log("[*] Closing browser...");
    await browser.close();
})();
