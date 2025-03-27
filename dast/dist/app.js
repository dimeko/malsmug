"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const puppeteer_1 = require("puppeteer");
const fs_1 = require("fs");
const scriptFile = process.argv[2];
if (!scriptFile) {
    console.error("Error: No JavaScript file provided!");
    console.error("Usage: docker run --rm -v $(pwd)/test.js:/sandbox/test.js js-sandbox /sandbox/test.js");
    process.exit(1);
}
if (!fs_1.default.existsSync(scriptFile)) {
    console.error(`Error: File "${scriptFile}" not found!`);
    process.exit(1);
}
(() => __awaiter(void 0, void 0, void 0, function* () {
    console.log("[*] Launching browser...");
    const browser = yield puppeteer_1.default.launch({
        headless: true,
        args: ["--disable-web-security", "--disable-features=IsolateOrigins,site-per-process"]
    });
    const page = yield browser.newPage();
    console.log("[*] Hooking JavaScript APIs...");
    yield page.evaluate(() => {
        const originalSetItem = localStorage.setItem;
        localStorage.setItem = function (key, value) {
            console.log(`[Hook] localStorage.setItem(${key}, ${value})`);
            return originalSetItem.apply(this, arguments);
        };
        const originalGetItem = localStorage.getItem;
        localStorage.getItem = function (key) {
            console.log(`[Hook] localStorage.getItem(${key})`);
            return originalGetItem.apply(this, arguments);
        };
        const originalFetch = window.fetch;
        window.fetch = function (...args) {
            console.log(`[Hook] fetch called with`, args);
            return originalFetch.apply(this, args);
        };
        const originalXHR = window.XMLHttpRequest.prototype.open;
        window.XMLHttpRequest.prototype.open = function (...args) {
            console.log(`[Hook] XMLHttpRequest called with`, args);
            return originalXHR.apply(this, args);
        };
    });
    console.log(`[*] Executing script: ${scriptFile}`);
    const scriptCode = fs_1.default.readFileSync(scriptFile, "utf-8");
    yield page.evaluate(scriptCode);
    console.log("[*] Closing browser...");
    yield browser.close();
}))();
