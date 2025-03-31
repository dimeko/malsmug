import puppeteer from "puppeteer";
import fs from "fs";
import { place_hooks, EventType, EventConsoleLog, EventHttpResponse, Event } from "./hooks";
import { Lure } from "./lure";

const scriptFile = process.argv[2];
const urlToVisit = process.argv[3];

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
            "--disable-web-security",
            "--disable-gpu",
            "--no-sandbox"
        ]
    });
    console.log("[analysis-debug] Launched ...");
    const page = await browser.newPage();

    await page.goto(urlToVisit);
    console.log("[analysis-debug] Hooking JavaScript APIs...");

    page.on('console', message => {
            if(!message.text().startsWith("[event]")) {
                let _event: Event = {
                    type: EventType.ConsoleLog,
                    value: {
                        text: message.text()
                    } as EventConsoleLog
                }
                console.log(`[event]:${JSON.stringify(_event)}`);
            } else {
                console.log(`${message.text()}`)
            }
        })
        .on('response', response => {
                response.json().then((_r) => {
                    let _event: Event = {
                        type: EventType.HttpResposne,
                        value: {
                            url: response.url(),
                            status: String(response.status()),
                            data: JSON.stringify(_r)
                        } as EventHttpResponse
                    }
                    console.log(`[event]:${JSON.stringify(_event)}`);
                }).catch((_e) => {
                    let _event: Event = {
                        type: EventType.HttpResposne,
                        value: {
                            url: response.url(),
                            status: String(response.status()),
                            data: JSON.stringify(_e)
                        } as EventHttpResponse
                    }
                    console.log(`[event]:${JSON.stringify(_event)}`);
                })
            }
        )

    await page.evaluate(place_hooks);

    console.log(`[analysis-debug] Executing script: ${scriptFile}`);
    
    const scriptCode = fs.readFileSync(scriptFile, "utf-8");
    
    await page.evaluate(scriptCode);
    const lure = new Lure(page)
    await lure.start_lure()

    setTimeout(async () => { 
        console.log("[analysis-debug] Closing browser...");
        await browser.close(); 
    }, 5000);
})();
