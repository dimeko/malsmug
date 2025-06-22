import puppeteer from "puppeteer";
import fs from "fs";
import { place_hooks, EventType, EventConsoleLog, EventHttpResponse, Event } from "./hooks";
import { Lure } from "./lure";
import { RBMQ } from "./rbmq";

import rsg from "random-string-generator";

const RABBITMQ_ANALYSIS_RESULTS_QUEUE = "analysis_results_queue"
const RABBITMQ_FILES_FOR_ANALYSIS = "files_for_analysis_queue"

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
        args: [
            "--ignore-certificate-errors",
            "--disable-web-security",
            "--disable-gpu",
            "--no-sandbox"
        ]
    });

    let rbmqc = await RBMQ.create(
        "rabbitmq:5672",
        "change_me_exchange_name",
        "change_me_routing_key"
    )

    while(true) {
        await rbmqc.consume(RABBITMQ_FILES_FOR_ANALYSIS, async (buff: Buffer<ArrayBufferLike>) => {
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
            let events: Event[] = [];

            var random_string = rsg()
            await page.exposeFunction('reportIoC' + random_string, async (event: Event) => {
                console.log('[analysis-debug] uspicious activity:', event);
                events.push(
                    event
                )
            });
            await page.evaluate((reportFnName: string) => {
                place_hooks(reportFnName);
            }, 'reportIoC' + random_string);

            console.log(`[analysis-debug] Executing script`);
            // const scriptCode = fs.readFileSync(scriptFile, "utf-8");
            
            await page.evaluate(buff.toString());
            const lure = new Lure(page)
            await lure.start_lure()
            setTimeout(async () => { 
                await rbmqc.publish(RABBITMQ_ANALYSIS_RESULTS_QUEUE, events)
                await page.close();
                // console.log("[analysis-debug] Closing browser...");
                // await browser.close(); 
            }, 5000);
        })
    }
    setTimeout(async () => { 
        console.log("[analysis-debug] Closing browser...");
        await browser.close(); 
}, 5000);
})();
