import puppeteer from "puppeteer";
import fs from "fs";
import { place_hooks, EventType, EventConsoleLog, EventHttpResponse, Event } from "./hooks";
import { Lure } from "./lure";
import { RBMQ } from "./rbmq";

import rsg from "random-string-generator";

const RABBITMQ_MALSMUG_ANALYSIS_EXCHANGE = "malsmug.analysis"
const RABBITMQ_FILES_QUEUE = "malsmug.files_queue"
const RABBITMQ_REPORTS_QUEUE = "malsmug.reports_queue"


// const urlToVisit = "https://facebook.com";
const args = process.argv;


var sampleFile = args[2]
var baitWebsite = args[3]

if (!sampleFile) {
    console.error("Error: No JavaScript file provided!");
    process.exit(1);
}

if (!fs.existsSync(sampleFile)) {
    console.error(`Error: File "${sampleFile}" not found!`);
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
        "rabbitmq",
        RABBITMQ_MALSMUG_ANALYSIS_EXCHANGE,
        RABBITMQ_FILES_QUEUE
    )

    // while(true) {
    //     await rbmqc.consume(RABBITMQ_FILES_QUEUE, async (buff: Buffer<ArrayBufferLike>) => {
    console.log("[analysis-debug] Launched ...");
    const page = await browser.newPage();

    await page.goto(baitWebsite);
    console.log("[analysis-debug] Hooking JavaScript APIs...");

    page.on('console', message => {
            // if(!message.text().startsWith("[dom-console]")) {
                // let _event: Event = {
                //     type: EventType.ConsoleLog,
                //     value: {
                //         text: message.text()
                //     } as EventConsoleLog
                // }
                console.log(`[dom-console]: ${message.text()}`);
            // } else {
            //     console.log(`${message.text()}`)
            // }
        })
    //     .on('response', response => {
    //             response.json().then((_r) => {
    //                 let _event: Event = {
    //                     type: EventType.HttpResposne,
    //                     value: {
    //                         url: response.url(),
    //                         status: String(response.status()),
    //                         data: JSON.stringify(_r)
    //                     } as EventHttpResponse
    //                 }
    //                 console.log(`[event]:${JSON.stringify(_event)}`);
    //             }).catch((_e) => {
    //                 let _event: Event = {
    //                     type: EventType.HttpResposne,
    //                     value: {
    //                         url: response.url(),
    //                         status: String(response.status()),
    //                         data: JSON.stringify(_e)
    //                     } as EventHttpResponse
    //                 }
    //                 console.log(`[event]:${JSON.stringify(_event)}`);
    //             })
    //         }
    //     )
    let events: Event[] = [];

    var random_string = rsg()
    var reportIocFunctionName = 'reportIoC' + random_string;
    console.log('[analysis-debug] report Ioc function name:', reportIocFunctionName);
    await page.exposeFunction(reportIocFunctionName, (event: Event) => {
        console.log('[analysis-debug] suspicious activity: ', event);
        events.push(
            event
        );
    });
    // var initHooksFunctionName = 'initHooks' + random_string;
    // await page.exposeFunction(initHooksFunctionName, () => {
    //     place_hooks(reportIocFunctionName)
    // });
    const place_hooks_source_code = place_hooks.toString();


    try {
        let place_hooks_wrapper = `
            ${place_hooks_source_code}

            place_hooks("${reportIocFunctionName}")
        `;
        await page.evaluate(place_hooks_wrapper);
        console.log(`[analysis-debug] Executing script`);   
        const scriptCode = fs.readFileSync(sampleFile, "utf-8");         
        await page.evaluate(scriptCode);
        
        console.log(`[analysis-debug] Executing Lure`);            
        const lure = new Lure(page)
        console.log(`[analysis-debug] Starting Lure`);
        await lure.start_lure()
        console.log(`[analysis-debug] Finishing Lure`);
        setTimeout(async () => { 
            // await rbmqc.
            await rbmqc.publish(RABBITMQ_REPORTS_QUEUE, events)
            await page.close();
            // console.log("[analysis-debug] Closing browser...");
            // await browser.close(); 
        }, 1000);
    } catch(err) {
        if (err instanceof SyntaxError) {
            console.log("[analysis-error] Error running script: SyntaxError")
        } else {
            console.log("[analysis-error] Unknown error: ", err);
        }
        await rbmqc.publish(RABBITMQ_REPORTS_QUEUE, "noooooooooooooo")
        await page.close();
    }
        // })
    // }
//     setTimeout(async () => { 
//         console.log("[analysis-debug] Closing browser...");
//         await browser.close(); 
// }, 5000);
})();
