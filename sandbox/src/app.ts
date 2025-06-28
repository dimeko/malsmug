import puppeteer from "puppeteer";
import fs from "fs";
import { place_hooks } from "./hooks";
import { Lure } from "./lure";
import { RBMQ } from "./rbmq";
import * as types from "./types";
import rsg from "random-string-generator";
import yaml from 'yaml';
import { sha256 } from 'js-sha256';

const args = process.argv;

var sampleFile = args[2]
var baitWebsite = args[3]
var configFolder = args[4]
var analysisId = args[5]

if (!sampleFile) {
    console.error("Error: No JavaScript file provided!");
    process.exit(1);
}

if (!fs.existsSync(sampleFile)) {
    console.error(`Error: File "${sampleFile}" not found!`);
    process.exit(1);
}

(async () => {
    console.log("[analysis-debug] Launching browser ...");
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
    console.log("[analysis-debug] Connecting to RabbitMQ ...");

    const rabbitmq_config_file = fs.readFileSync(configFolder + "/rabbitmq.yaml", 'utf8');
    const rabbitmq_config: types.RabbitMQConfig = yaml.parse(rabbitmq_config_file);

    let rbmqc = await RBMQ.create(rabbitmq_config)

    console.log("[analysis-debug] Launched ...");
    const page = await browser.newPage();

    await page.goto(baitWebsite);
    console.log("[analysis-debug] Hooking JavaScript APIs...");

    page.on('console', message => {
                console.log(`[dom-console]: ${message.text()}`);
        })
    let events: types.Event[] = [];

    var random_string = rsg()
    var reportIocFunctionName = 'reportIoC' + random_string;
    console.log('[analysis-debug] report Ioc function name:', reportIocFunctionName);
    await page.exposeFunction(reportIocFunctionName, (event: types.Event) => {
        console.log('[analysis-debug] suspicious activity: ', event);
        events.push(
            event
        );
    });
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
            let event_for_analysis: types.EventsFromAnalysis = {
                file_hash: sha256(scriptCode),
                analysis_id: analysisId,
                events: events
            }
            await rbmqc.publish(rabbitmq_config.queues.sandbox_iocs_queue.name, event_for_analysis)
            try {
                fs.rmSync(sampleFile)
            } catch(e) {
                console.log("[analysis-error] Could not remove sample file")
            }
            await page.close();
        }, 1000);
    } catch(err) {
        if (err instanceof SyntaxError) {
            console.log("[analysis-error] Error running script: SyntaxError")
        } else {
            console.log("[analysis-error] Unknown error: ", err);
        }
        await rbmqc.publish(rabbitmq_config.queues.sandbox_iocs_queue.name, `error analysing sample: ${err}`)
        await page.close();
    }
})();
