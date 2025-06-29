import puppeteer from "puppeteer";
import fs from "fs";
import { place_hooks } from "./hooks";
import { Lure } from "./lure";
import { RBMQ } from "./rbmq";
import * as types from "./types";
import rsg from "random-string-generator";
import yaml from 'yaml';
import { sha256 } from 'js-sha256';
import * as log from "log4js";
import { validate_logging_level } from "./utils";
const args = process.argv;

var sampleFile = args[2]
var baitWebsite = args[3]
var configFolder = args[4]
var analysisId = args[5]

const log_level = process.env.LOG_LEVEL;
let logger = log.getLogger();
logger.level = validate_logging_level(log_level ? log_level : 'info')

if (!sampleFile) {
    logger.error("Error: No JavaScript file provided!");
    process.exit(1);
}

if (!fs.existsSync(sampleFile)) {
    logger.error(`Error: File "${sampleFile}" not found!`);
    process.exit(1);
}

(async () => {
    logger.info("[analysis-debug] Launching browser ...");
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
    logger.info("[analysis-debug] Connecting to RabbitMQ ...");

    const rabbitmq_config_file = fs.readFileSync(configFolder + "/rabbitmq.yaml", 'utf8');
    const rabbitmq_config: types.RabbitMQConfig = yaml.parse(rabbitmq_config_file);

    let rbmqc = await RBMQ.create(rabbitmq_config)

    logger.info("[analysis-debug] Launched ...");
    const page = await browser.newPage();

    await page.goto(baitWebsite);
    logger.info("[analysis-debug] Hooking JavaScript APIs...");

    page.on('console', message => {
                logger.debug(`[dom-console]: ${message.text()}`);
        })
    let events: types.IoC[] = [];

    var random_string = rsg()
    var reportIocFunctionName = 'reportIoC' + random_string;
    logger.info('[analysis-debug] report Ioc function name:', reportIocFunctionName);

    // here we actually push events to the their final destination, the sandbox_ioc_queue
    // we can perform any kind of normalization to the event
    await page.exposeFunction(reportIocFunctionName, (event: types.IoC) => {
        logger.debug('[analysis-debug] suspicious activity: ', event);
        event.executed_on = baitWebsite
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
        logger.info(`[analysis-debug] Executing script`);   
        const scriptCode = fs.readFileSync(sampleFile, "utf-8");         
        await page.evaluate(scriptCode);
        
        logger.info(`[analysis-debug] Executing Lure`);            
        const lure = new Lure(page)
        logger.info(`[analysis-debug] Starting Lure`);
        await lure.start_lure()
        logger.info(`[analysis-debug] Finishing Lure`);
        setTimeout(async () => { 
            let event_for_analysis: types.IoCsFromAnalysis = {
                file_hash: sha256(scriptCode),
                analysis_id: analysisId,
                iocs: events
            }
            await rbmqc.publish(rabbitmq_config.queues.sandbox_iocs_queue.name, event_for_analysis)
            try {
                fs.rmSync(sampleFile)
            } catch(e) {
                logger.error("Could not remove sample file")
            }
            await rbmqc.close();
            await page.close();
            process.exit(0)
        }, 1000);
    } catch(err) {
        if (err instanceof SyntaxError) {
            logger.error("Error running script: SyntaxError")
        } else {
            logger.error("Unknown error: ", err);
        }
        await rbmqc.publish(rabbitmq_config.queues.sandbox_iocs_queue.name, `error analysing sample: ${err}`)
        await rbmqc.close();
        await page.close();
        process.exit(1)
    }
    process.exit(0)
})();
