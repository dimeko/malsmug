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
import { default_rabbitmq_conf, malicious_mime_types } from "./const"
import commandLineArgs from 'command-line-args'

const MAX_SET_TIMEOUT_DELAY_TO_WAIT = 5000;
const log_level = process.env.LOG_LEVEL;
let logger = log.getLogger();
logger.level = validate_logging_level(log_level ? log_level : 'info')
// const args = process.argv;
const cli_arg_options = [
    { name: 'dev', alias: 'd', type: Boolean, defaultValue: false },
    { name: 'just-check-page', alias: 'p', type: Boolean, defaultValue: false },
    { name: 'sample-file', alias: 'f', type: String, defaultValue: "" },
    { name: 'bait-website', alias: 'w', type: String, defaultValue: "https://google.com" },
    { name: 'conf-folder', alias: 'c', type: String, defaultValue: "/sandbox/config" },
    { name: 'analysis-id', alias: 'a', type: String, defaultValue: ""}
]

const cli_args = commandLineArgs(cli_arg_options)

logger.debug("cli_args: ", cli_args)
var sampleFile = cli_args["sample-file"]
var justCheckPage = cli_args["just-check-page"]

var baitWebsite = cli_args["bait-website"]
var configFolder = cli_args["conf-folder"]
var analysisId = cli_args["analysis-id"]

if (!sampleFile && !justCheckPage) {
    logger.error("Error: No JavaScript file provided!");
    process.exit(1);
}

if (!fs.existsSync(sampleFile) && !justCheckPage) {
    logger.error(`Error: File "${sampleFile}" not found!`);
    process.exit(1);
}

(async () => {
    logger.info("[analysis-info] Launching browser ...");
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
    logger.info("[analysis-info] Connecting to RabbitMQ ...");

    let rbmqc = await RBMQ.empty()
    let rabbitmq_config: types.RabbitMQConfig = default_rabbitmq_conf;
    try {
        const rabbitmq_config_file = fs.readFileSync(configFolder + "/rabbitmq.yaml", 'utf8');
        rabbitmq_config = yaml.parse(rabbitmq_config_file);
        rbmqc = await RBMQ.create(rabbitmq_config)
    } catch(err) {
        if (cli_args.dev) {
            logger.warn("[analysis-warn] In development mode, skipping queue connection ...");
        } else {
            logger.error(`[analysis-error] Could not connect to queue: ${err}`);
            process.exit(1)
        }
    }
    let iocs: types.IoC[] = [];

    logger.info("[analysis-info] Launched ...");
    const page = await browser.newPage();
    await page.setRequestInterception(true);
    page.on('request', request => {
        request.continue();
    });

    page.on('response', async response => {
        const headers = response.headers();
        if (malicious_mime_types.includes(headers["content-type"])) {
            logger.debug('[analysis-debug] suspicious file download');
            let file_extension = "";
            try {
                file_extension = headers["content-type"].split("/")[1]
            } catch(err) {
                logger.debug('[analysis-debug] could not get downloaded file extension');
            }
            let byte_array = Array.from(await response.content())
            let ioc = {
                type: types.IoCType.SuspiciousFileDownload,
                timestamp: Date.now(),
                executed_on: baitWebsite,
                value: {
                    url: response.url(),
                    extension: file_extension,
                    data: byte_array
                } as types.IoCSuspiciousFileDownload
            }
            logger.debug('[analysis-debug] adding ioc: ', ioc);
            iocs.push(ioc);
        }
    });
    browser.on('targetcreated', async target => {
        logger.warn("new page loaded: ", target)
    })

    // visiting bait_websites
    await page.goto(baitWebsite, {
        waitUntil: ['domcontentloaded', 'networkidle0']
    });
    logger.info("[analysis-info] Hooking JavaScript APIs...");

    page.on('console', message => {
        logger.debug(`[dom-console]: ${message.text()}`);
    })

    let max_delay = 0;

    // a random string suffix is created every time the analyser runs to make
    // sure Javascript cannot find and call our hook and mess with the analyser
    var random_string = rsg()
    var reportIocFunctionName = 'reportIoC' + random_string;
    logger.info('[analysis-info] report Ioc function name:', reportIocFunctionName);

    // here we actually push iocs to the their final destination, the sandbox_ioc_queue
    // we can perform any kind of normalization to the event
    await page.exposeFunction(reportIocFunctionName, (ioc: types.IoC) => {
        if (ioc.type == types.IoCType.SetTimeout) {
            let setTimeoutDelay = (ioc.value as types.IoCSetTimeout).delay
            logger.debug(
                '[analysis-debug] setTimeout was set with delay: ',
                setTimeoutDelay)
                if (max_delay < setTimeoutDelay && setTimeoutDelay <= MAX_SET_TIMEOUT_DELAY_TO_WAIT) {
                    max_delay = setTimeoutDelay
                }
        } else {
            logger.debug('[analysis-debug] adding ioc: ', ioc);
            ioc.executed_on = baitWebsite
            iocs.push(
                ioc
            );
        }
    });
    const place_hooks_source_code = place_hooks.toString();

    // we have to also set a random string suffix at the name of the place_hooks function
    // as Javascript can interact with it as soon as it is placed in the browser and possibly
    // prevent hooking!
    try {
        let place_hooks_wrapper = `
            ${place_hooks_source_code}

            place_hooks("${reportIocFunctionName}")
        `;
        // set the hooks in the browser
        await page.evaluate(place_hooks_wrapper);
        logger.info(`[analysis-info] Executing sample`);
    
        let fileHash = ""
        if(!justCheckPage){
            // open the sample copy
            const scriptCode = fs.readFileSync(sampleFile, "utf-8");
            fileHash = sha256(scriptCode)
    
            // run the sample file in the browser     
            await page.evaluate(scriptCode);
        }
        
        // run the Lure          
        const lure = new Lure(page)
        logger.debug(`[analysis-debug] Starting Lure`);
        await lure.start_lure()

        logger.debug(`[analysis-debug] Finishing Lure`);
        logger.info(`[analysis-info] Waiting for ${max_delay} before closing page`);
        await new Promise(resolve =>
            setTimeout(resolve, max_delay + 1000)
        );
        await page.close();

        if (!cli_args.dev) {
            let iocs_for_analysis: types.IoCsFromAnalysis = {
                file_hash: fileHash,
                analysis_id: analysisId,
                iocs: iocs
            }
            logger.info(`[analysis-info] found ${iocs_for_analysis.iocs.length} iocs`)
            await rbmqc.publish(rabbitmq_config.queues.sandbox_iocs_queue.name, iocs_for_analysis)
            try {
                fs.rmSync(sampleFile)
            } catch(e) {
                logger.error("Could not remove sample file")
            }
            await rbmqc.close();
        }

        process.exit(0)
    } catch(err) {
        if (err instanceof SyntaxError) {
            logger.error("Error running script: SyntaxError")
        } else {
            logger.error("Unknown error: ", err);
        }
        await page.close();
        if (!cli_args.dev) {
            // should send errors to another queue or anywhere else
            await rbmqc.publish(rabbitmq_config.queues.sandbox_iocs_queue.name, `error analysing sample: ${err}`)
            await rbmqc.close();
        }
        process.exit(1)
    }
})();
