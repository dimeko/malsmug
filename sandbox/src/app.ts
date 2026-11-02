import puppeteer from "puppeteer";
import fs from "fs";
import { place_hooks } from "./hooks";
import { Lure } from "./lure";
import { RBMQ } from "./rbmq";
import * as types from "./types";
import rsg from "random-string-generator";
import yaml from 'yaml';
import { sha256 } from 'js-sha256';
import { init_logger, analysis_debug, analysis_info, analysis_warn, analysis_error, dom_console } from "./logger";
import { elide_byte_arrays } from "./utils";
import { default_rabbitmq_conf, malicious_mime_types } from "./const"
import commandLineArgs from 'command-line-args'

const MAX_SET_TIMEOUT_DELAY_TO_WAIT = 5000;
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

init_logger(cli_args.dev)

analysis_debug("cli_args: ", cli_args)
var sampleFile = cli_args["sample-file"]
var justCheckPage = cli_args["just-check-page"]

var baitWebsite = cli_args["bait-website"]
var configFolder = cli_args["conf-folder"]
var analysisId = cli_args["analysis-id"]

if (!sampleFile && !justCheckPage) {
    analysis_error("No JavaScript file provided!");
    process.exit(1);
}

if (!fs.existsSync(sampleFile) && !justCheckPage) {
    analysis_error(`File "${sampleFile}" not found!`);
    process.exit(1);
}

(async () => {
    analysis_info("Launching browser ...");
    const browser = await puppeteer.launch({
        headless: true,
        dumpio: !cli_args.dev,
        args: [
            "--ignore-certificate-errors",
            "--disable-web-security",
            "--disable-gpu",
            "--no-sandbox"
        ]
    });

    let rbmqc = await RBMQ.empty()
    let rabbitmq_config: types.RabbitMQConfig = default_rabbitmq_conf;
    if (cli_args.dev) {
        analysis_info("In development mode, skipping queue connection ...");
    } else {
        analysis_info("Connecting to RabbitMQ ...");
        try {
            const rabbitmq_config_file = fs.readFileSync(configFolder + "/rabbitmq.yaml", 'utf8');
            rabbitmq_config = yaml.parse(rabbitmq_config_file);
            rbmqc = await RBMQ.create(rabbitmq_config)
        } catch(err) {
            analysis_error(`Could not connect to queue: ${err}`);
            process.exit(1)
        }
    }
    let iocs: types.IoC[] = [];

    analysis_info("Launched ...");
    const page = await browser.newPage();
    await page.setRequestInterception(true);
    page.on('request', request => {
        request.continue();
    });

    page.on('response', async response => {
        const headers = response.headers();
        if (malicious_mime_types.includes(headers["content-type"])) {
            analysis_debug('suspicious file download');
            let file_extension = "";
            try {
                file_extension = headers["content-type"].split("/")[1]
            } catch(err) {
                analysis_debug('could not get downloaded file extension');
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
            analysis_debug('adding ioc: ', ioc);
            iocs.push(ioc);
        }
    });
    browser.on('targetcreated', async target => {
        analysis_warn("new page loaded: ", target)
    })

    let max_delay = 0;

    // the bait website's own activity while loading is not part of the sample's behaviour.
    // This lives here and not in the browser, so that Javascript cannot change it.
    // When just checking a page, the page itself is what is being analysed.
    let reporting = justCheckPage;

    // a random string suffix is created every time the analyser runs to make
    // sure Javascript cannot find and call our hook and mess with the analyser
    var random_string = rsg()
    var reportIocFunctionName = random_string;
    analysis_info('report Ioc function name:', reportIocFunctionName);

    // here we actually push iocs to the their final destination, the sandbox_ioc_queue
    // we can perform any kind of normalization to the event
    await page.exposeFunction(reportIocFunctionName, (ioc: types.IoC) => {
        if (!reporting) return

        if (ioc.type == types.IoCType.SetTimeout) {
            let setTimeoutDelay = (ioc.value as types.IoCSetTimeout).delay
            analysis_debug(
                'setTimeout was set with delay: ',
                setTimeoutDelay)
                if (max_delay < setTimeoutDelay && setTimeoutDelay <= MAX_SET_TIMEOUT_DELAY_TO_WAIT) {
                    max_delay = setTimeoutDelay
                }
        } else {
            analysis_debug('adding ioc: ', ioc);
            ioc.executed_on = baitWebsite
            iocs.push(
                ioc
            );
        }
    });

    // the hooks run before any script of every new document, so they survive navigations
    // and they are not left behind as a global function that Javascript can interact with
    analysis_info("Hooking JavaScript APIs...");
    await page.evaluateOnNewDocument(place_hooks, reportIocFunctionName);

    // visiting bait_websites
    await page.goto(baitWebsite, {
        waitUntil: ['domcontentloaded', 'networkidle0']
    });

    page.on('console', message => {
        dom_console(message.text());
    })

    try {
        analysis_info(`Executing sample`);
    
        let fileHash = ""
        if(!justCheckPage){
            // open the sample copy
            const scriptCode = fs.readFileSync(sampleFile, "utf-8");
            fileHash = sha256(scriptCode)
    
            // run the sample file in the browser
            reporting = true
            await page.evaluate(scriptCode);
        }
        
        // run the Lure          
        const lure = new Lure(page)
        analysis_debug(`Starting Lure`);
        await lure.start_lure()

        analysis_debug(`Finishing Lure`);
        analysis_info(`Waiting for ${max_delay} before closing page`);
        await new Promise(resolve =>
            setTimeout(resolve, max_delay + 1000)
        );
        await page.close();

        let iocs_for_analysis: types.IoCsFromAnalysis = {
            file_hash: fileHash,
            analysis_id: analysisId,
            iocs: iocs
        }
        analysis_info(`found ${iocs_for_analysis.iocs.length} iocs`)

        if (cli_args.dev) {
            console.log(JSON.stringify(iocs_for_analysis, elide_byte_arrays, 2))
        } else {
            await rbmqc.publish(rabbitmq_config.queues.sandbox_iocs_queue.name, iocs_for_analysis)
            try {
                fs.rmSync(sampleFile)
            } catch(e) {
                analysis_error("Could not remove sample file")
            }
            await rbmqc.close();
        }

        process.exit(0)
    } catch(err) {
        if (err instanceof SyntaxError) {
            analysis_error("Error running script: SyntaxError")
        } else {
            analysis_error("Unknown error: ", err);
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
