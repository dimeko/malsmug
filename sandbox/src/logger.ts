import * as log from "log4js";

const logger = log.getLogger();

function validate_logging_level(lv: string): string {
    switch(lv) {
        case 'debug':{return 'debug'}
        case 'info':{return 'info'}
        case 'warn':{return 'warn'}
        case 'warning':{return 'warn'}
        case 'error':{return 'error'}
        default:{return 'info'}
    }
}

// must be called before any logging. In dev mode stdout is reserved for
// the iocs report, so logs go to stderr
function init_logger(dev: boolean) {
    if (dev) {
        log.configure({
            appenders: { err: { type: 'stderr' } },
            categories: { default: { appenders: ['err'], level: 'info' } }
        })
    }
    const log_level = process.env.LOG_LEVEL;
    logger.level = validate_logging_level(log_level ? log_level : 'info')
}

function analysis_debug(message: string, ...args: any[]) {
    logger.debug(`[analysis-debug] ${message}`, ...args);
}

function analysis_info(message: string, ...args: any[]) {
    logger.info(`[analysis-info] ${message}`, ...args);
}

function analysis_warn(message: string, ...args: any[]) {
    logger.warn(`[analysis-warn] ${message}`, ...args);
}

function analysis_error(message: string, ...args: any[]) {
    logger.error(`[analysis-error] ${message}`, ...args);
}

function dom_console(message: string) {
    logger.debug(`[dom-console]: ${message}`);
}

export {
    init_logger,
    analysis_debug,
    analysis_info,
    analysis_warn,
    analysis_error,
    dom_console
}
