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
export {
    validate_logging_level
}