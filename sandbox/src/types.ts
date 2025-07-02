interface RabbitMQQueue {
    name: string;
    durable: boolean;
    auto_delete: boolean;
}

interface RabbitMQExchange {
    name: string;
}

interface RabbitMQConfig {
    connection: {
        host: string;
        port: number;
        username: string;
        password: string;
    };
    queues: {
        core_files_queue: RabbitMQQueue;
        sandbox_iocs_queue: RabbitMQQueue;
    };
    exchanges: {
        main_exchange: RabbitMQExchange;
    }
}

const enum IoCType {
    HttpRequest = "http_request",
    HttpResposne = "http_response",
    FunctionCall = "function_call",
    NewNetworkHtmlElement = "new_network_html_element",
    SetCookie = "set_cookie",
    GetCookie = "get_cookie",
    ConsoleLog = "console_log",
    AddEventListener = "add_event_listener",
    SetTimeout = "set_timeout",
}

type IoCHttpRequest = {
    method: string,
    url: string,
    data: string
}

type IoCHttpResponse = {
    status: String,
    url: string,
    data: string
}

type IoCConsoleLog = {
    text: string
}

type IoCSetTimeout = {
    delay: number,
    arguments: any[]
}

type IoCFunctionCall = {
    callee: string,
    arguments: string[]
}

type IoCNewNetworkHtmlElement = {
    elementType: string,
    src: string
}

type IoCSetCookie = {
    cookie: string
}

type IoCGetCookie = {
    cookie: string
}

type IoCAddEventListener = {
    listener: string
}

type IoC = {
    type: IoCType,
    executed_on: string,
    timestamp: number,
    value: IoCHttpRequest | 
        IoCFunctionCall | 
        IoCNewNetworkHtmlElement | 
        IoCSetCookie | 
        IoCGetCookie | 
        IoCHttpResponse | 
        IoCConsoleLog | 
        IoCSetTimeout |
        IoCAddEventListener,
}

type IoCsFromAnalysis = {
    file_hash: string,
    analysis_id: string,
    iocs: IoC[]
}

export {
    IoC,
    IoCType,
    IoCHttpRequest, 
    IoCFunctionCall, 
    IoCNewNetworkHtmlElement, 
    IoCSetCookie, 
    IoCGetCookie, 
    IoCHttpResponse, 
    IoCConsoleLog, 
    IoCAddEventListener,
    IoCSetTimeout,
    IoCsFromAnalysis,
    RabbitMQConfig,
    RabbitMQQueue,
    RabbitMQExchange
}