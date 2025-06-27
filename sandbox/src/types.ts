const enum EventType {
    HttpRequest = "http_request",
    HttpResposne = "http_response",
    FunctionCall = "function_call",
    NewHtmlElement = "new_html_element",
    SetCookie = "set_cookie",
    GetCookie = "get_cookie",
    ConsoleLog = "console_log",
    AddEventListener = "add_event_listener"
}

type EventHttpRequest = {
    method: string,
    url: string,
    data: string
}

type EventHttpResponse = {
    status: String,
    url: string,
    data: string
}

type EventConsoleLog = {
    text: string
}

type EventFunctionCall = {
    callee: string,
    arguments: string[]
}

type EventNewHtmlElement = {
    elementType: string
}

type EventSetCookie = {
    cookie: string
}

type EventGetCookie = {
    cookie: string
}

type EventAddEventListener = {
    listener: string
}


type Event = {
    type: EventType,
    timestamp: number,
    value: EventHttpRequest | 
        EventFunctionCall | 
        EventNewHtmlElement | 
        EventSetCookie | 
        EventGetCookie | 
        EventHttpResponse | 
        EventConsoleLog | 
        EventAddEventListener,
}

type EventsFromAnalysis = {
    file_hash: string,
    events: Event[]
}

export {
    Event,
    EventType,
    EventHttpRequest, 
    EventFunctionCall, 
    EventNewHtmlElement, 
    EventSetCookie, 
    EventGetCookie, 
    EventHttpResponse, 
    EventConsoleLog, 
    EventAddEventListener,
    EventsFromAnalysis
}