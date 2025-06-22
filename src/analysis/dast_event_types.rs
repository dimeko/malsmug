use serde::{Serialize, Deserialize};
use core::fmt;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    HttpRequest,
    HttpResponse,
    FunctionCall,
    NewHtmlElement,
    SetCookie,
    GetCookie,
    ConsoleLog,
    AddEventListener
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter) -> std::fmt::Result {
        match self {
            EventType::HttpRequest => write!(f, "http_request"),
            EventType::HttpResponse => write!(f, "http_response"),
            EventType::FunctionCall => write!(f, "function_call"),
            EventType::NewHtmlElement => write!(f, "new_html_element"),
            EventType::SetCookie => write!(f, "set_cookie"),
            EventType::GetCookie => write!(f, "get_cookie"),
            EventType::ConsoleLog => write!(f, "console_log"),
            EventType::AddEventListener => write!(f, "add_event_listenet"),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EventHttpRequest {
    pub method: String,
    pub url: String,
    pub data: String
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EventHttpResponse {
    pub status: String,
    pub url: String,
    pub data: String
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EventConsoleLog {
    pub text: String
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EventFunctionCall {
    pub callee: String,
    pub arguments: Vec<String>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EventNewHtmlElement {
    #[serde(rename = "elementType")]
    pub element_type: String
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EventSetCookie {
    pub cookie: String
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EventGetCookie {
    pub cookie: String
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EventAddEventListener {
    pub listener: String
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum EventValue {
    EventHttpRequest(EventHttpRequest),
    EventHttpResponse(EventHttpResponse),
    EventFunctionCall(EventFunctionCall),
    EventNewHtmlElement(EventNewHtmlElement),
    EventSetCookie(EventSetCookie),
    EventGetCookie(EventGetCookie),
    EventConsoleLog(EventConsoleLog),
    EventAddEventListener(EventAddEventListener)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Event {
    #[serde(rename = "type")]
    pub event_type: EventType,
    pub value: EventValue,
}
