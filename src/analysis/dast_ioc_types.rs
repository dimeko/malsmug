use serde::{Serialize, Deserialize};
use core::fmt;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub enum IoCType {
    HttpRequest,
    HttpResponse,
    FunctionCall,
    NewHtmlElement,
    SetCookie,
    GetCookie,
    ConsoleLog,
    AddEventListener
}

impl fmt::Display for IoCType {
    fn fmt(&self, f: &mut fmt::Formatter) -> std::fmt::Result {
        match self {
            IoCType::HttpRequest => write!(f, "http_request"),
            IoCType::HttpResponse => write!(f, "http_response"),
            IoCType::FunctionCall => write!(f, "function_call"),
            IoCType::NewHtmlElement => write!(f, "new_html_element"),
            IoCType::SetCookie => write!(f, "set_cookie"),
            IoCType::GetCookie => write!(f, "get_cookie"),
            IoCType::ConsoleLog => write!(f, "console_log"),
            IoCType::AddEventListener => write!(f, "add_event_listener"),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IoCHttpRequest {
    pub method: String,
    pub url: String,
    pub data: String
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IoCHttpResponse {
    pub status: String,
    pub url: String,
    pub data: String
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IoCConsoleLog {
    pub text: String
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IoCFunctionCall {
    pub callee: String,
    pub arguments: Vec<String>
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IoCNewHtmlElement {
    #[serde(rename = "elementType")]
    pub element_type: String
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IoCSetCookie {
    pub cookie: String
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IoCGetCookie {
    pub cookie: String
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IoCAddEventListener {
    pub listener: String
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum IoCValue {
    IoCHttpRequest(IoCHttpRequest),
    IoCHttpResponse(IoCHttpResponse),
    IoCFunctionCall(IoCFunctionCall),
    IoCNewHtmlElement(IoCNewHtmlElement),
    IoCSetCookie(IoCSetCookie),
    IoCGetCookie(IoCGetCookie),
    IoCConsoleLog(IoCConsoleLog),
    IoCAddEventListener(IoCAddEventListener)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IoC {
    #[serde(rename = "type")]
    pub ioc_type: IoCType,
    pub executed_on: String,
    pub timestamp: u64,
    pub value: IoCValue,
}
