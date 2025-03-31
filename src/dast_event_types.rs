use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    HttpRequest,
    HttpResponse,
    FunctionCall,
    NewHtmlElement,
    SetCookie,
    GetCookie,
    ConsoleLog
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
#[serde(untagged)]
pub enum EventValue {
    EventHttpRequest(EventHttpRequest),
    EventHttpResponse(EventHttpResponse),
    EventFunctionCall(EventFunctionCall),
    EventNewHtmlElement(EventNewHtmlElement),
    EventSetCookie(EventSetCookie),
    EventGetCookie(EventGetCookie),
    EventConsoleLog(EventConsoleLog)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Event {
    #[serde(rename = "type")]
    pub event_type: EventType,
    pub value: EventValue,
}
