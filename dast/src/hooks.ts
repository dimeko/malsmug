const enum EventType {
    HttpRequest = "http_request",
    HttpResposne = "http_response",
    FunctionCall = "function_call",
    NewHtmlElement = "new_html_element",
    SetCookie = "set_cookie",
    GetCookie = "get_cookie",
    ConsoleLog = "console_log"
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

type Event = {
    type: EventType,
    value: EventHttpRequest | EventFunctionCall | EventNewHtmlElement | EventSetCookie | EventGetCookie | EventHttpResponse | EventConsoleLog,
}

function place_hooks() {
    const originalSetItem = window.localStorage.setItem;
    window.localStorage.setItem = function (key: string, value: string) {
        let _event: Event = {
            type: EventType.FunctionCall,
            value: {
                callee: "localStorage.setItem",
                arguments: [key, value]
            } as EventFunctionCall
        }
        console.log(`[event]:${JSON.stringify(_event)}`);
        return originalSetItem.apply(this, [key, value] as [key: string, value: string]);
    };

    const originalGetItem = window.localStorage.getItem;
    window.localStorage.getItem = function (key: string) {
        let _event: Event = {
            type: EventType.FunctionCall,
            value: {
                callee: "localStorage.getItem",
                arguments: [key]
            } as EventFunctionCall
        }
        console.log(`[event]:${JSON.stringify(_event)}`);
        return originalGetItem.apply(this, [key] as [key: string]);
    };

    const originalFetch = window.fetch;
    window.fetch = function (...args) {
        let _event: Event = {
            type: EventType.HttpRequest,
            value: {
                url: args[0],
                method: "GET",
                data: ""
            } as EventHttpRequest
        }
        console.log(`[event]:${JSON.stringify(_event)}`);
        return originalFetch.apply(this, args);
    };

    const originalXHROpen = window.XMLHttpRequest.prototype.open;
    window.XMLHttpRequest.prototype.open = function(...args: any) {
        let _event: Event = {
            type: EventType.HttpRequest,
            value: {
                url: args[1],
                method: args[0],
                data: ""
            } as EventHttpRequest
        }
        console.log(`[event]:${JSON.stringify(_event)}`);
        return originalXHROpen.apply(this, args);
    };

    // XMLHttpRequest.send hook logs will appear right below the logs
    // of XMLHttpRequest.open hook
    const originalXHRSend = window.XMLHttpRequest.prototype.send;
    window.XMLHttpRequest.prototype.send = function(...args: any) {
        let _event: Event = {
            type: EventType.HttpRequest,
            value: {
                url: "",
                method: "",
                data: JSON.stringify(args)
            } as EventHttpRequest
        }
        console.log(`[event]:${JSON.stringify(_event)}`);
        return originalXHRSend.apply(this, args);
    };

    let originalCookies = document.cookie;
    Object.defineProperty(document, "cookie", {
        get: function () {
            let _event: Event = {
                type: EventType.GetCookie,
                value: {
                    cookie: originalCookies,
                } as EventGetCookie
            }
            console.log(`[event]:${JSON.stringify(_event)}`);
            return originalCookies;
        },
        set: function (value) {
            let _event: Event = {
                type: EventType.SetCookie,
                value: {
                    cookie: value,
                } as EventSetCookie
            }
            console.log(`[event]:${JSON.stringify(_event)}`);
            originalCookies += value + "; "; 
        }
    });

    const observer = new MutationObserver((mutationList) => {
        for (const mutation of mutationList) {
            mutation.addedNodes.forEach((node: Node) => {
                let _event: Event = {
                    type: EventType.NewHtmlElement,
                    value: {
                        elementType: node.nodeName.toLowerCase()
                    } as EventNewHtmlElement
                }
                console.log(`[event]:${JSON.stringify(_event)}`);
            });
        }
    });

    observer.observe(document.body, { childList: true, subtree: true });

}

export {
    place_hooks,
    EventType,
    EventConsoleLog,
    EventHttpResponse,
    Event
}