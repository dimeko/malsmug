import * as types from "./types";

function place_hooks(reportFnName: string) {
    try {
        const originalSetItem = window.localStorage.setItem;
        window.localStorage.setItem = function (key: string, value: string) {
            let _event: types.Event = {
                type: types.EventType.FunctionCall,
                timestamp: Date.now(),
                value: {
                    callee: "window.localStorage.setItem",
                    arguments: [key, value]
                } as types.EventFunctionCall
            };
            (window[reportFnName as keyof typeof window] as (event: types.Event) => void)(_event)

            return originalSetItem.apply(this, [key, value] as [key: string, value: string]);
        };

        const originalGetItem = window.localStorage.getItem;
        window.localStorage.getItem = function (key: string) {
            let _event: types.Event = {
                type: types.EventType.FunctionCall,
                timestamp: Date.now(),
                value: {
                    callee: "window.localStorage.getItem",
                    arguments: [key]
                } as types.EventFunctionCall
            };
            (window[reportFnName as keyof typeof window] as (event: types.Event) => void)(_event)

            return originalGetItem.apply(this, [key] as [key: string]);
        };

        const originalDocumentWrite = document.write;
        document.write = function (code: string) {
            let _event: types.Event = {
                type: types.EventType.FunctionCall,
                timestamp: Date.now(),
                value: {
                    callee: "document.write",
                    arguments: [code]
                } as types.EventFunctionCall
            };
            (window[reportFnName as keyof typeof window] as (event: types.Event) => void)(_event)

            return originalDocumentWrite.apply(this, [code] as [code: string]);
        };

        const originalEval = window.eval;
        window.eval = function (code: string) {
            let _event: types.Event = {
                type: types.EventType.FunctionCall,
                timestamp: Date.now(),
                value: {
                    callee: "window.eval",
                    arguments: [code]
                } as types.EventFunctionCall
            };
            (window[reportFnName as keyof typeof window] as (event: types.Event) => void)(_event)

            return originalEval.apply(this, [code] as [code: string]);
        };

        // detect Internet Explorer
        if((window as any).execScript && 
            navigator.userAgent.indexOf("MSIE ") > -1 || 
            navigator.userAgent.indexOf("Trident/") > -1) {
            const originalExecScript = (window as any).execScript;
            window.eval = function (code: string) {
                let _event: types.Event = {
                    type: types.EventType.FunctionCall,
                    timestamp: Date.now(),
                    value: {
                        callee: "window.execScript",
                        arguments: [code]
                    } as types.EventFunctionCall
                };
                (window[reportFnName as keyof typeof window] as (event: types.Event) => void)(_event)

                return originalExecScript.apply(this, [code] as [code: string]);
            };
        }

        const originalFetch = window.fetch;
        window.fetch = function (...args) {
            let _event: types.Event = {
                type: types.EventType.HttpRequest,
                timestamp: Date.now(),
                value: {
                    url: args[0],
                    method: "GET",
                    data: ""
                } as types.EventHttpRequest
            };
            (window[reportFnName as keyof typeof window] as (event: types.Event) => void)(_event)

            return originalFetch.apply(this, args);
        };

        const originalXHROpen = window.XMLHttpRequest.prototype.open;
        window.XMLHttpRequest.prototype.open = function(...args: any) {
            let _event: types.Event = {
                type: types.EventType.HttpRequest,
                timestamp: Date.now(),
                value: {
                    url: args[1],
                    method: args[0],
                    data: ""
                } as types.EventHttpRequest
            };
            (window[reportFnName as keyof typeof window] as (event: types.Event) => void)(_event)

            return originalXHROpen.apply(this, args);
        };

        // XMLHttpRequest.send hook logs will appear right below the logs
        // of XMLHttpRequest.open hook
        const originalXHRSend = window.XMLHttpRequest.prototype.send;
        window.XMLHttpRequest.prototype.send = function(...args: any) {
            try {

                let _event: types.Event = {
                    type: types.EventType.HttpRequest,
                    timestamp: Date.now(),
                    value: {
                        url: "",
                        method: "",
                        data: JSON.stringify(args)
                    } as types.EventHttpRequest
                };
                (window[reportFnName as keyof typeof window] as (event: types.Event) => void)(_event)
                
                return originalXHRSend.apply(this, args);
            } catch(err) {
                console.log("[analysis-error] Error on XMLHttpRequest.send: ", err);
            }
        }

        let originalCookies = document.cookie;
        Object.defineProperty(document, "cookie", {
            get: function () {
                let _event: types.Event = {
                    type: types.EventType.GetCookie,
                    timestamp: Date.now(),
                    value: {
                        cookie: originalCookies,
                    } as types.EventGetCookie
                };
                (window[reportFnName as keyof typeof window] as (event: types.Event) => void)(_event)

                return originalCookies;
            },
            set: function (value) {
                let _event: types.Event = {
                    type: types.EventType.SetCookie,
                    timestamp: Date.now(),
                    value: {
                        cookie: value,
                    } as types.EventSetCookie
                };
                (window[reportFnName as keyof typeof window] as (event: types.Event) => void)(_event)

                originalCookies += value + "; "; 
            }
        });

        let originalAddEventListener = document.addEventListener
        document.addEventListener = function(listener: string, fn: any) {
            let _event: types.Event = {
                type: types.EventType.AddEventListener,
                timestamp: Date.now(),
                value: {
                    listener: listener
                } as types.EventAddEventListener
            };
            (window[reportFnName as keyof typeof window] as (event: types.Event) => void)(_event)

            return originalAddEventListener.apply(this, [listener, fn] as [listener: string, fn: any]);
        };

        const documentObserver = new MutationObserver((mutationList) => {
            for (const mutation of mutationList) {
                mutation.addedNodes.forEach((node: Node) => {
                    let _event: types.Event = {
                        type: types.EventType.NewHtmlElement,
                        timestamp: Date.now(),
                        value: {
                            elementType: node.nodeName.toLowerCase()
                        } as types.EventNewHtmlElement
                    };
                    (window[reportFnName as keyof typeof window] as (event: types.Event) => void)(_event)
                });
            }
        });

        documentObserver.observe(document, { childList: true, subtree: true });
    } catch(err) {
        console.log("Oops! Uncaught error in hooks: ", err)
    }
}

export {
    place_hooks,
}