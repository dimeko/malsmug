import * as types from "./types";
import { known_network_dom_elements } from "./const"

function place_hooks(reportFnName: string) {
    try {
        const originalSetItem = window.localStorage.setItem;
        window.localStorage.setItem = function (key: string, value: string) {
            let _event: types.IoC = {
                type: types.IoCType.FunctionCall,
                timestamp: Date.now(),
                executed_on: "",
                value: {
                    callee: "window.localStorage.setItem",
                    arguments: [key, value]
                } as types.IoCFunctionCall
            };
            (window[reportFnName as keyof typeof window] as (event: types.IoC) => void)(_event)

            return originalSetItem.apply(this, [key, value] as [key: string, value: string]);
        };

        const originalGetItem = window.localStorage.getItem;
        window.localStorage.getItem = function (key: string) {
            let _event: types.IoC = {
                type: types.IoCType.FunctionCall,
                timestamp: Date.now(),
                executed_on: "",
                value: {
                    callee: "window.localStorage.getItem",
                    arguments: [key]
                } as types.IoCFunctionCall
            };
            (window[reportFnName as keyof typeof window] as (event: types.IoC) => void)(_event)

            return originalGetItem.apply(this, [key] as [key: string]);
        };

        const originalDocumentWrite = document.write;
        document.write = function (code: string) {
            let _event: types.IoC = {
                type: types.IoCType.FunctionCall,
                timestamp: Date.now(),
                executed_on: "",
                value: {
                    callee: "document.write",
                    arguments: [code]
                } as types.IoCFunctionCall
            };
            (window[reportFnName as keyof typeof window] as (event: types.IoC) => void)(_event)

            return originalDocumentWrite.apply(this, [code] as [code: string]);
        };

        const originalEval = window.eval;
        window.eval = function (code: string) {
            let _event: types.IoC = {
                type: types.IoCType.FunctionCall,
                timestamp: Date.now(),
                executed_on: "",
                value: {
                    callee: "window.eval",
                    arguments: [code]
                } as types.IoCFunctionCall
            };
            (window[reportFnName as keyof typeof window] as (event: types.IoC) => void)(_event)

            return originalEval.apply(this, [code] as [code: string]);
        };

        // detect Internet Explorer
        if((window as any).execScript && 
            navigator.userAgent.indexOf("MSIE ") > -1 || 
            navigator.userAgent.indexOf("Trident/") > -1) {
            const originalExecScript = (window as any).execScript;
            window.eval = function (code: string) {
                let _event: types.IoC = {
                    type: types.IoCType.FunctionCall,
                    timestamp: Date.now(),
                    executed_on: "",
                    value: {
                        callee: "window.execScript",
                        arguments: [code]
                    } as types.IoCFunctionCall
                };
                (window[reportFnName as keyof typeof window] as (event: types.IoC) => void)(_event)

                return originalExecScript.apply(this, [code] as [code: string]);
            };
        }

        const originalFetch = window.fetch;
        window.fetch = function (...args) {
            let _event: types.IoC = {
                type: types.IoCType.HttpRequest,
                timestamp: Date.now(),
                executed_on: "",
                value: {
                    url: args[0],
                    method: "GET",
                    data: ""
                } as types.IoCHttpRequest
            };
            (window[reportFnName as keyof typeof window] as (event: types.IoC) => void)(_event)

            return originalFetch.apply(this, args);
        };

        const originalWindowOpen = window.open;
        window.open = function (...args) {
            let _event: types.IoC = {
                type: types.IoCType.HttpRequest,
                timestamp: Date.now(),
                executed_on: "",
                value: {
                    url: args[0],
                    method: "GET",
                    data: ""
                } as types.IoCHttpRequest
            };
            (window[reportFnName as keyof typeof window] as (event: types.IoC) => void)(_event)

            return originalWindowOpen.apply(this, args);
        };


        const originalXHROpen = window.XMLHttpRequest.prototype.open;
        window.XMLHttpRequest.prototype.open = function(...args: any) {
            let _event: types.IoC = {
                type: types.IoCType.HttpRequest,
                timestamp: Date.now(),
                executed_on: "",
                value: {
                    url: args[1],
                    method: args[0],
                    data: ""
                } as types.IoCHttpRequest
            };
            (window[reportFnName as keyof typeof window] as (event: types.IoC) => void)(_event)

            return originalXHROpen.apply(this, args);
        };

        // XMLHttpRequest.send hook logs will appear right below the logs
        // of XMLHttpRequest.open hook
        const originalXHRSend = window.XMLHttpRequest.prototype.send;
        window.XMLHttpRequest.prototype.send = function(...args: any) {
            try {

                let _event: types.IoC = {
                    type: types.IoCType.HttpRequest,
                    timestamp: Date.now(),
                    executed_on: "",
                    value: {
                        url: "",
                        method: "",
                        data: JSON.stringify(args)
                    } as types.IoCHttpRequest
                };
                (window[reportFnName as keyof typeof window] as (event: types.IoC) => void)(_event)
                
                return originalXHRSend.apply(this, args);
            } catch(err) {
                console.log("[analysis-error] Error on XMLHttpRequest.send: ", err);
            }
        }

        let originalCookies = document.cookie;
        Object.defineProperty(document, "cookie", {
            get: function () {
                let _event: types.IoC = {
                    type: types.IoCType.GetCookie,
                    timestamp: Date.now(),
                    executed_on: "",
                    value: {
                        cookie: originalCookies,
                    } as types.IoCGetCookie
                };
                (window[reportFnName as keyof typeof window] as (event: types.IoC) => void)(_event)

                return originalCookies;
            },
            set: function (value) {
                let _event: types.IoC = {
                    type: types.IoCType.SetCookie,
                    timestamp: Date.now(),
                    executed_on: "",
                    value: {
                        cookie: value,
                    } as types.IoCSetCookie
                };
                (window[reportFnName as keyof typeof window] as (event: types.IoC) => void)(_event)

                originalCookies += value + "; "; 
            }
        });

        let originalAddEventListener = document.addEventListener
        document.addEventListener = function(listener: string, fn: any) {
            let _event: types.IoC = {
                type: types.IoCType.AddEventListener,
                timestamp: Date.now(),
                executed_on: "",
                value: {
                    listener: listener
                } as types.IoCAddEventListener
            };
            (window[reportFnName as keyof typeof window] as (event: types.IoC) => void)(_event)

            return originalAddEventListener.apply(this, [listener, fn] as [listener: string, fn: any]);
        };

        let originalSetTimeout = setTimeout
        const hookedSetTimeout = function (
            callback: TimerHandler,
            delay?: number,
            ...args: any[]
        ): any {
            let _event: types.IoC = {
                type: types.IoCType.SetTimeout,
                timestamp: Date.now(),
                executed_on: "",
                value: {
                    delay: delay,
                    arguments: args.map((e: any) => {
                        return String(e)
                    })
                } as types.IoCSetTimeout
            };
            (window[reportFnName as keyof typeof window] as (event: types.IoC) => void)(_event)
            return originalSetTimeout(callback, delay, ...args);
        };
        (hookedSetTimeout as any).__promisify__ = (originalSetTimeout as any).__promisify__;

        (globalThis.setTimeout as any) = hookedSetTimeout;


        // let originalSetInterval = setInterval
        // const hookedSetInterval = function (
        //     callback: TimerHandler,
        //     delay?: number,
        //     ...args: any[]
        // ): any {
        //     let _event: types.IoC = {
        //         type: types.IoCType.SetInterval,
        //         timestamp: Date.now(),
        //         executed_on: "",
        //         value: {
        //             delay: delay,
        //             arguments: args.map((e: any) => {
        //                 return String(e)
        //             })
        //         } as types.IoCSetInterval
        //     };
        //     (window[reportFnName as keyof typeof window] as (event: types.IoC) => void)(_event)
        //     return originalSetInterval(callback, delay, ...args);
        // };
        // (hookedSetInterval as any).__promisify__ = (originalSetInterval as any).__promisify__;

        // (globalThis.setInterval as any) = hookedSetInterval;

        const documentObserver = new MutationObserver((mutationList) => {
            for (const mutation of mutationList) {
                mutation.addedNodes.forEach((node: Node, key: number, parent: NodeList) => {
                    if (node.ELEMENT_NODE == node.nodeType) {
                        if(node.nodeName.toLowerCase() in known_network_dom_elements) {
                            let _event: types.IoC = {
                                type: types.IoCType.NewNetworkHtmlElement,
                                timestamp: Date.now(),
                                executed_on: "",
                                value: {
                                    elementType: node.nodeName.toLowerCase(),
                                    src: (node as HTMLElement).getAttribute(known_network_dom_elements[node.nodeName.toLowerCase()])
                                } as types.IoCNewNetworkHtmlElement
                            };
                            (window[reportFnName as keyof typeof window] as (event: types.IoC) => void)(_event)
                        }
                    }


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