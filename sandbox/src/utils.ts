import * as types from "./types";

// JSON.stringify replacer that keeps downloaded files out of a printed report
function elide_byte_arrays(key: string, value: any): any {
    if (key === "data" && Array.isArray(value)) {
        return `<${value.length} bytes>`
    }
    return value
}

function as_text(value: unknown): string {
    if (typeof value === "string") return value
    if (value === undefined) return ""
    return JSON.stringify(value) ?? ""
}

function as_text_list(value: unknown): string[] {
    return Array.isArray(value) ? value.map(as_text) : []
}

// Reported iocs are controlled by the sample: it decides what the hooked functions are
// called with and it can also call the report function directly. TypeScript types do
// not exist at runtime, so here we make sure an ioc has the types the main application
// expects, as one ioc that does not match makes it reject the entire report.
// Returns null for anything that is not an ioc
function sanitize_ioc(reported: unknown): types.IoC | null {
    if (typeof reported !== "object" || reported === null) return null

    const { type, timestamp, value: reported_value } = reported as any
    const value = reported_value ?? {}
    let sanitized_value: types.IoC["value"]

    switch (type) {
        case types.IoCType.HttpRequest:
            sanitized_value = { method: as_text(value.method), url: as_text(value.url), data: as_text(value.data) }
            break;
        case types.IoCType.FunctionCall:
            sanitized_value = { callee: as_text(value.callee), arguments: as_text_list(value.arguments) }
            break;
        case types.IoCType.NewNetworkHtmlElement:
            sanitized_value = { elementType: as_text(value.elementType), src: as_text(value.src) }
            break;
        case types.IoCType.SetCookie:
        case types.IoCType.GetCookie:
            sanitized_value = { cookie: as_text(value.cookie) }
            break;
        case types.IoCType.AddEventListener:
            sanitized_value = { listener: as_text(value.listener) }
            break;
        case types.IoCType.SetTimeout:
            // the browser accepts any delay, e.g. setTimeout(fn, "1000")
            sanitized_value = { delay: Number(value.delay) || 0, arguments: as_text_list(value.arguments) }
            break;
        default:
            return null
    }

    return {
        type: type,
        executed_on: "",
        timestamp: Number.isSafeInteger(timestamp) && timestamp >= 0 ? timestamp : Date.now(),
        value: sanitized_value
    }
}

export {
    elide_byte_arrays,
    sanitize_ioc
}