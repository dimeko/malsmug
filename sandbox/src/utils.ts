// JSON.stringify replacer that keeps downloaded files out of a printed report
function elide_byte_arrays(key: string, value: any): any {
    if (key === "data" && Array.isArray(value)) {
        return `<${value.length} bytes>`
    }
    return value
}

export {
    elide_byte_arrays
}