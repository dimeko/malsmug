import * as types from "./types";

const known_network_dom_elements: {[key: string]:string} = {
    "form": "action",
    "img": "src",
    "audio": "src",
    "source": "src",
    "video": "src",
    "track": "src",
    "script": "src",
    "link": "href",
    "iframe": "src",
    "object": "src",
    "embed": "src"
};

const malicious_mime_types = [
    "application/octet-stream",
    "application/java-archive",
    "application/x-sh",
    "application/x-csh",
    "application/x-httpd-php",
    "text/javascript",
    "application/javascript",
    "application/ecmascript",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/rtf",
    "application/zip",
    "application/x-zip-compressed",
    "application/x-7z-compressed",
    "application/x-bzip",
    "application/x-bzip2",
    "application/gzip",
    "application/x-gzip",
    "application/x-tar",
    "application/vnd.rar",
    "application/x-freearc",
    "font/ttf",
    "font/otf",
    "font/woff",
    "font/woff2",
    "application/vnd.ms-fontobject",
    "application/xml",
    "text/xml",
    "application/ld+json",
    "application/manifest+json",
    "application/xul+xml",
    "application/vnd.mozilla.xul+xml",
    "application/json",
    "image/svg+xml"
];

const default_rabbitmq_conf: types.RabbitMQConfig = {
    connection: {
            host: "",
            port: 0,
            username: "",
            password: "",
        },
        queues: {
            core_files_queue: {
                name: "",
                durable: false,
                auto_delete: false
            },
            sandbox_iocs_queue: {
                name: "",
                durable: false,
                auto_delete: false
            },
        },
        exchanges: {
            main_exchange: {
                name: "",
            },
        }
}

export {
    default_rabbitmq_conf,
    malicious_mime_types,
    known_network_dom_elements
}