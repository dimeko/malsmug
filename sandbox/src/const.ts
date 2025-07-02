import * as types from "./types";

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
    default_rabbitmq_conf
}