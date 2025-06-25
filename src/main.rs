use std::path::PathBuf;
use clap::{Parser, Subcommand};
use log::info;
use env_logger::Builder;

// mod analyzer;
// mod sast;
// mod dast;
// mod dast_event_types;
mod store;
mod utils;
mod server;

use server::ServerMethods;

// const DEFAULT_URL_TO_VISIT: &'static str = "https://google.com";
const SERVER_ADDRESS: &'static str = "127.0.0.1:11234";

#[derive(Parser)]
struct Args {
    // #[command(subcommand)]
    // command: CliCommand,
    #[clap(long)]
    bindhost: String,
    #[clap(long)]
    bindport: u16,
    #[clap(
        long,
        short,
        default_missing_value("true"),
        default_value("false"),
    )]
    verbose: bool,
    #[clap(
        long,
        short,
        default_missing_value("true"),
        default_value("false"),
    )]
    debug: bool
}

// #[derive(Subcommand, Debug)]
// enum CliCommand {
//     All {
//         #[clap(long, default_value(DEFAULT_URL_TO_VISIT))]
//         url_to_visit: String
//     },
//     Sast {},
//     Dast {
//         #[clap(long, default_value(DEFAULT_URL_TO_VISIT))]
//         url_to_visit: String
//     },
// }

// fn run_sast(file_path: PathBuf) {
//     info!("starting static analyzer");
//     let mut sast = sast::SastAnalyzer::new(file_path);
//     sast.analyze().and_then(|_| {
//         let _findings = sast.get_findings();
//         info!("static analysis findings");
//         for _f in _findings.iter() {
//             println!("{}: {}", "sast finding".red(), _f);
//         }
//         Ok(true)
//     }).unwrap();
// }

// fn run_dast(file_path: PathBuf, url_to_visit: String, log_sandbox_out: bool) {
//     info!("starting dynamic analyzer");
//     let mut dast = dast::DastAnalyzer::new(file_path, url_to_visit, log_sandbox_out);
//     dast.analyze().and_then(|_| {
//         let _findings = dast.get_findings();
//         info!("dynamic analysis findings");
//         for _f in _findings.iter() {
//             println!("{}: {}", "dast finding".red(), _f);
//         }
//         Ok(true)
//     }).unwrap();
// }

#[tokio::main]
async fn main() {
    let mut builder = Builder::from_default_env();

    let mut log_level: log::LevelFilter = log::LevelFilter::Debug;
    let cli_args = Args::parse();

    if cli_args.verbose {
        log_level = log::LevelFilter::Info;
    }

    if cli_args.debug {
        log_level = log::LevelFilter::Debug;
    }

    builder
        .filter(None, log_level)
        .init();

    let server_address= cli_args.bindhost + &cli_args.bindport.to_string();

    info!("running server on {}", server_address);
    let s = server::Server::new(&server_address).await;
    let _ = s.start().await;

    // info!("analyzing file: {}", &cli_args.file_path.to_str().unwrap());
    // match cli_args.command {
    //     CliCommand::Dast { url_to_visit } => {
    //         run_dast(cli_args.file_path, url_to_visit, cli_args.debug);
    //     },
    //     CliCommand::Sast {} => {
    //         run_sast(cli_args.file_path);
    //     },
    //     CliCommand::All { url_to_visit } => {
    //         run_sast(cli_args.file_path.clone());
    //         run_dast(cli_args.file_path, url_to_visit, cli_args.debug);
    //     }
    // }
}
