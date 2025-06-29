use clap::{Parser};
use env_logger::Builder;

mod store;
mod utils;
mod app;
mod analysis;
mod bootstrap;

use crate::app::AppMethods;

#[derive(Parser)]
struct Args {
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

#[tokio::main]
async fn main() {
    let mut builder = Builder::from_default_env();

    let mut log_level: log::LevelFilter = log::LevelFilter::Warn;
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

    let app = bootstrap::bootstrap(cli_args).await;

    let _ = app.start().await;
}
