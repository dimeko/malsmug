use std::path::PathBuf;
use clap::{Parser, Subcommand};
use log::{info, warn, error};

mod analyzer;
mod sast;
mod dast;

use analyzer::Analyzer;

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: CliCommand,
    #[clap(long, default_value("world"))]
    file_path: PathBuf
}

#[derive(Subcommand)]
enum CliCommand {
    All,
    Sast,
    Dast,
}

#[derive(Parser, Debug)]
struct Sast;

#[derive(Parser, Debug)]
struct Dast;

fn run_sast(file_path: PathBuf) {
    info!("starting static analyzer");
    let mut sast = sast::SastAnalyzer::new(file_path);
    sast.analyze().and_then(|_| {
        let _findings = sast.get_findings();
        info!("static analysis findings");
        for _f in _findings.iter() {
            println!("  {}", _f);
        }
        Ok(true)
    }).unwrap();
}

fn run_dast(file_path: PathBuf) {
    info!("starting dynamic analyzer");
    let mut dast = dast::DastAnalyzer::new(file_path);
    dast.analyze().and_then(|_| {
        let _findings = dast.get_findings();
        info!("dynamic analysis findings");
        for _f in _findings.iter() {
            println!("  {}", _f);
        }
        Ok(true)
    }).unwrap();
}

fn main() {
    env_logger::init();
    let cli_args = Args::parse();
    info!("analyzing file: {}", &cli_args.file_path.to_str().unwrap());
    match cli_args.command {
        CliCommand::Dast => {
            run_dast(cli_args.file_path);
        },
        CliCommand::Sast => {
            run_sast(cli_args.file_path);
        },
        CliCommand::All => {
            run_sast(cli_args.file_path.clone());
            run_dast(cli_args.file_path);
        }
    }

}
