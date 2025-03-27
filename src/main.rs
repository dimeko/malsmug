use std::path::PathBuf;
use clap::{Parser, Subcommand};

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

fn main() {
    let cli_args = Args::parse();

    match cli_args.command {
        CliCommand::Dast => {
            
        },
        CliCommand::Sast => {
            let mut sast = sast::SastAnalyzer::new(cli_args.file_path);
            sast.analyze().and_then(|_| {
                let _findings = sast.get_findings();
                for _f in _findings.iter() {
                    println!("{}", _f);
                }
                Ok(true)
            }).unwrap();
        },
        CliCommand::All => {

        }
    }

}
