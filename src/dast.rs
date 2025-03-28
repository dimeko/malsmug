use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::fs::File;
use std::process::Command;
use crate::analyzer;

// struct DynamicAnalysisIoC {
//     severity: analyzer::Severity,
//     poc: String,
//     title: String,
// }


struct DastAnalyzer {
    file_path: PathBuf,
    findings: Vec<analyzer::Finding>
}

impl DastAnalyzer {
    fn new(file_path: PathBuf) -> Self {
        let mut _f = File::open(&file_path).expect("could not open file");
        DastAnalyzer { 
            file_path,
            findings: Vec::new() 
        }
    }
}


impl<'a> analyzer::Analyzer<'a> for DastAnalyzer {
    fn analyze(&mut self) -> Result<bool, String> {
        let mut _docker_analyze_cmd = Command::new("docker");
        _docker_analyze_cmd.args(
            [
                "run",
                "--rm",
                "--network=none",
                "-v",
                "$(pwd)/test.js:/sandbox/test.js",
                "js-sandbox",
                "/sandbox/test.js"
            ]
        );

        let _ = _docker_analyze_cmd.output().unwrap();
        Ok(true)
    }

    fn get_findings(&self) -> &Vec<analyzer::Finding> {
        &self.findings
    }
}