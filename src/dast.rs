use std::io::Read;
use std::path::PathBuf;
use std::fs::File;
use std::process::Command;
use crate::analyzer;

// struct DynamicAnalysisIoC {
//     severity: analyzer::Severity,
//     poc: String,
//     title: String,
// }


pub struct DastAnalyzer {
    file_path: PathBuf,
    findings: Vec<analyzer::Finding>
}

impl DastAnalyzer {
    pub fn new(file_path: PathBuf) -> Self {
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
        let mut file_volume: String = "".to_owned();
        file_volume.push_str("./");
        file_volume.push_str(self.file_path.to_str().unwrap());
        file_volume.push_str(":/js_dast/samples/file.js");

        _docker_analyze_cmd.args(
            [
                "run",
                "--rm",
                "-v",
                &file_volume.to_ascii_lowercase(),
                "--cap-add=NET_ADMIN",
                "js-dast",
                "/js_dast/samples/file.js"
            ]
        );

        let output = _docker_analyze_cmd.output().expect("docker command failed");
        let lines_stderr = output.stderr
            .split(|b| b == &0xA)
            .map(|line| line.strip_suffix(&[0xD])
            .unwrap_or(line));

        println!("Stderr");
        for mut _l in lines_stderr {
            let mut buf = String::new();
            let _ = _l.read_to_string(&mut buf);
            println!("{}", buf);
        }

        let lines_stdout = output.stdout
        .split(|b| b == &0xA)
        .map(|line| line.strip_suffix(&[0xD])
        .unwrap_or(line));
        println!("Stdout");

        for mut _l in lines_stdout {
            let mut buf = String::new();
            let _ = _l.read_to_string(&mut buf);
            println!("{}", buf);
        }

        Ok(true)
    }

    fn get_findings(&self) -> &Vec<analyzer::Finding> {
        &self.findings
    }
}