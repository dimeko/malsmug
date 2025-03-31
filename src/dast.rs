use std::io::Read;
use std::path::PathBuf;
use std::fs::File;
use std::process::Command;
use serde::Deserialize;
use serde_json::Value;
use log::{error, warn};
use std::collections::HashMap;
use futures::{future, Future};
use futures::executor::block_on;

use crate::analyzer;
use crate::dast_event_types;

const KNOWN_SENSITIVE_COOKIE_NAMES: [&str; 5] = [
    "ASPSESSIONID",
    "PHPSESSID",
    "JSESSIONID",
    "SID",
    "connect.sid"
];


struct DynamicAnalysisIoC {
    severity: analyzer::Severity,
    poc: String,
    title: String,
}

#[derive(Debug, Deserialize)]
struct SpamHausResponse {
    domain: String,
    #[serde(rename = "last-seen")]
    last_seen: u64,
    tags: Vec<String>,
    abused: bool,
    whois: Value,          // Generic JSON for whois
    score: i32,
    dimensions: Value,     // Generic JSON for dimensions
}

pub struct DastAnalyzer {
    file_path: PathBuf,
    test_url_to_visit: String,
    findings: Vec<analyzer::Finding>,
    log_sandbox_out: bool,
    cached_domain_reputations: HashMap<String, i32>,
    _interesting_items: Vec<DynamicAnalysisIoC>
}

impl DastAnalyzer {
    pub fn new(file_path: PathBuf, url_to_visit: String, log_sandbox_out: bool) -> Self {
        let mut _f = File::open(&file_path).expect("could not open file");
        DastAnalyzer { 
            file_path,
            findings: Vec::new(),
            test_url_to_visit: url_to_visit,
            log_sandbox_out,
            cached_domain_reputations: HashMap::new(),
            _interesting_items: Vec::new()
        }
    }

    // fetches given domain reputation score from spamhaus.com
    async  fn _get_domain_reputation(&self, url: &str) -> impl Future<Item = i32, Error = ()> {
        let response = reqwest::get(url).await;
        match response {
            Ok(_resp) => {
                let _resp_body = _resp.text().await.unwrap();
                let _domain_rep_resp = serde_json::from_str::<SpamHausResponse>(&_resp_body).unwrap();
                println!("{:?}", _domain_rep_resp);
                future::ok(_domain_rep_resp.score)
            },
            Err(_err) => {
                future::err(format!("error fetching domain reputation: {}", _err))
            }
        }
        future::ok(-1)
    }
}

impl<'a> analyzer::Analyzer<'a> for DastAnalyzer {
    fn analyze(&mut self) -> Result<bool, String> {
        // running sandbox
        // preparing sandbox parameters
        let mut _docker_analyze_cmd = Command::new("docker");
        let mut file_volume: String = "".to_owned();
        file_volume.push_str("./");
        file_volume.push_str(self.file_path.to_str().unwrap());
        file_volume.push_str(":/js_dast/samples/file.js");

        // spinning up sandbox
        _docker_analyze_cmd.args(
            [
                "run",
                "--rm",
                "-v",
                &file_volume.to_ascii_lowercase(),
                "--cap-add=NET_ADMIN",
                "js-dast",
                "/js_dast/samples/file.js",
                &self.test_url_to_visit
            ]
        );


        let output = _docker_analyze_cmd.output().expect("docker command failed");
        let lines_stderr = output.stderr
            .split(|b| b == &0xA)
            .map(|line| line.strip_suffix(&[0xD])
            .unwrap_or(line));
        // log sandbox output
        if self.log_sandbox_out {
            for mut _l in lines_stderr.clone() {
                let mut buf = String::new();
                let _ = _l.read_to_string(&mut buf);
                println!("{}", buf);
            }
        }

        let lines_stdout = output.stdout
        .split(|b| b == &0xA)
        .map(|line| line.strip_suffix(&[0xD])
        .unwrap_or(line));
        
        // log sandbox output
        if self.log_sandbox_out {
            for mut _l in lines_stdout.clone() {
                let mut buf = String::new();
                let _ = _l.read_to_string(&mut buf);
                println!("{}", buf);
            }
        }

        // ---------------------------------------------------
        // dynamic analysis steps
        
        // parse and examine every line of the stdout
        // this is a simple method at the moment.  In future versions
        // we can send events in and out of the sandbox by running a server
        // on the host
        for mut _l in lines_stdout {
            let mut buf = String::new();
            let _ = _l.read_to_string(&mut buf);
            if let Some(pos) = buf.find("[event]:") {
                let json_part = &buf[pos + 8..]; // Extract substring after ":"
                println!("{}", json_part);
                
                let event: dast_event_types::Event = match serde_json::from_str(json_part) {
                    Ok(_d) => _d,
                    Err(_e) => {
                        warn!("could not parse vent data from sandbox");
                        continue;
                    }
                };

                match event.value {
                    dast_event_types::EventValue::EventHttpRequest(_v) => {
                        if self.cached_domain_reputations.get(&_v.url) == None {
                            let _score = block_on(self._get_domain_reputation(_v.url.as_str()));
                            self.cached_domain_reputations.insert(
                                _v.url.clone(),
                                _score
                                ).unwrap();
                        }
                        
                        if self.cached_domain_reputations[&_v.url] <= 20 {
                            self._interesting_items.push(
                                DynamicAnalysisIoC { 
                                    severity: analyzer::Severity::High,
                                    poc: _v.url,
                                    title: "bad reputation url called".to_string()
                                });
                        }
                    },
                    dast_event_types::EventValue::EventHttpResponse(_v) => {
                        if self.cached_domain_reputations.get(&_v.url) == None {
                            let _score = block_on(self._get_domain_reputation(_v.url.as_str()));
                            self.cached_domain_reputations.insert(
                                _v.url.clone(),
                                _score
                                ).unwrap();
                        }
                        
                        if self.cached_domain_reputations[&_v.url] <= 20 {
                            self._interesting_items.push(
                                DynamicAnalysisIoC { 
                                    severity: analyzer::Severity::High,
                                    poc: _v.url,
                                    title: "bad reputation url called".to_string()
                                });
                        }
                    },
                    _ => {
                        warn!("event was not handled")
                    }
                };
            }
        }
        // end of analysis
        // ---------------------------------------------------


        Ok(true)
    }

    fn get_findings(&self) -> &Vec<analyzer::Finding> {
        &self.findings
    }
}