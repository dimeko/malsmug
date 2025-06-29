use std::io::Read;
use std::fs::File;
use serde::Deserialize;
use serde_json::Value;
use log::{error, warn, debug, info};
use std::collections::HashMap;
use url::Url;
use publicsuffix::{Psl, List};
use std::str;

use crate::analysis::analyzer::Finding;
use crate::store::models::FileAnalysisReport;
use crate::utils;
use crate::analysis::analyzer;
use crate::analysis::dast_ioc_types;

const KNOWN_SENSITIVE_DATA_KEYS: [&str; 5] = [
    "ASPSESSIONID",
    "PHPSESSID",
    "JSESSIONID",
    "SID",
    "connect.sid"
];

const DEFAULT_DOMAIN_REPUTATION: f32 = 15.0;

const KNOWN_NETWORK_DOM_ELEMENTS: [&str; 11] = [
    "form",
    "img",
    "audio",
    "source",
    "video",
    "track",
    "script",
    "link",
    "iframe",
    "object",
    "embed"
];

// DynamicAnalysisIoC is supposed to be used in multiple different scanners
// Currently, in our simple implementation, we use analyzer::Finding without
// converting from DynamicAnalysisIoC
#[allow(dead_code)]
struct DynamicAnalysisIoC {
    severity: analyzer::Severity,
    poc: String,
    title: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct SpamHausResponse {
    domain: String,
    #[serde(rename = "last-seen")]
    last_seen: u64,
    tags: Vec<String>,
    abused: bool,
    whois: Value,
    score: f32,
    dimensions: Value
}

#[derive(Clone)]
pub struct DastAnalyzer {
    cached_domain_reputations: HashMap<String, f32>,
    // file_hash_events:  Vec<dast_event_types::Event>,
    // file_hash_findings: Vec<Finding>,
}

impl DastAnalyzer {
    pub fn new() -> Self {
        DastAnalyzer { 
            cached_domain_reputations: HashMap::new(),
        }
    }

    // normalize url to make parsing easier
    fn _normalize_url(&self, url: &str) -> String {
        let mut url_normalized: String = url.to_string();

        if url.starts_with("//") {
            url_normalized = format!("https:{}", url);
        }
        return url_normalized;
    }

    // fetches given domain reputation score from spamhaus.com
    async fn _get_domain_reputation(&mut self, url: &str) -> f32 {
        let url_normalized: String = self._normalize_url(url);

        info!("get domain reputation for: {}", url_normalized);
        let domain = match Url::parse(&url_normalized) {
            Ok(_u) => {
                _u
            },
            Err(_e) => {
                error!("could not parse url: {}", _e);
                return -1.0;
            }
        };
        // load all public suffixes to achieve parsing arbitrary urls 
        let mut public_suffixes = match File::open("./public_suffix.txt") {
            Ok(_f) => _f,
            Err(_e) => {
                error!("{}", _e);
                return -1.0;
            }
        };
        let mut buf: String = String::new();
        let _ = public_suffixes.read_to_string(&mut buf);
        let list: List = match buf.parse() {
            Ok(_l) => _l,
            Err(_e) => {
                error!("could not open public suffix file");
                return -1.0;
            }
        };
        // parse the given url's domain
        let domain = match list.domain(domain.host_str().unwrap_or("").as_bytes()) {
            Some(_d) => _d,
            None => {
                error!("could not parse domain: {}", &url_normalized);
                return -1.0;
            }
        };

        let domain_string = match str::from_utf8(domain.as_bytes()) {
            Ok(_s) => _s,
            Err(_e) => {
                error!("could not parse domain: {}", &url_normalized);
                return -1.0;
            }
        };

        // get the domain reputation from the cache
        if self.cached_domain_reputations.contains_key(domain_string) {
            return match self.cached_domain_reputations.get(domain_string) {
                Some(_s) => {
                    debug!("cache hit for {} score={}", domain_string, *_s);
                    *_s
                },
                None => {
                    -1.0
                }
            }
        }
        self.cached_domain_reputations.insert(domain_string.to_string(), -1.0).map(|e|  {
            error!("could not create cache key for {}, error: {}", domain_string, e);
            return -1;
        });
        info!("checking domain: {}", domain_string);
        // TODO: move this url to a configuration file
        let spamhaus_url = format!("https://www.spamhaus.org/api/v1/sia-proxy/api/intel/v2/byobject/domain/{}/overview", domain_string);

        let _client = reqwest::Client::new();
        let response = _client.get(spamhaus_url)
                .header("User-Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0")
                .send().await;
        match response {
            Ok(_resp) => {
                debug!("got response from domain rep service: {:?}", _resp);

                let _resp_body = &_resp.text().await.unwrap_or("{}".to_string());
                debug!("response for {}: {}", domain_string, _resp_body);
                let _domain_resp = match serde_json::from_str::<SpamHausResponse>(&_resp_body) {
                    Ok(_r) => {
                        _r
                    },
                    Err(_e) => {
                        warn!("could not determine domain reputation, putting default value: {}", DEFAULT_DOMAIN_REPUTATION);
                        self.cached_domain_reputations
                            .entry(domain_string.to_string())
                            .and_modify(|e| { *e = DEFAULT_DOMAIN_REPUTATION })
                            .or_insert(DEFAULT_DOMAIN_REPUTATION);
                        return DEFAULT_DOMAIN_REPUTATION; // return a value for domains that are not found
                    }
                };
                // self.cached_domain_reputations.entry(domain_string.to_string()).or_insert(_domain_resp.score);
                self.cached_domain_reputations
                    .entry(domain_string.to_string())
                    .and_modify(|e| { *e = _domain_resp.score })
                    .or_insert(_domain_resp.score);

                info!("reputation score for {}: {}", domain_string, _domain_resp.score);
                return _domain_resp.score
            },
            Err(_err) => {
                error!("error fetching domain reputation: {}", _err);
                return -1.0;
            }
        }
    }
}

impl<'a> analyzer::DastAnalyze<'a> for DastAnalyzer {
    async fn analyze(&mut self, _: FileAnalysisReport, iocs: Vec<dast_ioc_types::IoC>) -> Result<Vec<Finding>, String> {
        // ---------------------------------------------------
        // dynamic analysis
        //
        // parse and examine every line of the stdout
        // this is a simple method at the moment.  In future versions
        // we can send iocs in and out of the sandbox by running a server
        // on the host
        let mut findings: Vec<Finding> = Vec::new();
        
        for event in iocs {
            // let inner_self = &mut self.clone();
            match event.clone().value {
                dast_ioc_types::IoCValue::IoCHttpRequest(_v) => {
                    // analysis: check response url domain reputation
                    let _score = self._get_domain_reputation(_v.url.as_str()).await;
                    if _score <= 20.0 && _score > 0.0 {
                        findings.push(
                                analyzer::Finding {
                                    r#type: analyzer::AnalysisType::Dynamic,
                                    executed_on: event.executed_on.clone(),
                                    severity: analyzer::Severity::High,
                                    poc: _v.url,
                                    title: "bad reputation url called".to_string()
                                });
                    }

                    // analysis: check for user input sent in request
                    // "fake_input_from_sandbox_" is the default input prefix that the sandbox puts inside the input fields 
                    if _v.data.contains("fake_input_from_sandbox_") {
                        findings.push(
                            analyzer::Finding {
                                r#type: analyzer::AnalysisType::Dynamic,
                                executed_on: event.executed_on.clone(), 
                                severity: analyzer::Severity::VeryHigh,
                                poc: _v.data,
                                title: "http request sent containing user input data".to_string()
                            });
                    }
                },
                dast_ioc_types::IoCValue::IoCHttpResponse(_v) => {
                    // analysis: check response url domain reputation
                    let _score = self._get_domain_reputation(_v.url.as_str()).await;
                    if _score <= 20.0 && _score > 0.0 {
                        findings.push(
                            analyzer::Finding {
                                r#type: analyzer::AnalysisType::Dynamic,
                                executed_on: event.executed_on.clone(), 
                                severity: analyzer::Severity::High,
                                poc: _v.url,
                                title: "bad reputation url called".to_string()
                            });
                    }

                },
                dast_ioc_types::IoCValue::IoCNewHtmlElement(_v) => {
                    // analysis: check if the target creates new html elements that can potentially access the internet
                    if KNOWN_NETWORK_DOM_ELEMENTS.contains(&_v.element_type.as_str()) {
                        findings.push(
                            analyzer::Finding {
                                r#type: analyzer::AnalysisType::Dynamic,
                                executed_on: event.executed_on.clone(), 
                                severity: analyzer::Severity::VeryHigh,
                                poc: _v.element_type,
                                title: "dangerous html element created".to_string()
                            });
                    }
                },
                dast_ioc_types::IoCValue::IoCFunctionCall(_v) => {
                    // analysis: check document.write call with the first argument being an html-like element
                    if matches!(_v.callee.as_str(), "document.write") && _v.arguments.len() > 0 {
                        if utils::contains_html_like_code(_v.arguments[0].as_str()) {
                            findings.push(
                                analyzer::Finding {
                                    r#type: analyzer::AnalysisType::Dynamic,
                                    executed_on: event.executed_on.clone(), 
                                    severity: analyzer::Severity::VeryHigh,
                                    poc: _v.callee,
                                    title: "document.write was called with html element as parameter".to_string()
                                });
                        }
                    } else if matches!(_v.callee.as_str(), "window.eval") {
                        // analysis: check window.eval call
                        // here we could also check whether the eval paramater is actually a malicious Javascript code
                        // for now we check just the dangerous call to `.eval`
                        findings.push(
                                analyzer::Finding {
                                    r#type: analyzer::AnalysisType::Dynamic,
                                    executed_on: event.executed_on.clone(), 
                                severity: analyzer::Severity::VeryHigh,
                                poc: _v.callee,
                                title: "window.eval was called".to_string()
                            });
                    } else if matches!(_v.callee.as_str(), "window.execScript") {
                        // analysis: check window.execScript call
                        findings.push(
                            analyzer::Finding {
                                r#type: analyzer::AnalysisType::Dynamic,
                                executed_on: event.executed_on.clone(), 
                                severity: analyzer::Severity::VeryHigh,
                                poc: _v.callee,
                                title: "window.execScript was called".to_string()
                            });
                    } else if matches!(_v.callee.as_str(), "window.localStorage.getItem")  && _v.arguments.len() > 0 {
                        // analysis: check whether the target tries to access sinsitive data keys
                        if KNOWN_SENSITIVE_DATA_KEYS.contains(&_v.arguments[0].as_str()) {
                            findings.push(
                                analyzer::Finding {
                                    r#type: analyzer::AnalysisType::Dynamic,
                                    executed_on: event.executed_on.clone(), 
                                    severity: analyzer::Severity::VeryHigh,
                                    poc: format!("{}({})", _v.callee, &_v.arguments[0].as_str()),
                                    title: "window.localStorage tried to access sensitive information".to_string()
                                });
                        }
                    }
                },
                dast_ioc_types::IoCValue::IoCGetCookie(_v) => {
                    if KNOWN_SENSITIVE_DATA_KEYS.contains(&_v.cookie.as_str()) {
                            findings.push(
                                analyzer::Finding {
                                    r#type: analyzer::AnalysisType::Dynamic,
                                    executed_on: event.executed_on.clone(), 
                                    severity: analyzer::Severity::VeryHigh,
                                    poc: "document.cookie".to_string(),
                                    title: "document.cookie tried to access sensitive data key".to_string()
                                });
                    }
                },
                dast_ioc_types::IoCValue::IoCAddEventListener(_v) => {
                    debug!("added event_listener: {}", _v.listener);
                }
                _ => {
                    warn!("event of type {} was not handled", event.ioc_type)
                }
            }
        }
        // end of analysis
        // ---------------------------------------------------
        Ok(findings.clone())
    }
}