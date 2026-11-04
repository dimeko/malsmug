#![allow(dead_code)]

use std::fs;
use std::fs::create_dir_all;
use std::io::Read;
use std::fs::File;
use std::path::PathBuf;
use serde::Deserialize;
use serde_json::Value;
use log::{error, warn, debug, info};
use std::collections::HashMap;
use url::Url;
use publicsuffix::{Psl, List};
use std::str;
use sha256;

use crate::analysis::analyzer::Finding;
use crate::integrations::virus_total::VTClient;
use crate::store::models::FileAnalysisReport;
use crate::utils;
use crate::analysis::analyzer;
use crate::analysis::dast_ioc_types;

use dast_ioc_types::IoCValue;

const KNOWN_SENSITIVE_DATA_KEYS: [&str; 5] = [
    "ASPSESSIONID",
    "PHPSESSID",
    "JSESSIONID",
    "SID",
    "connect.sid"
];

const DEFAULT_DOMAIN_REPUTATION: f32 = 15.0;

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

struct Cookie<'a>(&'a str, &'a str);

impl<'a> Cookie<'a> {
    fn to_str(&self) -> String {
        format!("{}={}", self.0, self.1)
    }
}
#[derive(Clone)]
pub struct DastAnalyzer {
    cached_domain_reputations: HashMap<String, f32>,
    malsmug_dir: PathBuf,
    tmp_dir: PathBuf
    // file_hash_events:  Vec<dast_event_types::Event>,
    // file_hash_findings: Vec<Finding>,
}

impl<'a> DastAnalyzer {
    pub fn new(h_dir: PathBuf) -> Self {
        let _tmp_dir = h_dir.join(PathBuf::from("dynamic_analysis_tmp"));
        match create_dir_all(&_tmp_dir) {
            Ok(_) => (),
            Err(_) => {
                panic!("could not create home dir");
            }
        };
        DastAnalyzer { 
            cached_domain_reputations: HashMap::new(),
            malsmug_dir: h_dir.clone(),
            tmp_dir: _tmp_dir
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

    fn _is_bad_domain_reputation(self, s: f32) -> bool {
        return s <= 20.0 && s > 0.0
    }

    fn _cookie_parser(&self, cookies_str: &'a str) -> Vec<Cookie<'a>> {
        let mut cookies: Vec<Cookie<'a>> = Vec::new();
        for _cookie in cookies_str.split(";") {
            let cookie_parts: Vec<&str> = _cookie.trim().split("=").collect();
            if cookie_parts.len() == 2 {
                cookies.push(Cookie(cookie_parts[0], cookie_parts[1]));
            }
        }
        cookies
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
        
        for ioc in iocs {
            // let inner_self = &mut self.clone();
            match ioc.clone().value {
                IoCValue::IoCHttpRequest(_v) => {
                    // analysis: check response url domain reputation
                    if self.clone()._is_bad_domain_reputation(self._get_domain_reputation(_v.url.as_str()).await) {
                        findings.push(
                                analyzer::Finding {
                                    r#type: analyzer::AnalysisType::Dynamic,
                                    ioc: IoCValue::IoCHttpRequest(_v.clone()),
                                    executed_on: ioc.executed_on.clone(),
                                    severity: analyzer::Severity::High,
                                    poc: _v.clone().url,
                                    title: "bad reputation url called".to_string()
                                });
                    }

                    // analysis: check for user input sent in request
                    // "fake_input_from_sandbox_" is the default input prefix that the sandbox puts inside the input fields 
                    if _v.data.contains("fake_input_from_sandbox_") {
                        findings.push(
                            analyzer::Finding {
                                r#type: analyzer::AnalysisType::Dynamic,
                                ioc: IoCValue::IoCHttpRequest(_v.clone()),
                                executed_on: ioc.executed_on.clone(), 
                                severity: analyzer::Severity::VeryHigh,
                                poc: _v.data,
                                title: "http request sent containing user input data".to_string()
                            });
                    }
                },
                IoCValue::IoCHttpResponse(_v) => {
                    // analysis: check response url domain reputation
                    if self.clone()._is_bad_domain_reputation(self._get_domain_reputation(_v.url.as_str()).await) {
                        findings.push(
                            analyzer::Finding {
                                r#type: analyzer::AnalysisType::Dynamic,
                                ioc: IoCValue::IoCHttpResponse(_v.clone()),
                                executed_on: ioc.executed_on.clone(), 
                                severity: analyzer::Severity::High,
                                poc: _v.url,
                                title: "bad reputation url called".to_string()
                            });
                    }
                },
                IoCValue::IoCSuspiciousFileDownload(_v) => {
                    match utils::get_env_var("VIRUS_TOTAL_API_KEY") {
                        Some(vt_api_key) => {
                            debug!("VT api key: {:?}", vt_api_key);
                            let file_sha256 = sha256::digest(&_v.clone().data).to_string();
                            let tmp_file_path = self.tmp_dir.join(PathBuf::from(&file_sha256));
                            match fs::write(&tmp_file_path, _v.clone().data) {
                                Ok(_) => {
                                    let inner_value = vt_api_key.clone();
                                    let _res = tokio::task::spawn_blocking(move || {
                                        let vtclient_inner: VTClient = VTClient::new(&inner_value);
                                        vtclient_inner.submit_file(tmp_file_path.as_os_str().to_str().unwrap())
                                    }).await;
                                    let vtclient: VTClient = VTClient::new(&vt_api_key);
                                    match vtclient.get_file_report(&file_sha256).await {
                                        Ok(r) => {
                                            info!("file: {:?}, VT score: {:?}", file_sha256, r);
                                            if r > 6 {
                                                findings.push(
                                                    analyzer::Finding {
                                                        r#type: analyzer::AnalysisType::Dynamic,
                                                        ioc: IoCValue::IoCSuspiciousFileDownload(_v.clone()),
                                                        executed_on: ioc.executed_on.clone(), 
                                                        severity: analyzer::Severity::High,
                                                        poc: _v.url,
                                                        title: "malicious file was downloaded".to_string()
                                                    }
                                                );
                                            }
                                        },
                                        Err(e) =>{
                                            error!("error analysing the file: {:?}", e);
                                        }
                                    }
                                },
                                Err(_) => {
                                    error!("Could not create tmp file for: {:?}", file_sha256)
                                }
                            }
                        },
                        None => {
                            warn!("could not get VIRUS_TOTAL_API_KEY")
                        }
                    }
                }
                IoCValue::IoCNewNetworkHtmlElement(_v) => {
                    if self.clone()._is_bad_domain_reputation(self._get_domain_reputation(&_v.src.as_str()).await) {
                        findings.push(
                            analyzer::Finding {
                                r#type: analyzer::AnalysisType::Dynamic,
                                ioc: IoCValue::IoCNewNetworkHtmlElement(_v.clone()),
                                executed_on: ioc.executed_on.clone(), 
                                severity: analyzer::Severity::VeryHigh,
                                poc: _v.element_type,
                                title: "dangerous html element was created with low reputation src".to_string()
                            });
                    }
                    // }
                },
                IoCValue::IoCFunctionCall(_v) => {
                    // analysis: check document.write call with the first argument being an html-like element
                    if matches!(_v.callee.as_str(), "document.write") && _v.arguments.len() > 0 {
                        if utils::contains_html_like_code(_v.arguments[0].as_str()) {
                            findings.push(
                                analyzer::Finding {
                                    r#type: analyzer::AnalysisType::Dynamic,
                                    ioc: IoCValue::IoCFunctionCall(_v.clone()),
                                    executed_on: ioc.executed_on.clone(), 
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
                                    ioc: IoCValue::IoCFunctionCall(_v.clone()),
                                    executed_on: ioc.executed_on.clone(), 
                                severity: analyzer::Severity::VeryHigh,
                                poc: _v.callee,
                                title: "window.eval was called".to_string()
                            });
                    } else if matches!(_v.callee.as_str(), "window.execScript") {
                        // analysis: check window.execScript call
                        findings.push(
                            analyzer::Finding {
                                r#type: analyzer::AnalysisType::Dynamic,
                                ioc: IoCValue::IoCFunctionCall(_v.clone()),
                                executed_on: ioc.executed_on.clone(), 
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
                                    ioc: IoCValue::IoCFunctionCall(_v.clone()),
                                    executed_on: ioc.executed_on.clone(), 
                                    severity: analyzer::Severity::VeryHigh,
                                    poc: format!("{}({})", _v.callee, &_v.arguments[0].as_str()),
                                    title: "window.localStorage tried to access sensitive information".to_string()
                                });
                        }
                    }
                },
                IoCValue::IoCGetCookie(_v) => {
                    let cookie_parts: Vec<Cookie> = self._cookie_parser(_v.got_cookie.as_str());
                    for cookie in cookie_parts {
                        if KNOWN_SENSITIVE_DATA_KEYS.contains(&cookie.0) {
                            findings.push(
                                analyzer::Finding {
                                    r#type: analyzer::AnalysisType::Dynamic,
                                    ioc: IoCValue::IoCGetCookie(_v.clone()),
                                    executed_on: ioc.executed_on.clone(), 
                                    severity: analyzer::Severity::VeryHigh,
                                    poc: "document.cookie".to_string(),
                                    title: "document.cookie tried to access sensitive data key".to_string()
                                });
                            }
                    }
                },
                IoCValue::IoCAddEventListener(_v) => {
                    debug!("added event_listener: {}", _v.listener);
                }
                _ => {
                    warn!("event of type {} was not handled", ioc.ioc_type)
                }
            }
        }
        // end of analysis
        // ---------------------------------------------------
        Ok(findings.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::analyzer::{AnalysisType, DastAnalyze, Severity};
    use crate::analysis::dast_ioc_types::*;
    use std::env;

    const BAD_SCORE: f32 = 5.0;
    const GOOD_SCORE: f32 = 80.0;
    const BAIT_WEBSITE: &str = "https://bait.example";

    // Domains are known to the analyzer before it runs, as a domain found in the cache
    // is never looked up on spamhaus. Fails the test if a lookup was attempted for any
    // other domain, so that the tests cannot depend on the network without us noticing.
    async fn analyze_with_reputations(reputations: &[(&str, f32)], iocs: Vec<IoC>) -> Vec<Finding> {
        let home = env::temp_dir().join(format!("malsmug-dast-tests-{}", uuid::Uuid::new_v4()));
        let mut analyzer = DastAnalyzer::new(home.clone());
        for (domain, score) in reputations {
            analyzer.cached_domain_reputations.insert(domain.to_string(), *score);
        }

        let findings = analyzer.analyze(FileAnalysisReport::empty(), iocs).await.unwrap();

        let _ = fs::remove_dir_all(home);
        let mut looked_up: Vec<&String> = analyzer.cached_domain_reputations.keys()
            .filter(|domain| !reputations.iter().any(|(known, _)| known == domain))
            .collect();
        looked_up.sort();
        assert!(looked_up.is_empty(), "these domains were looked up on the network: {:?}", looked_up);
        findings
    }

    async fn analyze_iocs(iocs: Vec<IoC>) -> Vec<Finding> {
        analyze_with_reputations(&[("evil.com", BAD_SCORE), ("good.com", GOOD_SCORE)], iocs).await
    }

    async fn analyze_one(value: IoCValue) -> Vec<Finding> {
        analyze_iocs(vec![ioc(value)]).await
    }

    // analyze decides only by the value of the ioc
    fn ioc(value: IoCValue) -> IoC {
        IoC {
            ioc_type: IoCType::FunctionCall,
            executed_on: BAIT_WEBSITE.to_string(),
            timestamp: 1,
            value,
        }
    }

    fn http_request(url: &str, data: &str) -> IoCValue {
        IoCValue::IoCHttpRequest(IoCHttpRequest { method: "GET".to_string(), url: url.to_string(), data: data.to_string() })
    }

    fn http_response(url: &str) -> IoCValue {
        IoCValue::IoCHttpResponse(IoCHttpResponse { status: "200".to_string(), url: url.to_string(), data: "".to_string() })
    }

    fn network_element(element_type: &str, src: &str) -> IoCValue {
        IoCValue::IoCNewNetworkHtmlElement(IoCNewNetworkHtmlElement { element_type: element_type.to_string(), src: src.to_string() })
    }

    fn function_call(callee: &str, arguments: &[&str]) -> IoCValue {
        IoCValue::IoCFunctionCall(IoCFunctionCall {
            callee: callee.to_string(),
            arguments: arguments.iter().map(|a| a.to_string()).collect(),
        })
    }

    fn get_cookie(cookie: &str) -> IoCValue {
        IoCValue::IoCGetCookie(IoCGetCookie { got_cookie: cookie.to_string() })
    }

    fn assert_finding(finding: &Finding, severity: Severity, title: &str, poc: &str) {
        assert_eq!(finding.title, title);
        assert_eq!(finding.severity, severity);
        assert_eq!(finding.poc, poc);
        assert_eq!(finding.r#type, AnalysisType::Dynamic);
        assert_eq!(finding.executed_on, BAIT_WEBSITE);
    }

    fn titles(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.title.as_str()).collect()
    }

    // ---------------------------------------------------
    // general behaviour
    #[tokio::test]
    async fn no_iocs_give_no_findings() {
        assert!(analyze_iocs(vec![]).await.is_empty());
    }

    #[tokio::test]
    async fn findings_keep_the_order_of_the_iocs() {
        let findings = analyze_iocs(vec![
            ioc(function_call("window.execScript", &[])),
            ioc(function_call("console.log", &[])),
            ioc(function_call("window.eval", &[])),
            ioc(http_request("https://evil.com", "")),
        ]).await;
        assert_eq!(titles(&findings), vec!["window.execScript was called", "window.eval was called", "bad reputation url called"]);
    }

    #[tokio::test]
    async fn every_finding_keeps_the_website_of_its_ioc() {
        let mut first = ioc(function_call("window.eval", &[]));
        first.executed_on = "https://first.example".to_string();
        let mut second = ioc(function_call("window.eval", &[]));
        second.executed_on = "https://second.example".to_string();

        let findings = analyze_iocs(vec![first, second]).await;
        assert_eq!(findings[0].executed_on, "https://first.example");
        assert_eq!(findings[1].executed_on, "https://second.example");
    }

    #[tokio::test]
    async fn repeated_iocs_give_repeated_findings() {
        let findings = analyze_iocs(vec![ioc(function_call("window.eval", &[])), ioc(function_call("window.eval", &[]))]).await;
        assert_eq!(findings.len(), 2);
    }

    #[tokio::test]
    async fn iocs_without_a_rule_give_no_findings() {
        for value in [
            IoCValue::IoCSetCookie(IoCSetCookie { set_cookie: "PHPSESSID=1".to_string() }),
            IoCValue::IoCConsoleLog(IoCConsoleLog { text: "<script>".to_string() }),
            IoCValue::IoCAddEventListener(IoCAddEventListener { listener: "keydown".to_string() }),
            IoCValue::None,
        ] {
            assert!(analyze_one(value).await.is_empty());
        }
    }

    // ---------------------------------------------------
    // domain reputation, the score decides the same way for all the iocs that have a url
    #[tokio::test]
    async fn reputation_scores_up_to_20_are_bad() {
        for (score, is_bad) in [(0.1, true), (BAD_SCORE, true), (20.0, true), (20.1, false), (GOOD_SCORE, false), (0.0, false), (-1.0, false)] {
            let findings = analyze_with_reputations(&[("scored.com", score)], vec![ioc(http_request("https://scored.com", ""))]).await;
            assert_eq!(findings.len() == 1, is_bad, "score {}", score);
        }
    }

    #[tokio::test]
    async fn urls_are_scored_by_their_registrable_domain() {
        for url in [
            "https://evil.com",
            "http://evil.com/path?query=1#fragment",
            "https://cdn.static.evil.com/x.js",
            "https://user:password@evil.com:8443/",
            "https://EVIL.com/",
            "//evil.com/x.js",
        ] {
            assert_eq!(analyze_one(http_request(url, "")).await.len(), 1, "url {}", url);
        }
    }

    #[tokio::test]
    async fn multi_part_public_suffixes_are_respected() {
        let reputations = [("evil.co.uk", BAD_SCORE), ("good.co.uk", GOOD_SCORE)];
        let findings = analyze_with_reputations(&reputations, vec![
            ioc(http_request("https://a.evil.co.uk", "")),
            ioc(http_request("https://a.good.co.uk", "")),
        ]).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].poc, "https://a.evil.co.uk");
    }

    #[tokio::test]
    async fn urls_without_a_domain_are_not_scored() {
        for url in ["", "/relative/path", "relative.js", "evil.com/no-scheme", "data:text/html,x", "javascript:alert(1)", "about:blank", "{}"] {
            assert!(analyze_one(http_request(url, "")).await.is_empty(), "url {}", url);
        }
    }

    #[tokio::test]
    async fn the_same_cached_domain_is_used_for_every_ioc() {
        let findings = analyze_iocs(vec![
            ioc(http_request("https://evil.com/a", "")),
            ioc(http_response("https://evil.com/b")),
            ioc(network_element("img", "https://evil.com/c")),
        ]).await;
        assert_eq!(findings.len(), 3);
    }

    // ---------------------------------------------------
    // http requests
    #[tokio::test]
    async fn request_to_a_bad_domain_is_a_finding() {
        let findings = analyze_one(http_request("https://evil.com/x", "")).await;
        assert_eq!(findings.len(), 1);
        assert_finding(&findings[0], Severity::High, "bad reputation url called", "https://evil.com/x");
        assert!(matches!(&findings[0].ioc, IoCValue::IoCHttpRequest(v) if v.url == "https://evil.com/x"));
    }

    #[tokio::test]
    async fn request_to_a_good_domain_is_not_a_finding() {
        assert!(analyze_one(http_request("https://good.com/x", "some data")).await.is_empty());
    }

    #[tokio::test]
    async fn request_with_user_input_is_a_finding() {
        let data = r#"["user=fake_input_from_sandbox_0"]"#;
        let findings = analyze_one(http_request("https://good.com", data)).await;
        assert_eq!(findings.len(), 1);
        assert_finding(&findings[0], Severity::VeryHigh, "http request sent containing user input data", data);
        assert!(matches!(&findings[0].ioc, IoCValue::IoCHttpRequest(v) if v.data == data));
    }

    // XMLHttpRequest.send is reported without a url
    #[tokio::test]
    async fn request_with_user_input_is_a_finding_without_a_url() {
        let findings = analyze_one(http_request("", "fake_input_from_sandbox_0")).await;
        assert_eq!(titles(&findings), vec!["http request sent containing user input data"]);
    }

    #[tokio::test]
    async fn request_with_user_input_to_a_bad_domain_gives_both_findings() {
        let findings = analyze_one(http_request("https://evil.com", "fake_input_from_sandbox_0")).await;
        assert_eq!(titles(&findings), vec!["bad reputation url called", "http request sent containing user input data"]);
    }

    #[tokio::test]
    async fn only_the_exact_user_input_prefix_counts() {
        for data in ["", "fake_input", "FAKE_INPUT_FROM_SANDBOX_0", "input_from_sandbox_0"] {
            assert!(analyze_one(http_request("https://good.com", data)).await.is_empty(), "data {}", data);
        }
    }

    // ---------------------------------------------------
    // http responses
    #[tokio::test]
    async fn response_from_a_bad_domain_is_a_finding() {
        let findings = analyze_one(http_response("https://evil.com/x")).await;
        assert_eq!(findings.len(), 1);
        assert_finding(&findings[0], Severity::High, "bad reputation url called", "https://evil.com/x");
        assert!(matches!(&findings[0].ioc, IoCValue::IoCHttpResponse(_)));
    }

    #[tokio::test]
    async fn response_from_a_good_domain_or_without_one_is_not_a_finding() {
        assert!(analyze_one(http_response("https://good.com/x")).await.is_empty());
        assert!(analyze_one(http_response("/relative")).await.is_empty());
    }

    // ---------------------------------------------------
    // network html elements
    #[tokio::test]
    async fn element_with_a_bad_domain_is_a_finding() {
        let findings = analyze_one(network_element("iframe", "https://evil.com/x")).await;
        assert_eq!(findings.len(), 1);
        assert_finding(&findings[0], Severity::VeryHigh, "dangerous html element was created with low reputation src", "iframe");
        assert!(matches!(&findings[0].ioc, IoCValue::IoCNewNetworkHtmlElement(v) if v.src == "https://evil.com/x"));
    }

    #[tokio::test]
    async fn element_with_a_good_domain_or_without_one_is_not_a_finding() {
        for src in ["https://good.com/x", "/relative.png", ""] {
            assert!(analyze_one(network_element("img", src)).await.is_empty(), "src {}", src);
        }
    }

    // ---------------------------------------------------
    // suspicious file downloads, only the path without a VirusTotal key
    // as with a key the file would really be uploaded to VirusTotal
    #[tokio::test]
    async fn downloads_are_not_analysed_without_a_virus_total_key() {
        // no other test reaches the code that reads this variable
        unsafe { env::remove_var("VIRUS_TOTAL_API_KEY") };
        let findings = analyze_one(IoCValue::IoCSuspiciousFileDownload(IoCSuspiciousFileDownload {
            url: "https://evil.com/x.zip".to_string(),
            extension: "zip".to_string(),
            data: vec![1, 2, 3],
        })).await;
        assert!(findings.is_empty());
    }

    // ---------------------------------------------------
    // document.write
    #[tokio::test]
    async fn document_write_with_html_is_a_finding() {
        for html in ["<script src='x'></script>", "text <b>bold</b>", "</div>", "<!DOCTYPE html>", "< img src=x>"] {
            let findings = analyze_one(function_call("document.write", &[html])).await;
            assert_eq!(findings.len(), 1, "html {}", html);
            assert_finding(&findings[0], Severity::VeryHigh, "document.write was called with html element as parameter", "document.write");
            assert!(matches!(&findings[0].ioc, IoCValue::IoCFunctionCall(v) if v.arguments[0] == html));
        }
    }

    #[tokio::test]
    async fn document_write_without_html_is_not_a_finding() {
        for text in ["", "plain text", "1 < 2", "a > b", "<>", "<1>"] {
            assert!(analyze_one(function_call("document.write", &[text])).await.is_empty(), "text {}", text);
        }
    }

    #[tokio::test]
    async fn document_write_without_arguments_is_not_a_finding() {
        assert!(analyze_one(function_call("document.write", &[])).await.is_empty());
    }

    #[tokio::test]
    async fn document_write_checks_only_the_first_argument() {
        assert!(analyze_one(function_call("document.write", &["text", "<script>"])).await.is_empty());
    }

    // ---------------------------------------------------
    // window.eval and window.execScript
    #[tokio::test]
    async fn eval_is_always_a_finding() {
        for arguments in [&[][..], &["1 + 1"][..], &[""][..]] {
            let findings = analyze_one(function_call("window.eval", arguments)).await;
            assert_eq!(findings.len(), 1);
            assert_finding(&findings[0], Severity::VeryHigh, "window.eval was called", "window.eval");
        }
    }

    #[tokio::test]
    async fn exec_script_is_always_a_finding() {
        for arguments in [&[][..], &["x"][..]] {
            let findings = analyze_one(function_call("window.execScript", arguments)).await;
            assert_eq!(findings.len(), 1);
            assert_finding(&findings[0], Severity::VeryHigh, "window.execScript was called", "window.execScript");
        }
    }

    // ---------------------------------------------------
    // window.localStorage.getItem
    #[tokio::test]
    async fn reading_a_sensitive_local_storage_key_is_a_finding() {
        for key in KNOWN_SENSITIVE_DATA_KEYS {
            let findings = analyze_one(function_call("window.localStorage.getItem", &[key])).await;
            assert_eq!(findings.len(), 1, "key {}", key);
            assert_finding(
                &findings[0],
                Severity::VeryHigh,
                "window.localStorage tried to access sensitive information",
                &format!("window.localStorage.getItem({})", key));
        }
    }

    #[tokio::test]
    async fn reading_other_local_storage_keys_is_not_a_finding() {
        for key in ["", "theme", "phpsessid", "PHPSESSID2", "my_SID"] {
            assert!(analyze_one(function_call("window.localStorage.getItem", &[key])).await.is_empty(), "key {}", key);
        }
    }

    #[tokio::test]
    async fn reading_local_storage_without_a_key_is_not_a_finding() {
        assert!(analyze_one(function_call("window.localStorage.getItem", &[])).await.is_empty());
    }

    #[tokio::test]
    async fn writing_a_sensitive_local_storage_key_is_not_a_finding() {
        assert!(analyze_one(function_call("window.localStorage.setItem", &["PHPSESSID", "1"])).await.is_empty());
    }

    #[tokio::test]
    async fn other_function_calls_are_not_a_finding() {
        for callee in ["", "console.log", "document.writeln", "eval", "WINDOW.EVAL", "window.eval.call"] {
            assert!(analyze_one(function_call(callee, &["<script>"])).await.is_empty(), "callee {}", callee);
        }
    }

    // ---------------------------------------------------
    // document.cookie
    #[tokio::test]
    async fn cookie_that_is_exactly_a_sensitive_key_is_a_finding() {
        for key in KNOWN_SENSITIVE_DATA_KEYS {
            let cookie = format!("{}=cookie_value", key);
            let findings = analyze_one(get_cookie(&cookie)).await;
            assert_eq!(findings.len(), 1, "key {}", key);
            assert_finding(&findings[0], Severity::VeryHigh, "document.cookie tried to access sensitive data key", "document.cookie");
            assert!(matches!(&findings[0].ioc, IoCValue::IoCGetCookie(v) if v.got_cookie == cookie));
        }
    }

    #[tokio::test]
    async fn other_cookies_are_not_a_finding() {
        for cookie in ["", "theme=dark", "phpsessid"] {
            assert!(analyze_one(get_cookie(cookie)).await.is_empty(), "cookie {}", cookie);
        }
    }

    #[tokio::test]
    // #[ignore = "known bug: document.cookie returns name=value pairs but the rule compares the whole string with the key"]
    async fn cookie_string_with_a_sensitive_key_is_a_finding() {
        for cookie in ["PHPSESSID=abc", "theme=dark; PHPSESSID=abc"] {
            assert_eq!(analyze_one(get_cookie(cookie)).await.len(), 1, "cookie {}", cookie);
        }
    }

    // ---------------------------------------------------
    // iocs in the format the sandbox sends them, the way the main application reads them
    fn from_sandbox(ioc_type: &str, value: &str) -> IoC {
        let json = format!(r#"{{"ioc_type":"{}","timestamp":1,"executed_on":"{}","value":{}}}"#, ioc_type, BAIT_WEBSITE, value);
        serde_json::from_str(&json).unwrap_or_else(|e| panic!("could not parse {}: {}", json, e))
    }

    #[tokio::test]
    async fn sandbox_iocs_reach_their_rules() {
        let findings = analyze_iocs(vec![
            from_sandbox("http_request", r#"{"method":"GET","url":"https://evil.com","data":""}"#),
            from_sandbox("function_call", r#"{"callee":"window.eval","arguments":["1"]}"#),
            from_sandbox("new_network_html_element", r#"{"elementType":"img","src":"https://evil.com"}"#),
        ]).await;
        assert_eq!(titles(&findings), vec![
            "bad reputation url called",
            "window.eval was called",
            "dangerous html element was created with low reputation src"
        ]);
    }

    #[tokio::test]
    async fn sandbox_iocs_without_a_rule_are_accepted() {
        let findings = analyze_iocs(vec![
            from_sandbox("set_cookie", r#"{"set_cookie":"a=b"}"#),
            from_sandbox("add_event_listener", r#"{"listener":"keydown"}"#),
        ]).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    // #[ignore = "known bug: the untagged IoCValue parses get_cookie as IoCSetCookie, as both have the same fields"]
    async fn sandbox_get_cookie_reaches_its_rule() {
        let findings = analyze_iocs(vec![from_sandbox("get_cookie", r#"{"got_cookie":"PHPSESSID=asd"}"#)]).await;
        assert_eq!(titles(&findings), vec!["document.cookie tried to access sensitive data key"]);
    }
}
