use std::{thread, time};
use log::{info, warn};
use virustotal3::VtClient;

const MAX_TRIES_ON_FILE_INFO: u8 = 5;

pub struct VTClient<'a> {
    vt_client: VtClient<'a>
}

impl<'a> VTClient<'a> {
    pub fn new(api_key: &str) -> VTClient {
        VTClient {
            vt_client: VtClient::new(&api_key)
        }
    }

    pub fn submit_file(&self, file: &str) -> bool{
        match self.vt_client.scan_file(file) {
            Ok(_) => true,
            Err(_) => false
        }
    }

    pub async fn get_file_report(&self, file_hash: &str) -> Result<i64, String> {
        let mut tries = 0;
        loop {
            info!("Polling Virus Total for results");
            thread::sleep(time::Duration::from_secs(3));
            match self.vt_client.get_report_file(file_hash).await {
                Ok(r) => {
                    match r["data"]["attributes"]["last_analysis_stats"]["malicious"].as_number() {
                        Some(n) => {
                            return Ok(n.as_i64().unwrap())
                        },
                        None => {
                            warn!("error getting file score");
                            return Err("error getting file score".to_string());
                        }
                    }
                },
                Err(e) => {
                    if tries >= MAX_TRIES_ON_FILE_INFO {
                        warn!("error scanning file: {:?}", &file_hash);
                        return Err(e.to_string());
                    } else {
                        warn!("file analysis not available yet: {:?}", &file_hash);
                    }
                    tries = tries + 1;
                }
            }
        }
    }


}