use std::{thread, time};

use anyhow::Error;
use log::{info, error};
use vt3::VtClient;

pub struct VTClient {
    api_key: String,
    vt_client: VtClient
}

impl VTClient {
    pub fn new(api_key: &str) -> VTClient {
        VTClient {
            api_key: api_key.to_string(),
            vt_client: VtClient::new(&api_key)
        }
    }

    pub fn scan_file(&self, file: &str, file_hash: &str) -> Result<i64, Error> {
        match self.vt_client.file_scan(file) {
            Ok(r) => {
                loop {
                    info!("Polling Virus Total for results");
                    thread::sleep(time::Duration::from_secs(3));
                    match self.vt_client.file_info(file_hash) {
                        Ok(r) => {
                            return Ok(r.data.unwrap().attributes.unwrap().last_analysis_stats.unwrap().malicious.unwrap())
                        },
                        Err(e) => {
                            error!("error scanning file: {:?}", &file_hash);
                            return Err(e.into());
                        }
                    }
                }
            },
            Err(e) => {
                return Err(e.into());
            }
        }
    }


}