use std::{thread, time};

use anyhow::Error;
use log::{info, warn};
use vt3::VtClient;

const MAX_TRIES_ON_FILE_INFO: u8 = 5;

pub struct VTClient {
    vt_client: VtClient
}

impl VTClient {
    pub fn new(api_key: &str) -> VTClient {
        VTClient {
            vt_client: VtClient::new(&api_key)
        }
    }

    pub fn scan_file(&self, file: &str, file_hash: &str) -> Result<i64, Error> {
        match self.vt_client.file_scan(file) {
            Ok(r) => {
                let mut tries = 0;
                loop {
                    info!("Polling Virus Total for results");
                    thread::sleep(time::Duration::from_secs(3));
                    match self.vt_client.file_info(file_hash) {
                        Ok(r) => {
                            return Ok(r.data.unwrap().attributes.unwrap().last_analysis_stats.unwrap().malicious.unwrap())
                        },
                        Err(e) => {
                            if tries >= MAX_TRIES_ON_FILE_INFO {
                                warn!("error scanning file: {:?}", &file_hash);
                                return Ok(-1);
                            } else {
                                warn!("file analysis not available yet: {:?}", &file_hash);
                            }
                            tries = tries + 1;
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