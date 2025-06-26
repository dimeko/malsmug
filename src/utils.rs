use std::{fs, io::Read, path::PathBuf};
// use yaml_rust2::{YamlLoader, YamlEmitter};
use serde::{Serialize, Deserialize};
use regex::Regex;
use serde_yaml::Error;

pub fn contains_html_like_code(input: &str) -> bool {
    let html_regex = Regex::new(r"<\s*!?[a-zA-Z][a-zA-Z0-9]*\b[^>]*>|</\s*[a-zA-Z][a-zA-Z0-9]*\s*>").unwrap();
    html_regex.is_match(input)
}

pub fn parse_yaml<T: for<'a> Deserialize<'a>>(p: PathBuf) -> Result<T, Error> {
    let mut f = fs::File::open(p).unwrap();
    let mut buf: String = String::new();
    f.read_to_string(&mut buf);
    let parsed_yaml: T = match serde_yaml::from_str(&buf) {
        Ok(p) => {
            p
        },
        Err(e) => {
            eprint!("error parsing yaml: {:?}", e);
            return Err(e);
        }
    };
    Ok(parsed_yaml)
}