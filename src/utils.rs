use std::{ffi::OsStr, fs, io::Read, path::{Path, PathBuf}};
// use yaml_rust2::{YamlLoader, YamlEmitter};
use serde::{Deserialize};
use regex::Regex;
use serde_yaml::Error;

pub fn contains_html_like_code(input: &str) -> bool {
    let html_regex = Regex::new(r"<\s*!?[a-zA-Z][a-zA-Z0-9]*\b[^>]*>|</\s*[a-zA-Z][a-zA-Z0-9]*\s*>").unwrap();
    html_regex.is_match(input)
}

pub fn parse_yaml<T: for<'a> Deserialize<'a>>(p: PathBuf) -> Result<T, Error> {
    let mut f = fs::File::open(p).unwrap();
    let mut buf: String = String::new();
    let _ = f.read_to_string(&mut buf); // TODO: handle error
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

pub fn parse_file_extension_of_file(file_name: String) -> String {
    Path::new(file_name.as_str())
        .extension()
        .and_then(OsStr::to_str).unwrap_or("").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_with_normal_file() {
        let ext = parse_file_extension_of_file("document.txt".to_string());
        assert_eq!(ext, "txt");
    }

    #[test]
    fn test_with_dot_file() {
        let ext = parse_file_extension_of_file(".hiddenfile".to_string());
        assert_eq!(ext, "");
    }

    #[test]
    fn test_with_multiple_dots() {
        let ext = parse_file_extension_of_file("archive.tar.gz".to_string());
        assert_eq!(ext, "gz");
    }

    #[test]
    fn test_with_path() {
        let ext = parse_file_extension_of_file("/some/path/to/file.rs".to_string());
        assert_eq!(ext, "rs");
    }
}
