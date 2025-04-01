use regex::Regex;

pub fn contains_html_like_code(input: &str) -> bool {
    let html_regex = Regex::new(r"<\s*!?[a-zA-Z][a-zA-Z0-9]*\b[^>]*>|</\s*[a-zA-Z][a-zA-Z0-9]*\s*>").unwrap();
    html_regex.is_match(input)
}