use std::process::Command;

fn main() {
    let _d = Command::new("docker")
        .args([
            "build",
            "-t",
            "js-dast",
            "./docker/js_dast_Dockerfile"
        ])
        .status();
}