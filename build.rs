use std::process::Command;

fn main() {
    let _d = Command::new("docker")
        .args([
            "build",
            ".",
            "--rm",
            "-t",
            "js-sandbox",
            "-f",
            "./docker/js_sandbox_Dockerfile"
        ])
        .status();
    match _d {
        Ok(_status) => {
            if _status.success() {
                println!("js-sandbox was build successfully");
            } else {
                panic!("something wrong building the image")
            }
        },
        Err(e) => {
            panic!("error running docker: {}", e);
        }
    }
}