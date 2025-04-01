use std::process::Command;

fn main() {
    // docker build . --rm -t js-sandbox -f ./docker/js_sandbox_Dockerfile
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
                println!("js-sandbox was built successfully");
            } else {
                panic!("error: could not build the image")
            }
        },
        Err(e) => {
            panic!("error running docker: {}", e);
        }
    }
}