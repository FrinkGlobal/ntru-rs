use std::process::Command;

fn main() {
    Command::new("make")
                .arg("-C")
                .arg("src/c")
                .arg("static-lib")
                .output().unwrap();

    println!("cargo:rustc-link-lib=static=ntru");
    println!("cargo:rustc-link-search=src/c");
}
