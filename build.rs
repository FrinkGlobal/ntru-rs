extern crate gcc;

use std::fs::File;
use std::path::Path;
use std::io::Write;
use std::process::Command;
use std::env;

// Only Linux yet
fn main() {
    env::set_var("CC", "gcc");
    env::set_var("AS", "gcc -c");
    env::set_var("AR", "ar");

    // /bin/grep -m 1 -o ssse3 /proc/cpuinfo
    let output = Command::new("grep")
                     .arg("-m")
                     .arg("1")
                     .arg("-o")
                     .arg("sse3")
                     .arg("/proc/cpuinfo")
                     .output()
                     .unwrap();
    let output = std::str::from_utf8(&output.stdout[..]).unwrap().trim();
    let sse3 = output == "sse3";

    let mut cflags = "-g -Wall -Wextra -Wno-unused-parameter".to_owned();
    if sse3 {
        // TODO check if SSE feature was enabled
        cflags = cflags + " -mssse3";
    }
    cflags = cflags + " -O2";

    env::set_var("CFLAGS", cflags);

    let mut config = gcc::Config::new();
    config.file("src/c/src/bitstring.c")
          .file("src/c/src/encparams.c")
          .file("src/c/src/hash.c")
          .file("src/c/src/idxgen.c")
          .file("src/c/src/key.c")
          .file("src/c/src/mgf.c")
          .file("src/c/src/ntru.c")
          .file("src/c/src/poly.c")
          .file("src/c/src/rand.c")
          .file("src/c/src/arith.c")
          .file("src/c/src/sha1.c")
          .file("src/c/src/sha2.c");

    if sse3 && cfg!(target_pointer_width = "64") {
        let out = Command::new("perl")
                      .arg("src/c/src/sha1-mb-x86_64.pl")
                      .arg("elf")
                      .output()
                      .unwrap();
        let out = std::str::from_utf8(&out.stdout[..]).unwrap().trim();

        let p = Path::new("src/c/src/sha1-mb-x86_64.s");
        let mut f = File::create(&p).unwrap();
        f.write(out.as_bytes()).unwrap();

        Command::new("gcc")
            .arg("-c")
            .arg("src/c/src/sha1-mb-x86_64.s")
            .arg("-o")
            .arg("src/c/src/sha1-mb-x86_64.o")
            .output()
            .unwrap();

        let out = Command::new("perl")
                      .arg("src/c/src/sha256-mb-x86_64.pl")
                      .arg("elf")
                      .output()
                      .unwrap();
        let out = std::str::from_utf8(&out.stdout[..]).unwrap().trim();

        let p = Path::new("src/c/src/sha256-mb-x86_64.s");
        let mut f = File::create(&p).unwrap();
        f.write(out.as_bytes()).unwrap();

        Command::new("gcc")
            .arg("-c")
            .arg("src/c/src/sha256-mb-x86_64.s")
            .arg("-o")
            .arg("src/c/src/sha256-mb-x86_64.o")
            .output()
            .unwrap();

        config.object("src/c/src/sha1-mb-x86_64.o").object("src/c/src/sha256-mb-x86_64.o");
    }

    config.include("src/c/src").compile("libntru.a");
}
