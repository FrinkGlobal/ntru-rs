extern crate gcc;

use std::fs::File;
use std::path::Path;
use std::io::Write;
use std::process::Command;
use std::env;

// Only Linux yet
fn main() {
    if cfg!(target_os = "linux") || cfg!(target_os = "macos") || cfg!(target_os = "windows") {
        env::set_var("CC", "gcc");
        env::set_var("AS", "gcc -c");
        if cfg!(target_os = "linux") {
            env::set_var("AR", "ar");
        }
    } else if cfg!(target_os = "freebsd") || cfg!(target_os = "openbsd") {
        env::set_var("CC", "cc");
        env::set_var("AS", "cc -c");
        env::set_var("AR", "ar");
    }

    let sse3 = if cfg!(target_os = "windows") {
        cfg!(feature = "sse")
    } else {
        let output = if cfg!(target_os = "freebsd") || cfg!(target_os = "openbsd") {
            // /usr/bin/grep -o SSSE3 /var/run/dmesg.boot | /usr/bin/head -1
            Command::new("/usr/bin/grep")
                .arg("-o")
                .arg("SSE3")
                .arg("/var/run/dmesg.boot")
                .arg("|")
                .arg("/usr/bin/head")
                .arg("-1")
                .output()
                .unwrap()
        } else if cfg!(target_os = "macos") {
            // /usr/sbin/sysctl machdep.cpu.features | grep -m 1 -ow SSSE3
            Command::new("/usr/sbin/sysctl")
                .arg("machdep.cpu.features")
                .arg("|")
                .arg("grep")
                .arg("-m")
                .arg("1")
                .arg("-ow")
                .arg("SSE3")
                .output()
                .unwrap()
        } else {
            // /bin/grep -m 1 -o ssse3 /proc/cpuinfo
            Command::new("/bin/grep")
                .arg("-m")
                .arg("1")
                .arg("-o")
                .arg("sse3")
                .arg("/proc/cpuinfo")
                .output()
                .unwrap()
        };
        let output = std::str::from_utf8(&output.stdout[..]).unwrap().trim();

        if cfg!(target_os = "freebsd") || cfg!(target_os = "openbsd") || cfg!(target_os = "macos") {
            output == "SSE3"
        } else {
            output == "sse3"
        }
    };

    let mut cflags = "-g -Wall -Wextra -Wno-unused-parameter".to_owned();
    if !cfg!(feature = "no-sse") && sse3 {
        cflags = cflags + " -mssse3";
    }
    if cfg!(feature = "no-sse") && cfg!(target_os = "macos") {
        cflags = cflags + " -march=x86-64";
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
          .file("src/c/src/sha2.c")
          .file("src/c/src/nist_ctr_drbg.c")
          .file("src/c/src/rijndael.c")
          .file("src/c/src/rijndael-alg-fst.c");

    if sse3 &&
       (cfg!(target_pointer_width = "64") || cfg!(target_os = "macos") ||
        cfg!(target_os = "windows")) {
        let out = if cfg!(target_os = "windows") {
            Command::new("c:\\mingw\\msys\\1.0\\bin\\perl")
                .arg("src/c/src/sha1-mb-x86_64.pl")
                .arg("elf")
                .output()
                .unwrap()
        } else {
            Command::new("/usr/bin/perl")
                .arg("src/c/src/sha1-mb-x86_64.pl")
                .arg("elf")
                .output()
                .unwrap()
        };
        let out = std::str::from_utf8(&out.stdout[..]).unwrap().trim();

        let p = Path::new("src/c/src/sha1-mb-x86_64.s");
        let mut f = File::create(&p).unwrap();
        f.write(out.as_bytes()).unwrap();

        if cfg!(target_os = "linux") || cfg!(target_os = "macos") {
            Command::new("gcc")
                .arg("-c")
                .arg("src/c/src/sha1-mb-x86_64.s")
                .arg("-o")
                .arg("src/c/src/sha1-mb-x86_64.o")
                .output()
                .unwrap();
        } else if cfg!(target_os = "freebsd") || cfg!(target_os = "openbsd") {
            Command::new("cc")
                .arg("-c")
                .arg("src/c/src/sha1-mb-x86_64.s")
                .arg("-o")
                .arg("src/c/src/sha1-mb-x86_64.o")
                .output()
                .unwrap();
        }

        let out = if cfg!(target_os = "windows") {
            Command::new("c:\\mingw\\msys\\1.0\\bin\\perl")
                .arg("src/c/src/sha256-mb-x86_64.pl")
                .arg("elf")
                .output()
                .unwrap()
        } else {
            Command::new("/usr/bin/perl")
                .arg("src/c/src/sha256-mb-x86_64.pl")
                .arg("elf")
                .output()
                .unwrap()
        };
        let out = std::str::from_utf8(&out.stdout[..]).unwrap().trim();

        let p = Path::new("src/c/src/sha256-mb-x86_64.s");
        let mut f = File::create(&p).unwrap();
        f.write(out.as_bytes()).unwrap();

        if cfg!(target_os = "linux") || cfg!(target_os = "macos") {
            Command::new("gcc")
                .arg("-c")
                .arg("src/c/src/sha256-mb-x86_64.s")
                .arg("-o")
                .arg("src/c/src/sha256-mb-x86_64.o")
                .output()
                .unwrap();
        } else if cfg!(target_os = "freebsd") || cfg!(target_os = "openbsd") {
            Command::new("cc")
                .arg("-c")
                .arg("src/c/src/sha256-mb-x86_64.s")
                .arg("-o")
                .arg("src/c/src/sha256-mb-x86_64.o")
                .output()
                .unwrap();
        }

        config.object("src/c/src/sha1-mb-x86_64.o").object("src/c/src/sha256-mb-x86_64.o");
    }

    config.include("src/c/src").compile("libntru.a");

    if !cfg!(feature = "no-sse") && sse3 {
        println!("cargo:rustc-cfg=SSE3")
    }
}
