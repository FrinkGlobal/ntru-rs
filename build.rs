extern crate gcc;

use std::fs::File;
use std::path::Path;
use std::io::Write;
use std::process::Command;
use std::env;

fn main() {
    if cfg!(feature = "no-sse") && cfg!(feature = "sse") {
        panic!("You need to decide if you want SSE support or not. If you have doubts, simply disable both options and let the build script autodetect it.");
    }
    if cfg!(feature = "no-avx2") && cfg!(feature = "avx2") {
        panic!("You need to decide if you want AVX2 support or not. If you have doubts, simply disable both options and let the build script autodetect it.");
    }
    if cfg!(feature = "no-sse") && cfg!(feature = "avx2") {
        panic!("SSE is needed for AVX2 support.");
    }

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

    let mut avx2 = if cfg!(feature = "no-avx2") { false } else if cfg!(target_os = "windows") {
        cfg!(feature = "avx2")
    } else {
        let output = if cfg!(target_os = "freebsd") || cfg!(target_os = "openbsd") {
            // /usr/bin/grep -o AVX2 /var/run/dmesg.boot | /usr/bin/head -1
            Command::new("/usr/bin/grep")
                .arg("-o")
                .arg("AVX2")
                .arg("/var/run/dmesg.boot")
                .output()
                .unwrap()
        } else if cfg!(target_os = "macos") {
            // /usr/sbin/sysctl machdep.cpu.features | grep -m 1 -ow AVX2
            Command::new("/usr/sbin/sysctl")
                .arg("machdep.cpu.features")
                .output()
                .unwrap()
        } else {
            // /bin/grep -m 1 -o avx2 /proc/cpuinfo
            Command::new("/bin/grep")
                .arg("-m")
                .arg("1")
                .arg("-o")
                .arg("avx2")
                .arg("/proc/cpuinfo")
                .output()
                .unwrap()
        };

        let output = std::str::from_utf8(&output.stdout[..]).unwrap().trim();

        if cfg!(target_os = "freebsd") || cfg!(target_os = "openbsd") || cfg!(target_os = "macos") {
            output.contains("AVX2")
        } else {
            output == "avx2"
        }
    };

    let sse3 = if cfg!(feature = "no-sse3") { false } else if avx2 { true } else if cfg!(target_os = "windows") {
        cfg!(feature = "sse")
    } else {
        let output = if cfg!(target_os = "freebsd") || cfg!(target_os = "openbsd") {
            // /usr/bin/grep -o SSSE3 /var/run/dmesg.boot | /usr/bin/head -1
            Command::new("/usr/bin/grep")
                .arg("-o")
                .arg("SSE3")
                .arg("/var/run/dmesg.boot")
                .output()
                .unwrap()
        } else if cfg!(target_os = "macos") {
            // /usr/sbin/sysctl machdep.cpu.features | grep -m 1 -ow SSSE3
            Command::new("/usr/sbin/sysctl")
                .arg("machdep.cpu.features")
                .output()
                .unwrap()
        } else {
            // /bin/grep -m 1 -o ssse3 /proc/cpuinfo
            Command::new("/bin/grep")
                .arg("-m")
                .arg("1")
                .arg("-o")
                .arg("ssse3")
                .arg("/proc/cpuinfo")
                .output()
                .unwrap()
        };
        let output = std::str::from_utf8(&output.stdout[..]).unwrap().trim();

        if cfg!(target_os = "freebsd") || cfg!(target_os = "openbsd") || cfg!(target_os = "macos") {
            output.contains("SSSE3")
        } else {
            output == "ssse3"
        }
    };

    if !sse3 {
        avx2 = false;
    }

    let mut cflags = "-g -Wall -Wextra -Wno-unused-parameter".to_owned();
    if avx2 {
        cflags = cflags + " -mavx2";
    }
    if sse3 {
        cflags = cflags + " -mssse3";
    } else if cfg!(target_os = "macos") {
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
          .file("src/c/src/rijndael.c");

    if sse3 &&
       (cfg!(target_pointer_width = "64") || cfg!(target_os = "macos") ||
        cfg!(target_os = "windows")) {
        let out = if cfg!(target_os = "windows") {
            Command::new("c:\\mingw\\msys\\1.0\\bin\\perl")
                .arg("src/c/src/sha1-mb-x86_64.pl")
                .arg("coff")
                .output()
                .unwrap()
        } else if cfg!(target_os = "macos") {
            Command::new("/usr/bin/perl")
                .arg("src/c/src/sha1-mb-x86_64.pl")
                .arg("macosx")
                .output()
                .unwrap()
        } else  {
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

        Command::new(env::var("CC").unwrap())
            .arg("-c")
            .arg("src/c/src/sha1-mb-x86_64.s")
            .arg("-o")
            .arg("src/c/src/sha1-mb-x86_64.o")
            .output()
            .unwrap();

        let out = if cfg!(target_os = "windows") {
            Command::new("c:\\mingw\\msys\\1.0\\bin\\perl")
                .arg("src/c/src/sha256-mb-x86_64.pl")
                .arg("coff")
                .output()
                .unwrap()
        } else if cfg!(target_os = "macos") {
            Command::new("/usr/bin/perl")
                .arg("src/c/src/sha256-mb-x86_64.pl")
                .arg("macosx")
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

        Command::new(env::var("CC").unwrap())
            .arg("-c")
            .arg("src/c/src/sha256-mb-x86_64.s")
            .arg("-o")
            .arg("src/c/src/sha256-mb-x86_64.o")
            .output()
            .unwrap();

        config.object("src/c/src/sha1-mb-x86_64.o").object("src/c/src/sha256-mb-x86_64.o");
    }

    config.include("src/c/src").compile("libntru.a");

    if sse3 {
        println!("cargo:rustc-cfg=SSE3")
    }
    if avx2 {
        println!("cargo:rustc-cfg=AVX2")
    }
}
