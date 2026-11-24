fn main() {
    println!("cargo:rerun-if-changed=src/biometric/macos.m");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        cc::Build::new()
            .file("src/biometric/macos.m")
            .flag("-fobjc-arc")
            .compile("silo_biometric_macos");
        println!("cargo:rustc-link-lib=framework=LocalAuthentication");
        println!("cargo:rustc-link-lib=framework=Security");
        println!("cargo:rustc-link-lib=framework=Foundation");
    }
}
