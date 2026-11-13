//! Embeds the app icon and version details into the Windows executable, so Explorer, the
//! taskbar, the Start menu and Task Manager show the right icon and name.

fn main() {
    println!("cargo:rerun-if-changed=assets/icon.ico");
    println!("cargo:rerun-if-changed=build.rs");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/icon.ico")
            .set("ProductName", "PDF Decoder")
            .set("FileDescription", "PDF Decoder")
            .set("CompanyName", "Bhathiya")
            .set("LegalCopyright", "© Bhathiya")
            .set("OriginalFilename", "pdf_decorder.exe");
        if let Err(e) = res.compile() {
            // Don't break the build when the Windows SDK resource compiler is missing;
            // the app still works, it just has the default icon.
            println!("cargo:warning=Could not embed the Windows icon: {e}");
        }
    }
}
