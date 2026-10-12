//! `silo browser …`: native messaging manifests that let the browser
//! extension start `silo-native-host`.
//!
//! Browsers look for `<host name>.json` in fixed per-user directories. The
//! manifest names the absolute path of the host binary and the one extension
//! allowed to start it. No ports, no tokens: the browser spawns the host and
//! talks to it over stdio, and the host talks to the agent socket.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::ValueEnum;
use serde_json::{Value, json};

use crate::args::BrowserCommand;
use crate::format;

/// Name the extension passes to `runtime.connectNative`.
pub const HOST_NAME: &str = "dev.silo.agent";
/// Binary next to `silo`, built from `src/bin/native_host.rs`.
pub const HOST_BINARY: &str = "silo-native-host";
/// Must equal `browser_specific_settings.gecko.id` in `apps/extension/wxt.config.ts`.
pub const FIREFOX_EXTENSION_ID: &str = "{a0c28bb5-d123-45d0-bc03-db1ac9a0a61d}";
/// Derived from the `key` in `apps/extension/wxt.config.ts`; the same on every machine.
pub const CHROME_EXTENSION_ID: &str = "mhngnkbgjofcmibiepppmjmhdcfmkama";

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Browser {
    Firefox,
    Zen,
    Chrome,
    Chromium,
    Brave,
    Edge,
}

/// Manifest dialect: Mozilla lists extension ids, Chromium lists origins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    Mozilla,
    Chromium,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Os {
    MacOs,
    Linux,
}

impl Browser {
    pub const ALL: [Self; 6] = [
        Self::Firefox,
        Self::Zen,
        Self::Chrome,
        Self::Chromium,
        Self::Brave,
        Self::Edge,
    ];

    pub fn family(self) -> Family {
        match self {
            Self::Firefox | Self::Zen => Family::Mozilla,
            Self::Chrome | Self::Chromium | Self::Brave | Self::Edge => Family::Chromium,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Firefox => "Firefox",
            Self::Zen => "Zen",
            Self::Chrome => "Chrome",
            Self::Chromium => "Chromium",
            Self::Brave => "Brave",
            Self::Edge => "Edge",
        }
    }
}

/// Where one user's browsers keep their data on this machine.
#[derive(Clone, Debug)]
pub struct Layout {
    home: PathBuf,
    config: PathBuf,
    os: Os,
}

impl Layout {
    pub fn from_env() -> Result<Self> {
        let os = if cfg!(target_os = "macos") {
            Os::MacOs
        } else if cfg!(target_os = "linux") {
            Os::Linux
        } else {
            bail!("browser integration is only implemented for macOS and Linux")
        };
        let home = std::env::var_os("HOME")
            .filter(|h| !h.is_empty())
            .map(PathBuf::from)
            .context("HOME is not set")?;
        let config = std::env::var_os("XDG_CONFIG_HOME")
            .filter(|c| !c.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".config"));
        Ok(Self::new(home, config, os))
    }

    pub fn new(home: impl Into<PathBuf>, config: impl Into<PathBuf>, os: Os) -> Self {
        Self {
            home: home.into(),
            config: config.into(),
            os,
        }
    }

    fn app_support(&self) -> PathBuf {
        self.home.join("Library/Application Support")
    }

    /// A directory whose presence means the browser has been run by this user.
    pub fn profile_dir(&self, browser: Browser) -> PathBuf {
        match self.os {
            Os::MacOs => {
                let base = self.app_support();
                match browser {
                    Browser::Firefox => base.join("Firefox"),
                    Browser::Zen => base.join("zen"),
                    Browser::Chrome => base.join("Google/Chrome"),
                    Browser::Chromium => base.join("Chromium"),
                    Browser::Brave => base.join("BraveSoftware/Brave-Browser"),
                    Browser::Edge => base.join("Microsoft Edge"),
                }
            }
            Os::Linux => match browser {
                Browser::Firefox => self.home.join(".mozilla"),
                Browser::Zen => self.home.join(".zen"),
                Browser::Chrome => self.config.join("google-chrome"),
                Browser::Chromium => self.config.join("chromium"),
                Browser::Brave => self.config.join("BraveSoftware/Brave-Browser"),
                Browser::Edge => self.config.join("microsoft-edge"),
            },
        }
    }

    /// Directories the browser scans for manifests. The first is the one that
    /// works today. Zen reads Firefox's directory (zen-browser/desktop#10622)
    /// and may grow its own, so it gets both.
    pub fn manifest_dirs(&self, browser: Browser) -> Vec<PathBuf> {
        match (self.os, browser) {
            (Os::MacOs, Browser::Firefox) => {
                vec![self.app_support().join("Mozilla/NativeMessagingHosts")]
            }
            (Os::MacOs, Browser::Zen) => vec![
                self.app_support().join("Mozilla/NativeMessagingHosts"),
                self.app_support().join("zen/NativeMessagingHosts"),
            ],
            (Os::Linux, Browser::Firefox) => {
                vec![self.home.join(".mozilla/native-messaging-hosts")]
            }
            (Os::Linux, Browser::Zen) => vec![
                self.home.join(".mozilla/native-messaging-hosts"),
                self.home.join(".zen/native-messaging-hosts"),
            ],
            (_, chromium) => vec![self.profile_dir(chromium).join("NativeMessagingHosts")],
        }
    }

    pub fn manifest_files(&self, browser: Browser) -> Vec<PathBuf> {
        self.manifest_dirs(browser)
            .into_iter()
            .map(|dir| dir.join(format!("{HOST_NAME}.json")))
            .collect()
    }

    pub fn is_present(&self, browser: Browser) -> bool {
        self.profile_dir(browser).is_dir()
    }

    pub fn detected(&self) -> Vec<Browser> {
        Browser::ALL
            .into_iter()
            .filter(|b| self.is_present(*b))
            .collect()
    }
}

/// The manifest body for one browser family.
pub fn manifest(family: Family, host: &Path, extra_ids: &[String]) -> Value {
    let mut value = json!({
        "name": HOST_NAME,
        "description": "Silo: connects the browser extension to the local agent",
        "path": host,
        "type": "stdio",
    });
    match family {
        Family::Mozilla => {
            let ids: Vec<&str> = std::iter::once(FIREFOX_EXTENSION_ID)
                .chain(extra_ids.iter().map(String::as_str))
                .collect();
            value["allowed_extensions"] = json!(ids);
        }
        Family::Chromium => {
            let origins: Vec<String> = std::iter::once(CHROME_EXTENSION_ID.to_owned())
                .chain(extra_ids.iter().cloned())
                .map(|id| chrome_origin(&id))
                .collect();
            value["allowed_origins"] = json!(origins);
        }
    }
    value
}

fn chrome_origin(id: &str) -> String {
    let id = id.trim().trim_end_matches('/');
    match id.strip_prefix("chrome-extension://") {
        Some(bare) => format!("chrome-extension://{bare}/"),
        None => format!("chrome-extension://{id}/"),
    }
}

/// Absolute path of `silo-native-host`, which `cargo install` puts next to `silo`.
pub fn host_binary() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("locating the secret binary")?;
    let dir = exe
        .parent()
        .context("the secret binary has no parent directory")?;
    let host = dir.join(HOST_BINARY);
    if !host.is_file() {
        bail!(
            "{} not found; install both binaries with `cargo install --path crates/cli`",
            host.display()
        );
    }
    Ok(host)
}

pub fn run(command: BrowserCommand) -> Result<()> {
    let layout = Layout::from_env()?;
    match command {
        BrowserCommand::Install {
            browser,
            extension_id,
            dir,
        } => install(&layout, browser, &extension_id, dir),
        BrowserCommand::Uninstall { browser } => uninstall(&layout, browser),
        BrowserCommand::Status => status(&layout),
    }
}

fn install(
    layout: &Layout,
    requested: Vec<Browser>,
    extra_ids: &[String],
    dir: Option<PathBuf>,
) -> Result<()> {
    let host = host_binary()?;
    if let Some(dir) = dir {
        let [browser] = requested.as_slice() else {
            bail!("--dir needs exactly one --browser to pick the manifest format");
        };
        let file = write_manifest(&dir, browser.family(), &host, extra_ids)?;
        println!("{:<9} {}", browser.label(), file.display());
        return Ok(());
    }
    let browsers = if requested.is_empty() {
        let detected = layout.detected();
        if detected.is_empty() {
            bail!(
                "no supported browser found for this user; pass --browser (firefox, zen, chrome, chromium, brave, edge)"
            );
        }
        detected
    } else {
        dedup(requested)
    };
    for browser in browsers {
        for dir in layout.manifest_dirs(browser) {
            let file = write_manifest(&dir, browser.family(), &host, extra_ids)?;
            println!("{:<9} {}", browser.label(), file.display());
        }
    }
    println!("Host: {}", host.display());
    println!("Reload the extension (or restart the browser) to connect.");
    Ok(())
}

fn write_manifest(
    dir: &Path,
    family: Family,
    host: &Path,
    extra_ids: &[String],
) -> Result<PathBuf> {
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let file = dir.join(format!("{HOST_NAME}.json"));
    let mut text = serde_json::to_string_pretty(&manifest(family, host, extra_ids))?;
    text.push('\n');
    fs::write(&file, text).with_context(|| format!("writing {}", file.display()))?;
    Ok(file)
}

fn uninstall(layout: &Layout, requested: Vec<Browser>) -> Result<()> {
    let browsers = if requested.is_empty() {
        Browser::ALL.to_vec()
    } else {
        dedup(requested)
    };
    let mut removed = 0;
    for browser in browsers {
        for file in layout.manifest_files(browser) {
            if file.is_file() {
                fs::remove_file(&file).with_context(|| format!("removing {}", file.display()))?;
                println!("Removed {}", file.display());
                removed += 1;
            }
        }
    }
    if removed == 0 {
        println!("No manifests found.");
    }
    Ok(())
}

fn status(layout: &Layout) -> Result<()> {
    let host = host_binary();
    let rows: Vec<Vec<String>> = Browser::ALL
        .into_iter()
        .map(|browser| {
            let present = layout.is_present(browser);
            let file = layout.manifest_files(browser).remove(0);
            let state = match fs::read_to_string(&file) {
                Ok(text) => match serde_json::from_str::<Value>(&text) {
                    Ok(value) => {
                        let path = value["path"].as_str().unwrap_or_default();
                        match &host {
                            Ok(host) if host.to_str() == Some(path) => "connected".to_owned(),
                            _ => format!("manifest points to {path}"),
                        }
                    }
                    Err(_) => "manifest is not valid JSON".to_owned(),
                },
                Err(_) => "not connected".to_owned(),
            };
            vec![
                browser.label().to_owned(),
                if present { "yes" } else { "no" }.to_owned(),
                state,
                file.display().to_string(),
            ]
        })
        .collect();
    println!(
        "{}",
        format::table(&["BROWSER", "FOUND", "STATE", "MANIFEST"], &rows)
    );
    match host {
        Ok(host) => println!("Host: {}", host.display()),
        Err(err) => println!("Host: {err:#}"),
    }
    Ok(())
}

fn dedup(mut browsers: Vec<Browser>) -> Vec<Browser> {
    let mut seen = Vec::new();
    browsers.retain(|b| {
        if seen.contains(b) {
            false
        } else {
            seen.push(*b);
            true
        }
    });
    browsers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifests_name_the_extension_in_each_dialect() {
        let host = Path::new("/opt/bin/silo-native-host");
        let mozilla = manifest(Family::Mozilla, host, &[]);
        assert_eq!(mozilla["name"], HOST_NAME);
        assert_eq!(mozilla["type"], "stdio");
        assert_eq!(mozilla["path"], "/opt/bin/silo-native-host");
        assert_eq!(mozilla["allowed_extensions"], json!([FIREFOX_EXTENSION_ID]));
        assert!(mozilla.get("allowed_origins").is_none());

        let extra = vec![
            "abcdefghijklmnopabcdefghijklmnop".to_owned(),
            "chrome-extension://zzzz".to_owned(),
        ];
        let chromium = manifest(Family::Chromium, host, &extra);
        assert_eq!(
            chromium["allowed_origins"],
            json!([
                format!("chrome-extension://{CHROME_EXTENSION_ID}/"),
                "chrome-extension://abcdefghijklmnopabcdefghijklmnop/",
                "chrome-extension://zzzz/",
            ])
        );
        assert!(chromium.get("allowed_extensions").is_none());
    }

    #[test]
    fn macos_layout_uses_application_support() {
        let layout = Layout::new("/Users/u", "/Users/u/.config", Os::MacOs);
        let zen = layout.manifest_dirs(Browser::Zen);
        assert_eq!(
            zen[0],
            Path::new("/Users/u/Library/Application Support/Mozilla/NativeMessagingHosts")
        );
        assert_eq!(
            zen[1],
            Path::new("/Users/u/Library/Application Support/zen/NativeMessagingHosts")
        );
        assert_eq!(
            layout.manifest_files(Browser::Chrome),
            [PathBuf::from(
                "/Users/u/Library/Application Support/Google/Chrome/NativeMessagingHosts/dev.silo.agent.json"
            )]
        );
    }

    #[test]
    fn linux_layout_uses_dotfiles_and_xdg_config() {
        let layout = Layout::new("/home/u", "/home/u/cfg", Os::Linux);
        assert_eq!(
            layout.manifest_dirs(Browser::Firefox),
            [PathBuf::from("/home/u/.mozilla/native-messaging-hosts")]
        );
        assert_eq!(
            layout.manifest_dirs(Browser::Zen)[1],
            Path::new("/home/u/.zen/native-messaging-hosts")
        );
        assert_eq!(
            layout.manifest_dirs(Browser::Brave),
            [PathBuf::from(
                "/home/u/cfg/BraveSoftware/Brave-Browser/NativeMessagingHosts"
            )]
        );
    }

    #[test]
    fn detection_and_manifest_round_trip_in_a_temp_home() {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::new(dir.path(), dir.path().join(".config"), Os::MacOs);
        assert!(layout.detected().is_empty());
        fs::create_dir_all(layout.profile_dir(Browser::Zen)).unwrap();
        fs::create_dir_all(layout.profile_dir(Browser::Chrome)).unwrap();
        assert_eq!(layout.detected(), [Browser::Zen, Browser::Chrome]);

        let host = dir.path().join("silo-native-host");
        for browser in layout.detected() {
            for d in layout.manifest_dirs(browser) {
                write_manifest(&d, browser.family(), &host, &[]).unwrap();
            }
        }
        let files: Vec<PathBuf> = layout
            .manifest_files(Browser::Zen)
            .into_iter()
            .chain(layout.manifest_files(Browser::Chrome))
            .collect();
        assert_eq!(files.len(), 3);
        for file in &files {
            let value: Value = serde_json::from_str(&fs::read_to_string(file).unwrap()).unwrap();
            assert_eq!(value["path"], host.to_str().unwrap());
        }
        uninstall(&layout, vec![]).unwrap();
        assert!(files.iter().all(|f| !f.exists()));
    }

    #[test]
    fn requested_browsers_are_deduplicated() {
        assert_eq!(
            dedup(vec![Browser::Zen, Browser::Chrome, Browser::Zen]),
            [Browser::Zen, Browser::Chrome]
        );
    }
}
