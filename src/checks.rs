//! Pure checks over repository text. No I/O here, so every rule is unit-tested.

use regex::Regex;
use std::collections::BTreeMap;
use std::sync::OnceLock;

/// `version = "x.y.z"` from the `[package]` table of a Cargo.toml.
pub fn cargo_package_version(cargo_toml: &str) -> Option<String> {
    let v: toml::Value = toml::from_str(cargo_toml).ok()?;
    v.get("package")?
        .get("version")?
        .as_str()
        .map(str::to_string)
}

/// A clap `#[command(...)]` attribute with a hard-coded `version = "x.y.z"`.
/// Bare `version` reads Cargo.toml; a literal drifts (Keysmith and CyberVault
/// 0.2.0 both printed "0.1.0").
pub fn hardcoded_clap_versions(rust_source: &str) -> Vec<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r#"(?s)#\[command\((?:[^\]]*?)\bversion\s*=\s*"(\d+\.\d+\.\d+[^"]*)""#).unwrap()
    });
    re.captures_iter(rust_source)
        .map(|c| c[1].to_string())
        .collect()
}

/// Every place a signing-certificate SHA-256 is pinned in a file, keyed by a
/// short label. Accepts plain 64-hex and colon-separated uppercase forms.
pub fn cert_pins(text: &str) -> Vec<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"(?i)(?:cert[a-z_ ]*sha-?256|signing cert[^\n]{0,40}|certificate[^\n]{0,40}sha-?256)[^0-9a-f]{0,60}((?:[0-9a-f]{2}:){31}[0-9a-f]{2}|[0-9a-f]{64})")
            .unwrap()
    });
    let mut out: Vec<String> = re
        .captures_iter(text)
        .map(|c| normalize_hex(&c[1]))
        .collect();
    out.sort();
    out.dedup();
    out
}

pub fn normalize_hex(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_ascii_lowercase()
}

/// Group pins by value → which files state them. More than one key means drift.
pub fn pin_drift(found: &[(String, Vec<String>)]) -> BTreeMap<String, Vec<String>> {
    let mut by_pin: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (file, pins) in found {
        for p in pins {
            by_pin.entry(p.clone()).or_default().push(file.clone());
        }
    }
    by_pin
}

/// What a repository owes its users when its Cargo.toml version changes.
#[derive(Debug, PartialEq, Eq)]
pub enum Expect {
    /// Built from source: no tag or release is promised.
    Nothing,
    /// A library published to crates.io: the version should be tagged.
    Tag,
    /// Downloadable assets: a tag and a GitHub release with assets.
    Release,
}

/// Decide from the release workflow and any installer what a version owes.
/// Plugins whose installers run `cargo build` don't promise a release; an
/// installer that downloads from `releases/` or a workflow that uploads
/// assets does.
pub fn release_expectation(release_yml: Option<&str>, installers: &[&str]) -> Expect {
    let downloads = installers
        .iter()
        .any(|t| t.contains("/releases/") || t.contains("gh release download"));
    let uploads = release_yml.is_some_and(|y| {
        y.contains("action-gh-release")
            || y.contains("gh release create")
            || y.contains("upload-release-asset")
            || y.contains("gh release upload")
    });
    if downloads || uploads {
        Expect::Release
    } else if release_yml
        .is_some_and(|y| y.contains("cargo publish") || y.contains("CARGO_REGISTRY_TOKEN"))
    {
        Expect::Tag
    } else {
        Expect::Nothing
    }
}

/// The prefix of the tags that trigger the release workflow ("v" for
/// `tags: ["v*"]`, "cli-v" for `- "cli-v*"`). A prefix other than "v" means
/// binaries are released under their own tag namespace, apart from the
/// crate's `vX.Y.Z` tags (diagprint does this).
pub fn release_tag_prefix(release_yml: &str) -> Option<String> {
    let mut lines = release_yml.lines();
    while let Some(line) = lines.next() {
        let t = line.trim_start();
        let Some(rest) = t.strip_prefix("tags:") else {
            continue;
        };
        let indent = line.len() - t.len();
        let first = if let Some(inline) = rest.trim().strip_prefix('[') {
            inline.split([',', ']']).next().map(str::to_string)
        } else {
            lines
                .by_ref()
                .take_while(|l| l.trim().is_empty() || l.len() - l.trim_start().len() > indent)
                .map(str::trim)
                .find(|l| l.starts_with("- "))
                .map(|l| l[2..].to_string())
        };
        let pattern = first?;
        let pattern = pattern.trim().trim_matches(|c| c == '"' || c == '\'');
        return Some(pattern.split('*').next().unwrap_or(pattern).to_string());
    }
    None
}

/// The signer line `apksigner verify --print-certs` prints for signer #1.
pub fn apksigner_cert(output: &str) -> Option<String> {
    output
        .lines()
        .find_map(|l| {
            l.split_once("certificate SHA-256 digest:")
                .map(|(_, h)| normalize_hex(h))
        })
        .filter(|h| h.len() == 64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_package_version_only() {
        assert_eq!(cargo_package_version("[package]\nname='x'\nversion = \"0.2.0\"\n[dependencies]\nfoo = { version = \"9.9.9\" }").as_deref(), Some("0.2.0"));
        assert_eq!(cargo_package_version("[workspace]\nmembers=[]"), None);
    }

    #[test]
    fn finds_hardcoded_clap_versions() {
        let bad = "#[derive(Parser)]\n#[command(\n    name = \"keysmith\",\n    version = \"0.1.0\",\n    about = \"x\"\n)]\nstruct A;";
        assert_eq!(hardcoded_clap_versions(bad), ["0.1.0"]);
        let good = "#[command(name = \"cybervault\", version, about = \"x\")]\nstruct A;";
        assert!(hardcoded_clap_versions(good).is_empty());
        let unrelated = "let dep = Dep { version = \"1.2.3\" };";
        assert!(hardcoded_clap_versions(unrelated).is_empty());
    }

    #[test]
    fn extracts_pins_in_every_format_we_use() {
        let install =
            "CERT_SHA256=\"9dfa3699b793ad16af999b2fbe99b4b13ee26f8014705cc661521ee2b15e52cb\"";
        let readme = "🪪 **Release signing certificate (SHA-256):**\n`9dfa3699b793ad16af999b2fbe99b4b13ee26f8014705cc661521ee2b15e52cb`";
        let colon = "Release signing certificate (SHA-256):\n\n```\n88:39:05:95:F5:FB:F1:71:DC:03:D0:40:AB:C8:ED:C2:A7:FB:9E:97:33:20:B3:C4:BB:E7:25:D4:13:9B:28:3C\n```";
        assert_eq!(
            cert_pins(install),
            ["9dfa3699b793ad16af999b2fbe99b4b13ee26f8014705cc661521ee2b15e52cb"]
        );
        assert_eq!(
            cert_pins(readme),
            ["9dfa3699b793ad16af999b2fbe99b4b13ee26f8014705cc661521ee2b15e52cb"]
        );
        assert_eq!(
            cert_pins(colon),
            ["88390595f5fbf171dc03d040abc8edc2a7fb9e973320b3c4bbe725d4139b283c"]
        );
        assert!(
            cert_pins(
                "APK SHA-256: 234aaf112638b74b78f1a279cc75bff4c8d81eda267375541cd07daa2e9759e5"
            )
            .is_empty(),
            "an APK checksum isn't a cert pin"
        );
    }

    #[test]
    fn drift_groups_files_by_pin() {
        let d = pin_drift(&[
            ("install.sh".into(), vec!["aa".into()]),
            ("README.md".into(), vec!["aa".into()]),
            ("site".into(), vec!["bb".into()]),
        ]);
        assert_eq!(d.len(), 2);
        assert_eq!(d["aa"], ["install.sh", "README.md"]);
    }

    #[test]
    fn release_tag_prefixes() {
        assert_eq!(
            release_tag_prefix("on:\n  push:\n    tags: [\"v*\"]\n").as_deref(),
            Some("v")
        );
        assert_eq!(
            release_tag_prefix("on:\n  push:\n    tags:\n      - 'v*.*.*'\njobs:\n").as_deref(),
            Some("v")
        );
        let diagprint = "on:\n  push:\n    tags:\n      # A separate tag namespace\n      # from the crate's tags\n      - \"cli-v*\"\n\npermissions:\n";
        assert_eq!(release_tag_prefix(diagprint).as_deref(), Some("cli-v"));
        assert_eq!(release_tag_prefix("on:\n  workflow_dispatch:\n"), None);
    }

    #[test]
    fn release_expectations() {
        let gh_release =
            "on:\n  push:\n    tags: [\"v*\"]\n...\n      - uses: softprops/action-gh-release@v2";
        let crate_only = "on:\n  workflow_dispatch:\n...\n      - run: cargo publish\n        env:\n          CARGO_REGISTRY_TOKEN: x";
        let from_source = "cargo build --release\ncp target/release/x ~/.local/bin";
        let downloader = "curl -fsSL https://github.com/o/r/releases/latest/download/x.tar.gz";
        assert_eq!(release_expectation(Some(gh_release), &[]), Expect::Release);
        assert_eq!(release_expectation(Some(crate_only), &[]), Expect::Tag);
        assert_eq!(release_expectation(None, &[from_source]), Expect::Nothing);
        assert_eq!(release_expectation(None, &[downloader]), Expect::Release);
        assert_eq!(
            release_expectation(Some(crate_only), &[downloader]),
            Expect::Release
        );
    }

    #[test]
    fn parses_apksigner_output() {
        let out = "Signer #1 certificate DN: CN=x\nSigner #1 certificate SHA-256 digest: 9dfa3699b793ad16af999b2fbe99b4b13ee26f8014705cc661521ee2b15e52cb\n";
        assert_eq!(
            apksigner_cert(out).unwrap(),
            "9dfa3699b793ad16af999b2fbe99b4b13ee26f8014705cc661521ee2b15e52cb"
        );
        assert!(apksigner_cert("nothing").is_none());
    }
}
