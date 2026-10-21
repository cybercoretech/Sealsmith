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
    fn parses_apksigner_output() {
        let out = "Signer #1 certificate DN: CN=x\nSigner #1 certificate SHA-256 digest: 9dfa3699b793ad16af999b2fbe99b4b13ee26f8014705cc661521ee2b15e52cb\n";
        assert_eq!(
            apksigner_cert(out).unwrap(),
            "9dfa3699b793ad16af999b2fbe99b4b13ee26f8014705cc661521ee2b15e52cb"
        );
        assert!(apksigner_cert("nothing").is_none());
    }
}
