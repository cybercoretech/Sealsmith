//! Sealsmith: release, verify and audit Cybercore software.
//!
//! Milestone 1 is read-only: `verify` and `audit`. GitHub is reached through
//! the `gh` CLI (so per-owner credentials just work) and APK signatures
//! through Android's `apksigner`.

mod checks;

use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

#[derive(Parser)]
#[command(
    name = "sealsmith",
    version,
    about = "Release, verify and audit Cybercore software"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Check a file's SHA-256 and (for APKs) its signing certificate.
    Verify {
        file: PathBuf,
        /// Expected SHA-256 of the file (64 hex), or a `.sha256` file next to it.
        #[arg(long)]
        sha256: Option<String>,
        /// Expected signing-certificate SHA-256 for an APK.
        #[arg(long)]
        cert: Option<String>,
    },
    /// Check repositories for version, tag, release and pin drift.
    Audit {
        /// Repositories to audit (default: every git repo two levels under
        /// ~/Devspace/Cybercore and one level under ~/Devspace/Android).
        repos: Vec<PathBuf>,
        /// Also download each Android app's latest release APK and check its
        /// signer against the pin.
        #[arg(long)]
        deep: bool,
        /// GitHub owner for release lookups.
        #[arg(long, default_value = "cybercoretech")]
        owner: String,
    },
}

fn main() -> ExitCode {
    match Cli::parse().cmd {
        Cmd::Verify { file, sha256, cert } => verify(&file, sha256.as_deref(), cert.as_deref()),
        Cmd::Audit { repos, deep, owner } => audit(repos, deep, &owner),
    }
}

// ── verify ──────────────────────────────────────────────────────────────

fn verify(file: &Path, want_sha: Option<&str>, want_cert: Option<&str>) -> ExitCode {
    let bytes = match std::fs::read(file) {
        Ok(b) => b,
        Err(e) => return fail(&format!("{}: {e}", file.display())),
    };
    let sha = hex(&Sha256::digest(&bytes));
    println!("sha256       {sha}");
    let mut ok = true;

    let sidecar = PathBuf::from(format!("{}.sha256", file.display()));
    let expected = match want_sha {
        Some(s) => Some(checks::normalize_hex(s)),
        None => std::fs::read_to_string(&sidecar)
            .ok()
            .map(|t| checks::normalize_hex(t.split_whitespace().next().unwrap_or(""))),
    };
    match expected {
        Some(e) if e == sha => println!("✓ checksum    matches"),
        Some(e) => {
            println!("✗ checksum    expected {e}");
            ok = false;
        }
        None => println!(
            "· checksum    nothing to compare (pass --sha256 or put a .sha256 next to the file)"
        ),
    }

    if is_apk(&bytes) {
        match apk_signer(file) {
            Ok(cert) => {
                println!("signer       {cert}");
                match want_cert.map(checks::normalize_hex) {
                    Some(w) if w == cert => println!("✓ signer      matches the pin"),
                    Some(w) => {
                        println!("✗ signer      expected {w}");
                        ok = false;
                    }
                    None => println!("· signer      no --cert pin given"),
                }
            }
            Err(e) => {
                println!("✗ signer      {e}");
                ok = false;
            }
        }
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn is_apk(b: &[u8]) -> bool {
    b.starts_with(b"PK\x03\x04") && b.windows(19).any(|w| w == b"AndroidManifest.xml")
}

fn apk_signer(apk: &Path) -> Result<String, String> {
    let tool =
        apksigner().ok_or("apksigner not found (install Android build-tools or put it on PATH)")?;
    let out = Command::new(&tool)
        .args(["verify", "--print-certs"])
        .arg(apk)
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!(
            "apksigner rejected the signature: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    checks::apksigner_cert(&String::from_utf8_lossy(&out.stdout))
        .ok_or_else(|| "no signer in apksigner output".into())
}

fn apksigner() -> Option<PathBuf> {
    if let Ok(p) = which("apksigner") {
        return Some(p);
    }
    let sdk = std::env::var_os("ANDROID_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join("android"));
    let mut tools: Vec<PathBuf> = std::fs::read_dir(sdk.join("build-tools"))
        .ok()?
        .flatten()
        .map(|e| e.path().join("apksigner"))
        .filter(|p| p.exists())
        .collect();
    tools.sort();
    tools.pop()
}

// ── audit ───────────────────────────────────────────────────────────────

#[derive(Default)]
struct Report {
    problems: usize,
}

impl Report {
    fn ok(&self, msg: &str) {
        println!("  ✓ {msg}");
    }
    fn bad(&mut self, msg: &str) {
        self.problems += 1;
        println!("  ✗ {msg}");
    }
    fn note(&self, msg: &str) {
        println!("  · {msg}");
    }
}

fn audit(repos: Vec<PathBuf>, deep: bool, owner: &str) -> ExitCode {
    let repos = if repos.is_empty() {
        default_repos()
    } else {
        repos
    };
    let mut r = Report::default();
    for repo in &repos {
        let Some(name) = github_name(repo) else {
            continue;
        };
        let cargo = std::fs::read_to_string(repo.join("Cargo.toml")).ok();
        let android = repo.join("app/build.gradle.kts").exists();
        if cargo.is_none() && !android {
            continue;
        }
        println!("▸ {name}  ({})", repo.display());
        if let Some(c) = &cargo {
            audit_cargo(repo, c, owner, &name, &mut r);
        }
        audit_pins(repo, android, deep, owner, &name, &mut r);
    }
    println!();
    if r.problems == 0 {
        println!("✓ {} repositories, no problems", repos.len());
        ExitCode::SUCCESS
    } else {
        println!("✗ {} problem(s)", r.problems);
        ExitCode::FAILURE
    }
}

fn audit_cargo(repo: &Path, cargo: &str, owner: &str, name: &str, r: &mut Report) {
    for src in rust_sources(&repo.join("src")) {
        if let Ok(text) = std::fs::read_to_string(&src) {
            for v in checks::hardcoded_clap_versions(&text) {
                r.bad(&format!("{}: clap `version = \"{v}\"` is hard-coded; use bare `version` so it follows Cargo.toml", src.strip_prefix(repo).unwrap_or(&src).display()));
            }
        }
    }
    let Some(version) = checks::cargo_package_version(cargo) else {
        return;
    };
    let read = |f: &str| std::fs::read_to_string(repo.join(f)).ok();
    let workflow = read(".github/workflows/release.yml");
    let installers: Vec<String> = ["install.sh", "docs/install.sh", "site/install.sh"]
        .iter()
        .filter_map(|f| read(f))
        .collect();
    let installer_refs: Vec<&str> = installers.iter().map(String::as_str).collect();
    let expect = checks::release_expectation(workflow.as_deref(), &installer_refs);
    if expect == checks::Expect::Nothing {
        r.note(&format!(
            "Cargo.toml {version} (built from source; no release promised)"
        ));
        return;
    }
    let tag = format!("v{version}");
    if git(
        repo,
        &["rev-parse", "-q", "--verify", &format!("refs/tags/{tag}")],
    )
    .is_some()
    {
        r.ok(&format!("Cargo.toml {version} has tag {tag}"));
    } else {
        r.bad(&format!(
            "Cargo.toml says {version} but there's no local tag {tag}"
        ));
    }
    if expect == checks::Expect::Tag {
        r.note("library published to crates.io: a tag is enough, no release assets expected");
        return;
    }
    match gh(&[
        "release",
        "view",
        &tag,
        "-R",
        &format!("{owner}/{name}"),
        "--json",
        "assets",
        "--jq",
        ".assets|length",
    ]) {
        Some(n) if n.trim() != "0" => r.ok(&format!(
            "GitHub release {tag} exists ({} assets)",
            n.trim()
        )),
        Some(_) => r.bad(&format!("GitHub release {tag} has no assets")),
        None => r.bad(&format!(
            "no GitHub release {tag} (installers and release links have nothing to download)"
        )),
    }
}

fn audit_pins(repo: &Path, android: bool, deep: bool, owner: &str, name: &str, r: &mut Report) {
    let candidates = [
        "install.sh",
        "docs/install.sh",
        "site/install.sh",
        "tools/release.conf",
        "tools/release.sh",
        "README.md",
        "SECURITY.md",
        "docs/index.html",
        "site/index.html",
    ];
    let found: Vec<(String, Vec<String>)> = candidates
        .iter()
        .filter_map(|f| {
            std::fs::read_to_string(repo.join(f))
                .ok()
                .map(|t| (f.to_string(), checks::cert_pins(&t)))
        })
        .filter(|(_, p)| !p.is_empty())
        .collect();
    if found.is_empty() {
        if android {
            r.note("no signing-certificate pin published");
        }
        return;
    }
    let drift = checks::pin_drift(&found);
    if drift.len() == 1 {
        let (pin, files) = drift.iter().next().unwrap();
        r.ok(&format!(
            "cert pin {}… consistent in {}",
            &pin[..8],
            files.join(", ")
        ));
    } else {
        for (pin, files) in &drift {
            r.bad(&format!(
                "cert pin {}… in {} (pins disagree)",
                &pin[..8],
                files.join(", ")
            ));
        }
    }
    if deep && android && drift.len() == 1 {
        let pin = drift.keys().next().unwrap().clone();
        deep_check_release(owner, name, &pin, r);
    }
}

fn deep_check_release(owner: &str, name: &str, pin: &str, r: &mut Report) {
    let Some(asset) = gh(&[
        "release",
        "view",
        "-R",
        &format!("{owner}/{name}"),
        "--json",
        "assets",
        "--jq",
        "[.assets[].name|select(endswith(\".apk\"))][0]",
    ]) else {
        r.bad("no GitHub release to check");
        return;
    };
    let asset = asset.trim().to_string();
    if asset.is_empty() || asset == "null" {
        r.bad("latest release has no .apk asset");
        return;
    }
    let dir = std::env::temp_dir().join(format!("sealsmith-{name}-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let got = gh(&[
        "release",
        "download",
        "-R",
        &format!("{owner}/{name}"),
        "-p",
        &asset,
        "-D",
        dir.to_str().unwrap_or("."),
        "--clobber",
    ]);
    let apk = dir.join(&asset);
    match (got, apk_signer(&apk)) {
        (Some(_), Ok(cert)) if cert == pin => r.ok(&format!(
            "latest release {asset} is signed by the pinned key"
        )),
        (Some(_), Ok(cert)) => r.bad(&format!(
            "latest release {asset} is signed by {}…, not the pin",
            &cert[..8]
        )),
        (_, Err(e)) => r.bad(&format!("couldn't check {asset}: {e}")),
        (None, _) => r.bad(&format!("couldn't download {asset}")),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// ── helpers ─────────────────────────────────────────────────────────────

fn default_repos() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let dev = home().join("Devspace");
    for (base, depth) in [(dev.join("Cybercore"), 2), (dev.join("Android"), 1)] {
        collect_repos(&base, depth, &mut out);
    }
    out.sort();
    out
}

fn collect_repos(dir: &Path, depth: u8, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if !p.is_dir()
            || p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with('.'))
        {
            continue;
        }
        if depth == 1 {
            if p.join(".git").exists() {
                out.push(p);
            }
        } else {
            collect_repos(&p, depth - 1, out);
        }
    }
}

fn rust_sources(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(rust_sources(&p));
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    out
}

/// `owner/name` from origin → `name`.
fn github_name(repo: &Path) -> Option<String> {
    let url = git(repo, &["remote", "get-url", "origin"])?;
    let tail = url
        .trim()
        .trim_end_matches(".git")
        .rsplit(['/', ':'])
        .next()?
        .to_string();
    (!tail.is_empty()).then_some(tail)
}

fn git(repo: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

fn gh(args: &[&str]) -> Option<String> {
    let out = Command::new("gh").args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

fn which(bin: &str) -> Result<PathBuf, ()> {
    std::env::var_os("PATH")
        .and_then(|paths| {
            std::env::split_paths(&paths)
                .map(|d| d.join(bin))
                .find(|p| p.is_file())
        })
        .ok_or(())
}

fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("✗ {msg}");
    ExitCode::FAILURE
}
