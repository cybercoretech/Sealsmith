# 🔏 Sealsmith

**Release, verify and audit Cybercore software, with signing keys that never leave your machine.**

Keysmith forges keys; Sealsmith seals releases. It's growing into the one tool that replaces the per-repo `tools/release.sh`, `install.sh` and F-Droid `publish.sh` scripts. Milestone 1 ships the read-only half.

## 🔎 `sealsmith audit`

Sweeps every repo under `~/Devspace/Cybercore` and `~/Devspace/Android` (or the paths you give) and reports:

| | Check |
|---|---|
| 🏷️ | `Cargo.toml` version has a matching **tag** and a **GitHub release with assets** (for repos that ship an installer or release workflow) |
| 🔢 | clap `#[command(version = "x.y.z")]` **hard-coded**, which drifts from Cargo.toml |
| 🪪 | the app's **signing-certificate pin** is identical in the installer, release config, README, SECURITY and site |
| 🧪 | `--deep`: downloads the latest release APK and checks its **signer is the pinned key** |

Exit status is non-zero when anything is wrong, so it can gate CI or a timer (and report to Warnflare).

## ✅ `sealsmith verify <file> [--sha256 HEX] [--cert HEX]`

Checks a file's SHA-256 (against `--sha256` or a `.sha256` next to it) and, for APKs, the signing certificate via `apksigner`.

```sh
sealsmith verify cybervault.apk --cert 9dfa3699b793ad16af999b2fbe99b4b13ee26f8014705cc661521ee2b15e52cb
sealsmith audit --deep
```

## 🛠️ Requirements

- `gh`, for release lookups (per-owner credentials are respected).
- `git`.
- Android build-tools, for `apksigner` (found on `PATH` or under `$ANDROID_HOME/build-tools`).

## 🗺️ Roadmap

See [DESIGN.md](DESIGN.md):

1. ✅ `verify` + `audit`
2. `release` for Android apps
3. `release` for Rust CLIs
4. `installer` + `fdroid publish`

MIT licensed.
