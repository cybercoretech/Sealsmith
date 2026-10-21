# Sealsmith: design (draft for review)

**Release, verify and publish Cybercore software, with keys that never leave
your machine.** It replaces `tools/release.sh`, `install.sh`, the F-Droid
`publish.sh` + `apps.tsv`, and the GitHub Release workflows that don't
trigger.

## Commands

- **`sealsmith release X.Y.Z`:** clean in-sync `main` → checks → build
  (cargo, cargo-ndk/gradle, cross targets) → sign locally → verify (cert
  pin, version, permissions, sha256) → tag → GitHub release with assets +
  `.sha256` + notes. A failed check stops it **before** tagging.
- **`sealsmith verify <file|url>`:** checks an APK or binary against the
  pins in `sealsmith.toml` (or the org registry) and reports its signer,
  checksum and the release it belongs to.
- **`sealsmith installer`:** generates the curl installers from one tested
  template: `main()`-wrapped, adb stdin-safe, cert pinned. Its test suite
  pipes every installer into `sh`.
- **`sealsmith fdroid publish`:** the F-Droid repo update with the
  index-integrity check, icons from metadata, byte-identity against
  GitHub.
- **`sealsmith audit`:** for every repo, check that the release, tag,
  `Cargo.toml` version and installer pins agree. It would have caught the
  hard-coded `--version 0.1.0`.

## Config (`sealsmith.toml` per repo)

App name, assets, Gradle version properties, cert pin, key env file,
allowed permissions. **No secrets.**

## Milestones

1. `verify` + `audit`: read-only, safe, immediately useful.
2. `release` for Android apps (to replace the bash script).
3. `release` for Rust CLIs (cross builds; replaces the GitHub Release
   workflows).
4. `installer` + `fdroid publish`.

## Decision needed

For the Rust CLIs, should the macOS binaries keep coming from GitHub
runners (there's no local Mac), or should desktop releases ship Linux
only? Recommended: keep GitHub for macOS builds, but **sign and publish
the checksums locally**.
