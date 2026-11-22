# Releasing

Releases are Git tags. CI builds the AppImage (+ `.zsync`) and the Flatpak, publishes the signed Flatpak remote and the landing page to GitHub Pages, and attaches both to the GitHub release; VirusTotal then scans each and adds its report to the notes.

1. Pick the version (`0.2.0`). Update:
    - [Cargo.toml](./Cargo.toml) → `version`
    - [io.github.evandro777.FastCheckup.metainfo.xml](./packaging/io.github.evandro777.FastCheckup.metainfo.xml) → add a `<release version="0.2.0" date="YYYY-MM-DD">` entry with notes (newest first). `flatpak.yml` fails the tag without it.
2. Run `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test && cargo audit`
    - It will update `Cargo.lock` follows the new version (CI uses `--locked` and fails on a stale lock). Commit both.
3. Stage the files, commit and push, and Merge to `master` through a pull request, wait for CI.
4. Tag and push (the tag must equal the version, or `appimage.yml` and `flatpak.yml` fail):

    ```bash
    git tag v0.2.0 -m "FastCheckup 0.2.0"
    git push origin v0.2.0
    ```

5. The `Flatpak` workflow checks that the tag equals the `Cargo.toml` version and that the metainfo has the `<release>` entry, builds the bundle, and publishes `*-x86_64.flatpak` on the release page.
    - The `AppImage` workflow adds `*-x86_64.AppImage`, and its `.zsync` (delta updates) to the same release (it waits up to 30 min for the release to exist).
6. Smoke-test the downloaded AppImage on a clean user, and the Flatpak: `flatpak update` from the previous version should offer the new one.

## Notes

- Every Pages deploy replaces the whole site (the OSTree repo is part of it), so the landing page changes only with a tag. Never add a Pages deploy from `master`: it would wipe the Flatpak repo.
- The release is created by whichever of the AppImage and Flatpak workflows gets there first; the Flatpak one waits for Pages.
- Flathub: [`docs/FLATHUB.md`](docs/FLATHUB.md).
- The AppImage `.DirIcon` comes from `packaging/io.github.evandro777.FastCheckup.png`: regenerate it when the SVG changes (command in `AGENTS.md`).

## One-time setup

Actions and settings, that needs to be done once.

### Flatpak remote & GitHub Pages

- Settings → Pages → Source: **GitHub Actions**.
- Settings → Environments → `github-pages` → deployment branches and tags → Add deployment branch or tag
    - Ref type: Tag
    - Name pattern: `v*`
    - ℹ️ Pages creates the environment with a default-branch-only rule, so the first tag deploy is refused ("Tag v… is not allowed to deploy").
- Create a pair signing key. Details are in [FLATPAK-SIGNING](docs/FLATPAK-SIGNING.md):
    - In terminal: `flatpak/new-signing-key.sh`
    - `flatpak/signing-key.b64` is the **public** half, committed, users check signatures with it.
    - CI needs the **private** half to sign each release, so store it as a secret named `FLATPAK_GPG_PRIVATE_KEY`
- Settings → Secrets and variables → Actions → New repository secret
    - Name: `FLATPAK_GPG_PRIVATE_KEY`
    - Secret: Paste the contents of the private key, whole file, from `-----BEGIN PGP PRIVATE KEY BLOCK-----` to the `END` line, as the secret's value
    - **Never commit the private file!** GitHub will not show the secret again, so keep a private backup (a password manager); if the key is lost, a new key breaks every user's existing remote and they must re-add it.

### Virus Total checking

Automatically check for virus on deploy, or delete `virustotal.yml`.

- Settings → Secrets and variables → Actions → New repository secret
- Name: `VIRUSTOTAL_API_KEY`
- Secret: Your Virus total api key
- Some antivirus may identify it as trojan, so you need to send the file to reanalyze:
    - [Microsoft Windows Defender](https://www.microsoft.com/en-us/wdsi/filesubmission)
