# Releasing

Releases are Git tags. CI builds the AppImage (+ `.zsync`) and the `.deb` and attaches them to the GitHub release; VirusTotal then scans both.

1. Pick the version (`0.2.0`). Update **both**:
   - `Cargo.toml` → `[workspace.package] version`
   - `packaging/io.github.evandro777.FastCheckup.metainfo.xml` → add a `<release version="0.2.0" date="YYYY-MM-DD">` entry (newest first)
2. `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`
3. Merge to `master` through a pull request, wait for CI.
4. Tag and push (the tag must equal the version, or `appimage.yml` fails):

   ```bash
   git tag v0.2.0 -m "FastCheckup 0.2.0"
   git push origin v0.2.0
   ```

5. Smoke-test the downloaded AppImage on a clean user, and install the `.deb` to check the password prompt on the Services page names FastCheckup.

`flatpak.yml` also builds the Flatpak on every push, and on the tag it publishes the signed remote and the landing page (`docs/site/index.html`) to GitHub Pages, then attaches the bundle to the release. The tag must have a `<release>` entry in the metainfo, as above.

One-time:

- Add the repository secret `VIRUSTOTAL_API_KEY` (or delete `virustotal.yml`).
- Flatpak remote: run `flatpak/new-signing-key.sh`, commit `flatpak/signing-key.b64`, store the private key as the secret `FLATPAK_GPG_PRIVATE_KEY`, set Settings → Pages → Source to **GitHub Actions**, and add a `v*` tag rule to the `github-pages` environment. Details in `docs/FLATPAK-SIGNING.md`. Without the key file and the secret a tag build stops at "Import signing key".
