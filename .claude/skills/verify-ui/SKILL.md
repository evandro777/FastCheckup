---
name: verify-ui
description: Render the changed FastCheckup Slint pages with canned data on a private Xvfb and read the screenshots before calling a UI change done. Use after any change to crates/app/ui or the Rust that feeds it.
---

# Verify a FastCheckup UI change

Do not commit, push or create branches. Never claim a UI change works from a passing build alone.

1. **Checks:** `cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test`. Fix any failure first.
2. **Snapshots:** `scripts/ui-snapshot.sh <page> [page ...]` (names: startup, services, boot, apps, leftovers, history, storage, disk-health; none = all; `MODES="many"` narrows). It builds, starts a private Xvfb, opens each page with `FASTCHECKUP_FIXTURES=empty|single|many` and writes `target/ui-snapshots/<page>-<mode>.png`. The real system is never scanned or changed.
3. **Read every PNG** of the pages you touched, in all three modes, and look for: stretched rows (rows spread over the window with one item), misaligned badges, truncated or overflowing text at the window edge, wrong units or float noise (`3.600000`), blank lists with no "Nothing found." state, text that should be selectable as one block.
   For opened rows and confirm dialogs run it again with `STATE=expanded` or `STATE=confirm` (startup, services, apps; boot has confirm). This sets the state directly, so it checks the look, not the click handlers.
4. **Fix and re-run** until every image is right. A new page or list needs fixture data in `crates/app/src/fixtures.rs`; a new `@tr` string needs `dev/gen_po.py`.
5. **Report:** what was verified in the images, what only by tests, and what the user must test by hand. Anything behind `pkexec` (SMART, uninstall, GRUB, systemctl changes, Trash/Docker actions) always goes in the manual list.
