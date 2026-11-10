@AGENTS.md

## UI changes must be verified with the snapshot script

Any change to `crates/app/ui` or to the Rust that fills it is not done until `scripts/ui-snapshot.sh <page>` has been run and the PNGs in `target/ui-snapshots/` (`<page>-empty|single|many.png`) have been read. Check for stretched rows, misaligned badges, truncated text, wrong units, missing empty states and errors, then fix and re-run. The script uses a private Xvfb display and canned data (`FASTCHECKUP_FIXTURES`), so it never scans or changes the real system. `STATE=expanded` or `STATE=confirm` (e.g. `STATE=confirm scripts/ui-snapshot.sh apps`) shows an opened row or the confirm dialog (`<page>-<mode>-<state>.png`); it sets the state directly, so it checks how the state looks, not that the click handlers work. Anything behind `pkexec` still goes on the manual test list.
