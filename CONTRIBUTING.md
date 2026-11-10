# Contributing

FastCheckup's goals are **light and fast** and **simple**: a change that adds memory, start-up time or a heavy dependency needs a measurement and a reason.

1. Branch from `master`, make a focused change.
2. Run the checks locally (same as CI): `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`.
3. Open a pull request and describe what changed and how you tested it.

System packages (Debian/Ubuntu/Mint): `libfontconfig-dev libxkbcommon-dev libxkbcommon-x11-dev libx11-dev libxcb1-dev`, plus a Rust toolchain.

AI tools are welcome as helpers, but you are responsible for what you submit: understand it, test it, and say so in the pull request if a substantial part was generated.
