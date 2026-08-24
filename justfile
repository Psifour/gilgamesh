set positional-arguments
import? 'justfile.local'

[private]
default:
    @just --list --unsorted

init: init-hermit

init-hermit:
  hermit init --quiet
  hermit install just
  hermit install rustup
  rustup default stable

fmt:
  cargo fmt --all

clippy:
  cargo clippy --all --all-targets --all-features -- --deny warnings

dev *args:
  cargo run -- {{args}}

build:
  cargo build --release --all-features

cross:
  cargo check --target x86_64-pc-windows-msvc --all-features
  cargo check --target aarch64-apple-darwin --all-features

ci: clippy cross
  cargo fmt -- --check
  cargo test --all --all-features

ignored:
  cargo test --all --all-features -- --ignored
