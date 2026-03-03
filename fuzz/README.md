<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Fuzz Targets

6 fuzz targets covering relay parsing, validation, and protocol boundaries.

## Targets

| Target | Module | What it fuzzes |
|--------|--------|---------------|
| `fuzz_federation_message` | `federation_protocol` | Padded binary frame + JSON deserialization |
| `fuzz_federation_padding` | `padding` | 4-byte BE length prefix unpadding + bucket validation |
| `fuzz_noise_handshake` | `noise_transport` | Noise NK handshake with arbitrary client data |
| `fuzz_noise_v2_detect` | `noise_transport` | Magic byte + size check for v2 protocol upgrade |
| `fuzz_federation_url` | `url_validation` | SSRF prevention URL/IP parsing |
| `fuzz_validate_client_id` | `handler` | 64-char hex client ID validation |

## Running Locally

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Run a single target (runs until crash or Ctrl-C)
cd relay/fuzz
cargo fuzz run fuzz_federation_message

# Run with time limit (5 minutes)
cargo fuzz run fuzz_federation_padding -- -max_total_time=300

# Run all targets (5 minutes each)
for target in $(cargo fuzz list); do
  echo "=== $target ==="
  cargo fuzz run "$target" -- -max_total_time=300
done
```

## CI

The `fuzz:nightly` scheduled pipeline job runs all 6 targets for 5 minutes each. Crashes are saved as artifacts for 1 month. Enable by setting `FUZZ_ENABLED=true` on the nightly schedule.

## Adding a New Target

1. Create `fuzz_targets/fuzz_<name>.rs`
2. Add `[[bin]]` entry to `Cargo.toml`
3. Update the target list in `.gitlab-ci.yml` `fuzz:nightly` job
4. Update this README
