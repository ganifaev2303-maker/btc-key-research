# Architecture

This document describes the internals of `btc-key-research` for contributors.

## Overview

The program has two binaries:

| Binary | Source | Purpose |
| --- | --- | --- |
| `btc-key-research` (default) | `src/main.rs` | Load targets, then generate & match keys in parallel forever. |
| `verify` | `src/bin/verify.rs` | One-shot known-answer test of the crypto pipeline. |

## Data flow (`src/main.rs`)

```
main()
 ├─ print_banner()
 ├─ load_target_hashes(".")                  # walk dir, decode addresses → Hash160 sets
 │     └─ TargetHashes::parse_and_insert()   # Base58Check + Bech32 decoding
 ├─ build rayon global thread pool (num_cpus)
 └─ loop {                                    # runs until Ctrl-C
        (0..500_000).into_par_iter()          # one batch
            .for_each_init(|| (Secp256k1, rng), |ctx, _| {
                generate keypair
                derive compressed + uncompressed Hash160
                check against target sets
                on hit → save_found()
            })
        update + print throughput counter
    }
```

### `TargetHashes`

```rust
struct TargetHashes {
    p2pkh_wpkh: HashSet<[u8; 20]>,  // Hash160(pubkey) — serves P2PKH (1...) and P2WPKH (bc1q...)
    p2sh:       HashSet<[u8; 20]>,  // Hash160(redeemScript) — serves P2SH (3...)
}
```

Two sets because the 20-byte payload means different things depending on the script:

- **P2PKH / P2WPKH** payload = `Hash160(pubkey)`. The two share a set because native
  SegWit v0 uses the same key hash as legacy P2PKH.
- **P2SH** payload = `Hash160(redeemScript)`. For the nested-SegWit case the redeem
  script is `OP_0 <20-byte-keyhash>` (`0x00 0x14 ...`), so the program computes
  `Hash160(0x0014 || Hash160(pubkey))` and looks it up here.

### Address decoding — `parse_and_insert()`

1. **Base58Check** (`bs58::decode`): a valid payload is 25 bytes
   (`version(1) || hash160(20) || checksum(4)`). Version `0x00` → P2PKH set,
   `0x05` → P2SH set.
2. **Bech32** (`bech32::decode`): HRP must be `bc`, witness version `0`, and the
   20-byte program is inserted into the P2PKH/P2WPKH set.

Anything that decodes to neither is counted as "skipped (unknown format)".

### Matching, per key

For each generated `SecretKey`:

| Step | Function | Set checked |
| --- | --- | --- |
| compressed pubkey → Hash160 | `hash160(pub_c)` | `p2pkh_wpkh` |
| compressed → P2SH-P2WPKH wrap | `p2sh_wpkh_hash(h160_c)` | `p2sh` (only if non-empty) |
| uncompressed pubkey → Hash160 | `hash160(pub_u)` | `p2pkh_wpkh` |

> Note: uncompressed keys are not checked against P2SH-P2WPKH, because nested SegWit
> is only defined for compressed keys.

### Concurrency

- `rayon`'s `for_each_init` gives each worker thread its own `Secp256k1` context and
  RNG, avoiding per-iteration allocation and lock contention on the hot path.
- The target `HashSet`s are wrapped in `Arc` and shared read-only — lookups need no
  locking.
- A `Mutex<()>` (`log_mutex`) serialises only the rare match-writing path so console
  output and `found.txt` appends do not interleave. It is never contended in normal
  operation (matches don't happen).
- The throughput `AtomicU64` counter is updated once per 500k-key batch with
  `Ordering::Relaxed`.

## Crypto primitives

| Operation | Crate |
| --- | --- |
| EC keygen / pubkey | `secp256k1` (bundled libsecp256k1 C) |
| `SHA-256` | `sha2` |
| `RIPEMD-160` | `ripemd` |
| Base58Check | `bs58` |
| Bech32 | `bech32` (pinned `=0.9.1`) |

`Hash160` = `RIPEMD-160(SHA-256(data))`, the standard Bitcoin construction.

## Self-test (`src/bin/verify.rs`)

Uses the canonical private key `0x0000…0001` and asserts the derived addresses match
the well-known published vectors:

| Form | Expected address |
| --- | --- |
| Uncompressed P2PKH | `1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm` |
| Compressed P2PKH | `1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH` |
| Nested P2SH-P2WPKH | `3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN` |
| Native P2WPKH | `bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4` |

If any of the first two mismatch, the crypto pipeline is broken; the test prints
`ОШИБКА ❌`.

## Performance notes

- `--release` with `lto = true`, `codegen-units = 1`, and `-C target-cpu=native`
  produces the fastest binary; debug builds are dramatically slower.
- The dominant cost is `secp256k1` point multiplication, not hashing. SHA-NI / NEON
  acceleration (enabled by `target-cpu=native`) helps the Hash160 stage.
- Throughput scales close to linearly with physical cores.

## Known limitations / future work

- The default scan path is hard-coded to `"."`. A CLI arg for the target path/file
  would be a natural improvement.
- The main loop never terminates and has no graceful-shutdown handler (relies on
  `Ctrl-C`).
- P2TR (Taproot, `bc1p...`) addresses are not derived or matched.
- `fs::File::open(...).unwrap()` in `load_target_hashes` will panic on an unreadable
  file rather than skipping it.
