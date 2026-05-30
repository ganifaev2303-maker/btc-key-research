# btc-key-research

> An educational, multi-threaded Bitcoin **key-space scanner** written in Rust.
> It generates random `secp256k1` private keys, derives their addresses, and checks
> them against a set of known funded ("rich") addresses — primarily to **benchmark
> key-derivation throughput** and to **demonstrate, empirically, why brute-forcing
> Bitcoin is impossible.**

<p align="left">
  <img alt="language" src="https://img.shields.io/badge/language-Rust-orange.svg">
  <img alt="edition" src="https://img.shields.io/badge/edition-2021-blue.svg">
  <img alt="license" src="https://img.shields.io/badge/license-MIT-green.svg">
  <img alt="platforms" src="https://img.shields.io/badge/platforms-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg">
</p>

---

## ⚠️ Disclaimer — read this first

This project is **educational and for benchmarking only**.

- Recovering the private key of a funded address by random search is **computationally
  impossible**. The address space is `2^160` (≈ `1.46 × 10^48`). At an optimistic
  **10 million keys/second**, exhausting even a billionth of that space would take
  **far longer than the age of the universe**. See [The math of impossibility](#the-math-of-impossibility).
- The realistic, intended output of this tool is **zero matches, forever**. Its value
  is as a *correctly-implemented* reference for Bitcoin address derivation and as a
  CPU benchmark.
- Attempting to access wallets you do not own is **illegal** in most jurisdictions.
  Do not use this software for that purpose. The authors accept **no liability** —
  see [LICENSE](LICENSE).

If you are here to "find lost coins," this tool will not help you, and neither will
any other. That is the entire point.

---

## What it does

For each randomly generated `secp256k1` keypair, the scanner derives and checks the
following address types against an in-memory target set:

| Address type        | Prefix  | Key form              | Checked |
| ------------------- | ------- | --------------------- | :-----: |
| P2PKH (Legacy)      | `1...`  | compressed            | ✅ |
| P2PKH (Legacy)      | `1...`  | uncompressed          | ✅ |
| P2WPKH (Native SegWit) | `bc1q...` | compressed (same Hash160 as P2PKH) | ✅ |
| P2SH-P2WPKH (Nested SegWit) | `3...` | compressed         | ✅ |

Targets are loaded by **scanning the working directory** for `*.txt`, `*.gz`, and
`*.csv` files, decoding each address to its 20-byte `Hash160` payload, and storing
those payloads in `HashSet`s for O(1) lookup. `.gz` files are decompressed on the fly,
so multi-hundred-megabyte address dumps can be used without unpacking them first.

## How it works

```
random 32 bytes ──► SecretKey ──► PublicKey (secp256k1)
                                      │
                ┌─────────────────────┴─────────────────────┐
                ▼                                            ▼
        compressed pubkey (33 B)                  uncompressed pubkey (65 B)
                │                                            │
            SHA-256                                      SHA-256
                │                                            │
           RIPEMD-160 ──► Hash160 (20 B)              RIPEMD-160 ──► Hash160 (20 B)
                │                                            │
    ┌───────────┼─────────────┐                              │
    ▼           ▼             ▼                              ▼
 P2PKH set?  P2SH-P2WPKH?   (P2WPKH                       P2PKH set?
             wrap+Hash160    shares set)
```

A match writes a line to `found.txt` and prints to the console. Work is parallelised
across **all CPU cores** with [`rayon`](https://crates.io/crates/rayon) in batches of
500,000 keys, with a live throughput counter.

The cryptographic pipeline (SHA-256 → RIPEMD-160, Base58Check, Bech32, P2SH wrapping)
is independently validated by the [`verify`](#self-test) binary against a textbook
known-answer vector (private key `0x…0001`).

## The math of impossibility

| Quantity | Value |
| --- | --- |
| Address (Hash160) space | `2^160 ≈ 1.46 × 10^48` |
| Optimistic single-machine speed | `~10^7` keys/sec |
| Keys checked in 1 year | `~3.15 × 10^14` |
| Fraction of space covered in 1 year | `~2 × 10^-34` |
| Time to brute-force one *specific* key (50% odds) | `~10^26` years |

For comparison, the universe is `~1.4 × 10^10` years old. Bitcoin's security is not
an implementation detail — it is arithmetic.

## Project structure

```
.
├── src/
│   ├── main.rs           # Scanner: load targets, parallel key generation & matching
│   └── bin/
│       └── verify.rs     # Self-test of the crypto pipeline (known-answer vector)
├── addresses.txt         # Small sample target list
├── .cargo/config.toml    # target-cpu=native build flag
├── Cargo.toml
└── README.md
```

> **Note:** large address datasets (`*.txt.gz`, `*.csv`) and `found.txt` are
> **git-ignored** — they are never committed. Provide your own target file locally.

## Requirements

- [Rust](https://rustup.rs/) **1.74+** (2021 edition), `cargo`
- A working C compiler — `secp256k1` builds bundled C via `cc` (Xcode CLT on macOS,
  `build-essential` on Linux, MSVC toolchain on Windows).

## Build

```bash
# Optimised release build (recommended — debug builds are far slower for this workload)
cargo build --release
```

The binary lands at `target/release/btc-key-research`.

> ℹ️ `.cargo/config.toml` enables `-C target-cpu=native`, which compiles the hot
> crypto loop for **your** CPU. The resulting binary is **not portable** to older
> CPUs. Comment that file out if you build on one machine and run on another.

Cross-platform notes:

| OS | Notes |
| --- | --- |
| **macOS** (Apple Silicon / Intel) | Primary dev/test platform. Needs Xcode Command Line Tools. |
| **Linux** | Fully supported; typically the fastest. Needs `build-essential`. |
| **Windows** | Supported via the MSVC toolchain (`rustup` default). |

## Usage

### 1. Provide a target file

Put one address per line in any `*.txt`, `*.csv`, or gzipped `*.txt.gz` file in the
project directory. Lines beginning with `#` and blank lines are ignored.

```text
# addresses.txt
1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN
```

### 2. Run the scanner

```bash
cargo run --release
# or directly:
./target/release/btc-key-research
```

Sample output:

```
╔══════════════════════════════════════════════════════╗
║      BTC Private Key Research Tool (Rust)              ║
╚══════════════════════════════════════════════════════╝

📂 Scanning path: .
   ⚙️ Reading: ./addresses.txt
✅ Parsing complete.
   - Unique payloads (P2PKH/P2WPKH): 16
🖥️  CPU threads: 10
🚀 Starting generation...

⚡ Checked:    12,500,000 keys | Speed:  2,300,000 keys/sec | Time: 5.4s
```

The scanner runs indefinitely; stop it with `Ctrl-C`.

### 3. Self-test

Verify the cryptographic pipeline against a known-answer vector:

```bash
cargo run --release --bin verify
```

```
🔑 Private key #1: 0000…0001
   └─ Uncompressed P2PKH: 1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm  ✅
   └─ Compressed   P2PKH: 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH  ✅
   └─ Nested P2SH-P2WPKH: 3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN
   └─ Native P2WPKH:      bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
```

## Output format

A match appends a line to `found.txt` (git-ignored):

```
FOUND! Type: P2PKH/P2WPKH | KeyContext: compressed | Default P2PKH Addr: <addr> | PrivKeyHex: <64-hex>
```

> `found.txt` may contain private keys. It is git-ignored by design — **never commit it.**

## Tech stack

`secp256k1` · `sha2` · `ripemd` · `bs58` · `bech32` · `rand` · `rayon` · `flate2` · `walkdir`

## License

[MIT](LICENSE) © 2026 btc-key-research contributors
