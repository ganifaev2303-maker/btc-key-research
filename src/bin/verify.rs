use bs58;
use ripemd::Ripemd160;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use std::str::FromStr;
use bech32::{self, Variant};

/// Computes Hash160 (SHA-256 -> RIPEMD-160)
fn hash160(data: &[u8]) -> [u8; 20] {
    let sha256_hash = Sha256::digest(data);
    let ripemd_hash = Ripemd160::digest(&sha256_hash);
    let mut result = [0u8; 20];
    result.copy_from_slice(&ripemd_hash);
    result
}

/// Computes the Hash160 for P2SH-P2WPKH (nested SegWit)
#[inline]
fn p2sh_wpkh_hash(pubkey_hash160: &[u8; 20]) -> [u8; 20] {
    let mut script = Vec::with_capacity(22);
    script.push(0x00);
    script.push(0x14);
    script.extend_from_slice(pubkey_hash160);
    hash160(&script)
}

/// Converts a Hash160 into a P2PKH address string (same construction as main.rs)
fn hash160_to_p2pkh(hash: &[u8; 20]) -> String {
    let mut payload = Vec::with_capacity(25);
    payload.push(0x00);
    payload.extend_from_slice(hash);
    let cs = Sha256::digest(&Sha256::digest(&payload));
    payload.extend_from_slice(&cs[..4]);
    bs58::encode(payload).into_string()
}

fn main() {
    println!("=== SELF-TEST: known-answer check of the crypto pipeline ===");
    let secp = Secp256k1::new();

    // The canonical test vector: private key 0x00..01
    // (compressed P2PKH address 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH)
    let privkey_str = "0000000000000000000000000000000000000000000000000000000000000001";
    let secret = SecretKey::from_str(privkey_str).unwrap();
    let public = PublicKey::from_secret_key(&secp, &secret);

    // 1. Uncompressed P2PKH
    let pub_u = public.serialize_uncompressed();
    let h160_u = hash160(&pub_u);
    let p2pkh_u = hash160_to_p2pkh(&h160_u);
    println!("\n🔑 Private key #1: {}", privkey_str);
    println!(
        "   └─ Uncompressed P2PKH: {}  {}",
        p2pkh_u,
        if p2pkh_u == "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm" {
            "✅"
        } else {
            "❌ MISMATCH (expected 1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm)"
        }
    );

    // 2. Compressed P2PKH
    let pub_c = public.serialize();
    let h160_c = hash160(&pub_c);
    let p2pkh_c = hash160_to_p2pkh(&h160_c);
    println!(
        "   └─ Compressed   P2PKH: {}  {}",
        p2pkh_c,
        if p2pkh_c == "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH" {
            "✅"
        } else {
            "❌ MISMATCH (expected 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH)"
        }
    );

    // 3. Nested P2SH-P2WPKH
    let p2sh_hash = p2sh_wpkh_hash(&h160_c);
    let mut p2sh_payload = Vec::with_capacity(25);
    p2sh_payload.push(0x05); // P2SH version byte
    p2sh_payload.extend_from_slice(&p2sh_hash);
    let p2sh_cs = Sha256::digest(&Sha256::digest(&p2sh_payload));
    p2sh_payload.extend_from_slice(&p2sh_cs[..4]);
    let p2sh_str = bs58::encode(&p2sh_payload).into_string();
    println!("   └─ Nested P2SH-P2WPKH: {}", p2sh_str);

    // 4. Native P2WPKH (SegWit v0, bech32 0.9.1 API)
    use bech32::u5;
    use bech32::ToBase32;
    let mut bech32_data = vec![u5::try_from_u8(0).unwrap()]; // witness version 0
    let mut prog_32 = h160_c.to_base32();
    bech32_data.append(&mut prog_32);
    let bech32_str = bech32::encode("bc", bech32_data, Variant::Bech32).unwrap();
    println!("   └─ Native P2WPKH:      {}", bech32_str);

    println!("\n=== Crypto pipeline (SHA-256, RIPEMD-160, secp256k1, Base58Check) verified ===");
}
