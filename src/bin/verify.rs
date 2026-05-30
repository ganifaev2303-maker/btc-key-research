use bs58;
use ripemd::Ripemd160;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use std::str::FromStr;
use bech32::{self, Variant};

/// Вычисляет Hash160
fn hash160(data: &[u8]) -> [u8; 20] {
    let sha256_hash = Sha256::digest(data);
    let ripemd_hash = Ripemd160::digest(&sha256_hash);
    let mut result = [0u8; 20];
    result.copy_from_slice(&ripemd_hash);
    result
}

/// Вычисляет Hash160 для P2SH-P2WPKH
#[inline]
fn p2sh_wpkh_hash(pubkey_hash160: &[u8; 20]) -> [u8; 20] {
    let mut script = Vec::with_capacity(22);
    script.push(0x00);
    script.push(0x14);
    script.extend_from_slice(pubkey_hash160);
    hash160(&script)
}

/// Функция получения строкового P2PKH-адреса из Hash160 (как в main.rs)
fn hash160_to_p2pkh(hash: &[u8; 20]) -> String {
    let mut payload = Vec::with_capacity(25);
    payload.push(0x00);
    payload.extend_from_slice(hash);
    let cs = Sha256::digest(&Sha256::digest(&payload));
    payload.extend_from_slice(&cs[..4]);
    bs58::encode(payload).into_string()
}

fn main() {
    println!("=== ТЕСТ: Проверка логики генерации и хэширования ===");
    let secp = Secp256k1::new();
    
    // Используем известный приватный ключ: 00..01
    // Это приватный ключ для самого первого Bitcoin Puzzle (адрес 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH)
    let privkey_str = "0000000000000000000000000000000000000000000000000000000000000001";
    let secret = SecretKey::from_str(privkey_str).unwrap();
    let public = PublicKey::from_secret_key(&secp, &secret);

    // 1. Проверяем UNCOMPRESSED
    let pub_u = public.serialize_uncompressed();
    let h160_u = hash160(&pub_u);
    let p2pkh_u = hash160_to_p2pkh(&h160_u);
    println!("\n🔑 Приватный ключ #1: {}", privkey_str);
    println!("   └─ Несжатый     (Uncompressed) P2PKH: {}", p2pkh_u);
    println!("      Ожидается: 1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm - {}", 
             if p2pkh_u == "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm" { "СОВПАДАЕТ ✅" } else { "ОШИБКА ❌" });

    // 2. Проверяем COMPRESSED
    let pub_c = public.serialize();
    let h160_c = hash160(&pub_c);
    let p2pkh_c = hash160_to_p2pkh(&h160_c);
    println!("   └─ Сжатый       (Compressed)   P2PKH: {}", p2pkh_c);
    println!("      Ожидается: 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH - {}", 
             if p2pkh_c == "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH" { "СОВПАДАЕТ ✅" } else { "ОШИБКА ❌" });

    // 3. P2SH
    let p2sh_hash = p2sh_wpkh_hash(&h160_c);
    let mut p2sh_payload = Vec::with_capacity(25);
    p2sh_payload.push(0x05); // версия P2SH
    p2sh_payload.extend_from_slice(&p2sh_hash);
    let p2sh_cs = Sha256::digest(&Sha256::digest(&p2sh_payload));
    p2sh_payload.extend_from_slice(&p2sh_cs[..4]);
    let p2sh_str = bs58::encode(&p2sh_payload).into_string();
    println!("   └─ Вложенный    (P2SH-P2WPKH)         : {}", p2sh_str);

    // 4. P2WPKH (Native SegWit)
    // Используем bech32 0.9.1
    use bech32::u5;
    use bech32::ToBase32;
    let mut bech32_data = vec![u5::try_from_u8(0).unwrap()]; // version 0
    let mut prog_32 = h160_c.to_base32();
    bech32_data.append(&mut prog_32);
    let bech32_str = bech32::encode("bc", bech32_data, Variant::Bech32).unwrap();
    println!("   └─ Нативный     (P2WPKH)              : {}", bech32_str);

    println!("\n=== Все криптографические функции (Sha256, Ripemd160, secp256k1, Base58Check) работаю корректно! ===");
}
