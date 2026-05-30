use bech32::{self, FromBase32};
use flate2::read::GzDecoder;
use rayon::prelude::*;
use ripemd::Ripemd160;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use walkdir::WalkDir;

/// Хранилище распарсенных Hash160 (бинарных payload'ов)
#[derive(Default)]
struct TargetHashes {
    // Хранит 20-байтный Hash160(PubKey). Подходит для P2PKH (1...) и P2WPKH (bc1q...)
    p2pkh_wpkh: HashSet<[u8; 20]>,
    // Хранит 20-байтный Hash160(RedeemScript). Подходит для P2SH (3...)
    p2sh: HashSet<[u8; 20]>,
}

impl TargetHashes {
    /// Парсит любую строку адреса и извлекает из неё Hash160 Payload
    fn parse_and_insert(&mut self, addr: &str) -> bool {
        // 1. Проверяем Base58Check (P2PKH или P2SH)
        if let Ok(decoded) = bs58::decode(addr).into_vec() {
            if decoded.len() == 25 {
                let mut hash = [0u8; 20];
                hash.copy_from_slice(&decoded[1..21]);

                if decoded[0] == 0x00 {
                    // P2PKH
                    self.p2pkh_wpkh.insert(hash);
                    return true;
                } else if decoded[0] == 0x05 {
                    // P2SH
                    self.p2sh.insert(hash);
                    return true;
                }
            }
        }

        // 2. Проверяем Bech32 (P2WPKH)
        #[allow(deprecated)] // Для совместимости с разными версиями bech32
        if let Ok((hrp, data, _variant)) = bech32::decode(addr) {
            if hrp == "bc" && !data.is_empty() {
                // Первый байт в data — версия SegWit. Нам нужен v0
                if data[0].to_u8() == 0 {
                    if let Ok(payload) = Vec::<u8>::from_base32(&data[1..]) {
                        if payload.len() == 20 {
                            let mut hash = [0u8; 20];
                            hash.copy_from_slice(&payload);
                            // Хэш публичного ключа P2WPKH такой же, как у P2PKH
                            self.p2pkh_wpkh.insert(hash);
                            return true;
                        }
                    }
                }
            }
        }

        false
    }
}

/// Вычисляет Hash160 (SHA256 -> RIPEMD160)
#[inline]
fn hash160(data: &[u8]) -> [u8; 20] {
    let sha256_hash = Sha256::digest(data);
    let ripemd_hash = Ripemd160::digest(&sha256_hash);
    let mut result = [0u8; 20];
    result.copy_from_slice(&ripemd_hash);
    result
}

/// Вычисляет Hash160 для P2SH-P2WPKH (Nested Segwit)
#[inline]
fn p2sh_wpkh_hash(pubkey_hash160: &[u8; 20]) -> [u8; 20] {
    let mut script = Vec::with_capacity(22);
    script.push(0x00);
    script.push(0x14);
    script.extend_from_slice(pubkey_hash160);
    hash160(&script)
}

/// Конвертирует Hash160 в строку адреса P2PKH (для логгирования)
fn hash160_to_p2pkh(hash: &[u8; 20]) -> String {
    let mut payload = Vec::with_capacity(25);
    payload.push(0x00);
    payload.extend_from_slice(hash);
    let cs = Sha256::digest(&Sha256::digest(&payload));
    payload.extend_from_slice(&cs[..4]);
    bs58::encode(payload).into_string()
}

/// Читает адреса из файла или директории
fn load_target_hashes(path: &str) -> TargetHashes {
    let mut targets = TargetHashes::default();
    let mut valid_count = 0;
    let mut skipped_count = 0;

    println!("📂 Сканирование пути: {}", path);

    for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
        let file_path = entry.path();
        if file_path.is_file() {
            let fname = file_path.file_name().unwrap_or_default().to_string_lossy();
            let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");

            if ext == "txt" || ext == "gz" || ext == "csv" || fname == "addresses.txt" {
                println!("   ⚙️ Читаем: {}", file_path.display());
                let file = fs::File::open(file_path).unwrap();

                // Обработка обычных и .gz файлов
                let reader: Box<dyn BufRead> = if ext == "gz" {
                    Box::new(BufReader::new(GzDecoder::new(file)))
                } else {
                    Box::new(BufReader::new(file))
                };

                for line in reader.lines() {
                    if let Ok(l) = line {
                        let trimmed = l.trim();
                        if !trimmed.is_empty() && !trimmed.starts_with('#') {
                            if targets.parse_and_insert(trimmed) {
                                valid_count += 1;
                            } else {
                                skipped_count += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    println!("✅ Парсинг завершен.");
    println!("📋 Найдено адресов всего: {}", valid_count + skipped_count);
    println!("📋 Из них успешно загружено: {}", valid_count);
    println!(
        "   - Уникальных Payload (P2PKH/P2WPKH): {}",
        targets.p2pkh_wpkh.len()
    );
    println!("   - Уникальных Payload (P2SH): {}", targets.p2sh.len());
    if skipped_count > 0 {
        println!("⚠️ Пропущено (неизвестный формат): {}", skipped_count);
    }
    println!();

    targets
}

fn save_found(privkey: &SecretKey, hash: &[u8; 20], key_type: &str, found_type: &str) {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("found.txt")
        .expect("Не удалось открыть found.txt");

    let privkey_hex = hex::encode(privkey.secret_bytes());
    // Генерируем классический адрес для отображения
    let p2pkh_addr = hash160_to_p2pkh(hash);

    let line = format!(
        "FOUND! Type: {} | KeyContext: {} | Default P2PKH Addr: {} | PrivKeyHex: {}\n",
        found_type, key_type, p2pkh_addr, privkey_hex
    );

    file.write_all(line.as_bytes())
        .expect("Не удалось записать");
    println!("\n🎉 НАЙДЕНО СОВПАДЕНИЕ! {:?}", line.trim());
}

fn print_banner() {
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║      BTC Private Key Research Tool (Rust)           ║");
    println!("║      P2PKH + P2SH + Native Segwit (Directory Scan)  ║");
    println!("╚══════════════════════════════════════════════════════╝");
    println!();
}

fn main() {
    print_banner();

    // Загружаем директорию (текущую или '.' где лежат адреса)
    let targets = load_target_hashes(".");

    if targets.p2pkh_wpkh.is_empty() && targets.p2sh.is_empty() {
        eprintln!("❌ В директории не найдено валидных Bitcoin адресов для сканирования.");
        std::process::exit(1);
    }

    let num_threads = num_cpus::get();
    println!("🖥️  Потоков CPU: {}", num_threads);
    println!("🔑 Проверяем: {{P2PKH, P2WPKH}} - Compressed/Uncompressed, P2SH-P2WPKH - Compressed");
    println!("🚀 Начинаем генерацию...");
    println!();

    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build_global()
        .unwrap();

    let p2pkh_arc = Arc::new(targets.p2pkh_wpkh);
    let p2sh_arc = Arc::new(targets.p2sh);

    let counter = Arc::new(AtomicU64::new(0));
    let start_time = Instant::now();
    let log_mutex = Arc::new(Mutex::new(()));

    let batch_size: u64 = 500_000;

    loop {
        (0..batch_size).into_par_iter().for_each_init(
            || (Secp256k1::new(), rand::thread_rng()),
            |(secp, rng), _| {
                let secret_key = SecretKey::new(rng);
                let public_key = PublicKey::from_secret_key(secp, &secret_key);

                // --- 1. Compressed ---
                let pub_c = public_key.serialize();
                let h160_c = hash160(&pub_c);

                // Check P2PKH / P2WPKH Compressed
                if p2pkh_arc.contains(&h160_c) {
                    let _lock = log_mutex.lock().unwrap();
                    save_found(&secret_key, &h160_c, "compressed", "P2PKH/P2WPKH");
                }

                // Check P2SH Compressed
                // P2SH checks only make sense for compressed keys mostly, but we do it anyway.
                if !p2sh_arc.is_empty() {
                    let p2sh_hash = p2sh_wpkh_hash(&h160_c);
                    if p2sh_arc.contains(&p2sh_hash) {
                        let _lock = log_mutex.lock().unwrap();
                        save_found(&secret_key, &h160_c, "compressed", "P2SH-P2WPKH");
                    }
                }

                // --- 2. Uncompressed ---
                let pub_u = public_key.serialize_uncompressed();
                let h160_u = hash160(&pub_u);

                if p2pkh_arc.contains(&h160_u) {
                    let _lock = log_mutex.lock().unwrap();
                    save_found(&secret_key, &h160_u, "uncompressed", "P2PKH/P2WPKH");
                }
            },
        );

        counter.fetch_add(batch_size, Ordering::Relaxed);

        let total = counter.load(Ordering::Relaxed);
        let elapsed = start_time.elapsed().as_secs_f64();
        let speed = total as f64 / elapsed;

        print!(
            "\r⚡ Проверено: {:>12} ключей | Скорость: {:>10.0} keys/sec | Время: {:.1}s   ",
            format_number(total),
            speed,
            elapsed
        );
        std::io::stdout().flush().unwrap();
    }
}

fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}
