use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use keyring::Entry;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};
use tiny_keccak::{Hasher, Keccak};

const ERC20_TRANSFER_TOPIC: &str =
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const KEYRING_SERVICE: &str = "com.hartsantivenom.desktop.windows";
const KEYRING_ACCOUNT: &str = "aes256gcm-master-key";

#[derive(Serialize, Deserialize, Clone)]
pub struct AddressInspection {
    pub is_valid_format: bool,
    pub checksum_valid: bool,
    pub normalized_eip55: String,
    pub prefix: String,
    pub middle_segment: String,
    pub suffix: String,
    pub color_blocks: Vec<String>,
    pub threat_flag: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RawLogEntry {
    pub tx_hash: String,
    pub topics: Vec<String>,
    pub data: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ScrubbedLogReport {
    pub total_logs: usize,
    pub quarantined_zero_value: usize,
    pub quarantined_dust: usize,
    pub clean_logs: Vec<CleanTransferEvent>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CleanTransferEvent {
    pub tx_hash: String,
    pub from: String,
    pub to: String,
    pub amount_raw: u128,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TxRecord {
    pub tx_hash: String,
    pub from: String,
    pub to: String,
    pub value_wei: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PairedHistoryReport {
    pub trusted_outbound_counterparties: Vec<String>,
    pub quarantined_unsolicited_inbound: Vec<TxRecord>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TrustedContact {
    pub label: String,
    pub address: String,
    pub added_unix: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PreflightResult {
    pub risk_level: String,
    pub matched_contact_label: Option<String>,
    pub matched_contact_address: Option<String>,
    pub boundary_collision_detected: bool,
    pub zero_nonce_eoa: bool,
    pub reason: String,
}

pub(crate) fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut out = [0u8; 32];
    hasher.update(bytes);
    hasher.finalize(&mut out);
    out
}

pub(crate) fn to_eip55(lower_hex_no_prefix: &str) -> String {
    let hash = keccak256(lower_hex_no_prefix.as_bytes());
    let mut result = String::with_capacity(42);
    result.push_str("0x");
    for (i, ch) in lower_hex_no_prefix.chars().enumerate() {
        if ch.is_ascii_digit() {
            result.push(ch);
        } else {
            let byte = hash[i / 2];
            let nibble = if i % 2 == 0 { byte >> 4 } else { byte & 0x0f };
            if nibble >= 8 {
                result.push(ch.to_ascii_uppercase());
            } else {
                result.push(ch.to_ascii_lowercase());
            }
        }
    }
    result
}

pub(crate) fn is_valid_hex_address(addr: &str) -> bool {
    addr.len() == 42
        && (addr.starts_with("0x") || addr.starts_with("0X"))
        && addr[2..].chars().all(|c| c.is_ascii_hexdigit())
}

pub(crate) fn parse_topic_address(topic: &str) -> Option<String> {
    let clean = topic
        .trim()
        .strip_prefix("0x")
        .or_else(|| topic.trim().strip_prefix("0X"))?;
    if clean.len() != 64 || !clean.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let addr_lower = clean[24..64].to_ascii_lowercase();
    Some(to_eip55(&addr_lower))
}

pub(crate) fn parse_u256_low_u128(hex_data: &str) -> Option<u128> {
    let clean = hex_data
        .trim()
        .strip_prefix("0x")
        .or_else(|| hex_data.trim().strip_prefix("0X"))
        .unwrap_or(hex_data.trim());
    if clean.is_empty() {
        return Some(0);
    }
    if clean.len() > 64 || !clean.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let padded = format!("{:0>64}", clean);
    let upper = u128::from_str_radix(&padded[0..32], 16).ok()?;
    let lower = u128::from_str_radix(&padded[32..64], 16).ok()?;
    if upper > 0 {
        Some(u128::MAX)
    } else {
        Some(lower)
    }
}

fn keystore_path() -> Result<PathBuf, String> {
    let base = dirs::data_local_dir()
        .ok_or_else(|| "Unable to resolve Windows %LOCALAPPDATA% directory".to_string())?;
    let dir = base.join("HartsAntiVenom");
    fs::create_dir_all(&dir).map_err(|e| format!("Failed creating keystore directory: {e}"))?;
    Ok(dir.join("keystore.enc"))
}

fn get_or_create_master_key() -> Result<[u8; 32], String> {
    let entry = Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT)
        .map_err(|e| format!("Windows Credential Manager init error: {e}"))?;

    match entry.get_password() {
        Ok(hex_key) => {
            let bytes = hex::decode(hex_key.trim())
                .map_err(|e| format!("Corrupted key in Credential Manager: {e}"))?;
            if bytes.len() != 32 {
                return Err("Invalid AES-256 key length in Credential Manager".to_string());
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            Ok(key)
        }
        Err(_) => {
            let mut key = [0u8; 32];
            OsRng.fill_bytes(&mut key);
            entry
                .set_password(&hex::encode(key))
                .map_err(|e| format!("Failed storing master key in Credential Manager: {e}"))?;
            Ok(key)
        }
    }
}

pub(crate) fn load_contacts_internal() -> Result<Vec<TrustedContact>, String> {
    let path = keystore_path()?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let blob = fs::read(&path).map_err(|e| format!("Failed reading encrypted keystore: {e}"))?;
    if blob.len() < 12 {
        return Err("Encrypted keystore truncated".to_string());
    }
    let key = get_or_create_master_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| format!("AES-256-GCM initialization failed: {e}"))?;
    let nonce = Nonce::from_slice(&blob[..12]);
    let plaintext = cipher
        .decrypt(nonce, &blob[12..])
        .map_err(|_| "Tamper alert: AES-256-GCM authentication tag verification failed!".to_string())?;
    serde_json::from_slice(&plaintext)
        .map_err(|e| format!("Failed deserializing decrypted contacts: {e}"))
}

pub(crate) fn persist_contacts_internal(contacts: &[TrustedContact]) -> Result<(), String> {
    let path = keystore_path()?;
    let key = get_or_create_master_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| format!("AES-256-GCM initialization failed: {e}"))?;
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext =
        serde_json::to_vec(contacts).map_err(|e| format!("Serialization error: {e}"))?;
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| format!("AES-256-GCM encryption failed: {e}"))?;

    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    fs::write(&path, out).map_err(|e| format!("Failed writing encrypted keystore: {e}"))
}

pub mod commands {
    use super::*;

    // LAYER 3: Anti-Vanity Visual Hashing & Middle-Hex Focus
    #[tauri::command]
    pub fn inspect_address(target: String) -> AddressInspection {
        let trimmed = target.trim();
        if !is_valid_hex_address(trimmed) {
            return AddressInspection {
                is_valid_format: false,
                checksum_valid: false,
                normalized_eip55: String::new(),
                prefix: String::new(),
                middle_segment: String::new(),
                suffix: String::new(),
                color_blocks: Vec::new(),
                threat_flag: Some(
                    "Invalid EVM address: expected 42-character 0x hex string".to_string(),
                ),
            };
        }

        let lower_body = trimmed[2..].to_ascii_lowercase();
        let eip55 = to_eip55(&lower_body);
        let is_all_lower = trimmed[2..] == lower_body;
        let is_all_upper = trimmed[2..] == trimmed[2..].to_ascii_uppercase();
        let checksum_valid = is_all_lower || is_all_upper || trimmed == eip55;

        let digest = keccak256(format!("0x{}", lower_body).as_bytes());
        let mut blocks = Vec::with_capacity(5);
        for i in 0..5 {
            let idx = i * 3;
            blocks.push(format!(
                "#{:02x}{:02x}{:02x}",
                digest[idx],
                digest[idx + 1],
                digest[idx + 2]
            ));
        }

        let threat_flag = if !checksum_valid {
            Some("EIP-55 mixed-case checksum mismatch — verify exact characters!".to_string())
        } else {
            None
        };

        AddressInspection {
            is_valid_format: true,
            checksum_valid,
            prefix: eip55[0..6].to_string(),
            middle_segment: eip55[6..38].to_string(),
            suffix: eip55[38..42].to_string(),
            normalized_eip55: eip55,
            color_blocks: blocks,
            threat_flag,
        }
    }

    // LAYER 1: Inbound Dust & Zero-Value Log Scrubbing
    #[tauri::command]
    pub fn scrub_transfer_logs(
        logs_json: String,
        min_dust_threshold: u128,
    ) -> Result<ScrubbedLogReport, String> {
        let entries: Vec<RawLogEntry> = serde_json::from_str(&logs_json)
            .map_err(|e| format!("Invalid RPC log JSON array: {e}"))?;

        let mut quarantined_zero_value = 0usize;
        let mut quarantined_dust = 0usize;
        let mut clean_logs = Vec::new();

        for entry in &entries {
            if entry.topics.len() < 3 {
                continue;
            }
            if entry.topics[0].trim().to_ascii_lowercase() != ERC20_TRANSFER_TOPIC {
                continue;
            }
            let from = match parse_topic_address(&entry.topics[1]) {
                Some(a) => a,
                None => continue,
            };
            let to = match parse_topic_address(&entry.topics[2]) {
                Some(a) => a,
                None => continue,
            };
            let amount = parse_u256_low_u128(&entry.data)
                .ok_or_else(|| format!("Malformed uint256 data field in tx {}", entry.tx_hash))?;

            if amount == 0 {
                quarantined_zero_value += 1;
                continue;
            }
            if amount < min_dust_threshold {
                quarantined_dust += 1;
                continue;
            }

            clean_logs.push(CleanTransferEvent {
                tx_hash: entry.tx_hash.clone(),
                from,
                to,
                amount_raw: amount,
            });
        }

        Ok(ScrubbedLogReport {
            total_logs: entries.len(),
            quarantined_zero_value,
            quarantined_dust,
            clean_logs,
        })
    }

    // LAYER 2: Outbound Signature & History Pairing
    #[tauri::command]
    pub fn classify_history(
        user_wallet: String,
        txs_json: String,
    ) -> Result<PairedHistoryReport, String> {
        let wallet = user_wallet.trim();
        if !is_valid_hex_address(wallet) {
            return Err("Invalid user wallet address".to_string());
        }
        let user_lower = wallet.to_ascii_lowercase();
        let txs: Vec<TxRecord> = serde_json::from_str(&txs_json)
            .map_err(|e| format!("Invalid transaction JSON: {e}"))?;

        let mut outbound = Vec::new();
        let mut inbound_quarantine = Vec::new();

        for tx in txs {
            if !is_valid_hex_address(tx.from.trim()) || !is_valid_hex_address(tx.to.trim()) {
                continue;
            }
            if tx.from.trim().to_ascii_lowercase() == user_lower {
                let eip = to_eip55(&tx.to.trim()[2..].to_ascii_lowercase());
                if !outbound.contains(&eip) {
                    outbound.push(eip);
                }
            } else if tx.to.trim().to_ascii_lowercase() == user_lower {
                inbound_quarantine.push(tx);
            }
        }

        Ok(PairedHistoryReport {
            trusted_outbound_counterparties: outbound,
            quarantined_unsolicited_inbound: inbound_quarantine,
        })
    }

    // LAYER 4: Tamper-Evident Local Keystore (AES-256-GCM + Windows Credential Manager)
    #[tauri::command]
    pub fn save_trusted_contact(
        label: String,
        address: String,
    ) -> Result<Vec<TrustedContact>, String> {
        let clean_label = label.trim();
        if clean_label.is_empty() {
            return Err("Contact label cannot be empty".to_string());
        }
        let clean_addr = address.trim();
        if !is_valid_hex_address(clean_addr) {
            return Err("Invalid EVM address".to_string());
        }
        let eip55 = to_eip55(&clean_addr[2..].to_ascii_lowercase());
        let mut contacts = load_contacts_internal()?;
        contacts.retain(|c| c.address.to_ascii_lowercase() != eip55.to_ascii_lowercase());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        contacts.push(TrustedContact {
            label: clean_label.to_string(),
            address: eip55,
            added_unix: now,
        });
        persist_contacts_internal(&contacts)?;
        Ok(contacts)
    }

    #[tauri::command]
    pub fn list_trusted_contacts() -> Result<Vec<TrustedContact>, String> {
        load_contacts_internal()
    }

    #[tauri::command]
    pub fn delete_trusted_contact(address: String) -> Result<Vec<TrustedContact>, String> {
        let target_lower = address.trim().to_ascii_lowercase();
        let mut contacts = load_contacts_internal()?;
        contacts.retain(|c| c.address.to_ascii_lowercase() != target_lower);
        persist_contacts_internal(&contacts)?;
        Ok(contacts)
    }

    // LAYER 5: Pre-Flight Nonce & Topology Oracle
    #[tauri::command]
    pub fn preflight_check(
        candidate_address: String,
        candidate_outbound_nonce: u64,
        is_contract: bool,
    ) -> Result<PreflightResult, String> {
        let trimmed = candidate_address.trim();
        if !is_valid_hex_address(trimmed) {
            return Err("Invalid candidate EVM address".to_string());
        }
        let cand_lower = trimmed.to_ascii_lowercase();
        let cand_eip55 = to_eip55(&cand_lower[2..]);
        let cand_prefix = &cand_lower[2..6];
        let cand_suffix = &cand_lower[38..42];

        let contacts = load_contacts_internal()?;

        if let Some(exact) = contacts
            .iter()
            .find(|c| c.address.to_ascii_lowercase() == cand_lower)
        {
            return Ok(PreflightResult {
                risk_level: "SAFE".to_string(),
                matched_contact_label: Some(exact.label.clone()),
                matched_contact_address: Some(exact.address.clone()),
                boundary_collision_detected: false,
                zero_nonce_eoa: candidate_outbound_nonce == 0 && !is_contract,
                reason: format!(
                    "Exact cryptographic match verified against trusted contact '{}'.",
                    exact.label
                ),
            });
        }

        for contact in &contacts {
            let c_lower = contact.address.to_ascii_lowercase();
            let c_prefix = &c_lower[2..6];
            let c_suffix = &c_lower[38..42];

            let prefix_match = cand_prefix == c_prefix;
            let suffix_match = cand_suffix == c_suffix;

            if prefix_match || suffix_match {
                let zero_nonce_eoa = candidate_outbound_nonce == 0 && !is_contract;
                let risk = if (prefix_match && suffix_match) || zero_nonce_eoa {
                    "CRITICAL_POISON_TRAP"
                } else {
                    "WARNING"
                };
                return Ok(PreflightResult {
                    risk_level: risk.to_string(),
                    matched_contact_label: Some(contact.label.clone()),
                    matched_contact_address: Some(contact.address.clone()),
                    boundary_collision_detected: true,
                    zero_nonce_eoa,
                    reason: format!(
                        "Boundary collision with '{}' ({})! Candidate {} has {} boundary overlap and outbound nonce = {}.",
                        contact.label,
                        contact.address,
                        cand_eip55,
                        if prefix_match && suffix_match {
                            "BOTH prefix & suffix"
                        } else if prefix_match {
                            "prefix"
                        } else {
                            "suffix"
                        },
                        candidate_outbound_nonce
                    ),
                });
            }
        }

        let zero_nonce_eoa = candidate_outbound_nonce == 0 && !is_contract;
        if zero_nonce_eoa {
            return Ok(PreflightResult {
                risk_level: "WARNING".to_string(),
                matched_contact_label: None,
                matched_contact_address: None,
                boundary_collision_detected: false,
                zero_nonce_eoa: true,
                reason: "Unrecognized EOA with outbound nonce 0 (fresh burner/uninitialized wallet). Verify full middle hex before signing.".to_string(),
            });
        }

        Ok(PreflightResult {
            risk_level: "SAFE".to_string(),
            matched_contact_label: None,
            matched_contact_address: None,
            boundary_collision_detected: false,
            zero_nonce_eoa: false,
            reason: "No boundary collisions detected against encrypted keystore; outbound nonce > 0 or verified contract.".to_string(),
        })
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            commands::inspect_address,
            commands::scrub_transfer_logs,
            commands::classify_history,
            commands::save_trusted_contact,
            commands::list_trusted_contacts,
            commands::delete_trusted_contact,
            commands::preflight_check
        ])
        .run(tauri::generate_context!())
        .expect("error while running Hart's Anti-Venom Windows application");
}
