// backend/src/encryption.rs
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

const KEY_FILE_PATH: &str = "/etc/rustykey/keys/master.key";
const KEY_SIZE: usize = 32;

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedData {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub metadata: EncryptionMetadata,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptionMetadata {
    pub algorithm: String,
    pub key_id: String,
    pub encrypted_at: u64,
}

pub struct EncryptionManager {
    cipher: Aes256Gcm,
    key_id: String,
}

impl EncryptionManager {
    pub fn init() -> Result<Self> {
        let key = Self::get_or_generate_key()?;
        let cipher = Aes256Gcm::new(&key);
        let key_id = Self::compute_key_id(&key);

        Ok(Self { cipher, key_id })
    }

    fn get_or_generate_key() -> Result<Key<Aes256Gcm>> {
        let key_path = Path::new(KEY_FILE_PATH);

        if key_path.exists() {
            Self::load_key_from_file(key_path)
        } else {
            Self::generate_and_save_key(key_path)
        }
    }

    fn generate_and_save_key(path: &Path) -> Result<Key<Aes256Gcm>> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;

            let mut perms = fs::metadata(parent)?.permissions();
            perms.set_mode(0o700);
            fs::set_permissions(parent, perms)?;
        }

        use aes_gcm::aead::rand_core::RngCore;
        let mut key_bytes = [0u8; KEY_SIZE];
        OsRng.fill_bytes(&mut key_bytes);

        fs::write(path, &key_bytes)?;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)?;

        Ok(Key::<Aes256Gcm>::from_slice(&key_bytes).clone())
    }

    fn load_key_from_file(path: &Path) -> Result<Key<Aes256Gcm>> {
        let metadata = fs::metadata(path)?;
        let mode = metadata.permissions().mode();

        if mode & 0o077 != 0 {
            return Err(anyhow::anyhow!(
                "SECURITY ERROR: Key file {} has insecure permissions {:o}. Expected 600.",
                path.display(),
                mode & 0o777
            ));
        }

        let key_bytes = fs::read(path)?;

        if key_bytes.len() != KEY_SIZE {
            return Err(anyhow::anyhow!(
                "Invalid key size: expected {} bytes, got {}",
                KEY_SIZE,
                key_bytes.len()
            ));
        }

        Ok(Key::<Aes256Gcm>::from_slice(&key_bytes).clone())
    }

    fn compute_key_id(key: &Key<Aes256Gcm>) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(key.as_slice());
        format!("{:x}", hasher.finalize())
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedData> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;

        Ok(EncryptedData {
            ciphertext,
            nonce: nonce.to_vec(),
            metadata: EncryptionMetadata {
                algorithm: "AES-256-GCM".to_string(),
                key_id: self.key_id.clone(),
                encrypted_at: chrono::Utc::now().timestamp() as u64,
            },
        })
    }

    pub fn decrypt(&self, encrypted: &EncryptedData) -> Result<Vec<u8>> {
        if !encrypted.metadata.key_id.starts_with(&self.key_id[..8]) {
            return Err(anyhow::anyhow!(
                "Key ID mismatch - wrong key or corrupted data"
            ));
        }

        let nonce = Nonce::from_slice(&encrypted.nonce);

        let plaintext = self
            .cipher
            .decrypt(nonce, encrypted.ciphertext.as_ref())
            .map_err(|e| anyhow::anyhow!("Decryption failed: {:?}", e))?;

        Ok(plaintext)
    }
}
