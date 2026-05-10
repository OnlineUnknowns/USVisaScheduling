use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce
};
use rand::RngCore;
use sha2::{Sha256, Digest};
use std::fs::File;
use std::io::{Read, Write};

pub struct CryptoEngine {
    key: [u8; 32],
}

impl CryptoEngine {
    pub fn new(password: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let result = hasher.finalize();

        let mut key = [0u8; 32];
        key.copy_from_slice(&result[..32]);

        CryptoEngine { key }
    }

    pub fn encrypt_data(&self, plaintext: &[u8]) -> Vec<u8> {
        let cipher = Aes256Gcm::new((&self.key).into());

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);

        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .expect("Encryption failed");

        let mut final_data = nonce_bytes.to_vec();
        final_data.extend(ciphertext);

        final_data
    }

    pub fn decrypt_data(&self, encrypted: &[u8]) -> Vec<u8> {
        let cipher = Aes256Gcm::new((&self.key).into());

        let nonce = Nonce::from_slice(&encrypted[..12]);
        let ciphertext = &encrypted[12..];

        cipher.decrypt(nonce, ciphertext)
            .expect("Decryption failed")
    }

    pub fn encrypt_file(
        &self,
        input_path: &str,
        output_path: &str
    ) {
        let mut file = File::open(input_path).unwrap();
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).unwrap();

        let encrypted = self.encrypt_data(&buffer);

        let mut out = File::create(output_path).unwrap();
        out.write_all(&encrypted).unwrap();
    }

    pub fn decrypt_file(
        &self,
        input_path: &str,
        output_path: &str
    ) {
        let mut file = File::open(input_path).unwrap();
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).unwrap();

        let decrypted = self.decrypt_data(&buffer);

        let mut out = File::create(output_path).unwrap();
        out.write_all(&decrypted).unwrap();
    }

    pub fn verify_integrity(
        &self,
        data: &[u8]
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);

        let hash = hasher.finalize();

        hex::encode(hash)
    }

    pub fn generate_session_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }

    pub fn rotate_keys(&mut self) {
        self.key = Self::generate_session_key();
    }
}

fn main() {
    let engine = CryptoEngine::new(
        "critical_secure_password"
    );

    let message = b"Military secure data transmission";

    let encrypted = engine.encrypt_data(message);

    println!("Encrypted: {:?}", encrypted);

    let decrypted = engine.decrypt_data(&encrypted);

    println!(
        "Decrypted: {}",
        String::from_utf8(decrypted).unwrap()
    );
}