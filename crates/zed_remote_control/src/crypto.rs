use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::{aead::Aead, XChaCha20Poly1305, XNonce};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

/// An X25519 keypair for the ECDH key exchange.
pub struct KeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    #[cfg(test)]
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }

    pub fn public_key_base64(&self) -> String {
        B64.encode(self.public.as_bytes())
    }

    pub fn diffie_hellman(&self, their_public: &PublicKey) -> SharedSecret {
        SharedSecret(*self.secret.diffie_hellman(their_public).as_bytes())
    }
}

/// Shared secret derived from X25519 ECDH.
pub struct SharedSecret(pub(crate) [u8; 32]);

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Derive the symmetric encryption key from the shared ECDH secret.
///
/// Uses Blake2b keyed MAC with key=b"zrc-symk", 32-byte output.
/// Matches Python: `crypto_generichash_blake2b_salt_personal(shared, key=b"zrc-symk", digest_size=32)`
pub fn derive_symmetric_key(shared: &SharedSecret) -> [u8; 32] {
    use blake2::digest::Mac;
    type Blake2bMac256 = blake2::Blake2bMac<blake2::digest::consts::U32>;
    let mut mac =
        Blake2bMac256::new_from_slice(b"zrc-symk").expect("key length is valid for Blake2b");
    Mac::update(&mut mac, &shared.0);
    let result = mac.finalize();
    let bytes = result.into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

/// Derive the 6-digit SAS verification code from the shared ECDH secret.
///
/// Uses Blake2b keyed MAC with key=b"zrc-sasc", 8-byte output.
/// Takes first 4 bytes as LE u32, mod 1_000_000, zero-padded to 6 digits.
pub fn derive_sas_code(shared: &SharedSecret) -> String {
    use blake2::digest::Mac;
    type Blake2bMac64 = blake2::Blake2bMac<blake2::digest::consts::U8>;
    let mut mac =
        Blake2bMac64::new_from_slice(b"zrc-sasc").expect("key length is valid for Blake2b");
    Mac::update(&mut mac, &shared.0);
    let result = mac.finalize();
    let bytes = result.into_bytes();
    let val = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    format!("{:06}", val % 1_000_000)
}

/// Build AAD bytes from envelope metadata: pairing_id || sender || sequence (LE u64).
pub fn build_aad(pairing_id: &str, sender: &str, sequence: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(pairing_id.len() + sender.len() + 8);
    aad.extend_from_slice(pairing_id.as_bytes());
    aad.extend_from_slice(sender.as_bytes());
    aad.extend_from_slice(&sequence.to_le_bytes());
    aad
}

/// Encrypt a plaintext string with XChaCha20-Poly1305 + AAD.
/// Returns (nonce_base64, ciphertext_base64).
pub fn encrypt(plaintext: &str, key: &[u8; 32], aad: &[u8]) -> Result<(String, String)> {
    use chacha20poly1305::aead::{KeyInit, Payload};
    use rand::RngCore;
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; 24];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let payload = Payload {
        msg: plaintext.as_bytes(),
        aad,
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;

    Ok((B64.encode(nonce_bytes), B64.encode(ciphertext)))
}

/// Encrypt with a specific nonce (for testing only).
#[cfg(test)]
pub fn encrypt_with_nonce(
    plaintext: &str,
    key: &[u8; 32],
    nonce_bytes: &[u8; 24],
    aad: &[u8],
) -> Result<(String, String)> {
    use chacha20poly1305::aead::{KeyInit, Payload};
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XNonce::from_slice(nonce_bytes);

    let payload = Payload {
        msg: plaintext.as_bytes(),
        aad,
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;

    Ok((B64.encode(nonce_bytes), B64.encode(ciphertext)))
}

/// Decrypt a ciphertext using XChaCha20-Poly1305 + AAD.
/// Takes base64-encoded nonce and ciphertext, returns plaintext string.
pub fn decrypt(nonce_b64: &str, ciphertext_b64: &str, key: &[u8; 32], aad: &[u8]) -> Result<String> {
    use chacha20poly1305::aead::{KeyInit, Payload};
    let nonce_bytes = B64.decode(nonce_b64).context("invalid nonce base64")?;
    let ciphertext = B64.decode(ciphertext_b64).context("invalid ciphertext base64")?;

    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XNonce::from_slice(&nonce_bytes);

    let payload = Payload {
        msg: ciphertext.as_ref(),
        aad,
    };

    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|e| anyhow::anyhow!("decryption failed: {e}"))?;

    String::from_utf8(plaintext).context("decrypted payload is not valid UTF-8")
}

/// Holds the session cryptographic state after pairing completes.
pub struct SessionKeys {
    pub pairing_id: String,
    pub symmetric_key: [u8; 32],
    pub sequence: u64,
}

impl SessionKeys {
    pub fn new(pairing_id: String, symmetric_key: [u8; 32]) -> Self {
        Self {
            pairing_id,
            symmetric_key,
            sequence: 0,
        }
    }

    pub fn next_sequence(&mut self) -> u64 {
        self.sequence += 1;
        self.sequence
    }
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        self.symmetric_key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors generated from Python mock_zed.py crypto functions.
    // These ensure byte-identical output across Rust and Python.
    const ZED_SK_HEX: &str = "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4";
    const MOBILE_SK_HEX: &str =
        "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d";
    const EXPECTED_ZED_PK_B64: &str = "HJ/Yj0VgbZMqgMcYJK4VHRXXPnfeOOjgAIUuYU+ucBk=";
    const EXPECTED_MOBILE_PK_B64: &str = "/2P+V7+/Q/o/VjYosUmvcE09tiU2nEmYNlA0empx4A4=";
    const EXPECTED_SHARED_HEX: &str =
        "739311d35d8d3c41da4062c799a6c748808a31343facaaa7aa7e311908c1846e";
    const EXPECTED_SYM_KEY_HEX: &str =
        "29625f868960648abb8e851f7d7860ae5ffaa8cf5c614d0edd514169b603cb29";
    const EXPECTED_SAS_CODE: &str = "102866";

    fn hex_to_bytes32(hex: &str) -> [u8; 32] {
        let bytes = hex::decode(hex).unwrap();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }

    mod hex {
        pub fn decode(s: &str) -> Result<Vec<u8>, String> {
            (0..s.len())
                .step_by(2)
                .map(|i| {
                    u8::from_str_radix(&s[i..i + 2], 16)
                        .map_err(|e| format!("hex decode error: {e}"))
                })
                .collect()
        }

        pub fn encode(bytes: &[u8]) -> String {
            bytes.iter().map(|b| format!("{:02x}", b)).collect()
        }
    }

    #[test]
    fn test_keypair_generation() {
        let kp = KeyPair::generate();
        assert_eq!(kp.public_key_bytes().len(), 32);
        // Public key should not be all zeros
        assert!(kp.public_key_bytes().iter().any(|&b| b != 0));
    }

    #[test]
    fn test_keypair_from_known_secret() {
        let zed_kp = KeyPair::from_secret_bytes(hex_to_bytes32(ZED_SK_HEX));
        assert_eq!(zed_kp.public_key_base64(), EXPECTED_ZED_PK_B64);

        let mobile_kp = KeyPair::from_secret_bytes(hex_to_bytes32(MOBILE_SK_HEX));
        assert_eq!(mobile_kp.public_key_base64(), EXPECTED_MOBILE_PK_B64);
    }

    #[test]
    fn test_ecdh_symmetry() {
        // Both sides should derive the same shared secret
        let zed_kp = KeyPair::from_secret_bytes(hex_to_bytes32(ZED_SK_HEX));
        let mobile_kp = KeyPair::from_secret_bytes(hex_to_bytes32(MOBILE_SK_HEX));

        let shared_zed = zed_kp.diffie_hellman(&PublicKey::from(mobile_kp.public_key_bytes()));
        let shared_mobile = mobile_kp.diffie_hellman(&PublicKey::from(zed_kp.public_key_bytes()));

        assert_eq!(
            hex::encode(&shared_zed.0),
            hex::encode(&shared_mobile.0),
            "ECDH shared secrets must match"
        );
    }

    #[test]
    fn test_ecdh_known_vector() {
        let zed_kp = KeyPair::from_secret_bytes(hex_to_bytes32(ZED_SK_HEX));
        let mobile_pk_bytes = B64.decode(EXPECTED_MOBILE_PK_B64).unwrap();
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&mobile_pk_bytes);
        let mobile_pk = PublicKey::from(pk_arr);

        let shared = zed_kp.diffie_hellman(&mobile_pk);
        assert_eq!(hex::encode(&shared.0), EXPECTED_SHARED_HEX);
    }

    #[test]
    fn test_derive_symmetric_key_known_vector() {
        let shared = SharedSecret(hex_to_bytes32(EXPECTED_SHARED_HEX));
        let sym_key = derive_symmetric_key(&shared);
        assert_eq!(hex::encode(&sym_key), EXPECTED_SYM_KEY_HEX);
    }

    #[test]
    fn test_derive_sas_code_known_vector() {
        let shared = SharedSecret(hex_to_bytes32(EXPECTED_SHARED_HEX));
        let sas = derive_sas_code(&shared);
        assert_eq!(sas, EXPECTED_SAS_CODE);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = hex_to_bytes32(EXPECTED_SYM_KEY_HEX);
        let plaintext = r#"{"type":"prompt","project":"test","text":"hello"}"#;
        let aad = build_aad("test-pairing", "zed", 1);

        let (nonce_b64, ct_b64) = encrypt(plaintext, &key, &aad).unwrap();
        let decrypted = decrypt(&nonce_b64, &ct_b64, &key, &aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_empty_aad() {
        let key = hex_to_bytes32(EXPECTED_SYM_KEY_HEX);
        let plaintext = r#"{"type":"prompt","project":"test","text":"hello"}"#;

        let (nonce_b64, ct_b64) = encrypt(plaintext, &key, &[]).unwrap();
        let decrypted = decrypt(&nonce_b64, &ct_b64, &key, &[]).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_known_vector() {
        let key = hex_to_bytes32(EXPECTED_SYM_KEY_HEX);
        let plaintext = r#"{"type":"prompt","project":"test","text":"hello"}"#;
        let nonce: [u8; 24] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        ];

        // Empty AAD to match legacy test vectors
        let (nonce_b64, ct_b64) = encrypt_with_nonce(plaintext, &key, &nonce, &[]).unwrap();
        assert_eq!(nonce_b64, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX");
        assert_eq!(
            ct_b64,
            "EvNfe7umiMqUidCCMskzF7TNMPjY640W9TO9w7AA9C0bcOhwui8YUzFIfYZhmQUcfJ5BiXYHSNhWJMP9hM/ipn4="
        );
    }

    #[test]
    fn test_encrypt_known_vector_with_aad() {
        // Cross-language vector: same key/nonce/plaintext but with AAD
        // Generated from Python: generate_test_vectors.py
        let key_hex = "abfe287ce3c2670f00a3647016492d0e55861d3e1bce153e2add588ea2e7d959";
        let key = hex_to_bytes32(key_hex);
        let plaintext = "Hello, ZRC!";
        let nonce: [u8; 24] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        ];
        let aad = build_aad("test-pairing-123", "zed", 42);

        let (_, ct_b64) = encrypt_with_nonce(plaintext, &key, &nonce, &aad).unwrap();
        assert_eq!(ct_b64, "oASVxuRZVc2jmT/SKcx3x8+WAC6sf4Gr3DN7");

        // Verify decrypt with same AAD
        let nonce_b64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX";
        let decrypted = decrypt(nonce_b64, &ct_b64, &key, &aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key = hex_to_bytes32(EXPECTED_SYM_KEY_HEX);
        let plaintext = "test message";
        let aad = build_aad("test-pairing", "zed", 1);

        let (nonce_b64, ct_b64) = encrypt(plaintext, &key, &aad).unwrap();

        let mut wrong_key = key;
        wrong_key[0] ^= 0xff;
        assert!(decrypt(&nonce_b64, &ct_b64, &wrong_key, &aad).is_err());
    }

    #[test]
    fn test_decrypt_wrong_aad_fails() {
        let key = hex_to_bytes32(EXPECTED_SYM_KEY_HEX);
        let plaintext = "test message";
        let aad = build_aad("test-pairing", "zed", 1);

        let (nonce_b64, ct_b64) = encrypt(plaintext, &key, &aad).unwrap();

        // Wrong sender
        let wrong_aad = build_aad("test-pairing", "mobile", 1);
        assert!(decrypt(&nonce_b64, &ct_b64, &key, &wrong_aad).is_err());

        // Wrong sequence
        let wrong_aad2 = build_aad("test-pairing", "zed", 2);
        assert!(decrypt(&nonce_b64, &ct_b64, &key, &wrong_aad2).is_err());

        // Wrong pairing_id
        let wrong_aad3 = build_aad("other-pairing", "zed", 1);
        assert!(decrypt(&nonce_b64, &ct_b64, &key, &wrong_aad3).is_err());
    }

    #[test]
    fn test_encrypt_nonce_uniqueness() {
        let key = hex_to_bytes32(EXPECTED_SYM_KEY_HEX);
        let plaintext = "same message";

        let (nonce1, _) = encrypt(plaintext, &key, &[]).unwrap();
        let (nonce2, _) = encrypt(plaintext, &key, &[]).unwrap();
        assert_ne!(nonce1, nonce2, "each encryption must use a unique nonce");
    }

    #[test]
    fn test_build_aad() {
        let aad = build_aad("abc", "zed", 1);
        // "abc" = [97, 98, 99], "zed" = [122, 101, 100], 1_u64 LE = [1, 0, 0, 0, 0, 0, 0, 0]
        assert_eq!(aad, vec![97, 98, 99, 122, 101, 100, 1, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_session_keys_sequence() {
        let key = hex_to_bytes32(EXPECTED_SYM_KEY_HEX);
        let mut sk = SessionKeys::new("test-pairing".to_string(), key);
        assert_eq!(sk.next_sequence(), 1);
        assert_eq!(sk.next_sequence(), 2);
        assert_eq!(sk.next_sequence(), 3);
    }

    #[test]
    fn test_full_pipeline_known_vectors() {
        // End-to-end: keypair → ECDH → KDF → SAS → encrypt → decrypt
        let zed_kp = KeyPair::from_secret_bytes(hex_to_bytes32(ZED_SK_HEX));
        let mobile_kp = KeyPair::from_secret_bytes(hex_to_bytes32(MOBILE_SK_HEX));

        // ECDH from Zed's perspective
        let shared = zed_kp.diffie_hellman(&PublicKey::from(mobile_kp.public_key_bytes()));

        // Derive keys
        let sym_key = derive_symmetric_key(&shared);
        let sas = derive_sas_code(&shared);

        // Verify against Python vectors
        assert_eq!(hex::encode(&sym_key), EXPECTED_SYM_KEY_HEX);
        assert_eq!(sas, EXPECTED_SAS_CODE);

        // Encrypt and decrypt with AAD
        let plaintext = r#"{"type":"entry.new","project":"myproj","thread_id":"t1","index":0,"entry":{"kind":"user_message","text":"hello world"}}"#;
        let aad = build_aad("test-pairing-id", "zed", 1);
        let (nonce_b64, ct_b64) = encrypt(plaintext, &sym_key, &aad).unwrap();
        let decrypted = decrypt(&nonce_b64, &ct_b64, &sym_key, &aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
