// Copyright gvolc 2026.
//
// The code is distributed under the Mozilla Public License Version 2.0 license
// (you can find the license file in the root folder).

use ring::aead::{LessSafeKey, UnboundKey, CHACHA20_POLY1305, Nonce, Aad};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{Ed25519KeyPair, UnparsedPublicKey, ED25519, KeyPair};
use zeroize::{Zeroize, Zeroizing};

pub const KEY_SIZE: usize = 32;       // 256-бит симметричный ключ
pub const NONCE_SIZE: usize = 12;     // 96-бит одноразовый код пакета
pub const TAG_SIZE: usize = 16;       // Тег аутентификации Poly1305
pub const SIGNATURE_SIZE: usize = 64; // Размер асимметричной подписи Ed25519
pub const VOICE_SAMPLE_RATE: u32 = 48000;

#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub enum CryptoError {
    BufferTooSmall,
    CiphertextTooShort,
    InvalidKey,
    IntegrityCompromised,
    SigningFailed,
    RngError,
    ReplayPacketDropped,
}

// =========================================================================
// STRUCT: ReplayWindow (Битовое скользящее окно WireGuard-класса)
// =========================================================================
pub struct ReplayWindow {
    highest_seen: u64,
    bitmap: u64, // Окно из 64 пакетов для отслеживания out-of-order трафика
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            highest_seen: 0,
            bitmap: 0,
        }
    }

    /// Проверяет sequence_number пакета на повтор (Replay Attack).
    /// Вызывается ИСКЛЮЧИТЕЛЬНО после успешной AEAD-дешифрации пакета.
    pub fn update(&mut self, seq: u64) -> Result<(), CryptoError> {
        if seq == 0 {
            return Err(CryptoError::ReplayPacketDropped);
        }

        if seq > self.highest_seen {
            let diff = seq - self.highest_seen;
            if diff >= 64 {
                self.bitmap = 1;
            } else {
                self.bitmap = (self.bitmap << diff) | 1;
            }
            self.highest_seen = seq;
            return Ok(());
        }

        let diff = self.highest_seen - seq;
        if diff >= 64 {
            return Err(CryptoError::ReplayPacketDropped);
        }

        let mask = 1 << diff;
        if (self.bitmap & mask) != 0 {
            return Err(CryptoError::ReplayPacketDropped);
        }

        self.bitmap |= mask;
        Ok(())
    }
}

// =========================================================================
// STRUCT: CryptoEngine
// =========================================================================
pub struct CryptoEngine {
    rng: SystemRandom,
    session_salt: [u8; 4],
}

impl CryptoEngine {
    /// Инициализация с готовой солью (согласованной на этапе handshake между клиентом и сервером)
    pub fn new(session_salt: [u8; 4]) -> Self {
        Self {
            rng: SystemRandom::new(),
            session_salt,
        }
    }

    /// Генерация движка на стороне сервера с созданием криптостойкой случайной соли
    pub fn new_server_side() -> Result<(Self, [u8; 4]), CryptoError> {
        let rng = SystemRandom::new();
        let mut session_salt = [0u8; 4];
        rng.fill(&mut session_salt).map_err(|_| CryptoError::RngError)?;
        
        let engine = Self { rng, session_salt };
        Ok((engine, session_salt))
    }

    // =========================================================================
    // 1. ГЕНЕРАЦИЯ КЛЮЧЕЙ И НОНСОВ
    // =========================================================================

    pub fn generate_session_key(&self) -> Result<Zeroizing<[u8; KEY_SIZE]>, CryptoError> {
        let mut key = [0u8; KEY_SIZE];
        self.rng.fill(&mut key).map_err(|_| CryptoError::RngError)?;
        Ok(Zeroizing::new(key))
    }

    #[inline]
    pub fn construct_nonce(&self, sequence_number: u64) -> [u8; NONCE_SIZE] {
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[..4].copy_from_slice(&self.session_salt);
        nonce[4..].copy_from_slice(&sequence_number.to_be_bytes());
        nonce
    }

    pub fn generate_ed25519_keypair(&self) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let doc = Ed25519KeyPair::generate_pkcs8(&self.rng)
            .map_err(|_| CryptoError::RngError)?;
        Ok(Zeroizing::new(doc.as_ref().to_vec()))
    }

    // =========================================================================
    // 2. ИГРОВЫЕ И ГОЛОСОВЫЕ ПАКЕТЫ (ChaCha20-Poly1305 + Проверка заголовков AAD)
    // =========================================================================

    /// Шифрует данные прямо внутри переданного буфера на месте.
    /// Буфер ДОЛЖЕН иметь запас в +16 байт (TAG_SIZE) после полезных данных!
    pub fn encrypt_in_place(
        &self,
        buffer: &mut [u8],
        payload_len: usize,
        key_bytes: &[u8; KEY_SIZE],
        sequence_number: u64,
        aad_bytes: &[u8],
    ) -> Result<usize, CryptoError> {
        if buffer.len() < payload_len + TAG_SIZE {
            return Err(CryptoError::BufferTooSmall);
        }
        
        let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, key_bytes).map_err(|_| CryptoError::InvalidKey)?;
        let key = LessSafeKey::new(unbound_key);
        
        let nonce_bytes = self.construct_nonce(sequence_number);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let encryption_area = &mut buffer[..payload_len];
        
        let tag = key.seal_in_place_separate_tag(nonce, Aad::from(aad_bytes), encryption_area)
            .map_err(|_| CryptoError::IntegrityCompromised)?;

        buffer[payload_len..payload_len + TAG_SIZE].copy_from_slice(tag.as_ref());

        Ok(payload_len + TAG_SIZE)
    }

    /// Расшифровывает данные внутри буфера и валидирует целостность через AAD.
    pub fn decrypt_in_place(
        &self,
        buffer: &mut [u8],
        ciphertext_len: usize,
        key_bytes: &[u8; KEY_SIZE],
        sequence_number: u64,
        aad_bytes: &[u8],
    ) -> Result<usize, CryptoError> {
        if ciphertext_len < TAG_SIZE {
            return Err(CryptoError::CiphertextTooShort);
        }
        
        let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, key_bytes).map_err(|_| CryptoError::InvalidKey)?;
        let key = LessSafeKey::new(unbound_key);
        
        let nonce_bytes = self.construct_nonce(sequence_number);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let working_area = &mut buffer[..ciphertext_len];

        let decrypted_slice = key
            .open_within(nonce, Aad::from(aad_bytes), working_area, 0..)
            .map_err(|_| CryptoError::IntegrityCompromised)?;

        Ok(decrypted_slice.len())
    }

    // =========================================================================
    // 3. АСИММЕТРИЧНАЯ ПОДПИСЬ (Ed25519)
    // =========================================================================

    pub fn sign_message(&self, private_key_pkcs8: &[u8], message: &[u8]) -> Result<[u8; SIGNATURE_SIZE], CryptoError> {
        let key_pair = Ed25519KeyPair::from_pkcs8(private_key_pkcs8).map_err(|_| CryptoError::InvalidKey)?;
        let sig = key_pair.sign(message);
        let mut sig_bytes = [0u8; SIGNATURE_SIZE];
        sig_bytes.copy_from_slice(sig.as_ref());
        Ok(sig_bytes)
    }

    pub fn verify_signature(&self, public_key_bytes: &[u8], message: &[u8], signature: &[u8; SIGNATURE_SIZE]) -> bool {
        let public_key = UnparsedPublicKey::new(&ED25519, public_key_bytes);
        public_key.verify(message, signature).is_ok()
    }
}

impl Drop for CryptoEngine {
    fn drop(&mut self) {
        self.session_salt.zeroize();
    }
}

// =========================================================================
// 4. ТЕСТЫ И БЕНЧМАРКИ
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_client_server_salt_alignment() {
        let (_server_engine, shared_salt) = CryptoEngine::new_server_side().unwrap();
        
        let server_crypto = CryptoEngine::new(shared_salt);
        let client_crypto = CryptoEngine::new(shared_salt);
        
        let key = server_crypto.generate_session_key().unwrap();
        let msg = b"HandshakeSuccess";
        let aad = b"HeaderData";
        let mut buffer = vec![0u8; msg.len() + TAG_SIZE];
        buffer[..msg.len()].copy_from_slice(msg);

        let cipher_len = client_crypto.encrypt_in_place(&mut buffer, msg.len(), &key, 1, aad).unwrap();
        let plain_len = server_crypto.decrypt_in_place(&mut buffer, cipher_len, &key, 1, aad).unwrap();
        
        assert_eq!(&buffer[..plain_len], msg);
    }

    #[test]
    fn test_replay_window_protection() {
        let mut window = ReplayWindow::new();

        // 1. Новые последовательные пакеты успешно проходят
        assert!(window.update(10).is_ok());
        assert!(window.update(15).is_ok());

        // 2. Повторные пакеты (Replay Attack) гарантированно дропаются
        assert_eq!(window.update(10), Err(CryptoError::ReplayPacketDropped));
        assert_eq!(window.update(15), Err(CryptoError::ReplayPacketDropped));

        // 3. Пакеты, улетевшие далеко в прошлое за пределы окна, отбрасываются
        assert_eq!(window.update(1), Err(CryptoError::ReplayPacketDropped));

        // 4. Задержавшийся пакет внутри скользящего окна принимается ровно один раз
        assert!(window.update(12).is_ok());
        
        // 5. Повтор этого же задержавшегося пакета теперь обязан упасть
        assert_eq!(window.update(12), Err(CryptoError::ReplayPacketDropped));
    }

    #[test]
    fn test_aad_modification_fails() {
        let crypto = CryptoEngine::new([1, 2, 3, 4]);
        let key = crypto.generate_session_key().unwrap();
        
        let msg = b"VoiceStream";
        let aad_voice = b"PacketType:Voice";
        let aad_game = b"PacketType:Game";
        
        let mut buffer = vec![0u8; msg.len() + TAG_SIZE];
        buffer[..msg.len()].copy_from_slice(msg);

        let cipher_len = crypto.encrypt_in_place(&mut buffer, msg.len(), &key, 1, aad_voice).unwrap();
        let result = crypto.decrypt_in_place(&mut buffer, cipher_len, &key, 1, aad_game);
        assert_eq!(result, Err(CryptoError::IntegrityCompromised));
    }

    #[test]
    fn test_wrong_key_fails() {
        let crypto = CryptoEngine::new([1, 2, 3, 4]);
        let key_a = crypto.generate_session_key().unwrap();
        let key_b = crypto.generate_session_key().unwrap();
        
        let msg = b"SecretData";
        let mut buffer = vec![0u8; msg.len() + TAG_SIZE];
        buffer[..msg.len()].copy_from_slice(msg);

        let cipher_len = crypto.encrypt_in_place(&mut buffer, msg.len(), &key_a, 1, &[]).unwrap();
        let result = crypto.decrypt_in_place(&mut buffer, cipher_len, &key_b, 1, &[]);
        assert_eq!(result, Err(CryptoError::IntegrityCompromised));
    }

    #[test]
    fn test_malformed_packet_no_panic() {
        let crypto = CryptoEngine::new([1, 2, 3, 4]);
        let key = crypto.generate_session_key().unwrap();

        let mut bad_buffer = vec![0u8; 32];
        let result = crypto.decrypt_in_place(&mut bad_buffer, 32, &key, 100, &[]);
        assert_eq!(result, Err(CryptoError::IntegrityCompromised));
    }

    #[test]
    fn test_ed25519_signatures() {
        let crypto = CryptoEngine::new([1, 2, 3, 4]);
        let keypair = crypto.generate_ed25519_keypair().unwrap();
        
        let key_pair_extracted = Ed25519KeyPair::from_pkcs8(&keypair).unwrap();
        let public_key_bytes = key_pair_extracted.public_key().as_ref();

        let message = b"AuthTokenValidUntil2026";
        let signature = crypto.sign_message(&keypair, message).unwrap();

        assert!(crypto.verify_signature(public_key_bytes, message, &signature));
        assert!(!crypto.verify_signature(public_key_bytes, b"AuthTokenValidUntil2027", &signature));
    }

    #[test]
    fn benchmark_production_voice_crypto() {
        let crypto = CryptoEngine::new([9, 9, 9, 9]);
        let key = crypto.generate_session_key().unwrap();
        let mut voice_buffer = [137u8; 120 + TAG_SIZE]; 
        let aad = b"CH_VOICE";
        
        let start = Instant::now();
        let total_packets = 500_000;

        for seq in 1..=total_packets {
            let _ = crypto.encrypt_in_place(&mut voice_buffer, 120, &key, seq, aad);
            let _ = crypto.decrypt_in_place(&mut voice_buffer, 120 + TAG_SIZE, &key, seq, aad);
        }

        let elapsed = start.elapsed();
        println!("\n--- WIREGUARD-GRADE SECURE BENCHMARK ---");
        println!("Обработано {} за {:?}", total_packets * 2, elapsed);
        println!("Производительность: {:.2} млн оп/сек", (total_packets * 2) as f64 / 1_000_000.0 / elapsed.as_secs_f64());
        println!("-------------------------------\n");
    }
}