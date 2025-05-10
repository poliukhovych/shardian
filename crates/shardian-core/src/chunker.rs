use std::fs::File;
use std::io::{BufReader, Read, Error as IoError};
use std::path::Path;
use sha2::{Sha256, Digest};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use rand_core::RngCore;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ChunkerError {
    #[error("I/O error: {0}")]
    Io(#[from] IoError),
    #[error("Cryptography error: {0}")]
    Crypto(String),
}

pub type Result<T> = std::result::Result<T, ChunkerError>;

pub struct EncryptedChunk {
    pub index: u64,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

pub struct Chunker {
    pub chunk_size: usize,
    cipher: Option<Aes256Gcm>,
}

impl Chunker {
    pub fn new(chunk_size: usize) -> Self {
        Self { chunk_size, cipher: None }
    }

    pub fn with_key(chunk_size: usize, key_bytes: &[u8; 32]) -> Self {
        let key = Key::<Aes256Gcm>::from_slice(key_bytes);
        let cipher = Aes256Gcm::new(key);
        Self { chunk_size, cipher: Some(cipher) }
    }

    pub fn split_file<P: AsRef<Path>>(&self, path: P) -> Result<Vec<Vec<u8>>> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        let mut chunks = Vec::new();
        loop {
            let mut buf = vec![0; self.chunk_size];
            let n = reader.read(&mut buf)?;
            if n == 0 { break; }
            buf.truncate(n);
            chunks.push(buf);
        }
        Ok(chunks)
    }

    pub fn hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    pub fn merkle_root(&self, chunks: &[Vec<u8>]) -> [u8; 32] {
        let mut hashes: Vec<[u8; 32]> = chunks.iter().map(|c| Self::hash(c)).collect();
        if hashes.is_empty() { return [0; 32]; }
        while hashes.len() > 1 {
            hashes = hashes.chunks(2)
                .map(|pair| {
                    let mut data = Vec::with_capacity(pair.len() * 32);
                    data.extend_from_slice(&pair[0]);
                    if pair.len() == 2 { data.extend_from_slice(&pair[1]); } else { data.extend_from_slice(&pair[0]); }
                    Self::hash(&data)
                })
                .collect();
        }
        hashes[0]
    }

    pub fn encrypt_chunk(&self, index: u64, chunk: &[u8]) -> Result<EncryptedChunk> {
        let cipher = self.cipher.as_ref().ok_or_else(|| ChunkerError::Crypto("No cipher configured".into()))?;
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), chunk)
            .map_err(|e| ChunkerError::Crypto(e.to_string()))?;
        Ok(EncryptedChunk { index, nonce, ciphertext })
    }

    pub fn decrypt_chunk(&self, enc: &EncryptedChunk) -> Result<Vec<u8>> {
        let cipher = self.cipher.as_ref().ok_or_else(|| ChunkerError::Crypto("No cipher configured".into()))?;
        let plaintext = cipher.decrypt(Nonce::from_slice(&enc.nonce), enc.ciphertext.as_ref())
            .map_err(|e| ChunkerError::Crypto(e.to_string()))?;
        Ok(plaintext)
    }

    pub fn process_file<P: AsRef<Path>>(&self, path: P) -> Result<ProcessOutput> {
        let raw = self.split_file(&path)?;
        if self.cipher.is_some() {
            let mut enc = Vec::with_capacity(raw.len());
            for (i, chunk) in raw.iter().enumerate() {
                enc.push(self.encrypt_chunk(i as u64, chunk)?);
            }
            Ok(ProcessOutput::Encrypted(enc))
        } else {
            let mut hashes = Vec::with_capacity(raw.len());
            for chunk in raw.iter() {
                hashes.push(Self::hash(chunk));
            }
            Ok(ProcessOutput::Raw { chunks: raw, hashes })
        }
    }
}

pub enum ProcessOutput {
    Raw {
        chunks: Vec<Vec<u8>>,
        hashes: Vec<[u8; 32]>,
    },
    Encrypted(Vec<EncryptedChunk>),
}
