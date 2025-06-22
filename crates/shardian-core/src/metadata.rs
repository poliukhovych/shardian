use serde::{Serialize, Deserialize};
use std::{path::Path, fs};
use crate::chunker::{Chunker, EncryptedChunk, Result as ChunkerResult};
use hex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkMetadata {
    pub index: u64,
    pub hash: [u8; 32],
    pub size: usize,
    pub nonce: Option<[u8; 12]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileManifest {
    pub file_id: String,
    pub file_name: String,
    pub file_size: u64,
    pub chunk_size: usize,
    pub merkle_root: [u8; 32],
    pub chunks: Vec<ChunkMetadata>,
}

impl FileManifest {
    pub fn new(
        file_name: String,
        file_size: u64,
        chunk_size: usize,
        merkle_root: [u8; 32],
        chunks: Vec<ChunkMetadata>,
    ) -> Self {
        let file_id = hex::encode(merkle_root);
        Self { file_id, file_name, file_size, chunk_size, merkle_root, chunks }
    }

    pub fn from_file<P: AsRef<Path>>(path: P, chunk_size: usize) -> ChunkerResult<Self> {
        let path_ref = path.as_ref();
        let file_name = path_ref.file_name()
            .map(|os| os.to_string_lossy().to_string())
            .unwrap_or_default();
        let file_size = fs::metadata(path_ref)?.len();
        let chunker = Chunker::new(chunk_size);
        let raw_chunks = chunker.split_file(path_ref)?;
        let merkle_root = chunker.merkle_root(&raw_chunks);
        let chunks = raw_chunks.into_iter().enumerate().map(|(i, c)| {
            let hash = Chunker::hash(&c);
            ChunkMetadata { index: i as u64, hash, size: c.len(), nonce: None }
        }).collect();
        Ok(FileManifest::new(file_name, file_size, chunk_size, merkle_root, chunks))
    }

    pub fn from_encrypted<P: AsRef<Path>>(path: P, chunk_size: usize, encrypted_chunks: Vec<EncryptedChunk>) -> ChunkerResult<Self> {
        let path_ref = path.as_ref();
        let file_name = path_ref.file_name()
            .map(|os| os.to_string_lossy().to_string())
            .unwrap_or_default();
        let file_size = fs::metadata(path_ref)?.len();
        let chunker = Chunker::new(chunk_size);
        let ciphertexts: Vec<Vec<u8>> = encrypted_chunks.iter().map(|e| e.ciphertext.clone()).collect();
        let merkle_root = chunker.merkle_root(&ciphertexts);
        let chunks = encrypted_chunks.into_iter().map(|e| {
            let hash = Chunker::hash(&e.ciphertext);
            ChunkMetadata { index: e.index, hash, size: e.ciphertext.len(), nonce: Some(e.nonce) }
        }).collect();
        Ok(FileManifest::new(file_name, file_size, chunk_size, merkle_root, chunks))
    }
}
