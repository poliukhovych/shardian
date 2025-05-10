use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use sha2::{Sha256, Digest};

/// Splits files into fixed-size chunks and computes Merkle roots.
pub struct Chunker {
    /// Size of each chunk in bytes
    pub chunk_size: usize,
}

impl Chunker {
    pub fn new(chunk_size: usize) -> Self {
        Self { chunk_size }
    }

    pub fn split_file<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<Vec<Vec<u8>>, std::io::Error> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        let mut chunks = Vec::new();

        loop {
            let mut buffer = vec![0u8; self.chunk_size];
            let n = reader.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            buffer.truncate(n);
            chunks.push(buffer);
        }

        Ok(chunks)
    }

    /// Compute the SHA-256 hash of a single chunk.
    pub fn hash_chunk(chunk: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(chunk);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Compute the Merkle root from a list of chunk hashes.
    pub fn compute_merkle_root(&self, chunks: &[Vec<u8>]) -> [u8; 32] {
        let mut hashes: Vec<[u8; 32]> = chunks
            .iter()
            .map(|c| Self::hash_chunk(c))
            .collect();

        if hashes.is_empty() {
            return [0u8; 32];
        }

        while hashes.len() > 1 {
            let mut next = Vec::with_capacity((hashes.len() + 1) / 2);
            for pair in hashes.chunks(2) {
                let mut combined = Vec::with_capacity(pair.len() * 32 * 2);
                combined.extend_from_slice(&pair[0]);
                if pair.len() == 2 {
                    combined.extend_from_slice(&pair[1]);
                } else {
                    combined.extend_from_slice(&pair[0]);
                }

                let parent = Self::hash_chunk(&combined);
                next.push(parent);
            }
            hashes = next;
        }

        hashes[0]
    }
}
