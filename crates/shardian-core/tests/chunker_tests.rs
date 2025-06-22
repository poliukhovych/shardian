use shardian_core::chunker::{Chunker};
use std::fs;

#[test]
fn test_split_file() {
    let data = b"abcdefghijklmnopqrstuvwxyz".to_vec();
    let tmp = std::env::temp_dir().join("shardian_test_split.bin");
    fs::write(&tmp, &data).unwrap();

    let chunker = Chunker::new(10);
    let chunks = chunker.split_file(&tmp).unwrap();

    assert_eq!(chunks.len(), 3);
    assert_eq!(chunks[0], data[0..10]);
    assert_eq!(chunks[1], data[10..20]);
    assert_eq!(chunks[2], data[20..26]);

    fs::remove_file(&tmp).unwrap();
}

#[test]
fn test_hash_consistency() {
    let data = b"hello";
    let hash1 = Chunker::hash(data);
    let hash2 = Chunker::hash(data);
    let hash3 = Chunker::hash(b"world");
    assert_eq!(hash1, hash2);
    assert_ne!(hash1, hash3);
}

#[test]
fn test_merkle_root_single() {
    let chunker = Chunker::new(1024);
    let chunks = vec![b"test".to_vec()];
    let root = chunker.merkle_root(&chunks);
    let expected = Chunker::hash(&chunks[0]);
    assert_eq!(root, expected);
}

#[test]
fn test_merkle_root_two() {
    let chunker = Chunker::new(1);
    let chunks = vec![b"a".to_vec(), b"b".to_vec()];
    let root = chunker.merkle_root(&chunks);

    let h0 = Chunker::hash(&chunks[0]);
    let h1 = Chunker::hash(&chunks[1]);
    let mut combined = h0.to_vec();
    combined.extend(&h1);
    let expected = Chunker::hash(&combined);

    assert_eq!(root, expected);
}

#[test]
fn test_encrypt_decrypt_chunk() {
    let key = [0u8; 32];
    let chunker = Chunker::with_key(4, &key);
    let plaintext = b"data";
    let enc = chunker.encrypt_chunk(0, plaintext).unwrap();
    let dec = chunker.decrypt_chunk(&enc).unwrap();
    assert_eq!(dec, plaintext);
}

#[test]
fn test_process_file_raw_and_encrypted() {
    let data = b"1234567890".to_vec();
    let tmp = std::env::temp_dir().join("shardian_test_process.bin");
    fs::write(&tmp, &data).unwrap();

    let chunker = Chunker::new(4);
    if let shardian_core::chunker::ProcessOutput::Raw { chunks, hashes } = chunker.process_file(&tmp).unwrap() {
        assert_eq!(chunks.len(), 3);
        assert_eq!(hashes.len(), 3);
    } else {
        panic!("Expected raw output");
    }

    let key = [1u8; 32];
    let cipher_chunker = Chunker::with_key(4, &key);
    if let shardian_core::chunker::ProcessOutput::Encrypted(enc_chunks) = cipher_chunker.process_file(&tmp).unwrap() {
        assert_eq!(enc_chunks.len(), 3);
        let dec_data: Vec<u8> = enc_chunks.iter()
            .map(|e| cipher_chunker.decrypt_chunk(e).unwrap())
            .flatten()
            .collect();
        assert_eq!(dec_data, data);
    } else {
        panic!("Expected encrypted output");
    }

    fs::remove_file(&tmp).unwrap();
}
