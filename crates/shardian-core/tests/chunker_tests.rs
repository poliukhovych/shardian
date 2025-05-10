use shardian_core::chunker::Chunker;
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
fn test_hash_chunk_consistency() {
    let hash1 = Chunker::hash_chunk(b"hello");
    let hash2 = Chunker::hash_chunk(b"hello");
    let hash3 = Chunker::hash_chunk(b"world");
    assert_eq!(hash1, hash2);
    assert_ne!(hash1, hash3);
}

#[test]
fn test_compute_merkle_root_single() {
    let chunk = b"test".to_vec();
    let chunker = Chunker::new(1024);
    let root = chunker.compute_merkle_root(&[chunk.clone()]);
    let expected = Chunker::hash_chunk(&chunk);
    assert_eq!(root, expected);
}

#[test]
fn test_compute_merkle_root_two() {
    let chunks = vec![b"a".to_vec(), b"b".to_vec()];
    let chunker = Chunker::new(1);
    let root = chunker.compute_merkle_root(&chunks);

    let h0 = Chunker::hash_chunk(&chunks[0]);
    let h1 = Chunker::hash_chunk(&chunks[1]);
    let mut combined = h0.to_vec();
    combined.extend(&h1);
    let expected = Chunker::hash_chunk(&combined);

    assert_eq!(root, expected);
}
