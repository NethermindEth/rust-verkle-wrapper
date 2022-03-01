use verkle_db::{
    BareMetalDiskDb, BareMetalKVDb,
    BatchDB, BatchWriter, RocksDb
};
use verkle_trie::{
    Trie,
    config::Config,
    database::VerkleDb,
    committer::test::TestCommitter,
    committer::precompute::PrecomputeLagrange,
    constants::CRS

};
use crate::verkle_variants::traits::FFI;

use ark_ec::ProjectiveCurve;
use verkle_trie::database::memory_db::MemoryDb;


pub type VerkleTrieRocksDBTest = Trie<VerkleDb<RocksDb>, TestCommitter>;
impl FFI for VerkleTrieRocksDBTest {
    fn verkle_trie_new(path: &str) -> Self {
        let _db = VerkleDb::from_path(path);
        let committer = TestCommitter;
        let config = Config{ db: _db, committer };
        let mut _trie = Trie::new(config);
        _trie
    }
}

pub type VerkleTrieRocksDBPreCompute = Trie<VerkleDb<RocksDb>, PrecomputeLagrange>;
impl FFI for VerkleTrieRocksDBPreCompute {
    fn verkle_trie_new(path: &str) -> Self {
        let db = VerkleDb::from_path(path);
        let g_aff: Vec<_> = CRS.G.iter().map(|point| point.into_affine()).collect();
        let committer = PrecomputeLagrange::precompute(&g_aff);
        let config = Config { db, committer};
        let mut _trie = Trie::new(config);
        _trie
    }
}


pub type VerkleTrieMemoryTest = Trie<MemoryDb, TestCommitter>;
impl FFI for VerkleTrieMemoryTest {
    fn verkle_trie_new(_path: &str) -> Self {
        let db = MemoryDb::new();
        let committer = TestCommitter;
        let config = Config { db, committer};
        let mut _trie = Trie::new(config);
        _trie
    }
}


pub type VerkleTrieMemoryPreCompute= Trie<MemoryDb, PrecomputeLagrange>;
impl FFI for VerkleTrieMemoryPreCompute {
    fn verkle_trie_new(_path: &str) -> Self {
        let db = MemoryDb::new();
        let g_aff: Vec<_> = CRS.G.iter().map(|point| point.into_affine()).collect();
        let committer = PrecomputeLagrange::precompute(&g_aff);
        let config = Config { db, committer};
        let mut _trie = Trie::new(config);
        _trie
    }
}

