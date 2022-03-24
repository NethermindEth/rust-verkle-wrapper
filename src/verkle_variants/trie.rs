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
use crate::verkle_variants::traits::{DB, FFI};

use ark_ec::ProjectiveCurve;
use verkle_trie::database::memory_db::MemoryDb;
use crate::memory_db::VerkleMemoryDb;
use crate::{Database, Proof};
use crate::verkle_variants::db::{VerkleMemDb, VerkleRocksDb};


pub type VerkleTrieRocksDBTest = Trie<VerkleRocksDb, TestCommitter>;

impl FFI for VerkleTrieRocksDBTest {

    type DbObject = VerkleRocksDb;

    fn verkle_trie_new(path: &str) -> Self {
        let db = VerkleRocksDb::create_db(path);
        let committer = TestCommitter;
        let config = Config{ db, committer };
        let mut _trie = Trie::new(config);
        _trie
    }

    fn create_from_db(db: VerkleRocksDb) -> Self {
        let committer = TestCommitter;
        let config = Config{ db, committer };
        let mut _trie = Trie::new(config);
        _trie
    }
}

pub type VerkleTrieRocksDBPreCompute = Trie<VerkleRocksDb, PrecomputeLagrange>;
impl FFI for VerkleTrieRocksDBPreCompute {

    type DbObject = VerkleRocksDb;

    fn verkle_trie_new(path: &str) -> Self {
        let db = VerkleRocksDb::create_db(path);
        let g_aff: Vec<_> = CRS.G.iter().map(|point| point.into_affine()).collect();
        let committer = PrecomputeLagrange::precompute(&g_aff);
        let config = Config { db, committer};
        let mut _trie = Trie::new(config);
        _trie
    }

    fn create_from_db(db: VerkleRocksDb)-> Self {
        let g_aff: Vec<_> = CRS.G.iter().map(|point| point.into_affine()).collect();
        let committer = PrecomputeLagrange::precompute(&g_aff);
        let config = Config { db, committer};
        let mut _trie = Trie::new(config);
        _trie
    }
}


pub type VerkleTrieMemoryTest = Trie<VerkleMemDb, TestCommitter>;
impl FFI for VerkleTrieMemoryTest {

    type DbObject = VerkleMemDb;

    fn verkle_trie_new(_path: &str) -> Self {
        let db = VerkleMemDb::create_db("");
        let committer = TestCommitter;
        let config = Config { db, committer};
        let mut _trie = Trie::new(config);
        _trie
    }

    fn create_from_db(db: VerkleMemDb) -> Self {
        let committer = TestCommitter;
        let config = Config { db, committer};
        let mut _trie = Trie::new(config);
        _trie
    }
}


pub type VerkleTrieMemoryPreCompute= Trie<VerkleMemDb, PrecomputeLagrange>;
impl FFI for VerkleTrieMemoryPreCompute {

    type DbObject = VerkleMemDb;

    fn verkle_trie_new(_path: &str) -> Self {
        let db = VerkleMemDb::create_db("");
        let g_aff: Vec<_> = CRS.G.iter().map(|point| point.into_affine()).collect();
        let committer = PrecomputeLagrange::precompute(&g_aff);
        let config = Config { db, committer};
        let mut _trie = Trie::new(config);
        _trie
    }

    fn create_from_db(db: VerkleMemDb) -> Self {
        let g_aff: Vec<_> = CRS.G.iter().map(|point| point.into_affine()).collect();
        let committer = PrecomputeLagrange::precompute(&g_aff);
        let config = Config { db, committer};
        let mut _trie = Trie::new(config);
        _trie
    }
}

