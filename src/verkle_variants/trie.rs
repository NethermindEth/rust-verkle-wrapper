use crate::verkle_variants::traits::{DB, FFI};
use verkle_db::{BareMetalDiskDb, BareMetalKVDb, BatchDB, BatchWriter, RocksDb};
use verkle_trie::{
    committer::precompute::PrecomputeLagrange, committer::test::TestCommitter, config::Config,
    constants::CRS, database::VerkleDb, Trie,
};

use crate::disk_db::VerkleDiskDb;
use crate::memory_db::VerkleMemoryDb;
use crate::verkle_variants::db::{VerkleMemDb, VerkleRocksDb};
use crate::{Database, Proof};
use ark_ec::ProjectiveCurve;
use verkle_trie::database::memory_db::MemoryDb;

pub type VerkleTrieRocksDBTest = Trie<VerkleDiskDb<RocksDb>, TestCommitter>;

impl FFI for VerkleTrieRocksDBTest {
    type DbObject = VerkleRocksDb;

    fn verkle_trie_new(path: &str) -> Self {
        let db = VerkleDiskDb::from_path(path);
        let committer = TestCommitter;
        let config = Config { db, committer };
        let mut _trie = Trie::new(config);
        _trie
    }

    fn create_from_db(db: &'static mut VerkleRocksDb) -> Self {
        let _db = VerkleDiskDb::new(db);
        let committer = TestCommitter;
        let config = Config { db: _db, committer };
        let mut _trie = Trie::new(config);
        _trie
    }
}

pub type VerkleTrieRocksDBPreCompute = Trie<VerkleDiskDb<RocksDb>, PrecomputeLagrange>;
impl FFI for VerkleTrieRocksDBPreCompute {
    type DbObject = VerkleRocksDb;

    fn verkle_trie_new(path: &str) -> Self {
        let db = VerkleDiskDb::from_path(path);
        let committer = PrecomputeLagrange::precompute(&CRS.G);
        let config = Config { db, committer };
        let mut _trie = Trie::new(config);
        _trie
    }

    fn create_from_db(db: &'static mut VerkleRocksDb) -> Self {
        let _db = VerkleDiskDb::new(db);
        let committer = PrecomputeLagrange::precompute(&CRS.G);
        let config = Config { db: _db, committer };
        let mut _trie = Trie::new(config);
        _trie
    }
}

pub type VerkleTrieMemoryTest = Trie<VerkleMemoryDb, TestCommitter>;
impl FFI for VerkleTrieMemoryTest {
    type DbObject = VerkleMemDb;

    fn verkle_trie_new(_path: &str) -> Self {
        let db = VerkleMemoryDb::new_db();
        let committer = TestCommitter;
        let config = Config { db, committer };
        let mut _trie = Trie::new(config);
        _trie
    }

    fn create_from_db(db: &'static mut VerkleMemDb) -> Self {
        let _db = VerkleMemoryDb::new(db);
        let committer = TestCommitter;
        let config = Config { db: _db, committer };
        let mut _trie = Trie::new(config);
        _trie
    }
}

pub type VerkleTrieMemoryPreCompute = Trie<VerkleMemoryDb, PrecomputeLagrange>;
impl FFI for VerkleTrieMemoryPreCompute {
    type DbObject = VerkleMemDb;

    fn verkle_trie_new(_path: &str) -> Self {
        let db = VerkleMemoryDb::new_db();
        let committer = PrecomputeLagrange::precompute(&CRS.G);
        let config = Config { db, committer };
        let mut _trie = Trie::new(config);
        _trie
    }

    fn create_from_db(db: &'static mut VerkleMemDb) -> Self {
        let _db = VerkleMemoryDb::new(db);
        let committer = PrecomputeLagrange::precompute(&CRS.G);
        let config = Config { db: _db, committer };
        let mut _trie = Trie::new(config);
        _trie
    }
}
