use crate::verkle_variants::traits::FFI;
use verkle_db::{BareMetalDiskDb, BareMetalKVDb, BatchDB, BatchWriter, RocksDb};
use verkle_trie::{
    committer::precompute::PrecomputeLagrange, committer::test::TestCommitter, config::Config,
    constants::CRS, database::VerkleDb, Key, Trie, TrieTrait, Value,
};

use crate::database::disk_db::{VerkleReadOnlyRocksDB, VerkleRocksDB};
use crate::database::generics::GenericMemoryDb;
use crate::database::memory_db::{VerkleMemoryDB, VerkleReadOnlyMemoryDB};
use crate::database::verkle_db::VerkleTreeDb;
use crate::verkle_variants::precompute::LagrangeCommitter;
use crate::{Database, Proof};
use ark_ec::ProjectiveCurve;
use bandersnatch::{EdwardsProjective, Fr};
use verkle_trie::database::generic::GenericBatchDB;
use verkle_trie::database::memory_db::MemoryDb;
use verkle_trie::proof::VerkleProof;

pub type VerkleTrieRocksDBTest = Trie<VerkleTreeDb<VerkleRocksDB>, TestCommitter>;
impl FFI for VerkleTrieRocksDBTest {
    type DbObject = VerkleRocksDB;

    fn verkle_trie_new(path: &str) -> Self {
        let db = VerkleTreeDb::from_path(path);
        let committer = TestCommitter;
        let config = Config { db, committer };
        let mut _trie = Trie::new(config);
        _trie
    }

    fn create_from_db(db: &'static mut VerkleRocksDB) -> Self {
        let _db = VerkleTreeDb::from_db(db);
        let committer = TestCommitter;
        let config = Config { db: _db, committer };
        let mut _trie = Trie::new(config);
        _trie
    }
}

pub type VerkleTrieReadOnlyRocksDBTest = Trie<VerkleTreeDb<VerkleReadOnlyRocksDB>, TestCommitter>;
impl FFI for VerkleTrieReadOnlyRocksDBTest {
    type DbObject = VerkleReadOnlyRocksDB;

    fn verkle_trie_new(path: &str) -> Self {
        todo!()
    }

    fn create_from_db(db: &'static mut VerkleReadOnlyRocksDB) -> Self {
        let _db = VerkleTreeDb::from_db(db);
        let committer = TestCommitter;
        let config = Config { db: _db, committer };
        let mut _trie = Trie::new(config);
        _trie
    }
}

pub type VerkleTrieRocksDBLagrange = Trie<VerkleTreeDb<VerkleRocksDB>, LagrangeCommitter>;
impl FFI for VerkleTrieRocksDBLagrange {
    type DbObject = VerkleRocksDB;

    fn verkle_trie_new(path: &str) -> Self {
        let db = VerkleTreeDb::from_path(path);
        let committer = LagrangeCommitter::default();
        let config = Config { db, committer };
        let mut _trie = Trie::new(config);
        _trie
    }

    fn create_from_db(db: &'static mut VerkleRocksDB) -> Self {
        let _db = VerkleTreeDb::from_db(db);
        let committer = LagrangeCommitter::default();
        let config = Config { db: _db, committer };
        let mut _trie = Trie::new(config);
        _trie
    }
}

pub type VerkleTrieReadOnlyRocksDBLagrange =
    Trie<VerkleTreeDb<VerkleReadOnlyRocksDB>, LagrangeCommitter>;
impl FFI for VerkleTrieReadOnlyRocksDBLagrange {
    type DbObject = VerkleReadOnlyRocksDB;

    fn verkle_trie_new(path: &str) -> Self {
        todo!()
    }

    fn create_from_db(db: &'static mut VerkleReadOnlyRocksDB) -> Self {
        let _db = VerkleTreeDb::from_db(db);
        let committer = LagrangeCommitter::default();
        let config = Config { db: _db, committer };
        let mut _trie = Trie::new(config);
        _trie
    }
}

pub type VerkleTrieMemoryTest = Trie<VerkleTreeDb<VerkleMemoryDB>, TestCommitter>;
impl FFI for VerkleTrieMemoryTest {
    type DbObject = VerkleMemoryDB;

    fn verkle_trie_new(_path: &str) -> Self {
        let db = VerkleTreeDb::new();
        let committer = TestCommitter;
        let config = Config { db, committer };
        let mut _trie = Trie::new(config);
        _trie
    }

    fn create_from_db(db: &'static mut VerkleMemoryDB) -> Self {
        let _db = VerkleTreeDb::from_db(db);
        let committer = TestCommitter;
        let config = Config { db: _db, committer };
        let mut _trie = Trie::new(config);
        _trie
    }
}

pub type VerkleTrieReadOnlyMemoryTest = Trie<VerkleTreeDb<VerkleReadOnlyMemoryDB>, TestCommitter>;
impl FFI for VerkleTrieReadOnlyMemoryTest {
    type DbObject = VerkleReadOnlyMemoryDB;

    fn verkle_trie_new(_path: &str) -> Self {
        todo!()
    }

    fn create_from_db(db: &'static mut VerkleReadOnlyMemoryDB) -> Self {
        let _db = VerkleTreeDb::from_db(db);
        let committer = TestCommitter;
        let config = Config { db: _db, committer };
        let mut _trie = Trie::new(config);
        _trie
    }
}

pub type VerkleTrieMemoryLagrange = Trie<VerkleTreeDb<VerkleMemoryDB>, LagrangeCommitter>;
impl FFI for VerkleTrieMemoryLagrange {
    type DbObject = VerkleMemoryDB;

    fn verkle_trie_new(_path: &str) -> Self {
        let db = VerkleTreeDb::new();
        let committer = LagrangeCommitter::default();
        let config = Config { db, committer };
        let mut _trie = Trie::new(config);
        _trie
    }

    fn create_from_db(db: &'static mut VerkleMemoryDB) -> Self {
        let _db = VerkleTreeDb::from_db(db);
        let committer = LagrangeCommitter::default();
        let config = Config { db: _db, committer };
        let mut _trie = Trie::new(config);
        _trie
    }
}

pub type VerkleTrieReadOnlyMemoryLagrange =
    Trie<VerkleTreeDb<VerkleReadOnlyMemoryDB>, LagrangeCommitter>;
impl FFI for VerkleTrieReadOnlyMemoryLagrange {
    type DbObject = VerkleReadOnlyMemoryDB;

    fn verkle_trie_new(_path: &str) -> Self {
        todo!()
    }

    fn create_from_db(db: &'static mut VerkleReadOnlyMemoryDB) -> Self {
        let _db = VerkleTreeDb::from_db(db);
        let committer = LagrangeCommitter::default();
        let config = Config { db: _db, committer };
        let mut _trie = Trie::new(config);
        _trie
    }
}
