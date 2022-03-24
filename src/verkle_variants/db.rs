use std::mem::transmute;
use verkle_db::{BareMetalDiskDb, RocksDb};
use verkle_trie::database::memory_db::MemoryDb;
use verkle_trie::database::{BranchChild, BranchMeta, Flush, ReadOnlyHigherDb, StemMeta, WriteOnlyHigherDb};
use verkle_trie::database::VerkleDb;
use crate::{CommitScheme, FFI, trie, VerkleTrie};
use crate::memory_db::VerkleMemoryDb;
use crate::verkle_variants::traits::DB;

use verkle_trie::{
    database::generic::GenericBatchDB
};

pub type VerkleRocksDb = GenericBatchDB<RocksDb>;
impl DB for VerkleRocksDb {
    fn create_db(path: &str) -> Self {
        let _db = GenericBatchDB::from_path(path);
        _db
    }
}

pub type VerkleMemDb = MemoryDb;
impl DB for VerkleMemDb {
    fn create_db(path: &str) -> Self {
        let _db = MemoryDb::new();
        _db
    }
}
