use std::collections::HashMap;
use std::convert::TryFrom;
use std::mem::transmute;
use std::slice;
use verkle_db::RocksDb;
use verkle_db::{BareMetalDiskDb, BareMetalKVDb, BatchDB, BatchWriter};
use verkle_trie::database::generic::GenericBatchDB;
use verkle_trie::database::generic::GenericBatchWriter;
use verkle_trie::database::memory_db::MemoryDb;
use verkle_trie::database::{
    BranchChild, BranchMeta, Flush, ReadOnlyHigherDb, StemMeta, WriteOnlyHigherDb,
};

pub struct ReadOnlyKVDB<Storage: 'static> {
    // The underlying key value database
    // We will not be updating this
    pub db: &'static mut Storage,
    // This stores the key-value pairs that we need to insert into the storage
    pub temp: HashMap<[u8; 32], [u8; 32]>,
}

impl<S: BareMetalDiskDb> ReadOnlyKVDB<S> {
    pub fn from_db(db: &'static mut S) -> Self {
        ReadOnlyKVDB {
            db,
            temp: HashMap::new(),
        }
    }
}

impl<S: BareMetalDiskDb> BareMetalDiskDb for ReadOnlyKVDB<S> {
    fn from_path<P: AsRef<std::path::Path>>(path: P) -> Self {
        let _db = S::from_path(path);
        let db: &mut S = unsafe { transmute(Box::new(_db)) };
        ReadOnlyKVDB {
            db,
            temp: HashMap::new(),
        }
    }

    const DEFAULT_PATH: &'static str = S::DEFAULT_PATH;
}

impl<S: BareMetalKVDb + BareMetalDiskDb> BareMetalKVDb for ReadOnlyKVDB<S> {
    fn fetch(&self, key: &[u8]) -> Option<Vec<u8>> {
        if let Some(val) = self.temp.get(key) {
            return Some(val.to_vec());
        }
        self.db.fetch(key)
    }
    // Create a database given the default path
    fn new() -> Self {
        Self::from_path(Self::DEFAULT_PATH)
    }
}

pub struct MemoryBatchDB {
    pub(crate) inner: HashMap<[u8; 32], [u8; 32]>,
}

impl MemoryBatchDB {
    pub fn new() -> Self {
        MemoryBatchDB {
            inner: HashMap::new(),
        }
    }
}

impl BatchWriter for MemoryBatchDB {
    fn new() -> Self {
        MemoryBatchDB::new()
    }

    fn batch_put(&mut self, key: &[u8], val: &[u8]) {
        self.inner.insert(
            <[u8; 32]>::try_from(key).unwrap(),
            <[u8; 32]>::try_from(val).unwrap(),
        );
    }
}

impl<S: BatchDB> BatchDB for ReadOnlyKVDB<S> {
    type BatchWrite = MemoryBatchDB;

    fn flush(&mut self, batch: Self::BatchWrite) {
        self.temp.extend(batch.inner.into_iter());
    }
}
