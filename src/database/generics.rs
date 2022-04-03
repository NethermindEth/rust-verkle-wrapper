use std::collections::HashMap;
use std::convert::TryInto;
use std::mem::transmute;
use verkle_db::RocksDb;
use verkle_db::{BareMetalDiskDb, BareMetalKVDb, BatchDB, BatchWriter};
use verkle_trie::database::generic::GenericBatchDB;
use verkle_trie::database::generic::GenericBatchWriter;
use verkle_trie::database::memory_db::MemoryDb;
use verkle_trie::database::{
    BranchChild, BranchMeta, Flush, ReadOnlyHigherDb, StemMeta, WriteOnlyHigherDb,
};

pub trait MemDB {
    fn new() -> Self;
    fn clear(&mut self);
}

pub struct GenericMemoryDb<T> {
    pub inner: T,
}

impl<T: MemDB> MemDB for GenericMemoryDb<T> {
    fn new() -> Self {
        Self { inner: T::new() }
    }

    fn clear(&mut self) {
        self.inner.clear();
    }
}

impl<T: ReadOnlyHigherDb> ReadOnlyHigherDb for GenericMemoryDb<T> {
    fn get_stem_meta(&self, stem_key: [u8; 31]) -> Option<StemMeta> {
        self.inner.get_stem_meta(stem_key)
    }

    fn get_branch_meta(&self, key: &[u8]) -> Option<BranchMeta> {
        self.inner.get_branch_meta(key)
    }

    fn get_leaf(&self, key: [u8; 32]) -> Option<[u8; 32]> {
        self.inner.get_leaf(key)
    }

    fn get_branch_children(&self, branch_id: &[u8]) -> Vec<(u8, BranchChild)> {
        self.inner.get_branch_children(branch_id)
    }

    fn get_stem_children(&self, stem_key: [u8; 31]) -> Vec<(u8, [u8; 32])> {
        self.inner.get_stem_children(stem_key)
    }

    fn get_branch_child(&self, branch_id: &[u8], index: u8) -> Option<BranchChild> {
        self.inner.get_branch_child(branch_id, index)
    }
}

impl<T: WriteOnlyHigherDb> WriteOnlyHigherDb for GenericMemoryDb<T> {
    fn insert_stem(&mut self, key: [u8; 31], meta: StemMeta, _depth: u8) -> Option<StemMeta> {
        self.inner.insert_stem(key, meta, _depth)
    }

    fn insert_branch(&mut self, key: Vec<u8>, meta: BranchMeta, _depth: u8) -> Option<BranchMeta> {
        self.inner.insert_branch(key, meta, _depth)
    }

    fn insert_leaf(&mut self, key: [u8; 32], value: [u8; 32], _depth: u8) -> Option<Vec<u8>> {
        self.inner.insert_leaf(key, value, _depth)
    }

    fn add_stem_as_branch_child(
        &mut self,
        branch_child_id: Vec<u8>,
        stem_id: [u8; 31],
        _depth: u8,
    ) -> Option<BranchChild> {
        self.inner
            .add_stem_as_branch_child(branch_child_id, stem_id, _depth)
    }
}
