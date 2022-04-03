use crate::database::generics::MemDB;
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

pub struct ReadOnlyMemoryDB<Storage: 'static> {
    pub db: &'static mut Storage,
    pub temp: MemoryDb,
}

impl<S> ReadOnlyMemoryDB<S> {
    pub fn from_db(db: &'static mut S) -> Self {
        ReadOnlyMemoryDB {
            db,
            temp: MemoryDb::new(),
        }
    }
}

impl<S: MemDB> ReadOnlyMemoryDB<S> {
    pub fn new() -> Self {
        let db: &mut S = unsafe { transmute(Box::new(S::new())) };
        ReadOnlyMemoryDB {
            db,
            temp: MemoryDb::new(),
        }
    }

    pub fn clear(&mut self) {
        self.temp.clear();
    }
}

impl<S: ReadOnlyHigherDb> ReadOnlyHigherDb for ReadOnlyMemoryDB<S> {
    fn get_stem_meta(&self, stem_key: [u8; 31]) -> Option<StemMeta> {
        if let Some(val) = self.temp.get_stem_meta(stem_key) {
            return Some(val);
        }
        self.db.get_stem_meta(stem_key)
    }

    fn get_branch_meta(&self, key: &[u8]) -> Option<BranchMeta> {
        if let Some(val) = self.temp.get_branch_meta(key) {
            return Some(val);
        }
        // Now try the disk
        self.db.get_branch_meta(key)
    }

    fn get_leaf(&self, key: [u8; 32]) -> Option<[u8; 32]> {
        if let Some(val) = self.temp.get_leaf(key) {
            return Some(val);
        }
        // Now try the disk
        self.db.get_leaf(key)
    }

    fn get_branch_children(&self, branch_id: &[u8]) -> Vec<(u8, BranchChild)> {
        let mut children: HashMap<_, _> = self
            .db
            .get_branch_children(branch_id)
            .into_iter()
            .map(|(index, val)| (index, val))
            .collect();
        //
        // Then get the children from the batch
        let children_from_batch = self.temp.get_branch_children(branch_id);
        //
        // Now insert the children from batch into the storage children as they will be fresher
        // overwriting if they have the same indices
        for (index, val) in children_from_batch {
            children.insert(index, val);
        }
        children
            .into_iter()
            .map(|(index, val)| (index, val))
            .collect()
    }

    fn get_stem_children(&self, stem_key: [u8; 31]) -> Vec<(u8, [u8; 32])> {
        // It's possible that they are in disk storage and that batch storage has some recent updates
        // First get the children from storage
        let mut children: HashMap<_, _> = self
            .db
            .get_stem_children(stem_key)
            .into_iter()
            .map(|(index, val)| (index, val))
            .collect();
        //
        // Then get the children from the batch
        let children_from_batch = self.temp.get_stem_children(stem_key);
        //
        // Now insert the children from batch into the storage children as they will be fresher
        // overwriting if they have the same indices
        for (index, val) in children_from_batch {
            children.insert(index, val);
        }
        children
            .into_iter()
            .map(|(index, val)| (index, val))
            .collect()
    }

    fn get_branch_child(&self, branch_id: &[u8], index: u8) -> Option<BranchChild> {
        if let Some(val) = self.temp.get_branch_child(branch_id, index) {
            return Some(val);
        }
        // Now try the disk
        self.db.get_branch_child(branch_id, index)
    }
}

impl<S> WriteOnlyHigherDb for ReadOnlyMemoryDB<S> {
    fn insert_leaf(&mut self, key: [u8; 32], value: [u8; 32], depth: u8) -> Option<Vec<u8>> {
        self.temp.insert_leaf(key, value, depth)
    }

    fn insert_stem(&mut self, key: [u8; 31], meta: StemMeta, depth: u8) -> Option<StemMeta> {
        self.temp.insert_stem(key, meta, depth)
    }

    fn add_stem_as_branch_child(
        &mut self,
        branch_child_id: Vec<u8>,
        stem_id: [u8; 31],
        depth: u8,
    ) -> Option<BranchChild> {
        self.temp
            .add_stem_as_branch_child(branch_child_id, stem_id, depth)
    }

    fn insert_branch(&mut self, key: Vec<u8>, meta: BranchMeta, depth: u8) -> Option<BranchMeta> {
        self.temp.insert_branch(key, meta, depth)
    }
}

impl<S> Flush for ReadOnlyMemoryDB<S> {
    fn flush(&mut self) {
        // No-op since this database is in memory
        // The flush trait is for databases which have a
        // memory database and a disk storage, flush signals them to flush the
        // memory to database to disk
        //
        // This is implemented for the MemoryDb so that we can use it for
        // tests in the Trie
    }
}
