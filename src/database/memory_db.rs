use crate::database::generics::{GenericMemoryDb, MemDB};
use crate::database::memory_ro::ReadOnlyMemoryDB;
use crate::database::traits::{ReadOnlyDB, DB};
use crate::database::verkle_db::VerkleTreeDb;
use verkle_trie::database::memory_db::MemoryDb;
use verkle_trie::database::{BranchChild, Flush, ReadOnlyHigherDb, WriteOnlyHigherDb};

impl MemDB for MemoryDb {
    fn new() -> Self {
        MemoryDb::new()
    }

    fn clear(&mut self) {
        self.clear()
    }
}

pub type VerkleMemoryDB = GenericMemoryDb<MemoryDb>;
impl DB for VerkleMemoryDB {
    fn create_db(path: &str) -> Self {
        let _db = VerkleMemoryDB::new();
        _db
    }
}

pub type VerkleReadOnlyMemoryDB = GenericMemoryDb<ReadOnlyMemoryDB<GenericMemoryDb<MemoryDb>>>;
impl ReadOnlyDB for VerkleReadOnlyMemoryDB {
    type DbObject = VerkleMemoryDB;

    fn create_from_db(db: &'static mut Self::DbObject) -> Self {
        let _db = ReadOnlyMemoryDB::from_db(db);
        GenericMemoryDb { inner: _db }
    }

    fn clear_temp_changes(&mut self) {
        self.inner.temp.clear();
    }
}

impl<T: ReadOnlyHigherDb + WriteOnlyHigherDb> Flush for VerkleTreeDb<GenericMemoryDb<T>> {
    fn flush(&mut self) {
        let now = std::time::Instant::now();

        for (key, value) in self.batch.leaf_table.iter() {
            self.storage.insert_leaf(*key, *value, 0);
        }

        for (key, meta) in self.batch.stem_table.iter() {
            self.storage.insert_stem(*key, *meta, 0);
        }

        for (branch_id, b_child) in self.batch.branch_table.iter() {
            let branch_id = branch_id.clone();
            match b_child {
                BranchChild::Stem(stem_id) => {
                    self.storage
                        .add_stem_as_branch_child(branch_id, *stem_id, 0);
                }
                BranchChild::Branch(b_meta) => {
                    self.storage.insert_branch(branch_id, *b_meta, 0);
                }
            };
        }

        let num_items = self.batch.num_items();
        println!(
            "write to batch time: {}, item count : {}",
            now.elapsed().as_millis(),
            num_items
        );

        self.batch.clear();
    }
}
