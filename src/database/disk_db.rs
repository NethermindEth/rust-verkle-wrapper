use crate::database::key_value_ro::ReadOnlyKVDB;
use crate::database::traits::{ReadOnlyDB, DB};
use crate::database::verkle_db::VerkleTreeDb;
use verkle_db::{BareMetalDiskDb, BatchDB, BatchWriter, RocksDb};
use verkle_trie::database::generic::{GenericBatchDB, GenericBatchWriter};
use verkle_trie::database::{BranchChild, Flush, WriteOnlyHigherDb};

pub type VerkleRocksDB = GenericBatchDB<RocksDb>;
impl DB for VerkleRocksDB {
    fn create_db(path: &str) -> Self {
        let _db = GenericBatchDB::from_path(path);
        _db
    }
}

pub type VerkleReadOnlyRocksDB = GenericBatchDB<ReadOnlyKVDB<GenericBatchDB<RocksDb>>>;
impl ReadOnlyDB for VerkleReadOnlyRocksDB {
    type DbObject = VerkleRocksDB;

    fn create_from_db(db: &'static mut Self::DbObject) -> Self {
        let _db = ReadOnlyKVDB::from_db(db);
        GenericBatchDB { inner: _db }
    }

    fn clear_temp_changes(&mut self) {
        self.inner.temp.clear();
    }
}

impl<S: BatchDB> Flush for VerkleTreeDb<GenericBatchDB<S>> {
    // flush the batch to the storage
    fn flush(&mut self) {
        let writer = S::BatchWrite::new();
        let mut w = GenericBatchWriter { inner: writer };

        let now = std::time::Instant::now();

        for (key, value) in self.batch.leaf_table.iter() {
            w.insert_leaf(*key, *value, 0);
        }

        for (key, meta) in self.batch.stem_table.iter() {
            w.insert_stem(*key, *meta, 0);
        }

        for (branch_id, b_child) in self.batch.branch_table.iter() {
            let branch_id = branch_id.clone();
            match b_child {
                BranchChild::Stem(stem_id) => {
                    w.add_stem_as_branch_child(branch_id, *stem_id, 0);
                }
                BranchChild::Branch(b_meta) => {
                    w.insert_branch(branch_id, *b_meta, 0);
                }
            };
        }

        let num_items = self.batch.num_items();
        println!(
            "write to batch time: {}, item count : {}",
            now.elapsed().as_millis(),
            num_items
        );

        self.storage.flush(w.inner);

        self.batch.clear();
        self.cache.clear();
    }
}
