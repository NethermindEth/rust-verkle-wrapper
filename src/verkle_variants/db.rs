use std::mem::transmute;
use verkle_db::{BareMetalDiskDb, RocksDb};
use verkle_trie::database::VerkleDb;
use crate::{CommitScheme, FFI, trie, VerkleTrie};
use crate::memory_db::VerkleMemoryDb;
use crate::verkle_variants::traits::DB;

pub type VerkleRocksDb = VerkleDb<RocksDb>;
impl DB for VerkleRocksDb {
    fn create_db(path: &str) -> Self {
        let _db = VerkleDb::from_path(path);
        _db
    }

    // fn get_trie(&mut self, commit_scheme: CommitScheme) -> *mut VerkleTrie {
    //     let db: VerkleRocksDb = *unsafe { Box::from_raw(self) };
    //     let vt = match commit_scheme {
    //         CommitScheme::TestCommitment => {
    //             let _vt = trie::VerkleTrieRocksDBTest::create_from_db(db);
    //             VerkleTrie::RocksdbTest(_vt)
    //         },
    //         CommitScheme::PrecomputeLagrange => {
    //             let _vt = trie::VerkleTrieRocksDBPreCompute::create_from_db(db);
    //             VerkleTrie::RocksdbPrelagrange(_vt)
    //         },
    //     };
    //     let ret = unsafe { transmute (Box::new(vt))};
    //     ret
    // }
}

pub type VerkleMemDb = VerkleMemoryDb;
impl DB for VerkleMemDb {
    fn create_db(path: &str) -> Self {
        let _db = VerkleMemoryDb::new();
        _db
    }

    // fn get_trie(&mut self, commit_scheme: CommitScheme) -> *mut VerkleTrie {
    //     let db: VerkleMemDb = *unsafe { Box::from_raw(self) };
    //     let vt = match commit_scheme {
    //         CommitScheme::TestCommitment => {
    //             let _vt = trie::VerkleTrieMemoryTest::create_from_db(db);
    //             VerkleTrie::MemoryTest(_vt)
    //         },
    //         CommitScheme::PrecomputeLagrange => {
    //             let _vt = trie::VerkleTrieMemoryPreCompute::create_from_db(db);
    //             VerkleTrie::MemoryPrelagrange(_vt)
    //         },
    //     };
    //     let ret = unsafe { transmute (Box::new(vt))};
    //     ret
    // }

}

// pub type VerkleRocksReadOnlyDb = VerkleDb<RocksDb>;
// impl DB for VerkleRocksReadOnlyDb {
//     fn create_db(path: &str) -> Self {
//         let _db = VerkleDb::from_path(path);
//         _db
//     }
//
//     // fn get_trie(&mut self, commit_scheme: CommitScheme) -> *mut VerkleTrie {
//     //     let vt = match commit_scheme {
//     //         CommitScheme::TestCommitment => {
//     //             let _vt = trie::VerkleTrieRocksDBTest::create_from_db(self);
//     //             VerkleTrie::RocksdbReadOnlyTest(_vt)
//     //         },
//     //         CommitScheme::PrecomputeLagrange => {
//     //             let _vt = trie::VerkleTrieRocksDBPreCompute::create_from_db(db);
//     //             VerkleTrie::RocksdbReadOnlyPrelagrange(_vt)
//     //         },
//     //     };
//     //     let ret = unsafe { transmute (Box::new(vt))};
//     //     ret
//     // }
// }