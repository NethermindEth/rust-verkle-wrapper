#![feature(vec_into_raw_parts)]
mod verkle_variants;
mod memory_db;
mod disk_db;

use std::slice;
use std::mem::transmute;
use std::convert::TryInto;
use verkle_variants::{
    trie,
    traits::FFI,
    db,
};
use std::ffi::CStr;
use std::ops::Deref;
use std::os::raw::c_char;
use verkle_trie::database::Flush;
use crate::Database::{VerkleDiskDb, VerkleReadOnlyDiskDb};
use crate::Database::VerkleMemoryDb;
use crate::db::VerkleMemDb;
use crate::verkle_variants::traits::DB;

#[repr(C)]
pub enum VerkleTrie {
    MemoryTest(trie::VerkleTrieMemoryTest),
    MemoryPrelagrange(trie::VerkleTrieMemoryPreCompute),
    RocksdbTest(trie::VerkleTrieRocksDBTest),
    RocksdbPrelagrange(trie::VerkleTrieRocksDBPreCompute),
    RocksdbReadOnlyTest(trie::VerkleTrieRocksDBTest),
    RocksdbReadOnlyPrelagrange(trie::VerkleTrieRocksDBPreCompute),
}

#[repr(C)]
pub enum Database {
    VerkleDiskDb(db::VerkleRocksDb),
    VerkleReadOnlyDiskDb(db::VerkleRocksDb),
    VerkleMemoryDb(db::VerkleMemDb)
}

#[repr(C)]
pub struct Proof {
    pub ptr: *const u8,
    pub len: usize,
}

#[repr(C)]
pub enum DatabaseScheme {
    MemoryDb,
    RocksDb,
    RocksDbReadOnly,
}

#[repr(C)]
pub enum CommitScheme {
    TestCommitment,
    PrecomputeLagrange,
}

#[no_mangle]
pub extern fn create_verkle_db(
    database_scheme: DatabaseScheme,
    db_path: *const c_char
) -> *mut Database {

    let db_path = unsafe {
        CStr::from_ptr(db_path)
            .to_str().expect("Invalid pathname")
    };

    let db = match database_scheme {
        DatabaseScheme::RocksDb => {
            let _db = db::VerkleRocksDb::create_db(db_path);
            VerkleDiskDb(_db)
        },
        DatabaseScheme::MemoryDb =>  {
            let _db = db::VerkleMemDb::create_db(db_path);
            VerkleMemoryDb(_db)
        },
        DatabaseScheme::RocksDbReadOnly => {
            let _db = db::VerkleRocksDb::create_db(db_path);
            VerkleReadOnlyDiskDb(_db)
        }
    };
    let ret = unsafe { transmute (Box::new(db))};
    ret
}


#[no_mangle]
pub extern fn verkle_trie_new(
    database_scheme: DatabaseScheme,
    commit_scheme: CommitScheme,
    db_path: *const c_char
) -> *mut VerkleTrie {

    let db_path = unsafe {
        CStr::from_ptr(db_path)
        .to_str().expect("Invalid pathname")
    };

    let vt = match database_scheme {
        DatabaseScheme::MemoryDb => match commit_scheme {
            CommitScheme::TestCommitment => {
                let _vt = trie::VerkleTrieMemoryTest::verkle_trie_new(db_path);
                VerkleTrie::MemoryTest(_vt)
            },
            CommitScheme::PrecomputeLagrange => {
                let _vt = trie::VerkleTrieMemoryPreCompute::verkle_trie_new(db_path);
                VerkleTrie::MemoryPrelagrange(_vt)
            },
        },
        DatabaseScheme::RocksDb => match commit_scheme {
            CommitScheme::TestCommitment => {
                let _vt = trie::VerkleTrieRocksDBTest::verkle_trie_new(db_path);
                VerkleTrie::RocksdbTest(_vt)
            },
            CommitScheme::PrecomputeLagrange => {
                let _vt = trie::VerkleTrieRocksDBPreCompute::verkle_trie_new(db_path);
                VerkleTrie::RocksdbPrelagrange(_vt)
            }
        },
        DatabaseScheme::RocksDbReadOnly => match commit_scheme {
            CommitScheme::TestCommitment => {
                let _vt = trie::VerkleTrieRocksDBTest::verkle_trie_new(db_path);
                VerkleTrie::RocksdbReadOnlyTest(_vt)
            },
            CommitScheme::PrecomputeLagrange => {
                let _vt = trie::VerkleTrieRocksDBPreCompute::verkle_trie_new(db_path);
                VerkleTrie::RocksdbReadOnlyPrelagrange(_vt)
            }
        }
    };
    let ret = unsafe { transmute (Box::new(vt))};
    ret
}

#[no_mangle]
pub extern fn verkle_trie_get(vt: *mut VerkleTrie, key: *const u8) -> *const u8 {
    let _vt = unsafe{&mut *vt};
    match _vt {
        VerkleTrie::MemoryTest(vt) => vt.verkle_trie_get(key),
        VerkleTrie::MemoryPrelagrange(vt) => vt.verkle_trie_get(key),
        VerkleTrie::RocksdbTest(vt) => vt.verkle_trie_get(key),
        VerkleTrie::RocksdbPrelagrange(vt) => vt.verkle_trie_get(key),
        VerkleTrie::RocksdbReadOnlyTest(vt) => vt.verkle_trie_get(key),
        VerkleTrie::RocksdbReadOnlyPrelagrange(vt) => vt.verkle_trie_get(key),
    }
}

#[no_mangle]
pub extern fn verkle_trie_flush(vt: *mut VerkleTrie) {
    let _vt = unsafe{&mut *vt};
    match _vt {
        VerkleTrie::MemoryTest(vt) => vt.storage.flush(),
        VerkleTrie::MemoryPrelagrange(vt) => vt.storage.flush(),
        VerkleTrie::RocksdbTest(vt) => vt.storage.flush(),
        VerkleTrie::RocksdbPrelagrange(vt) => vt.storage.flush(),
        VerkleTrie::RocksdbReadOnlyTest(_vt) => (),
        VerkleTrie::RocksdbReadOnlyPrelagrange(_vt) => (),
    }
}


#[no_mangle]
pub extern fn create_trie_from_db(commit_scheme: CommitScheme, db: *mut Database) -> *mut VerkleTrie {
    let _db = unsafe{&mut *db};
    let vt = match _db {
        Database::VerkleDiskDb(db) => match commit_scheme {
            CommitScheme::TestCommitment => {
                let _vt = trie::VerkleTrieRocksDBTest::create_from_db( db);
                VerkleTrie::RocksdbTest(_vt)
            },
            CommitScheme::PrecomputeLagrange => {
                let _vt = trie::VerkleTrieRocksDBPreCompute::create_from_db( db);
                VerkleTrie::RocksdbPrelagrange(_vt)
            },
        },
        Database::VerkleMemoryDb(db) => match commit_scheme {
            CommitScheme::TestCommitment => {
                let _vt = trie::VerkleTrieMemoryTest::create_from_db(db);
                VerkleTrie::MemoryTest(_vt)
            },
            CommitScheme::PrecomputeLagrange => {
                let _vt = trie::VerkleTrieMemoryPreCompute::create_from_db(db);
                VerkleTrie::MemoryPrelagrange(_vt)
            },
        },
        Database::VerkleReadOnlyDiskDb(db) => match commit_scheme {
            CommitScheme::TestCommitment => {
                let _vt = trie::VerkleTrieRocksDBTest::create_from_db(db);
                VerkleTrie::RocksdbReadOnlyTest(_vt)
            },
            CommitScheme::PrecomputeLagrange => {
                let _vt = trie::VerkleTrieRocksDBPreCompute::create_from_db(db);
                VerkleTrie::RocksdbReadOnlyPrelagrange(_vt)
            },
        }
    };

    let ret = unsafe { transmute (Box::new(vt))};
    ret
}


#[no_mangle]
pub extern fn verkle_trie_clear(vt: *mut VerkleTrie) {
    let _vt = unsafe{&mut *vt};
    match _vt {
        VerkleTrie::MemoryTest(vt) => {
            vt.storage.batch.clear();
            vt.storage.cache.clear()
        },
        VerkleTrie::MemoryPrelagrange(vt) => {
            vt.storage.batch.clear();
            vt.storage.cache.clear()
        },
        VerkleTrie::RocksdbTest(vt) => {
            vt.storage.batch.clear();
            vt.storage.cache.clear()
        },
        VerkleTrie::RocksdbPrelagrange(vt) => {
            vt.storage.batch.clear();
            vt.storage.cache.clear()
        },
        VerkleTrie::RocksdbReadOnlyTest(vt) => {
            vt.storage.batch.clear();
            vt.storage.cache.clear()
        },
        VerkleTrie::RocksdbReadOnlyPrelagrange(vt) => {
            vt.storage.batch.clear();
            vt.storage.cache.clear()
        },
    }
}

#[no_mangle]
pub extern fn verkle_trie_insert(vt: *mut VerkleTrie, key: *const u8, value: *const u8) {
    let _vt = unsafe{&mut *vt};
    match _vt {
        VerkleTrie::MemoryTest(vt) => vt.verkle_trie_insert(key, value),
        VerkleTrie::MemoryPrelagrange(vt) => vt.verkle_trie_insert(key, value),
        VerkleTrie::RocksdbTest(vt) => vt.verkle_trie_insert(key, value),
        VerkleTrie::RocksdbPrelagrange(vt) => vt.verkle_trie_insert(key, value),
        VerkleTrie::RocksdbReadOnlyTest(vt) => vt.verkle_trie_insert(key, value),
        VerkleTrie::RocksdbReadOnlyPrelagrange(vt) => vt.verkle_trie_insert(key, value),
    }
}

#[no_mangle]
pub extern fn get_root_hash(vt: *mut VerkleTrie) -> *const u8 {
    let _vt = unsafe{&mut *vt};
    match _vt {
        VerkleTrie::MemoryTest(vt) => vt.get_root_hash(),
        VerkleTrie::MemoryPrelagrange(vt) => vt.get_root_hash(),
        VerkleTrie::RocksdbTest(vt) => vt.get_root_hash(),
        VerkleTrie::RocksdbPrelagrange(vt) => vt.get_root_hash(),
        VerkleTrie::RocksdbReadOnlyTest(vt) => vt.get_root_hash(),
        VerkleTrie::RocksdbReadOnlyPrelagrange(vt) => vt.get_root_hash(),
    }
}

#[no_mangle]
pub extern fn get_verkle_proof(vt: *mut VerkleTrie, key: *const u8) -> *mut Proof {
    let _vt = unsafe{&mut *vt};
    match _vt {
        VerkleTrie::MemoryTest(vt) => vt.get_verkle_proof(key),
        VerkleTrie::MemoryPrelagrange(vt) => vt.get_verkle_proof(key),
        VerkleTrie::RocksdbTest(vt) => vt.get_verkle_proof(key),
        VerkleTrie::RocksdbPrelagrange(vt) => vt.get_verkle_proof(key),
        VerkleTrie::RocksdbReadOnlyTest(vt) => vt.get_verkle_proof(key),
        VerkleTrie::RocksdbReadOnlyPrelagrange(vt) => vt.get_verkle_proof(key),
    }
}

#[no_mangle]
pub extern fn verify_verkle_proof(vt: *mut VerkleTrie, ptr: *const u8, proof_len: usize, key: *const u8, value: *const u8) -> u8 {
    let _vt = unsafe{&mut *vt};
    match _vt {
        VerkleTrie::MemoryTest(vt) => vt.verify_verkle_proof(ptr, proof_len, key, value),
        VerkleTrie::MemoryPrelagrange(vt) => vt.verify_verkle_proof(ptr, proof_len, key, value),
        VerkleTrie::RocksdbTest(vt) => vt.verify_verkle_proof(ptr, proof_len, key, value),
        VerkleTrie::RocksdbPrelagrange(vt) => vt.verify_verkle_proof(ptr, proof_len, key, value),
        VerkleTrie::RocksdbReadOnlyTest(vt) => vt.verify_verkle_proof(ptr, proof_len, key, value),
        VerkleTrie::RocksdbReadOnlyPrelagrange(vt) => vt.verify_verkle_proof(ptr, proof_len, key, value),
    }
}

#[no_mangle]
pub extern fn get_verkle_proof_multiple(vt: *mut VerkleTrie, keys: *const [u8;32], len: usize) -> *mut Proof{
    let _vt = unsafe{&mut *vt};
    match _vt {
        VerkleTrie::MemoryTest(vt) => vt.get_verkle_proof_multiple(keys, len),
        VerkleTrie::MemoryPrelagrange(vt) => vt.get_verkle_proof_multiple(keys, len),
        VerkleTrie::RocksdbTest(vt) => vt.get_verkle_proof_multiple(keys, len),
        VerkleTrie::RocksdbPrelagrange(vt) => vt.get_verkle_proof_multiple(keys, len),
        VerkleTrie::RocksdbReadOnlyTest(vt) => vt.get_verkle_proof_multiple(keys, len),
        VerkleTrie::RocksdbReadOnlyPrelagrange(vt) => vt.get_verkle_proof_multiple(keys, len),
    }
}

#[no_mangle]
pub extern fn verify_verkle_proof_multiple(vt: *mut VerkleTrie, ptr: *const u8, proof_len: usize, keys: *const [u8;32], vals: *const [u8;32], len: usize) -> u8 {
    let _vt = unsafe{&mut *vt};
    match _vt {
        VerkleTrie::MemoryTest(vt) => vt.verify_verkle_proof_multiple(ptr, proof_len, keys, vals, len),
        VerkleTrie::MemoryPrelagrange(vt) => vt.verify_verkle_proof_multiple(ptr, proof_len, keys, vals, len),
        VerkleTrie::RocksdbTest(vt) => vt.verify_verkle_proof_multiple(ptr, proof_len, keys, vals, len),
        VerkleTrie::RocksdbPrelagrange(vt) => vt.verify_verkle_proof_multiple(ptr, proof_len, keys, vals, len),
        VerkleTrie::RocksdbReadOnlyTest(vt) => vt.verify_verkle_proof_multiple(ptr, proof_len, keys, vals, len),
        VerkleTrie::RocksdbReadOnlyPrelagrange(vt) => vt.verify_verkle_proof_multiple(ptr, proof_len, keys, vals, len),
    }
}

#[no_mangle]
pub extern fn verkle_trie_insert_multiple(vt: *mut VerkleTrie, keys: *const [u8;32], vals: *const [u8;32], len: usize){
    let _vt = unsafe{&mut *vt};
    match _vt {
        VerkleTrie::MemoryTest(vt) => vt.verkle_trie_insert_multiple(keys, vals, len),
        VerkleTrie::MemoryPrelagrange(vt) => vt.verkle_trie_insert_multiple(keys, vals, len),
        VerkleTrie::RocksdbTest(vt) => vt.verkle_trie_insert_multiple(keys, vals, len),
        VerkleTrie::RocksdbPrelagrange(vt) => vt.verkle_trie_insert_multiple(keys, vals, len),
        VerkleTrie::RocksdbReadOnlyTest(vt) => vt.verkle_trie_insert_multiple(keys, vals, len),
        VerkleTrie::RocksdbReadOnlyPrelagrange(vt) => vt.verkle_trie_insert_multiple(keys, vals, len),
    }
}

pub fn get_array_from_slice_argument(sl: *const u8) -> [u8; 32] {
    let _raw_slice = unsafe {
        assert!(!sl.is_null());
        slice::from_raw_parts(sl, 32)
    };
    _raw_slice.try_into().expect("slice with incorrect length")
}

pub fn get_vector_from_slice_argument(ptr: *const [u8;32], len: usize) -> Vec<[u8;32]>{
    assert!(!ptr.is_null());
    let _raw_slice = unsafe { slice::from_raw_parts(ptr, len)};
    let mut raw_slice = vec![_raw_slice[0]];
    for i in 1..= len - 1{
        raw_slice.push(_raw_slice[i]);
    }
    raw_slice
}

pub fn proof_ptr_to_proof_vec(ptr: *const u8, len:usize) -> Vec<u8>{
    assert!(!ptr.is_null());
    let _raw_slice = unsafe { slice::from_raw_parts(ptr, len)};
    // println!("{:?}",_raw_slice);
    let mut raw_slice = vec![_raw_slice[0]];
    for i in 1..= len - 1{
        raw_slice.push(_raw_slice[i]);
    }
    raw_slice
}
