#![feature(vec_into_raw_parts)]
#![feature(core_panic)]
extern crate core;

mod database;
mod verkle_variants;
pub mod utils;

use crate::database::traits::{ReadOnlyDB, DB};
use crate::Database::VerkleMemoryDb;
use crate::Database::{VerkleDiskDb, VerkleReadOnlyDiskDb};
use std::convert::TryInto;
use std::ffi::CStr;
use std::mem::transmute;
use std::ops::Deref;
use std::os::raw::c_char;
use std::slice;
use verkle_spec::Hasher;
use verkle_trie::database::Flush;
use verkle_variants::{traits::FFI, trie};
use crate::utils::PedersenHasher;

#[repr(C)]
pub enum VerkleTrie {
    MemoryTest(trie::VerkleTrieMemoryTest),
    MemoryLagrange(trie::VerkleTrieMemoryLagrange),
    MemoryReadOnlyTest(trie::VerkleTrieReadOnlyMemoryTest),
    MemoryReadonlyLagrange(trie::VerkleTrieReadOnlyMemoryLagrange),
    RocksdbTest(trie::VerkleTrieRocksDBTest),
    RocksdbLagrange(trie::VerkleTrieRocksDBLagrange),
    RocksdbReadOnlyTest(trie::VerkleTrieReadOnlyRocksDBTest),
    RocksdbReadOnlyLagrange(trie::VerkleTrieReadOnlyRocksDBLagrange),
}

#[repr(C)]
pub enum Database {
    VerkleDiskDb(database::disk_db::VerkleRocksDB),
    VerkleReadOnlyDiskDb(database::disk_db::VerkleReadOnlyRocksDB),
    VerkleMemoryDb(database::memory_db::VerkleMemoryDB),
    VerkleReadOnlyMemoryDb(database::memory_db::VerkleReadOnlyMemoryDB),
}

#[repr(C)]
pub struct Proof {
    pub ptr: *const u8,
    pub len: usize,
}

#[repr(C)]
#[derive(Clone)]
pub enum DatabaseScheme {
    MemoryDb,
    RocksDb,
    MemoryDbReadOnly,
    RocksDbReadOnly,
}

#[repr(C)]
pub enum CommitScheme {
    TestCommitment,
    PrecomputeLagrange,
}

#[no_mangle]
pub extern "C" fn create_verkle_db(
    database_scheme: DatabaseScheme,
    db_path: *const c_char,
) -> *mut Database {
    let db_path = unsafe { CStr::from_ptr(db_path).to_str().expect("Invalid pathname") };

    let db = match database_scheme {
        DatabaseScheme::RocksDb => {
            let _db = database::disk_db::VerkleRocksDB::create_db(db_path);
            Some(VerkleDiskDb(_db))
        }
        DatabaseScheme::MemoryDb => {
            let _db = database::memory_db::VerkleMemoryDB::create_db(db_path);
            Some(VerkleMemoryDb(_db))
        }
        DatabaseScheme::RocksDbReadOnly => {
            let _db = database::disk_db::VerkleReadOnlyRocksDB::create_db(db_path);
            Some(VerkleMemoryDb(_db))
        }
        _ => None,
    };
    let ret = unsafe { transmute(Box::new(db.unwrap())) };
    ret
}

#[no_mangle]
pub extern "C" fn create_read_only_verkle_db(db: *mut Database) -> *mut Database {
    let _db = unsafe { &mut *db };
    let db_object = match _db {
        Database::VerkleDiskDb(db) => {
            let db = Database::VerkleReadOnlyDiskDb(
                database::disk_db::VerkleReadOnlyRocksDB::create_from_db(db),
            );
            unsafe { transmute(Box::new(db)) }
        }
        Database::VerkleMemoryDb(db) => {
            let db = Database::VerkleReadOnlyMemoryDb(
                database::memory_db::VerkleReadOnlyMemoryDB::create_from_db(db),
            );
            unsafe { transmute(Box::new(db)) }
        }
        _ => _db,
    };

    db_object
}

#[no_mangle]
pub extern "C" fn clear_temp_changes_read_only_db(db: *mut Database) {
    let _db = unsafe { &mut *db };

    match _db {
        Database::VerkleReadOnlyDiskDb(db) => db.clear_temp_changes(),
        Database::VerkleReadOnlyMemoryDb(db) => db.clear_temp_changes(),
        _ => (),
    };
}

#[no_mangle]
pub extern "C" fn verkle_trie_new(
    database_scheme: DatabaseScheme,
    commit_scheme: CommitScheme,
    db_path: *const c_char,
) -> *mut VerkleTrie {
    let db_path = unsafe { CStr::from_ptr(db_path).to_str().expect("Invalid pathname") };

    let vt = match database_scheme {
        DatabaseScheme::MemoryDb => match commit_scheme {
            CommitScheme::TestCommitment => {
                let _vt = trie::VerkleTrieMemoryTest::verkle_trie_new(db_path);
                Some(VerkleTrie::MemoryTest(_vt))
            }
            CommitScheme::PrecomputeLagrange => {
                let _vt = trie::VerkleTrieMemoryLagrange::verkle_trie_new(db_path);
                Some(VerkleTrie::MemoryLagrange(_vt))
            }
        },
        DatabaseScheme::RocksDb => match commit_scheme {
            CommitScheme::TestCommitment => {
                let _vt = trie::VerkleTrieRocksDBTest::verkle_trie_new(db_path);
                Some(VerkleTrie::RocksdbTest(_vt))
            }
            CommitScheme::PrecomputeLagrange => {
                let _vt = trie::VerkleTrieRocksDBLagrange::verkle_trie_new(db_path);
                Some(VerkleTrie::RocksdbLagrange(_vt))
            }
        },
        // DatabaseScheme::RocksDbReadOnly => match commit_scheme {
        //     CommitScheme::TestCommitment => {
        //         let _vt = trie::VerkleTrieRocksDBTest::verkle_trie_new(db_path);
        //         VerkleTrie::RocksdbReadOnlyTest(_vt)
        //     }
        //     CommitScheme::PrecomputeLagrange => {
        //         let _vt = trie::VerkleTrieRocksDBLagrange::verkle_trie_new(db_path);
        //         VerkleTrie::RocksdbReadOnlyLagrange(_vt)
        //     }
        // },
        _ => None,
    };
    let ret = unsafe { transmute(Box::new(vt.unwrap())) };
    ret
}

#[no_mangle]
pub extern "C" fn verkle_trie_get(vt: *mut VerkleTrie, key: *const u8) -> *const u8 {
    let _vt = unsafe { &mut *vt };
    match _vt {
        VerkleTrie::MemoryTest(vt) => vt.verkle_trie_get(key),
        VerkleTrie::MemoryLagrange(vt) => vt.verkle_trie_get(key),
        VerkleTrie::MemoryReadOnlyTest(vt) => vt.verkle_trie_get(key),
        VerkleTrie::MemoryReadonlyLagrange(vt) => vt.verkle_trie_get(key),
        VerkleTrie::RocksdbTest(vt) => vt.verkle_trie_get(key),
        VerkleTrie::RocksdbLagrange(vt) => vt.verkle_trie_get(key),
        VerkleTrie::RocksdbReadOnlyTest(vt) => vt.verkle_trie_get(key),
        VerkleTrie::RocksdbReadOnlyLagrange(vt) => vt.verkle_trie_get(key),
    }
}

#[no_mangle]
pub extern "C" fn verkle_trie_flush(vt: *mut VerkleTrie) {
    let _vt = unsafe { &mut *vt };
    match _vt {
        VerkleTrie::MemoryTest(vt) => vt.storage.flush(),
        VerkleTrie::MemoryLagrange(vt) => vt.storage.flush(),
        VerkleTrie::MemoryReadOnlyTest(vt) => vt.storage.flush(),
        VerkleTrie::MemoryReadonlyLagrange(vt) => vt.storage.flush(),
        VerkleTrie::RocksdbTest(vt) => vt.storage.flush(),
        VerkleTrie::RocksdbLagrange(vt) => vt.storage.flush(),
        VerkleTrie::RocksdbReadOnlyTest(vt) => vt.storage.flush(),
        VerkleTrie::RocksdbReadOnlyLagrange(vt) => vt.storage.flush(),
    }
}

#[no_mangle]
pub extern "C" fn create_trie_from_db(
    commit_scheme: CommitScheme,
    db: *mut Database,
) -> *mut VerkleTrie {
    let _db = unsafe { &mut *db };
    let vt = match _db {
        Database::VerkleDiskDb(db) => match commit_scheme {
            CommitScheme::TestCommitment => {
                let _vt = trie::VerkleTrieRocksDBTest::create_from_db(db);
                Some(VerkleTrie::RocksdbTest(_vt))
            }
            CommitScheme::PrecomputeLagrange => {
                let _vt = trie::VerkleTrieRocksDBLagrange::create_from_db(db);
                Some(VerkleTrie::RocksdbLagrange(_vt))
            }
        },
        Database::VerkleMemoryDb(db) => match commit_scheme {
            CommitScheme::TestCommitment => {
                let _vt = trie::VerkleTrieMemoryTest::create_from_db(db);
                Some(VerkleTrie::MemoryTest(_vt))
            }
            CommitScheme::PrecomputeLagrange => {
                let _vt = trie::VerkleTrieMemoryLagrange::create_from_db(db);
                Some(VerkleTrie::MemoryLagrange(_vt))
            }
        },
        Database::VerkleReadOnlyDiskDb(db) => match commit_scheme {
            CommitScheme::TestCommitment => {
                let _vt = trie::VerkleTrieReadOnlyRocksDBTest::create_from_db(db);
                Some(VerkleTrie::RocksdbReadOnlyTest(_vt))
            }
            CommitScheme::PrecomputeLagrange => {
                let _vt = trie::VerkleTrieReadOnlyRocksDBLagrange::create_from_db(db);
                Some(VerkleTrie::RocksdbReadOnlyLagrange(_vt))
            }
        },
        Database::VerkleReadOnlyMemoryDb(db) => match commit_scheme {
            CommitScheme::TestCommitment => {
                let _vt = trie::VerkleTrieReadOnlyMemoryTest::create_from_db(db);
                Some(VerkleTrie::MemoryReadOnlyTest(_vt))
            }
            CommitScheme::PrecomputeLagrange => {
                let _vt = trie::VerkleTrieReadOnlyMemoryLagrange::create_from_db(db);
                Some(VerkleTrie::MemoryReadonlyLagrange(_vt))
            }
        },
    };

    let ret = unsafe { transmute(Box::new(vt.unwrap())) };
    ret
}

#[no_mangle]
pub extern "C" fn verkle_trie_clear(vt: *mut VerkleTrie) {
    let _vt = unsafe { &mut *vt };
    match _vt {
        VerkleTrie::MemoryTest(vt) => {
            vt.storage.batch.clear();
            vt.storage.cache.clear()
        }
        VerkleTrie::MemoryLagrange(vt) => {
            vt.storage.batch.clear();
            vt.storage.cache.clear()
        }
        VerkleTrie::MemoryReadOnlyTest(vt) => {
            vt.storage.batch.clear();
            vt.storage.cache.clear()
        }
        VerkleTrie::MemoryReadonlyLagrange(vt) => {
            vt.storage.batch.clear();
            vt.storage.cache.clear()
        }
        VerkleTrie::RocksdbTest(vt) => {
            vt.storage.batch.clear();
            vt.storage.cache.clear()
        }
        VerkleTrie::RocksdbLagrange(vt) => {
            vt.storage.batch.clear();
            vt.storage.cache.clear()
        }
        VerkleTrie::RocksdbReadOnlyTest(vt) => {
            vt.storage.batch.clear();
            vt.storage.cache.clear()
        }
        VerkleTrie::RocksdbReadOnlyLagrange(vt) => {
            vt.storage.batch.clear();
            vt.storage.cache.clear()
        }
    }
}

#[no_mangle]
pub extern "C" fn calculate_pedersan_hash(value: *const u8) -> *const u8 {
    let _raw_slice = unsafe {
        assert!(!value.is_null());
        slice::from_raw_parts(value, 64)
    };
    let _value: &[u8;64] = _raw_slice.try_into().expect("slice with incorrect length");
    let _hash = PedersenHasher::hash64(*_value);

    let _result = unsafe { transmute(Box::new(_hash.0)) };
    _result
}

#[no_mangle]
pub extern "C" fn verkle_trie_insert(vt: *mut VerkleTrie, key: *const u8, value: *const u8) {
    let _vt = unsafe { &mut *vt };
    match _vt {
        VerkleTrie::MemoryTest(vt) => vt.verkle_trie_insert(key, value),
        VerkleTrie::MemoryLagrange(vt) => vt.verkle_trie_insert(key, value),
        VerkleTrie::MemoryReadOnlyTest(vt) => vt.verkle_trie_insert(key, value),
        VerkleTrie::MemoryReadonlyLagrange(vt) => vt.verkle_trie_insert(key, value),
        VerkleTrie::RocksdbTest(vt) => vt.verkle_trie_insert(key, value),
        VerkleTrie::RocksdbLagrange(vt) => vt.verkle_trie_insert(key, value),
        VerkleTrie::RocksdbReadOnlyTest(vt) => vt.verkle_trie_insert(key, value),
        VerkleTrie::RocksdbReadOnlyLagrange(vt) => vt.verkle_trie_insert(key, value),
    }
}

#[no_mangle]
pub extern "C" fn get_root_hash(vt: *mut VerkleTrie) -> *const u8 {
    let _vt = unsafe { &mut *vt };
    match _vt {
        VerkleTrie::MemoryTest(vt) => vt.get_root_hash(),
        VerkleTrie::MemoryLagrange(vt) => vt.get_root_hash(),
        VerkleTrie::MemoryReadOnlyTest(vt) => vt.get_root_hash(),
        VerkleTrie::MemoryReadonlyLagrange(vt) => vt.get_root_hash(),
        VerkleTrie::RocksdbTest(vt) => vt.get_root_hash(),
        VerkleTrie::RocksdbLagrange(vt) => vt.get_root_hash(),
        VerkleTrie::RocksdbReadOnlyTest(vt) => vt.get_root_hash(),
        VerkleTrie::RocksdbReadOnlyLagrange(vt) => vt.get_root_hash(),
    }
}

#[no_mangle]
pub extern "C" fn get_verkle_proof(vt: *mut VerkleTrie, key: *const u8) -> *mut Proof {
    let _vt = unsafe { &mut *vt };
    match _vt {
        VerkleTrie::MemoryTest(vt) => vt.get_verkle_proof(key),
        VerkleTrie::MemoryLagrange(vt) => vt.get_verkle_proof(key),
        VerkleTrie::MemoryReadOnlyTest(vt) => vt.get_verkle_proof(key),
        VerkleTrie::MemoryReadonlyLagrange(vt) => vt.get_verkle_proof(key),
        VerkleTrie::RocksdbTest(vt) => vt.get_verkle_proof(key),
        VerkleTrie::RocksdbLagrange(vt) => vt.get_verkle_proof(key),
        VerkleTrie::RocksdbReadOnlyTest(vt) => vt.get_verkle_proof(key),
        VerkleTrie::RocksdbReadOnlyLagrange(vt) => vt.get_verkle_proof(key),
    }
}

#[no_mangle]
pub extern "C" fn verify_verkle_proof(
    vt: *mut VerkleTrie,
    ptr: *const u8,
    proof_len: usize,
    key: *const u8,
    value: *const u8,
) -> u8 {
    let _vt = unsafe { &mut *vt };
    match _vt {
        VerkleTrie::MemoryTest(vt) => vt.verify_verkle_proof(ptr, proof_len, key, value),
        VerkleTrie::MemoryLagrange(vt) => vt.verify_verkle_proof(ptr, proof_len, key, value),
        VerkleTrie::MemoryReadOnlyTest(vt) => vt.verify_verkle_proof(ptr, proof_len, key, value),
        VerkleTrie::MemoryReadonlyLagrange(vt) => {
            vt.verify_verkle_proof(ptr, proof_len, key, value)
        }
        VerkleTrie::RocksdbTest(vt) => vt.verify_verkle_proof(ptr, proof_len, key, value),
        VerkleTrie::RocksdbLagrange(vt) => vt.verify_verkle_proof(ptr, proof_len, key, value),
        VerkleTrie::RocksdbReadOnlyTest(vt) => vt.verify_verkle_proof(ptr, proof_len, key, value),
        VerkleTrie::RocksdbReadOnlyLagrange(vt) => {
            vt.verify_verkle_proof(ptr, proof_len, key, value)
        }
    }
}

#[no_mangle]
pub extern "C" fn get_verkle_proof_multiple(
    vt: *mut VerkleTrie,
    keys: *const [u8; 32],
    len: usize,
) -> *mut Proof {
    let _vt = unsafe { &mut *vt };
    match _vt {
        VerkleTrie::MemoryTest(vt) => vt.get_verkle_proof_multiple(keys, len),
        VerkleTrie::MemoryLagrange(vt) => vt.get_verkle_proof_multiple(keys, len),
        VerkleTrie::MemoryReadOnlyTest(vt) => vt.get_verkle_proof_multiple(keys, len),
        VerkleTrie::MemoryReadonlyLagrange(vt) => vt.get_verkle_proof_multiple(keys, len),
        VerkleTrie::RocksdbTest(vt) => vt.get_verkle_proof_multiple(keys, len),
        VerkleTrie::RocksdbLagrange(vt) => vt.get_verkle_proof_multiple(keys, len),
        VerkleTrie::RocksdbReadOnlyTest(vt) => vt.get_verkle_proof_multiple(keys, len),
        VerkleTrie::RocksdbReadOnlyLagrange(vt) => vt.get_verkle_proof_multiple(keys, len),
    }
}

#[no_mangle]
pub extern "C" fn verify_verkle_proof_multiple(
    vt: *mut VerkleTrie,
    ptr: *const u8,
    proof_len: usize,
    keys: *const [u8; 32],
    vals: *const [u8; 32],
    len: usize,
) -> u8 {
    let _vt = unsafe { &mut *vt };
    match _vt {
        VerkleTrie::MemoryTest(vt) => {
            vt.verify_verkle_proof_multiple(ptr, proof_len, keys, vals, len)
        }
        VerkleTrie::MemoryLagrange(vt) => {
            vt.verify_verkle_proof_multiple(ptr, proof_len, keys, vals, len)
        }
        VerkleTrie::MemoryReadOnlyTest(vt) => {
            vt.verify_verkle_proof_multiple(ptr, proof_len, keys, vals, len)
        }
        VerkleTrie::MemoryReadonlyLagrange(vt) => {
            vt.verify_verkle_proof_multiple(ptr, proof_len, keys, vals, len)
        }
        VerkleTrie::RocksdbTest(vt) => {
            vt.verify_verkle_proof_multiple(ptr, proof_len, keys, vals, len)
        }
        VerkleTrie::RocksdbLagrange(vt) => {
            vt.verify_verkle_proof_multiple(ptr, proof_len, keys, vals, len)
        }
        VerkleTrie::RocksdbReadOnlyTest(vt) => {
            vt.verify_verkle_proof_multiple(ptr, proof_len, keys, vals, len)
        }
        VerkleTrie::RocksdbReadOnlyLagrange(vt) => {
            vt.verify_verkle_proof_multiple(ptr, proof_len, keys, vals, len)
        }
    }
}

#[no_mangle]
pub extern "C" fn verkle_trie_insert_multiple(
    vt: *mut VerkleTrie,
    keys: *const [u8; 32],
    vals: *const [u8; 32],
    len: usize,
) {
    let _vt = unsafe { &mut *vt };
    match _vt {
        VerkleTrie::MemoryTest(vt) => vt.verkle_trie_insert_multiple(keys, vals, len),
        VerkleTrie::MemoryLagrange(vt) => vt.verkle_trie_insert_multiple(keys, vals, len),
        VerkleTrie::MemoryReadOnlyTest(vt) => vt.verkle_trie_insert_multiple(keys, vals, len),
        VerkleTrie::MemoryReadonlyLagrange(vt) => vt.verkle_trie_insert_multiple(keys, vals, len),
        VerkleTrie::RocksdbTest(vt) => vt.verkle_trie_insert_multiple(keys, vals, len),
        VerkleTrie::RocksdbLagrange(vt) => vt.verkle_trie_insert_multiple(keys, vals, len),
        VerkleTrie::RocksdbReadOnlyTest(vt) => vt.verkle_trie_insert_multiple(keys, vals, len),
        VerkleTrie::RocksdbReadOnlyLagrange(vt) => vt.verkle_trie_insert_multiple(keys, vals, len),
    }
}

pub fn get_array_from_slice_argument(sl: *const u8) -> [u8; 32] {
    let _raw_slice = unsafe {
        assert!(!sl.is_null());
        slice::from_raw_parts(sl, 32)
    };
    _raw_slice.try_into().expect("slice with incorrect length")
}

pub fn get_vector_from_slice_argument(ptr: *const [u8; 32], len: usize) -> Vec<[u8; 32]> {
    assert!(!ptr.is_null());
    let _raw_slice = unsafe { slice::from_raw_parts(ptr, len) };
    let mut raw_slice = vec![_raw_slice[0]];
    for i in 1..=len - 1 {
        raw_slice.push(_raw_slice[i]);
    }
    raw_slice
}

pub fn proof_ptr_to_proof_vec(ptr: *const u8, len: usize) -> Vec<u8> {
    assert!(!ptr.is_null());
    let _raw_slice = unsafe { slice::from_raw_parts(ptr, len) };
    // println!("{:?}",_raw_slice);
    let mut raw_slice = vec![_raw_slice[0]];
    for i in 1..=len - 1 {
        raw_slice.push(_raw_slice[i]);
    }
    raw_slice
}


#[cfg(test)]
mod test {
    use std::convert::TryInto;
    use std::mem::transmute;
    use hex::FromHex;
    use verkle_spec::{Address32, H256, Hasher, Header};
    use crate::{calculate_pedersan_hash, get_array_from_slice_argument};

    // input and outputs for these tests were taken from https://github.com/gballet/verkle-block-sample
    #[test]
    fn hash_test_wrapper_function() {
        let tests = [
            (
                <[u8;64]>::from_hex("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").expect("Decoding failed"),
                <[u8;32]>::from_hex("695921dca3b16c5cc850e94cdd63f573c467669e89cec88935d03474d6bdf9d4").expect("Decoding failed")
            ),
            (
                <[u8;64]>::from_hex("00020300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").expect("Decoding failed"),
                <[u8;32]>::from_hex("5010fabfb319bf84136db68445972cdd5476ff2fbf3e5133330b3946b84b4e6a").expect("Decoding failed")
            ),
            (
                <[u8;64]>::from_hex("0071562b71999873db5b286df957af199ec946170000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").expect("Decoding failed"),
                <[u8;32]>::from_hex("6fc5ac021ff2468685885ad7fdb31a0c58d1ee93254a58c9e9e0809187c53e71").expect("Decoding failed")
            )
        ];
        for (input, output) in tests.iter() {
            let hash = calculate_pedersan_hash(unsafe { transmute(Box::new(*input))});
            let _hash = get_array_from_slice_argument(hash);
            assert_eq!(
                &_hash,
                output
            );
        }
    }
}