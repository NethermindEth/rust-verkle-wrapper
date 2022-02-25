#![feature(vec_into_raw_parts)]
mod verkle_variants;
use std::slice;
use std::mem::transmute;
use std::convert::TryInto;
use verkle_variants::{
    memory_test,
    memory_prelagrange,
    rocksdb_test,
    rocksdb_prelagrange,
    traits::FFI,
};
use std::ffi::CStr;
use std::os::raw::c_char;

#[repr(C)]
pub enum VerkleTrie {
    MemoryTest(memory_test::VerkleTrie),
    MemoryPrelagrange(memory_prelagrange::VerkleTrie),
    RocksdbTest(rocksdb_test::VerkleTrie),
    RocksdbPrelagrange(rocksdb_prelagrange::VerkleTrie),
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
}

#[repr(C)]
pub enum CommitScheme {
    TestCommitment,
    PrecomputeLagrange,
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
                let _vt = memory_test::VerkleTrie::verkle_trie_new(db_path);
                VerkleTrie::MemoryTest(_vt)
            },
            CommitScheme::PrecomputeLagrange => {
                let _vt = memory_prelagrange::VerkleTrie::verkle_trie_new(db_path);
                VerkleTrie::MemoryPrelagrange(_vt)
            },
        },
        DatabaseScheme::RocksDb => match commit_scheme {
            CommitScheme::TestCommitment => {
                let _vt = rocksdb_test::VerkleTrie::verkle_trie_new(db_path);
                VerkleTrie::RocksdbTest(_vt)
            },
            CommitScheme::PrecomputeLagrange => {
                let _vt = rocksdb_prelagrange::VerkleTrie::verkle_trie_new(db_path);
                VerkleTrie::RocksdbPrelagrange(_vt)
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

#[cfg(test)]
mod test_helper {
    use super::*;
    use std::mem::transmute;

    pub fn str_to_cstr(val: &str) -> *const c_char {
        let byte = val.as_bytes();
        unsafe {
            CStr::from_bytes_with_nul_unchecked(byte)
            .as_ptr()
        }
    }

    pub fn root_hash(trie: *mut VerkleTrie) {
        let hash_ptr = get_root_hash(trie);
        let hash = get_array_from_slice_argument(hash_ptr);
        assert_eq!(hash, [0u8; 32]);
    }

    pub fn insert_fetch(trie: *mut VerkleTrie) {
        let _one:[u8;32] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ];
        let one: *const u8  = unsafe {transmute(Box::new(_one))};
        let _one_32:[u8;32] = [1; 32];
        let one_32 = unsafe {transmute(Box::new(_one_32))};
        verkle_trie_insert(trie, one, one);
        verkle_trie_insert(trie, one_32, one);
        let val = verkle_trie_get(trie, one_32);
        let _val: Box<[u8;32]> = unsafe { transmute(val)};
        let result = * _val;
        assert_eq!(result, _one);
    }

    pub fn insert_account_fetch(trie: *mut VerkleTrie) {
        let tree_key_version:[u8;32] = [ 121, 85, 7, 198, 131, 230, 143, 90, 165, 129, 173, 81, 186,
            89, 19, 191, 13, 107, 197, 120, 243, 229, 224, 183, 72, 25, 6, 8, 210, 159, 31, 0];

        let tree_key_balance:[u8;32] = [ 121, 85, 7, 198, 131, 230, 143, 90, 165, 129, 173, 81, 186,
            89, 19, 191, 13, 107, 197, 120, 243, 229, 224, 183, 72, 25, 6, 8, 210, 159, 31, 1];

        let tree_key_nonce:[u8;32] = [ 121, 85, 7, 198, 131, 230, 143, 90, 165, 129, 173, 81, 186,
            89, 19, 191, 13, 107, 197, 120, 243, 229, 224, 183, 72, 25, 6, 8, 210, 159, 31, 2];

        let tree_key_code_keccak:[u8;32] = [ 121, 85, 7, 198, 131, 230, 143, 90, 165, 129, 173, 81,
            186, 89, 19, 191, 13, 107, 197, 120, 243, 229, 224, 183, 72, 25, 6, 8, 210, 159, 31, 3];

        let tree_key_code_size:[u8;32] = [ 121, 85, 7, 198, 131, 230, 143, 90, 165, 129, 173, 81,
            186, 89, 19, 191, 13, 107, 197, 120, 243, 229, 224, 183, 72, 25, 6, 8, 210, 159, 31, 4];

        let empty_code_hash_value:[u8;32] = [ 197, 210, 70, 1, 134, 247, 35, 60, 146, 126, 125, 178,
            220, 199, 3, 192, 229, 0, 182, 83, 202, 130, 39, 59, 123, 250, 216, 4, 93, 133, 164, 112];

        let value_0:[u8;32] = [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0];

        let value_2:[u8;32] = [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 2];


        verkle_trie_insert(
            trie,
            unsafe {transmute(Box::new(tree_key_version))},
            unsafe {transmute(Box::new(value_0))}
        );

        verkle_trie_insert(
            trie,
            unsafe {transmute(Box::new(tree_key_balance))},
            unsafe {transmute(Box::new(value_2))}
        );

        verkle_trie_insert(
            trie,
            unsafe {transmute(Box::new(tree_key_nonce))},
            unsafe {transmute(Box::new(value_0))}
        );

        verkle_trie_insert(
            trie,
            unsafe {transmute(Box::new(tree_key_code_keccak))},
            unsafe {transmute(Box::new(empty_code_hash_value))}
        );

        verkle_trie_insert(
            trie,
            unsafe {transmute(Box::new(tree_key_code_size))},
            unsafe {transmute(Box::new(value_0))}
        );

        let val = verkle_trie_get(trie, unsafe {transmute(Box::new(tree_key_version))});
        assert!(!val.is_null());
        let val = verkle_trie_get(trie, unsafe {transmute(Box::new(tree_key_balance))});
        assert!(!val.is_null());
        let val = verkle_trie_get(trie, unsafe {transmute(Box::new(tree_key_nonce))});
        assert!(!val.is_null());
        let val = verkle_trie_get(trie, unsafe {transmute(Box::new(tree_key_code_keccak))});
        assert!(!val.is_null());
        let val = verkle_trie_get(trie, unsafe {transmute(Box::new(tree_key_code_size))});
        assert!(!val.is_null());
    }

    pub fn gen_verify_proof(trie: *mut VerkleTrie) {
        let _one:[u8;32] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ];
        let one: *const u8  = unsafe {transmute(Box::new(_one))};
        let _one_32:[u8;32] = [1; 32];
        let one_32 = unsafe {transmute(Box::new(_one_32))};
        verkle_trie_insert(trie, one, one);
        verkle_trie_insert(trie, one_32, one);
        let _proof = get_verkle_proof(trie, one);
        let proof = unsafe{&mut *_proof};
        let verif = verify_verkle_proof(trie, proof.ptr, proof.len, one, one);
        assert_eq!(verif, 1);
        let verif = verify_verkle_proof(trie, proof.ptr, proof.len, one, one_32);
        assert_eq!(verif, 0);
    }

    pub fn generate_proof_test(trie: *mut VerkleTrie){
        let tree_key_version:[u8;32] = [ 121, 85, 7, 198, 131, 230, 143, 90, 165, 129, 173, 81, 186,
            89, 19, 191, 13, 107, 197, 120, 243, 229, 224, 183, 72, 25, 6, 8, 210, 159, 31, 0];

        let tree_key_balance:[u8;32] = [ 121, 85, 7, 198, 131, 230, 143, 90, 165, 129, 173, 81, 186,
            89, 19, 191, 13, 107, 197, 120, 243, 229, 224, 183, 72, 25, 6, 8, 210, 159, 31, 1];

        let tree_key_nonce:[u8;32] = [ 121, 85, 7, 198, 131, 230, 143, 90, 165, 129, 173, 81, 186,
            89, 19, 191, 13, 107, 197, 120, 243, 229, 224, 183, 72, 25, 6, 8, 210, 159, 31, 2];

        let tree_key_code_keccak:[u8;32] = [ 121, 85, 7, 198, 131, 230, 143, 90, 165, 129, 173, 81,
            186, 89, 19, 191, 13, 107, 197, 120, 243, 229, 224, 183, 72, 25, 6, 8, 210, 159, 31, 3];

        let tree_key_code_size:[u8;32] = [ 121, 85, 7, 198, 131, 230, 143, 90, 165, 129, 173, 81,
            186, 89, 19, 191, 13, 107, 197, 120, 243, 229, 224, 183, 72, 25, 6, 8, 210, 159, 31, 4];
        
        let empty_code_hash_value:[u8;32] = [ 197, 210, 70, 1, 134, 247, 35, 60, 146, 126, 125, 178,
            220, 199, 3, 192, 229, 0, 182, 83, 202, 130, 39, 59, 123, 250, 216, 4, 93, 133, 164, 112];

        let value_0:[u8;32] = [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0];

        let value_2:[u8;32] = [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 2];

        let all_keys = vec![tree_key_version, tree_key_balance, tree_key_nonce, tree_key_code_keccak, tree_key_code_size];
        let all_vals = vec![value_0, value_2, value_0, empty_code_hash_value, value_0];

        verkle_trie_insert_multiple(trie, all_keys.as_ptr(), all_vals.as_ptr(), all_keys.len());

        let mut _proof = get_verkle_proof_multiple(trie, all_keys.as_ptr(), all_keys.len());
        let proof = unsafe{&mut *_proof};
        let verification = verify_verkle_proof_multiple(trie, proof.ptr, proof.len, all_keys.as_ptr(), all_vals.as_ptr(), all_keys.len());
        assert_eq!(verification, 1);
    }
}

macro_rules! test_model {
    (
        $MD: ident;   /// Module Name
        $DB: ident;  /// Database enum
        $CMT: ident; /// Commit enum
        $($FN: ident),*  /// list of functions to implement
    ) => {
        #[cfg(test)]
        #[allow(non_snake_case)]
        mod $MD {
            use super::*;
            use tempfile::Builder;
            
            $(
                #[test]
                fn $FN() {
                    let dir = Builder::new().tempdir().unwrap();
                    let path = dir.path().to_str().unwrap();
                    let trie = verkle_trie_new(
                        DatabaseScheme::$DB,
                        CommitScheme::$CMT,
                        test_helper::str_to_cstr(path),
                    );
                    test_helper::$FN(trie);
                }
            )*
        }
    };
}

test_model![
    MemoryTest;
    MemoryDb;
    TestCommitment;
    root_hash,
    insert_fetch,
    insert_account_fetch,
    gen_verify_proof,
    generate_proof_test
];

test_model![
    RocksdbTest;
    RocksDb;
    TestCommitment;
    root_hash,
    insert_fetch,
    insert_account_fetch,
    gen_verify_proof,
    generate_proof_test
];

test_model![
    MemoryPrelagrange;
    MemoryDb;
    PrecomputeLagrange;
    root_hash,
    insert_fetch,
    insert_account_fetch,
    gen_verify_proof,
    generate_proof_test
];

test_model![
    RocksdbPrelagrange;
    RocksDb;
    PrecomputeLagrange;
    root_hash,
    insert_fetch,
    insert_account_fetch,
    gen_verify_proof,
    generate_proof_test
];
