use rust_verkle::*;

#[cfg(test)]
mod trie_test_helper {
    use std::ffi::CStr;
    use std::mem::transmute;
    use std::os::raw::c_char;
    use rust_verkle::*;

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

    pub fn insert_fetch_flush_clear(trie: *mut VerkleTrie) {
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
        verkle_trie_flush(trie);
        verkle_trie_insert(trie, one, one_32);
        let val = verkle_trie_get(trie, one);
        let _val: Box<[u8;32]> = unsafe { transmute(val)};
        let result = * _val;
        assert_eq!(result, _one_32);
        verkle_trie_clear(trie);
        let val = verkle_trie_get(trie, one);
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

macro_rules! trie_test {
    (
        $module_name: ident;   // Module Name
        $database_enum: ident;  // Database enum
        $commit_enum: ident; // Commit enum
        $($function_name: ident),*  // list of functions to implement
    ) => {
        #[cfg(test)]
        #[allow(non_snake_case)]
        mod $module_name {
            use super::*;
            use tempfile::Builder;

            $(
                #[test]
                fn $function_name() {
                    let dir = Builder::new().tempdir().unwrap();
                    let path = dir.path().to_str().unwrap();
                    let trie = verkle_trie_new(
                        DatabaseScheme::$database_enum,
                        CommitScheme::$commit_enum,
                        trie_test_helper::str_to_cstr(path),
                    );
                    trie_test_helper::$function_name(trie);
                }
            )*
        }
    };
}

trie_test![
    MemoryTest;
    MemoryDb;
    TestCommitment;
    root_hash,
    insert_fetch,
    insert_account_fetch,
    gen_verify_proof,
    generate_proof_test
];

trie_test![
    RocksdbTest;
    RocksDb;
    TestCommitment;
    root_hash,
    insert_fetch,
    insert_account_fetch,
    gen_verify_proof,
    generate_proof_test,
    insert_fetch_flush_clear
];

trie_test![
    MemoryPrelagrange;
    MemoryDb;
    PrecomputeLagrange;
    root_hash,
    insert_fetch,
    insert_account_fetch,
    gen_verify_proof,
    generate_proof_test
];

trie_test![
    RocksdbPrelagrange;
    RocksDb;
    PrecomputeLagrange;
    root_hash,
    insert_fetch,
    insert_account_fetch,
    gen_verify_proof,
    generate_proof_test,
    insert_fetch_flush_clear
];

trie_test![
    RocksdbReadOnlyTest;
    RocksDb;
    TestCommitment;
    root_hash,
    insert_fetch,
    insert_account_fetch,
    gen_verify_proof,
    generate_proof_test,
    insert_fetch_flush_clear
];

trie_test![
    RocksdbReadOnlyPrelagrange;
    RocksDb;
    PrecomputeLagrange;
    root_hash,
    insert_fetch,
    insert_account_fetch,
    gen_verify_proof,
    generate_proof_test,
    insert_fetch_flush_clear
];


macro_rules! trie_from_db_test {
    (
        $module_name: ident;   // Module Name
        $database_enum: ident;  // Database enum
        $commit_enum: ident; // Commit enum
        $($function_name: ident),*  // list of functions to implement
    ) => {
        #[cfg(test)]
        #[allow(non_snake_case)]
        mod $module_name {
            use super::*;
            use tempfile::Builder;

            $(
                #[test]
                fn $function_name() {
                    let dir = Builder::new().tempdir().unwrap();
                    let path = dir.path().to_str().unwrap();
                    let db = create_verkle_db(DatabaseScheme::$database_enum, trie_test_helper::str_to_cstr(path));
                    let trie = create_trie_from_db(CommitScheme::$commit_enum, db);
                    trie_test_helper::$function_name(trie);
                }
            )*
        }
    };
}


trie_from_db_test![
    MemoryTestDB;
    MemoryDb;
    TestCommitment;
    root_hash,
    insert_fetch,
    insert_account_fetch,
    gen_verify_proof,
    generate_proof_test
];

trie_from_db_test![
    RocksdbTestDB;
    RocksDb;
    TestCommitment;
    root_hash,
    insert_fetch,
    insert_account_fetch,
    gen_verify_proof,
    generate_proof_test,
    insert_fetch_flush_clear
];

trie_from_db_test![
    MemoryPrelagrangeDB;
    MemoryDb;
    PrecomputeLagrange;
    root_hash,
    insert_fetch,
    insert_account_fetch,
    gen_verify_proof,
    generate_proof_test
];

trie_from_db_test![
    RocksdbPrelagrangeDB;
    RocksDb;
    PrecomputeLagrange;
    root_hash,
    insert_fetch,
    insert_account_fetch,
    gen_verify_proof,
    generate_proof_test,
    insert_fetch_flush_clear
];

trie_from_db_test![
    RocksdbReadOnlyTestDB;
    RocksDb;
    TestCommitment;
    root_hash,
    insert_fetch,
    insert_account_fetch,
    gen_verify_proof,
    generate_proof_test,
    insert_fetch_flush_clear
];

trie_from_db_test![
    RocksdbReadOnlyPrelagrangeDB;
    RocksDb;
    PrecomputeLagrange;
    root_hash,
    insert_fetch,
    insert_account_fetch,
    gen_verify_proof,
    generate_proof_test,
    insert_fetch_flush_clear
];
