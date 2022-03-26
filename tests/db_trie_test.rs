use rust_verkle::*;

#[cfg(test)]
mod db_trie_test_helper {

    use crate::{
        create_trie_from_db, create_verkle_db, verkle_trie_flush, verkle_trie_get,
        verkle_trie_insert, CommitScheme, DatabaseScheme,
    };
    use std::ffi::CStr;
    use std::intrinsics::transmute;
    use std::os::raw::c_char;
    use tempfile::Builder;

    pub fn str_to_cstr(val: &str) -> *const c_char {
        let byte = val.as_bytes();
        unsafe { CStr::from_bytes_with_nul_unchecked(byte).as_ptr() }
    }

    pub fn create_db_trie(db_scheme: DatabaseScheme) {
        let dir = Builder::new().tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        let db = create_verkle_db(db_scheme, str_to_cstr(path));

        let trie = create_trie_from_db(CommitScheme::TestCommitment, db);

        let _one: [u8; 32] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ];
        let one: *const u8 = unsafe { transmute(Box::new(_one)) };
        let _one_32: [u8; 32] = [1; 32];
        let one_32 = unsafe { transmute(Box::new(_one_32)) };
        verkle_trie_insert(trie, one, one);
        verkle_trie_insert(trie, one_32, one);
        let val = verkle_trie_get(trie, one_32);
        let _val: Box<[u8; 32]> = unsafe { transmute(val) };
        let result = *_val;
        assert_eq!(result, _one);
    }

    pub fn create_trie_from_empty_db(db_scheme: DatabaseScheme) {
        let dir = Builder::new().tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        let db = create_verkle_db(db_scheme, str_to_cstr(path));

        let trie = create_trie_from_db(CommitScheme::TestCommitment, db);

        let _one: [u8; 32] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ];
        let one: *const u8 = unsafe { transmute(Box::new(_one)) };
        let _one_32: [u8; 32] = [1; 32];
        let one_32 = unsafe { transmute(Box::new(_one_32)) };
        verkle_trie_insert(trie, one, one);
        verkle_trie_insert(trie, one_32, one);
        let val = verkle_trie_get(trie, one_32);
        let _val: Box<[u8; 32]> = unsafe { transmute(val) };
        let result = *_val;
        assert_eq!(result, _one);

        let trie_2 = create_trie_from_db(CommitScheme::TestCommitment, db);
        let val = verkle_trie_get(trie_2, one_32);
        val.is_null();
    }

    pub fn create_trie_from_flushed_db(db_scheme: DatabaseScheme) {
        let dir = Builder::new().tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        let db = create_verkle_db(db_scheme, str_to_cstr(path));

        let trie = create_trie_from_db(CommitScheme::TestCommitment, db);

        let _one: [u8; 32] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ];
        let one: *const u8 = unsafe { transmute(Box::new(_one)) };
        let _one_32: [u8; 32] = [1; 32];
        let one_32 = unsafe { transmute(Box::new(_one_32)) };
        verkle_trie_insert(trie, one, one);
        verkle_trie_insert(trie, one_32, one);
        let val = verkle_trie_get(trie, one_32);
        let _val: Box<[u8; 32]> = unsafe { transmute(val) };
        let result = *_val;
        assert_eq!(result, _one);
        verkle_trie_flush(trie);

        let trie_2 = create_trie_from_db(CommitScheme::TestCommitment, db);
        let val = verkle_trie_get(trie_2, one_32);
        let _val: Box<[u8; 32]> = unsafe { transmute(val) };
        let result = *_val;
        assert_eq!(result, _one);
    }

    pub fn create_trie_from_flushed_db_readonly(db_scheme: DatabaseScheme) {
        let dir = Builder::new().tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        let db = create_verkle_db(db_scheme, str_to_cstr(path));

        let trie = create_trie_from_db(CommitScheme::TestCommitment, db);

        let _one: [u8; 32] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ];
        let one: *const u8 = unsafe { transmute(Box::new(_one)) };
        let _one_32: [u8; 32] = [1; 32];
        let one_32 = unsafe { transmute(Box::new(_one_32)) };
        verkle_trie_insert(trie, one, one);
        verkle_trie_insert(trie, one_32, one);
        let val = verkle_trie_get(trie, one_32);
        let _val: Box<[u8; 32]> = unsafe { transmute(val) };
        let result = *_val;
        assert_eq!(result, _one);
        verkle_trie_flush(trie);

        let trie_2 = create_trie_from_db(CommitScheme::TestCommitment, db);
        let val = verkle_trie_get(trie_2, one_32);
        val.is_null();
    }
}

macro_rules! db_trie_test {
    (
        $module_name: ident;   // Module Name
        $database_enum: ident;  // Database enum
        $($function_name: ident),*  // list of functions to implement
    ) => {
        #[cfg(test)]
        #[allow(non_snake_case)]
        mod $module_name {
            use super::*;

            $(
                #[test]
                fn $function_name() {
                    db_trie_test_helper::$function_name(DatabaseScheme::$database_enum);
                }
            )*
        }
    };
}

db_trie_test![
    MemoryDBTrie;
    MemoryDb;
    create_db_trie,
    create_trie_from_empty_db,
    create_trie_from_flushed_db
];

db_trie_test![
    RocksDBTrie;
    RocksDb;
    create_db_trie,
    create_trie_from_empty_db,
    create_trie_from_flushed_db
];

db_trie_test![
    RocksReadOnlyDBTrie;
    RocksDbReadOnly;
    create_db_trie,
    create_trie_from_empty_db,
    create_trie_from_flushed_db_readonly
];
