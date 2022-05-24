use rust_verkle::*;

#[cfg(test)]
mod db_trie_test_helper {

    use crate::{
        create_trie_from_db, create_verkle_db, verkle_trie_flush, verkle_trie_get,
        verkle_trie_insert, CommitScheme, DatabaseScheme,
    };
    use rust_verkle::utils::{assert_value, get_boxed_value, str_to_cstr};
    use rust_verkle::{clear_temp_changes_read_only_db, create_read_only_verkle_db};
    use std::ffi::CStr;
    use std::intrinsics::transmute;
    use std::os::raw::c_char;
    use tempfile::Builder;

    const _ONE: [u8; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ];
    const _ONE32: [u8; 32] = [1; 32];

    pub fn create_db_trie(db_scheme: DatabaseScheme) {
        let one: *const u8 = get_boxed_value(_ONE);
        let one32: *const u8 = get_boxed_value(_ONE32);

        let dir = Builder::new().tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        let db = create_verkle_db(db_scheme, str_to_cstr(path));

        let trie = create_trie_from_db(CommitScheme::TestCommitment, db);

        verkle_trie_insert(trie, one, one);
        verkle_trie_insert(trie, one32, one);

        let val = verkle_trie_get(trie, one32);
        assert_value(val, _ONE);
    }

    pub fn create_trie_from_empty_db(db_scheme: DatabaseScheme) {
        let one: *const u8 = get_boxed_value(_ONE);
        let one32: *const u8 = get_boxed_value(_ONE32);

        let dir = Builder::new().tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        let db = create_verkle_db(db_scheme, str_to_cstr(path));

        let trie = create_trie_from_db(CommitScheme::TestCommitment, db);

        verkle_trie_insert(trie, one, one);
        verkle_trie_insert(trie, one32, one);
        let val = verkle_trie_get(trie, one32);
        assert_value(val, _ONE);

        let trie_2 = create_trie_from_db(CommitScheme::TestCommitment, db);
        let val = verkle_trie_get(trie_2, one32);
        assert!(val.is_null());
    }

    pub fn create_trie_from_flushed_db(db_scheme: DatabaseScheme) {
        let one: *const u8 = get_boxed_value(_ONE);
        let one32: *const u8 = get_boxed_value(_ONE32);

        let dir = Builder::new().tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        let db = create_verkle_db(db_scheme, str_to_cstr(path));

        let trie = create_trie_from_db(CommitScheme::TestCommitment, db);

        verkle_trie_insert(trie, one, one);
        verkle_trie_insert(trie, one32, one);
        let val = verkle_trie_get(trie, one32);
        assert_value(val, _ONE);

        verkle_trie_flush(trie);

        let trie_2 = create_trie_from_db(CommitScheme::TestCommitment, db);
        let val = verkle_trie_get(trie_2, one32);
        assert_value(val, _ONE);
    }

    pub fn create_trie_from_flushed_db_readonly(db_scheme: DatabaseScheme) {
        let one: *const u8 = get_boxed_value(_ONE);
        let one32: *const u8 = get_boxed_value(_ONE32);

        let dir = Builder::new().tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        let db = create_verkle_db(db_scheme, str_to_cstr(path));

        let trie = create_trie_from_db(CommitScheme::TestCommitment, db);

        verkle_trie_insert(trie, one, one);
        verkle_trie_insert(trie, one32, one);
        let val = verkle_trie_get(trie, one32);
        assert_value(val, _ONE);

        verkle_trie_flush(trie);

        let ro_db = create_read_only_verkle_db(db);

        let trie_2 = create_trie_from_db(CommitScheme::TestCommitment, ro_db);

        let val = verkle_trie_get(trie_2, one32);
        assert_value(val, _ONE);

        verkle_trie_insert(trie_2, one, one32);
        let val = verkle_trie_get(trie_2, one);
        assert_value(val, _ONE32);

        let val = verkle_trie_get(trie, one);
        assert_value(val, _ONE);

        verkle_trie_flush(trie_2);

        let val = verkle_trie_get(trie_2, one);
        assert_value(val, _ONE32);

        clear_temp_changes_read_only_db(ro_db);

        let val = verkle_trie_get(trie_2, one);
        assert_value(val, _ONE);
    }

    pub fn create_trie_on_same_db_path(db_scheme: DatabaseScheme) {
        let one: *const u8 = get_boxed_value(_ONE);
        let one32: *const u8 = get_boxed_value(_ONE32);

        let dir = Builder::new().tempdir().unwrap();
        let path = dir.path().to_str().unwrap();

        let db1 = create_verkle_db(db_scheme.clone(), str_to_cstr(path));
        let trie1 = create_trie_from_db(CommitScheme::TestCommitment, db1);

        verkle_trie_insert(trie1, one, one);
        verkle_trie_insert(trie1, one32, one);

        let db2 = create_verkle_db(db_scheme.clone(), str_to_cstr(path));
        let trie2 = create_trie_from_db(CommitScheme::TestCommitment, db1);

        let val = verkle_trie_get(trie2, one32);
        assert_value(val, _ONE);

        let val1 = verkle_trie_get(trie2, one);
        assert_value(val1, _ONE);
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
    create_trie_from_flushed_db,
    create_trie_from_flushed_db_readonly
];

db_trie_test![
    RocksDBTrie;
    RocksDb;
    create_db_trie,
    create_trie_from_empty_db,
    create_trie_from_flushed_db,
    create_trie_from_flushed_db_readonly
];
