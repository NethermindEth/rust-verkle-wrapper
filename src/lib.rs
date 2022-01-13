#![feature(vec_into_raw_parts)]
use std::ptr;
use std::mem::transmute;
use std::mem;
use std::slice;

use ark_ec::ProjectiveCurve;
use once_cell::sync::Lazy;
use std::convert::TryInto;
use verkle_trie::{database::{memory_db::MemoryDb}, trie::Trie};
use verkle_trie::committer::precompute::PrecomputeLagrange;
use verkle_trie::config::{VerkleConfig};
use verkle_trie::TrieTrait;
use verkle_trie::proof::VerkleProof;

#[repr(C)]
pub struct VerkleTrie {
    trie: Trie<MemoryDb, PrecomputeLagrange>,
}

#[repr(C)]
pub struct Proof {
    pub ptr: *const u8,
    pub len: usize,
} 

pub extern fn get_verkle_trie() -> Trie<MemoryDb, PrecomputeLagrange> {
    let _db = MemoryDb::new();
    let config = VerkleConfig::new(_db);
    let mut _trie = Trie::new(config);
    _trie
}

#[no_mangle]
pub extern fn verkle_trie_new() -> *mut VerkleTrie {

    let _db = MemoryDb::new();
    let config = VerkleConfig::new(_db);
    let mut _trie = Trie::new(config);
    let mut vt = VerkleTrie {
        trie: _trie,
    };
    let ret = unsafe { transmute (Box::new(vt))};
    ret
}

#[no_mangle]
pub extern fn verkle_trie_get(vt: *mut VerkleTrie, key: *const u8) -> *const u8 {
    let mut _vt = unsafe { &mut * vt };
    let _key = get_array_from_slice_argument(key);
    let _result = &_vt.trie.get(_key);
    match _result {
        Some(x) => {
            let _result = unsafe { transmute ( Box::new(*x))};
            _result
        }
        None  => ptr::null(),
    }
}

#[no_mangle]
pub extern fn verkle_trie_insert(vt: *mut VerkleTrie, key: *const u8, value: *const u8) {
    let mut _vt = unsafe { &mut * vt };
    let _key = get_array_from_slice_argument(key);
    let _value = get_array_from_slice_argument(value);
    _vt.trie.insert_single(_key,_value);
}

#[no_mangle]
pub extern fn get_verkle_proof(vt: *mut VerkleTrie, key: *const u8) -> *mut Proof {
    let mut _vt = unsafe { &mut *vt};
    let _key = get_array_from_slice_argument(key);
    let _proof = _vt.trie.create_verkle_proof(vec![_key].into_iter());
    let mut proof_bytes = Vec::new();
    _proof.write(&mut proof_bytes);
    // println!("{}",bytes.len());
    // println!("{:?}",bytes);
    let(_ptr, _len, _) = proof_bytes.into_raw_parts();
    let mut proof = Proof{ ptr: _ptr, len: _len};
    unsafe{ transmute( Box::new(proof))}
}

#[no_mangle]
pub extern fn verify_verkle_proof(vt: *mut VerkleTrie, ptr: *const u8, proof_len: usize, key: *const u8, value: *const u8) -> bool{
    let mut proof_bytes = proof_ptr_to_proof_vec(ptr, proof_len);
    let mut proof = VerkleProof::read(&proof_bytes[..]).unwrap();
    let mut _vt = unsafe { &mut *vt};
    let _key = get_array_from_slice_argument(key);
    let _value = get_array_from_slice_argument(value);
    let root = _vt.trie.root_commitment();
    let val_iter = vec![Some(_value)];
    let vpp = proof.clone();
    let (res, _) = vpp.check( vec![_key], val_iter, root);
    return res;
}

#[no_mangle]
pub extern fn get_verkle_proof_multiple(vt: *mut VerkleTrie, keys: *const [u8;32], len: usize) -> *mut Proof{
    let mut _vt = unsafe{ &mut * vt};
    let _keys = get_vector_from_slice_argument(keys, len);
    let _proof = _vt.trie.create_verkle_proof(_keys.into_iter());
    let mut proof_bytes = Vec::new();
    _proof.write(&mut proof_bytes);
    let(_ptr, _len, _) = proof_bytes.into_raw_parts();
    let mut proof = Proof{ ptr: _ptr, len: _len};
    unsafe{ transmute( Box::new(proof))}
}

#[no_mangle]
pub extern fn verify_verkle_proof_multiple(vt: *mut VerkleTrie, ptr: *const u8, proof_len: usize, keys: *const [u8;32], vals: *const [u8;32], len: usize) -> bool{
    let mut proof_bytes = proof_ptr_to_proof_vec(ptr, proof_len);
    let mut _vt = unsafe{&mut * vt};
    let mut proof = VerkleProof::read(&proof_bytes[..]).unwrap();
    let _keys = get_vector_from_slice_argument(keys, len);
    let _vals = get_vector_from_slice_argument(vals, len);
    let root = _vt.trie.root_commitment();
    let values: Vec<_> = _vals.iter().map(|val| Some(*val)).collect();
    let vpp = proof.clone();
    let (res, _) = vpp.check(_keys, values, root);
    return res;
}
#[no_mangle]
pub extern fn verkle_trie_insert_multiple(vt: *mut VerkleTrie, keys: *const [u8;32], vals: *const [u8;32], len: usize){
    let mut _vt = unsafe {&mut * vt};
    let _keys = get_vector_from_slice_argument(keys, len);
    let _vals = get_vector_from_slice_argument(vals, len);
    let mut itr = vec![(_keys[0], _vals[0])];
    for i in 1..=_keys.len() - 1{
        itr.push((_keys[i], _vals[i]));
    }
    _vt.trie.insert(itr.into_iter());
}

#[no_mangle]
pub extern fn get_proof_len(_vp: *mut Proof) -> usize{
    let mut vp = unsafe {&mut *_vp};
    vp.len
}

#[no_mangle]
pub extern fn get_proof_ptr(_vp: *mut Proof) -> *const u8{
    let mut vp = unsafe {&mut *_vp};
    vp.ptr
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
mod tests {
    use crate::verkle_trie_new;
    use crate::verkle_trie_insert;
    use crate::verkle_trie_get;
    use crate::verkle_trie_insert_multiple;
    use crate::get_verkle_proof_multiple;
    use crate::verify_verkle_proof_multiple;
    use crate::get_proof_len;
    use crate::get_proof_ptr;
    use crate::get_array_from_slice_argument;
    use std::mem::transmute;

    #[test]
    fn insert_fetch() {
        let trie = verkle_trie_new();

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

    #[test]
    fn insert_account_fetch() {
        let trie = verkle_trie_new();

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

    #[test]
    fn generate_proof_test(){
        let trie = verkle_trie_new();

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

        let mut multi_proof = get_verkle_proof_multiple(trie, all_keys.as_ptr(), all_keys.len());
        let proof_ptr = get_proof_ptr(multi_proof);
        let proof_len = get_proof_len(multi_proof);
        let verification = verify_verkle_proof_multiple(trie, proof_ptr, proof_len, all_keys.as_ptr(), all_vals.as_ptr(), all_keys.len());
        assert!(verification);
    }
}
