use std::ptr;
use std::mem::transmute;
use verkle_trie::TrieTrait;
use verkle_trie::proof::VerkleProof;
use verkle_trie::from_to_bytes::ToBytes;

use crate::{
    Proof,
    get_array_from_slice_argument,
    get_vector_from_slice_argument,
    proof_ptr_to_proof_vec,
    Database,
    CommitScheme,
    VerkleTrie
};

pub trait FFI: TrieTrait {

    type DbObject;

    fn verkle_trie_new(path: &str) -> Self;

    fn create_from_db(db: &'static mut Self::DbObject) -> Self;

    fn verkle_trie_get(&mut self, key: *const u8) -> *const u8 {
        let _key = get_array_from_slice_argument(key);
        let _result = &self.get(_key);
        match _result {
            Some(x) => {
                let _result = unsafe { transmute ( Box::new(*x))};
                _result
            }
            None  => ptr::null(),
        }
    }
    
    fn verkle_trie_insert(&mut self, key: *const u8, value: *const u8) {
        let _key = get_array_from_slice_argument(key);
        let _value = get_array_from_slice_argument(value);
        self.insert_single(_key,_value);
    }
    
    fn get_root_hash(&mut self) -> *const u8 {
        let hash = self.root_hash();
        let (hash_ptr, _, _) = hash.to_bytes().into_raw_parts();
        hash_ptr
    }
    
    fn get_verkle_proof(&mut self, key: *const u8) -> *mut Proof {
        let _key = get_array_from_slice_argument(key);
        let _proof = self.create_verkle_proof(vec![_key].into_iter());
        let mut proof_bytes = Vec::new();
        _proof.write(&mut proof_bytes).expect("Could write proof");
        let(_ptr, _len, _) = proof_bytes.into_raw_parts();
        let proof = Proof{ ptr: _ptr, len: _len};
        unsafe{ transmute( Box::new(proof))}
    }
    
    fn verify_verkle_proof(&mut self, ptr: *const u8, proof_len: usize, key: *const u8, value: *const u8) -> u8 {
        let proof_bytes = proof_ptr_to_proof_vec(ptr, proof_len);
        let proof = VerkleProof::read(&proof_bytes[..]).unwrap();
        let _key = get_array_from_slice_argument(key);
        let _value = get_array_from_slice_argument(value);
        let root = self.root_commitment();
        let val_iter = vec![Some(_value)];
        let vpp = proof.clone();
        let (res, _) = vpp.check( vec![_key], val_iter, root);
        let result = res as u8;
        result
    }
    
    fn get_verkle_proof_multiple(&mut self, keys: *const [u8;32], len: usize) -> *mut Proof{
        let _keys = get_vector_from_slice_argument(keys, len);
        let _proof = self.create_verkle_proof(_keys.into_iter());
        let mut proof_bytes = Vec::new();
        _proof.write(&mut proof_bytes).expect("Could write proof");
        let(_ptr, _len, _) = proof_bytes.into_raw_parts();
        let proof = Proof{ ptr: _ptr, len: _len};
        unsafe{ transmute( Box::new(proof))}
    }
    
    fn verify_verkle_proof_multiple(&mut self, ptr: *const u8, proof_len: usize, keys: *const [u8;32], vals: *const [u8;32], len: usize) -> u8 {
        let proof_bytes = proof_ptr_to_proof_vec(ptr, proof_len);
        let proof = VerkleProof::read(&proof_bytes[..]).expect("Could write proof");
        let _keys = get_vector_from_slice_argument(keys, len);
        let _vals = get_vector_from_slice_argument(vals, len);
        let root = self.root_commitment();
        let values: Vec<_> = _vals.iter().map(|val| Some(*val)).collect();
        let vpp = proof.clone();
        let (res, _) = vpp.check(_keys, values, root);
        let result = res as u8;
        result
    }
    
    fn verkle_trie_insert_multiple(&mut self, keys: *const [u8;32], vals: *const [u8;32], len: usize){
        let _keys = get_vector_from_slice_argument(keys, len);
        let _vals = get_vector_from_slice_argument(vals, len);
        let mut itr = vec![(_keys[0], _vals[0])];
        for i in 1..=_keys.len() - 1{
            itr.push((_keys[i], _vals[i]));
        }
        self.insert(itr.into_iter());
    }
}


pub trait DB {
    fn create_db(path: &str) -> Self;
}