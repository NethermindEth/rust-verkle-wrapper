use std::ffi::CStr;
use std::mem::transmute;
use std::os::raw::c_char;
use tempfile::Builder;
use verkle_spec::{H256, Hasher};
use verkle_trie::{committer::Committer, from_to_bytes::ToBytes, Fr};

pub fn assert_value(value1: *const u8, value2: [u8; 32]) {
    let _val: Box<[u8; 32]> = unsafe { transmute(value1) };
    let result = *_val;
    assert_eq!(result, value2);
}

pub fn get_boxed_value(value: [u8; 32]) -> *const u8 {
    unsafe { transmute(Box::new(value)) }
}

pub fn str_to_cstr(val: &str) -> *const c_char {
    let byte = val.as_bytes();
    unsafe { CStr::from_bytes_with_nul_unchecked(byte).as_ptr() }
}


pub struct PedersenHasher;
impl Hasher for PedersenHasher {
    fn hash64(bytes64: [u8; 64]) -> H256 {
        use verkle_trie::committer::test::TestCommitter;
        let chunks = PedersenHasher::chunk64(bytes64);
        let fr_data: Vec<_> = chunks.iter().map(|x| -> Fr { Fr::from(*x) }).collect();
        let bytes = TestCommitter.commit_lagrange(&fr_data[..]).to_bytes();
        return H256::from_slice(&bytes[..]);
    }
}


#[cfg(test)]
mod test {
    use hex::FromHex;
    use verkle_spec::{Address32, H256, Hasher, Header};
    use crate::utils::PedersenHasher;

    // input and outputs for these tests were taken from https://github.com/gballet/verkle-block-sample
    #[test]
    fn hash_test() {
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
            assert_eq!(
                PedersenHasher::hash64(*input),
                H256::from_slice(&output[..])
            );
        }
    }

    #[test]
    fn header_test() {
        let tests = [
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                [
                    "695921dca3b16c5cc850e94cdd63f573c467669e89cec88935d03474d6bdf900",
                    "695921dca3b16c5cc850e94cdd63f573c467669e89cec88935d03474d6bdf901",
                    "695921dca3b16c5cc850e94cdd63f573c467669e89cec88935d03474d6bdf902",
                    "695921dca3b16c5cc850e94cdd63f573c467669e89cec88935d03474d6bdf903",
                    "695921dca3b16c5cc850e94cdd63f573c467669e89cec88935d03474d6bdf904",
                ],
            ),
            (
                "0002030000000000000000000000000000000000000000000000000000000000",
                [
                    "5010fabfb319bf84136db68445972cdd5476ff2fbf3e5133330b3946b84b4e00",
                    "5010fabfb319bf84136db68445972cdd5476ff2fbf3e5133330b3946b84b4e01",
                    "5010fabfb319bf84136db68445972cdd5476ff2fbf3e5133330b3946b84b4e02",
                    "5010fabfb319bf84136db68445972cdd5476ff2fbf3e5133330b3946b84b4e03",
                    "5010fabfb319bf84136db68445972cdd5476ff2fbf3e5133330b3946b84b4e04",
                ],
            ),
            (
                "0071562b71999873db5b286df957af199ec94617000000000000000000000000",
                [
                    "6fc5ac021ff2468685885ad7fdb31a0c58d1ee93254a58c9e9e0809187c53e00",
                    "6fc5ac021ff2468685885ad7fdb31a0c58d1ee93254a58c9e9e0809187c53e01",
                    "6fc5ac021ff2468685885ad7fdb31a0c58d1ee93254a58c9e9e0809187c53e02",
                    "6fc5ac021ff2468685885ad7fdb31a0c58d1ee93254a58c9e9e0809187c53e03",
                    "6fc5ac021ff2468685885ad7fdb31a0c58d1ee93254a58c9e9e0809187c53e04",
                ],
            ),
        ];
        for (input, output) in tests.iter() {
            let input_bytes = <[u8; 32]>::from_hex(input).expect("Error decoding");
            let add = Address32::from_slice(&input_bytes[..]);
            let header = Header::new::<PedersenHasher>(add);

            assert_eq!(
                header.version(),
                Address32::from_slice(&<[u8; 32]>::from_hex(output[0]).expect("Error decoding"))
            );
            assert_eq!(
                header.balance(),
                Address32::from_slice(&<[u8; 32]>::from_hex(output[1]).expect("Error decoding"))
            );
            assert_eq!(
                header.nonce(),
                Address32::from_slice(&<[u8; 32]>::from_hex(output[2]).expect("Error decoding"))
            );
            assert_eq!(
                header.code_keccak(),
                Address32::from_slice(&<[u8; 32]>::from_hex(output[3]).expect("Error decoding"))
            );
            assert_eq!(
                header.code_size(),
                Address32::from_slice(&<[u8; 32]>::from_hex(output[4]).expect("Error decoding"))
            );
        }
    }
}
