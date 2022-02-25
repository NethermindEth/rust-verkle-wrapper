use verkle_trie::{
    committer::precompute::PrecomputeLagrange,
    constants::CRS,
    database::memory_db::MemoryDb,
    trie::Trie,
    Config
};
use ark_ec::ProjectiveCurve;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use crate::verkle_variants::traits::FFI;

pub type VerkleTrie = Trie<MemoryDb, PrecomputeLagrange>;

impl FFI for VerkleTrie {

    fn verkle_trie_new(_path: &str) -> Self {
        let db = MemoryDb::new();
        let g_aff: Vec<_> = CRS.G.iter().map(|point| point.into_affine()).collect();
        let committer = PrecomputeLagrange::precompute(&g_aff);
        let config = Config { db, committer};
        let mut _trie = Trie::new(config);
        _trie
    }
}
