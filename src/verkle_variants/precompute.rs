use ark_ec::ProjectiveCurve;
use bandersnatch::{EdwardsProjective, Fr};
use verkle_trie::committer::precompute::{LagrangeTablePoints, PrecomputeLagrange};
use verkle_trie::committer::Committer;
use verkle_trie::constants::CRS;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LagrangeCommitter {
    inner: PrecomputeLagrange,
}

impl Committer for LagrangeCommitter {
    fn commit_lagrange(&self, evaluations: &[Fr]) -> EdwardsProjective {
        self.inner.commit_lagrange(evaluations)
    }

    fn scalar_mul(&self, value: Fr, lagrange_index: usize) -> EdwardsProjective {
        self.inner.scalar_mul(value, lagrange_index)
    }
}

impl Default for LagrangeCommitter {
    fn default() -> Self {
        let g_aff: Vec<_> = CRS.G.iter().map(|point| point.into_affine()).collect();
        let committer = PrecomputeLagrange::precompute(&g_aff);
        LagrangeCommitter { inner: committer }
    }
}
