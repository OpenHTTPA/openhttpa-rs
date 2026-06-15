use aws_lc_rs::signature::{ML_DSA_65, ML_DSA_65_FIXED_SIGNING, MlDsaKeyPair};

pub fn test() {
    let kp = MlDsaKeyPair::generate(&ML_DSA_65_FIXED_SIGNING).unwrap();
}
