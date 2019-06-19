mod util;

extern crate rcgen;

use rcgen::{RcgenError, KeyPair, Certificate};

#[test]
fn test_key_params_mismatch() {
	let available_key_params = [
		&rcgen::PKCS_RSA_SHA256,
		&rcgen::PKCS_ECDSA_P256_SHA256,
		&rcgen::PKCS_ECDSA_P384_SHA384,
		&rcgen::PKCS_ED25519,
	];
	for (i, kalg_1) in available_key_params.iter().enumerate() {
		for (j, kalg_2) in available_key_params.iter().enumerate() {
			if i == j {
				continue;
			}
			let mut wrong_params = util::default_params();
			if i != 0 {
				wrong_params.key_pair = Some(KeyPair::generate(kalg_1).unwrap());
			} else {
				let kp = KeyPair::from_pem(util::RSA_TEST_KEY_PAIR_PEM).unwrap();
				wrong_params.key_pair = Some(kp);
			}
			wrong_params.alg = *kalg_2;

			assert_eq!(
				Certificate::from_params(wrong_params).err(),
				Some(RcgenError::CertificateKeyPairMismatch),
				"i: {} j: {}", i, j);
		}
	}
}
