mod util;

use rcgen::{RcgenError, KeyPair, Certificate};
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

fn generate_hash<T: Hash>(subject: &T) -> u64 {
	let mut hasher = DefaultHasher::new();
	subject.hash(&mut hasher);
	hasher.finish()
}

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
				assert_eq!(*kalg_1, *kalg_2);
				assert_eq!(generate_hash(*kalg_1), generate_hash(*kalg_2));
				continue;
			}

			assert_ne!(*kalg_1, *kalg_2);
			assert_ne!(generate_hash(*kalg_1), generate_hash(*kalg_2));

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

#[cfg(feature = "x509-parser")]
mod test_convert_x509_subject_alternative_name {
	use std::net::{IpAddr, Ipv4Addr};
	use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa, KeyPair, PKCS_ECDSA_P256_SHA256, SanType};

	#[test]
	fn converts_from_ip() {
		let ip = Ipv4Addr::new(2, 4, 6, 8);
		let ip_san = SanType::IpAddress(IpAddr::V4(ip));

		let mut params = super::util::default_params();

		// Add the SAN we want to test the parsing for
		params.subject_alt_names.push(ip_san.clone());

		// Because we're using a function for CA certificates
		params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

		let cert = Certificate::from_params(params).unwrap();

		// Serialize our cert that has our chosen san, so we can testing parsing/deserializing it.
		let ca_der = cert.serialize_der().unwrap();

		// Arbitrary key pair not used with the test, but required by the parsing function
		let key_pair = KeyPair::generate(&PKCS_ECDSA_P256_SHA256).unwrap();

		let actual = CertificateParams::from_ca_cert_der(&ca_der, key_pair).unwrap();

		assert!(actual.subject_alt_names.contains(&ip_san));
	}
}
