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

#[cfg(feature = "x509-parser")]
mod test_x509_parser_crl {
	use x509_parser::num_bigint::BigUint;
	use x509_parser::prelude::{FromDer, X509Certificate};
	use x509_parser::revocation_list::CertificateRevocationList;
	use x509_parser::x509::X509Version;
	use crate::util;

	#[test]
	fn parse_crl() {
		// Create a CRL with one revoked cert, and an issuer to sign the CRL.
		let (crl, issuer) = util::test_crl();
		let revoked_cert = crl.get_params().revoked_certs.first().unwrap();
		let revoked_cert_serial = BigUint::from_bytes_be(revoked_cert.serial_number.as_ref());
		let issuer_der = issuer.serialize_der().unwrap();
		let (_, x509_issuer) = X509Certificate::from_der(&issuer_der).unwrap();

		// Serialize the CRL signed by the issuer in DER form.
		let crl_der = crl.serialize_der_with_signer(&issuer).unwrap();

		// We should be able to parse the CRL with x509-parser without error.
		let (_, x509_crl) = CertificateRevocationList::from_der(&crl_der)
			.expect("failed to parse CRL DER");

		// The properties of the CRL should match expected.
		assert_eq!(x509_crl.version().unwrap(), X509Version(1));
		assert_eq!(x509_crl.issuer(), x509_issuer.subject());
		assert_eq!(x509_crl.last_update().to_datetime().unix_timestamp(),
				   crl.get_params().this_update.unix_timestamp());
		assert_eq!(x509_crl.next_update().unwrap().to_datetime().unix_timestamp(),
				   crl.get_params().next_update.unix_timestamp());
		// TODO(XXX): Waiting on https://github.com/rusticata/x509-parser/pull/144
		// let crl_number = BigUint::from_bytes_be(crl.get_params().crl_number.as_ref());
		// assert_eq!(x509_crl.crl_number().unwrap(), &crl_number);

		// We should find the expected revoked certificate serial with the correct reason code.
		let x509_revoked_cert = x509_crl.iter_revoked_certificates().next()
			.expect("failed to find revoked cert in CRL");
		assert_eq!(x509_revoked_cert.user_certificate, revoked_cert_serial);
		let (_, reason_code) = x509_revoked_cert.reason_code().unwrap();
	 	assert_eq!(reason_code.0, revoked_cert.reason_code.unwrap() as u8);

		// We should be able to verify the CRL signature with the issuer.
		assert!(x509_crl.verify_signature(&x509_issuer.public_key()).is_ok());
	}
}

#[cfg(feature = "x509-parser")]
mod test_parse_crl_dps {
	use x509_parser::extensions::{DistributionPointName, ParsedExtension};
	use crate::util;

	#[test]
	fn parse_crl_dps() {
		// Generate and parse a certificate that includes two CRL distribution points.
		let der = util::cert_with_crl_dps();
		let (_, parsed_cert) = x509_parser::parse_x509_certificate(&der).unwrap();

		// We should find a CRL DP extension was parsed.
		let crl_dps = parsed_cert.get_extension_unique(&x509_parser::oid_registry::OID_X509_EXT_CRL_DISTRIBUTION_POINTS)
			.expect("malformed CRL distribution points extension")
			.expect("missing CRL distribution points extension");

		// The extension should not be critical.
		assert!(!crl_dps.critical);

		// We should be able to parse the definition.
		let crl_dps = match crl_dps.parsed_extension() {
			ParsedExtension::CRLDistributionPoints(crl_dps) => crl_dps,
			_ => panic!("unexpected parsed extension type")
		};

		// There should be two DPs.
		assert_eq!(crl_dps.points.len(), 2);

		// Each distribution point should only include a distribution point name holding a sequence
		// of general names.
		let general_names = crl_dps.points.iter().flat_map(|dp| {
			// We shouldn't find a cRLIssuer or onlySomeReasons field.
			assert!(dp.crl_issuer.is_none());
			assert!(dp.reasons.is_none());

			match dp.distribution_point.as_ref().expect("missing distribution point name") {
				DistributionPointName::FullName(general_names) => general_names.iter(),
				DistributionPointName::NameRelativeToCRLIssuer(_) => panic!("unexpected name relative to cRL issuer")
			}
		}).collect::<Vec<_>>();

		// All of the general names should be URIs.
		let uris = general_names.iter().map(|general_name| {
			match general_name {
				x509_parser::extensions::GeneralName::URI(uri) => *uri,
				_ => panic!("unexpected general name type")
			}
		}).collect::<Vec<_>>();

		// We should find the expected URIs.
		assert_eq!(uris, &["http://example.com/crl.der", "http://crls.example.com/1234", "ldap://example.com/crl.der"]);
	}
}
