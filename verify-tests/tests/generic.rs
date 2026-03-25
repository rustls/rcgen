#[cfg(feature = "pem")]
mod test_key_params_mismatch {
	use std::collections::hash_map::DefaultHasher;
	use std::hash::{Hash, Hasher};

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
			#[cfg(feature = "aws_lc_rs")]
			&rcgen::PKCS_ECDSA_P521_SHA256,
			#[cfg(feature = "aws_lc_rs")]
			&rcgen::PKCS_ECDSA_P521_SHA384,
			#[cfg(feature = "aws_lc_rs")]
			&rcgen::PKCS_ECDSA_P521_SHA512,
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
				let names = [format!("{kalg_1:?}"), format!("{kalg_2:?}")];
				if names.into_iter().all(|n| n.starts_with("PKCS_ECDSA_P521")) {
					continue;
				}

				assert_ne!(
					generate_hash(*kalg_1),
					generate_hash(*kalg_2),
					"{kalg_1:?} vs {kalg_2:?}",
				);
			}
		}
	}
}

#[cfg(feature = "x509-parser")]
mod test_x509_custom_ext {
	use rcgen::CustomExtension;
	use verify_tests as util;
	use x509_parser::oid_registry::asn1_rs;
	use x509_parser::prelude::{
		FromDer, ParsedCriAttribute, X509Certificate, X509CertificationRequest,
	};

	#[test]
	fn custom_ext() {
		// Create an imaginary critical custom extension for testing.
		let test_oid = asn1_rs::Oid::from(&[2, 5, 29, 999999]).unwrap();
		let test_ext = yasna::construct_der(|writer| {
			writer.write_utf8_string("🦀 greetz to ferris 🦀");
		});
		let mut custom_ext = CustomExtension::from_oid_content(
			test_oid.iter().unwrap().collect::<Vec<u64>>().as_slice(),
			test_ext.clone(),
		);
		custom_ext.set_criticality(true);

		// Generate a certificate with the custom extension, parse it with x509-parser.
		let (mut params, test_key) = util::default_params();
		params.custom_extensions = vec![custom_ext];
		// Ensure the custom exts. being omitted into a CSR doesn't require SAN ext being present.
		// See https://github.com/rustls/rcgen/issues/122
		params.subject_alt_names = Vec::default();
		let test_cert = params.self_signed(&test_key).unwrap();
		let (_, x509_test_cert) = X509Certificate::from_der(test_cert.der()).unwrap();

		// We should be able to find the extension by OID, with expected criticality and value.
		let favorite_drink_ext = x509_test_cert
			.get_extension_unique(&test_oid)
			.expect("invalid extensions")
			.expect("missing custom extension");
		assert!(favorite_drink_ext.critical);
		assert_eq!(favorite_drink_ext.value, test_ext);

		// Generate a CSR with the custom extension, parse it with x509-parser.
		let test_cert_csr = params.serialize_request(&test_key).unwrap();
		let (_, x509_csr) = X509CertificationRequest::from_der(test_cert_csr.der()).unwrap();

		// We should find that the CSR contains requested extensions.
		// Note: we can't use `x509_csr.requested_extensions()` here because it maps the raw extension
		// request extensions to their parsed form, and of course x509-parser doesn't parse our custom extension.
		let exts = x509_csr
			.certification_request_info
			.iter_attributes()
			.find_map(|attr| {
				if let ParsedCriAttribute::ExtensionRequest(requested) = &attr.parsed_attribute() {
					Some(requested.extensions.iter().collect::<Vec<_>>())
				} else {
					None
				}
			})
			.expect("missing requested extensions");

		// We should find the custom extension with expected criticality and value.
		let custom_ext = exts
			.iter()
			.find(|ext| ext.oid == test_oid)
			.expect("missing requested custom extension");
		assert!(custom_ext.critical);
		assert_eq!(custom_ext.value, test_ext);
	}
}

#[cfg(feature = "x509-parser")]
mod test_csr_custom_attributes {
	use rcgen::{Attribute, CertificateParams, KeyPair};
	use x509_parser::der_parser::Oid;
	use x509_parser::prelude::{FromDer, X509CertificationRequest};

	/// Test serializing a CSR with custom attributes.
	/// This test case uses `challengePassword` from [RFC 2985], a simple
	/// ATTRIBUTE that contains a single UTF8String.
	///
	/// [RFC 2985]: <https://datatracker.ietf.org/doc/html/rfc2985>
	#[test]
	fn test_csr_custom_attributes() {
		// OID for challengePassword
		const CHALLENGE_PWD_OID: &[u64] = &[1, 2, 840, 113549, 1, 9, 7];

		// Attribute values for challengePassword
		let challenge_pwd_values = yasna::try_construct_der::<_, ()>(|writer| {
			// Reminder: CSR attribute values are contained in a SET
			writer.write_set(|writer| {
				// Challenge passwords only have one value, a UTF8String
				writer
					.next()
					.write_utf8_string("nobody uses challenge passwords anymore");
				Ok(())
			})
		})
		.unwrap();

		// Challenge password attribute
		let challenge_password_attribute = Attribute {
			oid: CHALLENGE_PWD_OID,
			values: challenge_pwd_values.clone(),
		};

		// Serialize a DER-encoded CSR
		let params = CertificateParams::default();
		let key_pair = KeyPair::generate().unwrap();
		let csr = params
			.serialize_request_with_attributes(&key_pair, vec![challenge_password_attribute])
			.unwrap();

		// Parse the CSR
		let (_, x509_csr) = X509CertificationRequest::from_der(csr.der()).unwrap();
		let parsed_attribute_value = x509_csr
			.certification_request_info
			.attributes_map()
			.unwrap()
			.get(&Oid::from(CHALLENGE_PWD_OID).unwrap())
			.unwrap()
			.value;
		assert_eq!(parsed_attribute_value, challenge_pwd_values);
	}
}

#[cfg(feature = "x509-parser")]
mod test_csr_basic_constraints {
	use rcgen::{BasicConstraints, CertificateSigningRequestParams, Error, IsCa};

	/// Tests deserializing a csr with a basic constraint of CA:TRUE,pathlen:5
	///
	/// This should deserialize fine to a ca constrained to 5
	#[test]
	fn test_csr_basic_constraints_true_pathlen() {
		let csr_params =
			CertificateSigningRequestParams::from_pem(CSR_TEST_BASIC_CONSTRAINTS_CA_TRUE_5_PEM)
				.unwrap();

		assert_eq!(
			csr_params.params.is_ca,
			IsCa::Ca(BasicConstraints::Constrained(5))
		);
	}

	/*
	Generated by: openssl req -new -key ./tmp.key \
	 -subj "/CN=test.local" -addext "basicConstraints=CA:TRUE,pathlen:5"
	Where `verify_tests::RSA_TEST_KEY_PAIR_PEM`'s content is stored in ./tmp.key
	 */
	const CSR_TEST_BASIC_CONSTRAINTS_CA_TRUE_5_PEM: &str = r#"
-----BEGIN CERTIFICATE REQUEST-----
MIICfDCCAWQCAQAwFTETMBEGA1UEAwwKdGVzdC5sb2NhbDCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBANiOaDJXf8tKLMletisBNmus+vYR2jzKI6AEsWaL
iyB4Z1DmfqeGNMZ8EQg/YhrrP6FuIY4ydxpsQFzOR0wT4kVhUJKRLuviK8w7OnZ6
DEuBw8px6sGhcjwNRseEhH3Pz2UeI8cMm/f53QBzVv1vP1vw4B5laJCYW+aOltzY
N+FDY4XHYzAVkJgXX3qutc5zr9JHZ6xlVGuRbbZEEoVODPoYgDkD/lVYoghJKoQH
WA5wzPaKrn3zsjbz4TPitwtnaUHtxntNs3GQDC3R88v4S7I/tc7NsiPj+RICVTnF
/A0RFrcES44WujiLkSZIOP6VHnF1GkWfHSPnM6jNQvaUcb0CAwEAAaAiMCAGCSqG
SIb3DQEJDjETMBEwDwYDVR0TBAgwBgEB/wIBBTANBgkqhkiG9w0BAQsFAAOCAQEA
T9NEuWv7p/zJgGPEROpd7f6uguZU0fldW8c6NdilYSYTWGk2CKxK1tV77Dh34TWX
c/KtDONZ26lsJzgxZ4anDJ91Qi7SAPzPK5aqSfR4kOAfSmtlg/iAHPJxOcyeEDCQ
s0WPMbnDQs7mzPH8rEQyjeEj+wqnuG75eNWw4Vaz67dLYDrGEhm799tpZcaRhIvH
suZNckh3DzhMHTstIMxMhlrjFuoe8OvzGfcNAOJYYz+T4E4PZWsNDXKi67iTtsbz
JotPi403/0BNGtis/EjzClzSOHKJvWvA2dn7XEoQx3yTMWqGf3p1GEwYPBcFKCN1
p5evxprnXDk0qMh66vSZ3Q==
-----END CERTIFICATE REQUEST-----
"#;

	/// Tests deserializing a csr with a basic constraint of CA:TRUE,pathlen:256
	///
	/// This should be too large for a u8 and fail
	#[test]
	fn test_csr_basic_constraints_true_pathlen_too_large() {
		let result =
			CertificateSigningRequestParams::from_pem(CSR_TEST_BASIC_CONSTRAINTS_CA_TRUE_256_PEM);

		assert_eq!(result.unwrap_err(), Error::CouldNotParseCertificate);
	}

	/*
	Generated by: openssl req -new -key ./tmp.key \
	 -subj "/CN=test.local" -addext "basicConstraints=CA:TRUE,pathlen:256"
	Where `verify_tests::RSA_TEST_KEY_PAIR_PEM`'s content is stored in ./tmp.key
	 */
	const CSR_TEST_BASIC_CONSTRAINTS_CA_TRUE_256_PEM: &str = r#"
-----BEGIN CERTIFICATE REQUEST-----
MIICfTCCAWUCAQAwFTETMBEGA1UEAwwKdGVzdC5sb2NhbDCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBANiOaDJXf8tKLMletisBNmus+vYR2jzKI6AEsWaL
iyB4Z1DmfqeGNMZ8EQg/YhrrP6FuIY4ydxpsQFzOR0wT4kVhUJKRLuviK8w7OnZ6
DEuBw8px6sGhcjwNRseEhH3Pz2UeI8cMm/f53QBzVv1vP1vw4B5laJCYW+aOltzY
N+FDY4XHYzAVkJgXX3qutc5zr9JHZ6xlVGuRbbZEEoVODPoYgDkD/lVYoghJKoQH
WA5wzPaKrn3zsjbz4TPitwtnaUHtxntNs3GQDC3R88v4S7I/tc7NsiPj+RICVTnF
/A0RFrcES44WujiLkSZIOP6VHnF1GkWfHSPnM6jNQvaUcb0CAwEAAaAjMCEGCSqG
SIb3DQEJDjEUMBIwEAYDVR0TBAkwBwEB/wICAQAwDQYJKoZIhvcNAQELBQADggEB
AJvBfceI2fbBwW/wjtOJYUlYJR72X8ZeMSbRkl0hbd+UxjB7uces5aq0RTXALYGx
Ikw3ZWf4aODxeWHWGzESJMBowi5DWunVwmM3Qu7SNVPQfBgZ79LVkjz5c1Ig9TXv
avZnsmojq2/q2xBllK27nbhlsaNcM+SJEX4BiuYkDoCL13bmzwgnbFMR2gyWE7qD
WQiZbH+NRvQbdu7PSzYHIzc6e4p+k2dub6P8aW2hB+XOfMJecWwYKO2d+vo0M0FA
bpKr1I9iw98R+A3WMfEsWVpCEERQtu7t3N4Pd97sLKoa3woGBfHk9BoGM8zCdneG
RioOvAyCH6bFMvSJxZm7FYM=
-----END CERTIFICATE REQUEST-----
"#;

	/// Tests deserializing a csr with a basic constraint of CA:TRUE
	///
	/// This should deserialize fine to a ca unconstrained
	#[test]
	fn test_csr_basic_constraints_true() {
		let csr_params =
			CertificateSigningRequestParams::from_pem(CSR_TEST_BASIC_CONSTRAINTS_CA_TRUE).unwrap();

		assert_eq!(
			csr_params.params.is_ca,
			IsCa::Ca(BasicConstraints::Unconstrained)
		);
	}

	/*
	Generated by: openssl req -new -key ./tmp.key \
	 -subj "/CN=test.local" -addext "basicConstraints=CA:TRUE"
	Where `verify_tests::RSA_TEST_KEY_PAIR_PEM`'s content is stored in ./tmp.key
	 */
	const CSR_TEST_BASIC_CONSTRAINTS_CA_TRUE: &str = r#"
-----BEGIN CERTIFICATE REQUEST-----
MIICeTCCAWECAQAwFTETMBEGA1UEAwwKdGVzdC5sb2NhbDCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBANiOaDJXf8tKLMletisBNmus+vYR2jzKI6AEsWaL
iyB4Z1DmfqeGNMZ8EQg/YhrrP6FuIY4ydxpsQFzOR0wT4kVhUJKRLuviK8w7OnZ6
DEuBw8px6sGhcjwNRseEhH3Pz2UeI8cMm/f53QBzVv1vP1vw4B5laJCYW+aOltzY
N+FDY4XHYzAVkJgXX3qutc5zr9JHZ6xlVGuRbbZEEoVODPoYgDkD/lVYoghJKoQH
WA5wzPaKrn3zsjbz4TPitwtnaUHtxntNs3GQDC3R88v4S7I/tc7NsiPj+RICVTnF
/A0RFrcES44WujiLkSZIOP6VHnF1GkWfHSPnM6jNQvaUcb0CAwEAAaAfMB0GCSqG
SIb3DQEJDjEQMA4wDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAGzzg
376bY6J2+bnhmbsxjFGrbI57OvIEefQxQ+1vAHirvdAvXMZcV5Y3CRZdIg3t0/0j
2B+K2dqHuEMlSYp0fBa76A/qUGfujucq04ti2xau1Pd2Nmx9KA9eFZ2g1yGkSCEH
Dt9lS7NjYOGIU5QkvCChJUaP5pFxn3HIFuWzLRjuvS7wiHAB5hMU479cmF0zu3Qs
l5B/4S4l8rcX1uLfRviiOJSrSpoTJDJjQwsks6j/iu99cYBmULLNrpUP+sIYP7hZ
IJgMpHPIiotOsYV16GPOStG9Fyz3bKH6NFWwkC4ncGul7wzQdXj/qr29HNmP+2fB
lZLnFMmv1pkn052qtQ==
-----END CERTIFICATE REQUEST-----
"#;

	/// Tests deserializing a csr with a basic constraint of CA:TRUE
	///
	/// This should deserialize fine to explicitly no ca
	#[test]
	fn test_csr_basic_constraints_false() {
		let csr_params =
			CertificateSigningRequestParams::from_pem(CSR_TEST_BASIC_CONSTRAINTS_CA_FALSE).unwrap();

		assert_eq!(csr_params.params.is_ca, IsCa::ExplicitNoCa);
	}

	/*
	Generated by: openssl req -new -key ./tmp.key \
	 -subj "/CN=test.local" -addext "basicConstraints=CA:FALSE"
	Where `verify_tests::RSA_TEST_KEY_PAIR_PEM`'s content is stored in ./tmp.key
	 */
	const CSR_TEST_BASIC_CONSTRAINTS_CA_FALSE: &str = r#"
-----BEGIN CERTIFICATE REQUEST-----
MIICdjCCAV4CAQAwFTETMBEGA1UEAwwKdGVzdC5sb2NhbDCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBANiOaDJXf8tKLMletisBNmus+vYR2jzKI6AEsWaL
iyB4Z1DmfqeGNMZ8EQg/YhrrP6FuIY4ydxpsQFzOR0wT4kVhUJKRLuviK8w7OnZ6
DEuBw8px6sGhcjwNRseEhH3Pz2UeI8cMm/f53QBzVv1vP1vw4B5laJCYW+aOltzY
N+FDY4XHYzAVkJgXX3qutc5zr9JHZ6xlVGuRbbZEEoVODPoYgDkD/lVYoghJKoQH
WA5wzPaKrn3zsjbz4TPitwtnaUHtxntNs3GQDC3R88v4S7I/tc7NsiPj+RICVTnF
/A0RFrcES44WujiLkSZIOP6VHnF1GkWfHSPnM6jNQvaUcb0CAwEAAaAcMBoGCSqG
SIb3DQEJDjENMAswCQYDVR0TBAIwADANBgkqhkiG9w0BAQsFAAOCAQEAJ14zBkXP
VmllImMlJ4BeQZkBEKj60hMu7xJLiy0isdt7R1q6Hwaot7ibS9magRhhBQDE64dA
U0UX+3T97eDf8vT0g1A7KBILE9dHFAmB6RuzYXX1BNXQSmFQ8ygUbvf9uZYwG4/o
YAYYRuGyw3Nah2KJIMJMlNLaowrQojas0tHQnelBv6phHwi8eDKZnQgvHOczJkGH
+0+KrUr5Vh9DzMZSfiqCaKu3JbfEHuypPEzNGBEhP75c1+9j8khpsM6nEMB8CuGn
t7TyFr3lPp7qn5metrd8n9soFSodJqb3bkcLHKGCUbHY74wMylZLBdKNd0esQpZ1
9n2hz8T5m4UTlg==
-----END CERTIFICATE REQUEST-----
"#;
}

#[cfg(feature = "x509-parser")]
mod test_x509_parser_crl {
	use verify_tests as util;
	use x509_parser::extensions::{DistributionPointName, ParsedExtension};
	use x509_parser::num_bigint::BigUint;
	use x509_parser::prelude::{FromDer, GeneralName, IssuingDistributionPoint, X509Certificate};
	use x509_parser::revocation_list::CertificateRevocationList;
	use x509_parser::x509::X509Version;

	#[test]
	fn parse_crl() {
		// Create a CRL with one revoked cert, and an issuer to sign the CRL.
		let (crl_params, crl, issuer) = util::test_crl();
		let revoked_cert = crl_params.revoked_certs.first().unwrap();
		let revoked_cert_serial = BigUint::from_bytes_be(revoked_cert.serial_number.as_ref());
		let (_, x509_issuer) = X509Certificate::from_der(issuer.der()).unwrap();

		// We should be able to parse the CRL with x509-parser without error.
		let (_, x509_crl) =
			CertificateRevocationList::from_der(crl.der()).expect("failed to parse CRL DER");

		// The properties of the CRL should match expected.
		assert_eq!(x509_crl.version().unwrap(), X509Version(1));
		assert_eq!(x509_crl.issuer(), x509_issuer.subject());
		assert_eq!(
			x509_crl.last_update().to_datetime().unix_timestamp(),
			crl_params.this_update.unix_timestamp()
		);
		assert_eq!(
			x509_crl
				.next_update()
				.unwrap()
				.to_datetime()
				.unix_timestamp(),
			crl_params.next_update.unix_timestamp()
		);
		let crl_number = BigUint::from_bytes_be(crl_params.crl_number.as_ref());
		assert_eq!(x509_crl.crl_number().unwrap(), &crl_number);

		// We should find the expected revoked certificate serial with the correct reason code.
		let x509_revoked_cert = x509_crl
			.iter_revoked_certificates()
			.next()
			.expect("failed to find revoked cert in CRL");
		assert_eq!(x509_revoked_cert.user_certificate, revoked_cert_serial);
		let (_, reason_code) = x509_revoked_cert.reason_code().unwrap();
		assert_eq!(reason_code.0, revoked_cert.reason_code.unwrap() as u8);

		// The issuing distribution point extension should be present and marked critical.
		let issuing_dp_ext = x509_crl
			.extensions()
			.iter()
			.find(|ext| {
				ext.oid == x509_parser::oid_registry::OID_X509_EXT_ISSUER_DISTRIBUTION_POINT
			})
			.expect("failed to find issuing distribution point extension");
		assert!(issuing_dp_ext.critical);

		// The parsed issuing distribution point extension should match expected.
		let ParsedExtension::IssuingDistributionPoint(idp) = issuing_dp_ext.parsed_extension()
		else {
			panic!("missing parsed CRL IDP ext");
		};
		assert_eq!(
			idp,
			&IssuingDistributionPoint {
				only_contains_user_certs: true,
				only_contains_ca_certs: false,
				only_contains_attribute_certs: false,
				indirect_crl: false,
				only_some_reasons: None,
				distribution_point: Some(DistributionPointName::FullName(vec![GeneralName::URI(
					"http://example.com/crl",
				)])),
			}
		);

		// We should be able to verify the CRL signature with the issuer.
		assert!(x509_crl.verify_signature(x509_issuer.public_key()).is_ok());
	}
}

#[cfg(feature = "x509-parser")]
mod test_parse_crl_dps {
	use verify_tests as util;
	use x509_parser::extensions::{DistributionPointName, ParsedExtension};

	#[test]
	fn parse_crl_dps() {
		// Generate and parse a certificate that includes two CRL distribution points.
		let der = util::cert_with_crl_dps();
		let (_, parsed_cert) = x509_parser::parse_x509_certificate(&der).unwrap();

		// We should find a CRL DP extension was parsed.
		let crl_dps = parsed_cert
			.get_extension_unique(&x509_parser::oid_registry::OID_X509_EXT_CRL_DISTRIBUTION_POINTS)
			.expect("malformed CRL distribution points extension")
			.expect("missing CRL distribution points extension");

		// The extension should not be critical.
		assert!(!crl_dps.critical);

		// We should be able to parse the definition.
		let crl_dps = match crl_dps.parsed_extension() {
			ParsedExtension::CRLDistributionPoints(crl_dps) => crl_dps,
			_ => panic!("unexpected parsed extension type"),
		};

		// There should be two DPs.
		assert_eq!(crl_dps.points.len(), 2);

		// Each distribution point should only include a distribution point name holding a sequence
		// of general names.
		let general_names = crl_dps
			.points
			.iter()
			.flat_map(|dp| {
				// We shouldn't find a cRLIssuer or onlySomeReasons field.
				assert!(dp.crl_issuer.is_none());
				assert!(dp.reasons.is_none());

				match dp
					.distribution_point
					.as_ref()
					.expect("missing distribution point name")
				{
					DistributionPointName::FullName(general_names) => general_names.iter(),
					DistributionPointName::NameRelativeToCRLIssuer(_) => {
						panic!("unexpected name relative to cRL issuer")
					},
				}
			})
			.collect::<Vec<_>>();

		// All of the general names should be URIs.
		let uris = general_names
			.iter()
			.map(|general_name| match general_name {
				x509_parser::extensions::GeneralName::URI(uri) => *uri,
				_ => panic!("unexpected general name type"),
			})
			.collect::<Vec<_>>();

		// We should find the expected URIs.
		assert_eq!(
			uris,
			&[
				"http://example.com/crl.der",
				"http://crls.example.com/1234",
				"ldap://example.com/crl.der"
			]
		);
	}
}

#[cfg(feature = "x509-parser")]
mod test_csr_extension_request {
	use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};
	use x509_parser::prelude::{FromDer, ParsedExtension, X509CertificationRequest};

	#[test]
	fn dont_write_sans_extension_if_no_sans_are_present() {
		let mut params = CertificateParams::default();
		params.key_usages.push(KeyUsagePurpose::DigitalSignature);
		let key_pair = KeyPair::generate().unwrap();
		let csr = params.serialize_request(&key_pair).unwrap();
		let (_, parsed_csr) = X509CertificationRequest::from_der(csr.der()).unwrap();
		assert!(!parsed_csr
			.requested_extensions()
			.unwrap()
			.any(|ext| matches!(ext, ParsedExtension::SubjectAlternativeName(_))));
	}

	#[test]
	fn write_extension_request_if_ekus_are_present() {
		let mut params = CertificateParams::default();
		params
			.extended_key_usages
			.push(ExtendedKeyUsagePurpose::ClientAuth);
		let key_pair = KeyPair::generate().unwrap();
		let csr = params.serialize_request(&key_pair).unwrap();
		let (_, parsed_csr) = X509CertificationRequest::from_der(csr.der()).unwrap();
		let requested_extensions = parsed_csr
			.requested_extensions()
			.unwrap()
			.collect::<Vec<_>>();
		assert!(matches!(
			requested_extensions.first().unwrap(),
			ParsedExtension::ExtendedKeyUsage(_)
		));
	}
}

#[cfg(feature = "x509-parser")]
mod test_csr {
	use rcgen::{
		CertificateParams, CertificateSigningRequestParams, ExtendedKeyUsagePurpose, KeyPair,
		KeyUsagePurpose,
	};

	#[test]
	fn test_csr_roundtrip() {
		// We should be able to serialize a CSR, and then parse the CSR.
		let params = CertificateParams::default();
		generate_and_test_parsed_csr(&params);
	}

	#[test]
	fn test_csr_with_key_usages_roundtrip() {
		let mut params = CertificateParams::default();
		params.key_usages = vec![
			KeyUsagePurpose::DigitalSignature,
			KeyUsagePurpose::ContentCommitment,
			KeyUsagePurpose::KeyEncipherment,
			KeyUsagePurpose::DataEncipherment,
			KeyUsagePurpose::KeyAgreement,
			KeyUsagePurpose::KeyCertSign,
			KeyUsagePurpose::CrlSign,
			// It doesn't make sense to have both encipher and decipher only
			// So we'll take this opportunity to test omitting a key usage
			// KeyUsagePurpose::EncipherOnly,
			KeyUsagePurpose::DecipherOnly,
		];
		generate_and_test_parsed_csr(&params);
	}

	#[test]
	fn test_csr_with_extended_key_usages_roundtrip() {
		let mut params = CertificateParams::default();
		params.extended_key_usages = vec![
			ExtendedKeyUsagePurpose::ServerAuth,
			ExtendedKeyUsagePurpose::ClientAuth,
		];
		generate_and_test_parsed_csr(&params);
	}

	#[test]
	fn test_csr_with_key_usgaes_and_extended_key_usages_roundtrip() {
		let mut params = CertificateParams::default();
		params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
		params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
		generate_and_test_parsed_csr(&params);
	}

	fn generate_and_test_parsed_csr(params: &CertificateParams) {
		// Generate a key pair for the CSR
		let key_pair = KeyPair::generate().unwrap();
		// Serialize the CSR into DER from the given parameters
		let csr = params.serialize_request(&key_pair).unwrap();
		// Parse the CSR we just serialized
		let csrp = CertificateSigningRequestParams::from_der(csr.der()).unwrap();

		// Ensure algorithms match.
		assert_eq!(key_pair.algorithm(), csrp.public_key.algorithm());
		// Assert that our parsed parameters match our initial parameters
		assert_eq!(*params, csrp.params);
	}
}

#[cfg(feature = "x509-parser")]
mod test_subject_alternative_name_criticality {
	use verify_tests::default_params;
	use x509_parser::certificate::X509Certificate;
	use x509_parser::extensions::X509Extension;
	use x509_parser::{oid_registry, parse_x509_certificate};

	#[test]
	fn with_subject_sans_not_critical() {
		let (params, keypair) = default_params();
		assert!(
			!params
				.distinguished_name
				.iter()
				.collect::<Vec<_>>()
				.is_empty(),
			"non-empty subject required for test"
		);

		let cert = params.self_signed(&keypair).unwrap();
		let cert = cert.der();
		let (_, parsed) = parse_x509_certificate(cert).unwrap();
		assert!(
			!san_ext(&parsed).critical,
			"with subject, SAN ext should not be critical"
		);
	}

	#[test]
	fn without_subject_sans_critical() {
		let (mut params, keypair) = default_params();
		params.distinguished_name = Default::default();

		let cert = params.self_signed(&keypair).unwrap();
		let cert = cert.der();
		let (_, parsed) = parse_x509_certificate(cert).unwrap();
		assert!(
			san_ext(&parsed).critical,
			"without subject, SAN ext should be critical"
		);
	}

	fn san_ext<'cert>(cert: &'cert X509Certificate) -> &'cert X509Extension<'cert> {
		cert.extensions()
			.iter()
			.find(|ext| ext.oid == oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)
			.expect("missing SAN extension")
	}
}
