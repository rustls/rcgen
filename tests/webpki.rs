extern crate webpki;
extern crate rcgen;
extern crate ring;
extern crate pem;

#[cfg(feature = "x509-parser")]
use rcgen::{CertificateSigningRequest, DnValue};
use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair, RemoteKeyPair};
use webpki::{EndEntityCert, TlsServerTrustAnchors, TrustAnchor};
use webpki::SignatureAlgorithm;
use webpki::{Time, DnsNameRef};

use ring::{rand::SystemRandom};
use ring::signature::{self, EcdsaKeyPair, EcdsaSigningAlgorithm,
	Ed25519KeyPair, KeyPair as _, RsaEncoding, RsaKeyPair};

use std::convert::TryFrom;

mod util;

fn sign_msg_ecdsa(cert :&Certificate, msg :&[u8], alg :&'static EcdsaSigningAlgorithm) -> Vec<u8> {
	let pk_der = cert.serialize_private_key_der();
	let key_pair = EcdsaKeyPair::from_pkcs8(&alg, &pk_der).unwrap();
	let system_random = SystemRandom::new();
	let signature = key_pair.sign(&system_random, &msg).unwrap();
	signature.as_ref().to_vec()
}

fn sign_msg_ed25519(cert :&Certificate, msg :&[u8]) -> Vec<u8> {
	let pk_der = cert.serialize_private_key_der();
	let key_pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(&pk_der).unwrap();
	let signature = key_pair.sign(&msg);
	signature.as_ref().to_vec()
}

fn sign_msg_rsa(cert :&Certificate, msg :&[u8], encoding :&'static dyn RsaEncoding) -> Vec<u8> {
	let pk_der = cert.serialize_private_key_der();
	let key_pair = RsaKeyPair::from_pkcs8(&pk_der).unwrap();
	let system_random = SystemRandom::new();
	let mut signature = vec![0; key_pair.public_modulus_len()];
	key_pair.sign(encoding, &system_random, &msg,
		&mut signature).unwrap();
	signature
}

fn check_cert<'a, 'b>(cert_der :&[u8], cert :&'a Certificate, alg :&SignatureAlgorithm,
		sign_fn :impl FnOnce(&'a Certificate, &'b [u8]) -> Vec<u8>) {
	println!("{}", cert.serialize_pem().unwrap());
	check_cert_ca(cert_der, cert, cert_der, alg, alg, sign_fn);
}

fn check_cert_ca<'a, 'b>(cert_der :&[u8], cert :&'a Certificate, ca_der :&[u8],
		cert_alg :&SignatureAlgorithm, ca_alg :&SignatureAlgorithm,
		sign_fn :impl FnOnce(&'a Certificate, &'b [u8]) -> Vec<u8>) {
	let trust_anchor = TrustAnchor::try_from_cert_der(&ca_der).unwrap();
	let trust_anchor_list = &[trust_anchor];
	let trust_anchors = TlsServerTrustAnchors(trust_anchor_list);
	let end_entity_cert = EndEntityCert::try_from(cert_der).unwrap();

	// Set time to Jan 10, 2004
	let time = Time::from_seconds_since_unix_epoch(0x40_00_00_00);

	// (1/3) Check whether the cert is valid
	end_entity_cert.verify_is_valid_tls_server_cert(
		&[&cert_alg, &ca_alg],
		&trust_anchors,
		&[],
		time,
	).expect("valid TLS server cert");

	// (2/3) Check that the cert is valid for the given DNS name
	let dns_name = DnsNameRef::try_from_ascii_str("crabs.crabs").unwrap();
	end_entity_cert.verify_is_valid_for_dns_name(
		dns_name,
	).expect("valid for DNS name");

	// (3/3) Check that a message signed by the cert is valid.
	let msg = b"Hello, World! This message is signed.";
	let signature = sign_fn(&cert, msg);
	end_entity_cert.verify_signature(
		&cert_alg,
		msg,
		&signature,
	).expect("signature is valid");
}

#[test]
fn test_webpki() {
	let params = util::default_params();
	let cert = Certificate::from_params(params).unwrap();

	// Now verify the certificate.
	let cert_der = cert.serialize_der().unwrap();

	let sign_fn = |cert, msg| sign_msg_ecdsa(cert, msg,
		&signature::ECDSA_P256_SHA256_ASN1_SIGNING);
	check_cert(&cert_der, &cert, &webpki::ECDSA_P256_SHA256, sign_fn);
}

#[test]
fn test_webpki_256() {
	let mut params = util::default_params();
	params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;

	let cert = Certificate::from_params(params).unwrap();

	// Now verify the certificate.
	let cert_der = cert.serialize_der().unwrap();

	let sign_fn = |cert, msg| sign_msg_ecdsa(cert, msg,
		&signature::ECDSA_P256_SHA256_ASN1_SIGNING);
	check_cert(&cert_der, &cert, &webpki::ECDSA_P256_SHA256, sign_fn);
}

#[test]
fn test_webpki_384() {
	let mut params = util::default_params();
	params.alg = &rcgen::PKCS_ECDSA_P384_SHA384;

	let cert = Certificate::from_params(params).unwrap();

	// Now verify the certificate.
	let cert_der = cert.serialize_der().unwrap();

	let sign_fn = |cert, msg| sign_msg_ecdsa(cert, msg,
		&signature::ECDSA_P384_SHA384_ASN1_SIGNING);
	check_cert(&cert_der, &cert, &webpki::ECDSA_P384_SHA384, sign_fn);
}

#[test]
fn test_webpki_25519() {
	let mut params = util::default_params();
	params.alg = &rcgen::PKCS_ED25519;

	let cert = Certificate::from_params(params).unwrap();

	// Now verify the certificate.
	let cert_der = cert.serialize_der().unwrap();

	check_cert(&cert_der, &cert, &webpki::ED25519, &sign_msg_ed25519);
}

#[test]
fn test_webpki_25519_v1_given() {
	let mut params = util::default_params();
	params.alg = &rcgen::PKCS_ED25519;

	let kp = rcgen::KeyPair::from_pem(util::ED25519_TEST_KEY_PAIR_PEM_V1).unwrap();
	params.key_pair = Some(kp);

	let cert = Certificate::from_params(params).unwrap();

	// Now verify the certificate.
	let cert_der = cert.serialize_der().unwrap();

	check_cert(&cert_der, &cert, &webpki::ED25519, &sign_msg_ed25519);
}

#[test]
fn test_webpki_25519_v2_given() {
	let mut params = util::default_params();
	params.alg = &rcgen::PKCS_ED25519;

	let kp = rcgen::KeyPair::from_pem(util::ED25519_TEST_KEY_PAIR_PEM_V2).unwrap();
	params.key_pair = Some(kp);

	let cert = Certificate::from_params(params).unwrap();

	// Now verify the certificate.
	let cert_der = cert.serialize_der().unwrap();

	check_cert(&cert_der, &cert, &webpki::ED25519, &sign_msg_ed25519);
}

#[test]
fn test_webpki_rsa_given() {
	let mut params = util::default_params();
	params.alg = &rcgen::PKCS_RSA_SHA256;

	let kp = rcgen::KeyPair::from_pem(util::RSA_TEST_KEY_PAIR_PEM).unwrap();
	params.key_pair = Some(kp);

	let cert = Certificate::from_params(params).unwrap();

	// Now verify the certificate.
	let cert_der = cert.serialize_der().unwrap();

	check_cert(&cert_der, &cert, &webpki::RSA_PKCS1_2048_8192_SHA256,
		|msg, cert| sign_msg_rsa(msg, cert, &signature::RSA_PKCS1_SHA256));
}

#[test]
fn test_webpki_rsa_combinations_given() {
	let configs :&[(_, _, &'static dyn signature::RsaEncoding)] = &[
		(&rcgen::PKCS_RSA_SHA256, &webpki::RSA_PKCS1_2048_8192_SHA256, &signature::RSA_PKCS1_SHA256),
		(&rcgen::PKCS_RSA_SHA384, &webpki::RSA_PKCS1_2048_8192_SHA384, &signature::RSA_PKCS1_SHA384),
		(&rcgen::PKCS_RSA_SHA512, &webpki::RSA_PKCS1_2048_8192_SHA512, &signature::RSA_PKCS1_SHA512),
		//(&rcgen::PKCS_RSA_PSS_SHA256, &webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY, &signature::RSA_PSS_SHA256),
	];
	for c in configs {
		let mut params = util::default_params();
		params.alg = c.0;
		let kp = rcgen::KeyPair::from_pem_and_sign_algo(util::RSA_TEST_KEY_PAIR_PEM, c.0).unwrap();
		params.key_pair = Some(kp);

		let cert = Certificate::from_params(params).unwrap();

		// Now verify the certificate.
		let cert_der = cert.serialize_der().unwrap();

		check_cert(&cert_der, &cert, c.1,
			|msg, cert| sign_msg_rsa(msg, cert, c.2));
	}
}

#[test]
fn test_webpki_separate_ca() {
	let mut params = util::default_params();
	params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
	let ca_cert = Certificate::from_params(params).unwrap();

	let ca_der = ca_cert.serialize_der().unwrap();

	let mut params = CertificateParams::new(vec!["crabs.crabs".to_string()]);
	params.distinguished_name.push(DnType::OrganizationName, "Crab widgits SE");
	params.distinguished_name.push(DnType::CommonName, "Dev domain");

	let cert = Certificate::from_params(params).unwrap();
	let cert_der = cert.serialize_der_with_signer(&ca_cert).unwrap();

	let sign_fn = |cert, msg| sign_msg_ecdsa(cert, msg,
		&signature::ECDSA_P256_SHA256_ASN1_SIGNING);
	check_cert_ca(&cert_der, &cert, &ca_der,
		&webpki::ECDSA_P256_SHA256, &webpki::ECDSA_P256_SHA256, sign_fn);
}

#[test]
fn test_webpki_separate_ca_with_other_signing_alg() {
	let mut params = util::default_params();
	params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
	params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
	let ca_cert = Certificate::from_params(params).unwrap();

	let ca_der = ca_cert.serialize_der().unwrap();

	let mut params = CertificateParams::new(vec!["crabs.crabs".to_string()]);
	params.alg = &rcgen::PKCS_ED25519;
	params.distinguished_name.push(DnType::OrganizationName, "Crab widgits SE");
	params.distinguished_name.push(DnType::CommonName, "Dev domain");

	let cert = Certificate::from_params(params).unwrap();
	let cert_der = cert.serialize_der_with_signer(&ca_cert).unwrap();

	check_cert_ca(&cert_der, &cert, &ca_der,
				&webpki::ED25519, &webpki::ECDSA_P256_SHA256, sign_msg_ed25519);
}

#[test]
fn from_remote() {
	struct Remote(EcdsaKeyPair);

	impl RemoteKeyPair for Remote {
		fn public_key(&self) -> &[u8] {
			self.0.public_key().as_ref()
		}

		fn sign(&self, msg :&[u8]) -> Result<Vec<u8>, rcgen::RcgenError> {
			let system_random = SystemRandom::new();
			self.0.sign(&system_random, msg)
				.map(|s| s.as_ref().to_owned())
				.map_err(rcgen::RcgenError::from)
		}

		fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
			&rcgen::PKCS_ECDSA_P256_SHA256
		}
	}

	let key_pair = KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
	let remote = EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &key_pair.serialize_der()).unwrap();
	let key_pair = EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &key_pair.serialize_der()).unwrap();
	let remote = KeyPair::from_remote(Box::new(Remote(remote))).unwrap();

	let mut params = util::default_params();
	params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
	params.key_pair = Some(remote);
	let cert = Certificate::from_params(params).unwrap();

	// Now verify the certificate.
	let cert_der = cert.serialize_der().unwrap();

	let sign_fn = move |_, msg| {
		let system_random = SystemRandom::new();
		let signature = key_pair.sign(&system_random, msg).unwrap();
		signature.as_ref().to_vec()
	};
	check_cert(&cert_der, &cert, &webpki::ECDSA_P256_SHA256, sign_fn);
}

/*
// TODO https://github.com/briansmith/webpki/issues/134
// TODO https://github.com/briansmith/webpki/issues/135
#[test]
fn test_webpki_separate_ca_name_constraints() {
	let mut params = util::default_params();
	params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
	params.name_constraints = Some(NameConstraints {
		// TODO also add a test with non-empty permitted_subtrees that
		// doesn't contain a DirectoryName entry. This isn't possible
		// currently due to a limitation of webpki.
		permitted_subtrees : vec![GeneralSubtree::DnsName("dev".to_string()), GeneralSubtree::DirectoryName(rcgen::DistinguishedName::new())],
		//permitted_subtrees : vec![GeneralSubtree::DnsName("dev".to_string())],
		//permitted_subtrees : Vec::new(),
		//excluded_subtrees : vec![GeneralSubtree::DnsName("v".to_string())],
		excluded_subtrees : Vec::new(),
	});

	let ca_cert = Certificate::from_params(params).unwrap();
	println!("{}", ca_cert.serialize_pem().unwrap());

	let ca_der = ca_cert.serialize_der().unwrap();

	let mut params = CertificateParams::new(vec!["crabs.dev".to_string()]);
	params.distinguished_name = rcgen::DistinguishedName::new();
	//params.distinguished_name.push(DnType::OrganizationName, "Crab widgits SE");
	//params.distinguished_name.push(DnType::CommonName, "Dev domain");
	let cert = Certificate::from_params(params).unwrap();
	let cert_der = cert.serialize_der_with_signer(&ca_cert).unwrap();
	println!("{}", cert.serialize_pem_with_signer(&ca_cert).unwrap());

	let sign_fn = |cert, msg| sign_msg_ecdsa(cert, msg,
		&signature::ECDSA_P256_SHA256_ASN1_SIGNING);
	check_cert_ca(&cert_der, &cert, &ca_der,
		&webpki::ECDSA_P256_SHA256, &webpki::ECDSA_P256_SHA256, sign_fn);
}
*/

#[cfg(feature = "x509-parser")]
#[test]
fn test_webpki_imported_ca() {
	use std::convert::TryInto;
	let mut params = util::default_params();
	params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
	let ca_cert = Certificate::from_params(params).unwrap();

	let (ca_cert_der, ca_key_der) = (ca_cert.serialize_der().unwrap(), ca_cert.serialize_private_key_der());

	let ca_key_pair = ca_key_der.as_slice().try_into().unwrap();
	let imported_ca_cert_params = CertificateParams::from_ca_cert_der(ca_cert_der.as_slice(), ca_key_pair)
		.unwrap();
	let imported_ca_cert = Certificate::from_params(imported_ca_cert_params).unwrap();

	let mut params = CertificateParams::new(vec!["crabs.crabs".to_string()]);
	params.distinguished_name.push(DnType::OrganizationName, "Crab widgits SE");
	params.distinguished_name.push(DnType::CommonName, "Dev domain");
	let cert = Certificate::from_params(params).unwrap();
	let cert_der = cert.serialize_der_with_signer(&imported_ca_cert).unwrap();

	let sign_fn = |cert, msg| sign_msg_ecdsa(cert, msg,
		&signature::ECDSA_P256_SHA256_ASN1_SIGNING);
	check_cert_ca(&cert_der, &cert, &ca_cert_der,
		&webpki::ECDSA_P256_SHA256, &webpki::ECDSA_P256_SHA256, sign_fn);
}

#[cfg(feature = "x509-parser")]
#[test]
fn test_webpki_imported_ca_with_printable_string() {
	use std::convert::TryInto;
	let mut params = util::default_params();
	params.distinguished_name.push(DnType::CountryName, DnValue::PrintableString("US".to_string()));
	params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
	let ca_cert = Certificate::from_params(params).unwrap();

	let (ca_cert_der, ca_key_der) = (ca_cert.serialize_der().unwrap(), ca_cert.serialize_private_key_der());

	let ca_key_pair = ca_key_der.as_slice().try_into().unwrap();
	let imported_ca_cert_params = CertificateParams::from_ca_cert_der(ca_cert_der.as_slice(), ca_key_pair)
		.unwrap();
	let imported_ca_cert = Certificate::from_params(imported_ca_cert_params).unwrap();

	let mut params = CertificateParams::new(vec!["crabs.crabs".to_string()]);
	params.distinguished_name.push(DnType::OrganizationName, "Crab widgits SE");
	params.distinguished_name.push(DnType::CommonName, "Dev domain");
	let cert = Certificate::from_params(params).unwrap();
	let cert_der = cert.serialize_der_with_signer(&imported_ca_cert).unwrap();

	let sign_fn = |cert, msg| sign_msg_ecdsa(cert, msg,
		&signature::ECDSA_P256_SHA256_ASN1_SIGNING);
	check_cert_ca(&cert_der, &cert, &ca_cert_der,
		&webpki::ECDSA_P256_SHA256, &webpki::ECDSA_P256_SHA256, sign_fn);
}

#[cfg(feature = "x509-parser")]
#[test]
fn test_certificate_from_csr() {
	let mut params = CertificateParams::new(vec!["crabs.crabs".to_string()]);
	params.distinguished_name.push(DnType::OrganizationName, "Crab widgits SE");
	params.distinguished_name.push(DnType::CommonName, "Dev domain");
	let cert = Certificate::from_params(params).unwrap();
	let csr_der = cert.serialize_request_der().unwrap();
	let csr = CertificateSigningRequest::from_der(&csr_der).unwrap();

	let mut params = util::default_params();
	params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
	let ca_cert = Certificate::from_params(params).unwrap();
	let ca_cert_der = ca_cert.serialize_der().unwrap();
	let cert_der = csr.serialize_der_with_signer(&ca_cert).unwrap();

	let sign_fn = |cert, msg| sign_msg_ecdsa(cert, msg,
		&signature::ECDSA_P256_SHA256_ASN1_SIGNING);
	check_cert_ca(&cert_der, &cert, &ca_cert_der,
		&webpki::ECDSA_P256_SHA256, &webpki::ECDSA_P256_SHA256, sign_fn);
}
