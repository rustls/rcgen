extern crate webpki;
extern crate untrusted;
extern crate rcgen;
extern crate ring;

use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, IsCa};
use untrusted::Input;
use webpki::{EndEntityCert, TLSServerTrustAnchors};
use webpki::trust_anchor_util::cert_der_as_trust_anchor;
use webpki::SignatureAlgorithm;
use webpki::{Time, DNSNameRef};

use ring::rand::SystemRandom;
use ring::signature;
use ring::signature::{EcdsaKeyPair, EcdsaSigningAlgorithm};

fn sign_msg_ecdsa(cert :&Certificate, msg :&[u8], alg :&'static EcdsaSigningAlgorithm) -> Vec<u8> {
	let pk_der = cert.serialize_private_key_der();
	let key_pair = EcdsaKeyPair::from_pkcs8(&alg, Input::from(&pk_der)).unwrap();
	let system_random = SystemRandom::new();
	let msg_input = Input::from(&msg);
	let signature = key_pair.sign(&system_random, msg_input).unwrap();
	signature.as_ref().to_vec()
}

fn check_cert(cert_der :&[u8], cert :&Certificate, alg :&SignatureAlgorithm,
		sign_alg :&'static EcdsaSigningAlgorithm) {
	let trust_anchor = cert_der_as_trust_anchor(Input::from(&cert_der)).unwrap();
	let trust_anchor_list = &[trust_anchor];
	let trust_anchors = TLSServerTrustAnchors(trust_anchor_list);
	let end_entity_cert = EndEntityCert::from(Input::from(&cert_der)).unwrap();

	// Set time to Jan 10, 2004
	let time = Time::from_seconds_since_unix_epoch(0x40_00_00_00);

	// (1/3) Check whether the cert is valid
	end_entity_cert.verify_is_valid_tls_server_cert(
		&[&alg],
		&trust_anchors,
		&[],
		time,
	).expect("valid TLS server cert");

	// (2/3) Check that the cert is valid for the given DNS name
	let dns_name = DNSNameRef::try_from_ascii_str("crabs.crabs").unwrap();
	end_entity_cert.verify_is_valid_for_dns_name(
		dns_name,
	).expect("valid for DNS name");

	// (3/3) Check that a message signed by the cert is valid.
	let msg = b"Hello, World! This message is signed.";
	let signature = sign_msg_ecdsa(&cert, msg, sign_alg);
	end_entity_cert.verify_signature(
		&alg,
		Input::from(msg),
		Input::from(&signature),
	).expect("signature is valid");
}

#[test]
fn test_webpki() {
	let mut params = CertificateParams::new(vec![
		"crabs.crabs".to_string(), "localhost".to_string(),
	]);
	params.distinguished_name.push(DnType::OrganizationName, "Crab widgits SE");
	params.distinguished_name.push(DnType::CommonName, "Master CA");
	let cert = Certificate::from_params(params);

	println!("{}", cert.serialize_pem());

	// Now verify the certificate.

	let cert_der = cert.serialize_der();

	check_cert(&cert_der, &cert, &webpki::ECDSA_P256_SHA256,
		&signature::ECDSA_P256_SHA256_ASN1_SIGNING);
}

#[test]
fn test_webpki_384() {
	let mut params = CertificateParams::new(vec![
		"crabs.crabs".to_string(), "localhost".to_string(),
	]);
	params.alg = &rcgen::PKCS_ECDSA_P384_SHA384;

	params.distinguished_name.push(DnType::OrganizationName, "Crab widgits SE");
	params.distinguished_name.push(DnType::CommonName, "Master CA");
	let cert = Certificate::from_params(params);

	println!("{}", cert.serialize_pem());

	// Now verify the certificate.

	let cert_der = cert.serialize_der();

	check_cert(&cert_der, &cert, &webpki::ECDSA_P384_SHA384,
		&signature::ECDSA_P384_SHA384_ASN1_SIGNING);
}

#[test]
fn test_webpki_separate_ca() {
	let mut params = CertificateParams::new(vec![
		"crabs.crabs".to_string(), "localhost".to_string(),
	]);
	params.distinguished_name.push(DnType::OrganizationName, "Crab widgits SE");
	params.distinguished_name.push(DnType::CommonName, "Master CA");
	params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
	let ca_cert = Certificate::from_params(params);

	let ca_der = ca_cert.serialize_der();
	let trust_anchor_list = &[cert_der_as_trust_anchor(Input::from(&ca_der)).unwrap()];
	let trust_anchors = TLSServerTrustAnchors(trust_anchor_list);

	let mut params = CertificateParams::new(vec!["crabs.dev".to_string()]);
	params.distinguished_name.push(DnType::OrganizationName, "Crab widgits SE");
	params.distinguished_name.push(DnType::CommonName, "Dev domain");
	let cert = Certificate::from_params(params).serialize_der_with_signer(&ca_cert);
	let end_entity_cert = EndEntityCert::from(Input::from(&cert)).unwrap();

	// Set time to Jan 10, 2004
	let time = Time::from_seconds_since_unix_epoch(0x40_00_00_00);

	end_entity_cert.verify_is_valid_tls_server_cert(
		&[&webpki::ECDSA_P256_SHA256],
		&trust_anchors,
		&[Input::from(&ca_der)],
		time,
	).expect("valid TLS server cert");
}
