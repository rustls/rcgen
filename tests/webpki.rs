extern crate webpki;
extern crate untrusted;
extern crate rcgen;
extern crate ring;

use rcgen::{Certificate, CertificateParams,
	DistinguishedName, DnType,
	PKCS_WITH_SHA256_WITH_ECDSA_ENCRYPTION,
	date_time_ymd};
use untrusted::Input;
use webpki::{EndEntityCert, TLSServerTrustAnchors};
use webpki::trust_anchor_util::cert_der_as_trust_anchor;
use webpki::ECDSA_P256_SHA256;
use webpki::{Time, DNSNameRef};

use ring::rand::SystemRandom;
use ring::signature::ECDSAKeyPair;
use ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING as KALG;

fn sign_msg(cert :&Certificate, msg :&[u8]) -> Vec<u8> {
	let pk_der = cert.serialize_private_key_der();
	let key_pair = ECDSAKeyPair::from_pkcs8(&KALG, Input::from(&pk_der)).unwrap();
	let system_random = SystemRandom::new();
	let msg_input = Input::from(&msg);
	let signature = key_pair.sign(msg_input, &system_random).unwrap();
	signature.as_ref().to_vec()
}

#[test]
fn test_webpki() {
	let not_before = date_time_ymd(1975, 01, 01);
	let not_after = date_time_ymd(4096, 01, 01);
	let mut distinguished_name = DistinguishedName::new();
	distinguished_name.push(DnType::OrganizationName, "Crab widgits SE");
	distinguished_name.push(DnType::CommonName, "Master CA");
	let params = CertificateParams {
		alg : PKCS_WITH_SHA256_WITH_ECDSA_ENCRYPTION,
		not_before,
		not_after,
		serial_number : None,
		subject_alt_names : vec!["crabs.crabs".to_string(), "localhost".to_string()],
		distinguished_name,
	};
	let cert = Certificate::from_params(params);

	println!("{}", cert.serialize_pem());

	// Now verify the certificate.

	let cert_der = cert.serialize_der();
	let trust_anchor = cert_der_as_trust_anchor(Input::from(&cert_der)).unwrap();
	let trust_anchor_list = &[trust_anchor];
	let trust_anchors = TLSServerTrustAnchors(trust_anchor_list);
	let end_entity_cert = EndEntityCert::from(Input::from(&cert_der)).unwrap();

	// Set time to Jan 10, 2004
	let time = Time::from_seconds_since_unix_epoch(0x40_00_00_00);

	// (1/3) Check whether the cert is valid
	end_entity_cert.verify_is_valid_tls_server_cert(
		&[&ECDSA_P256_SHA256],
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
	let signature = sign_msg(&cert, msg);
	end_entity_cert.verify_signature(
		&ECDSA_P256_SHA256,
		Input::from(msg),
		Input::from(&signature),
	).expect("signature is valid");
}
