extern crate yasna;
extern crate ring;
extern crate pem;
extern crate untrusted;
extern crate chrono;

use yasna::Tag;
use yasna::models::ObjectIdentifier;
use pem::Pem;
use ring::signature::{EcdsaKeyPair, KeyPair};
use ring::rand::SystemRandom;
use untrusted::Input;
use ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING as KALG;
use yasna::DERWriter;
use chrono::NaiveDateTime;

pub struct Certificate {
	params :CertificateParams,
	key_pair :EcdsaKeyPair,
	key_pair_serialized :Vec<u8>,
}

// https://tools.ietf.org/html/rfc5280#section-4.1.1

// Example certs usable as reference:
// Uses ECDSA: https://crt.sh/?asn1=607203242

const OID_COUNTRY_NAME :&[u64] = &[2, 5, 4, 6];
const OID_ORG_NAME :&[u64] = &[2, 5, 4, 10];
const OID_COMMON_NAME :&[u64] = &[2, 5, 4, 3];

// https://tools.ietf.org/html/rfc5480#section-2.1.1
const OID_EC_PUBLIC_KEY :&[u64] = &[1, 2, 840, 10045, 2, 1];
const OID_EC_SECP_256_R1 :&[u64] = &[1, 2, 840, 10045, 3, 1, 7];

pub struct CertificateParams {
	pub alg :SignatureAlgorithm,
	pub not_before :NaiveDateTime,
	pub not_after :NaiveDateTime,
	pub serial_number :Option<u64>,
}

impl Certificate {
	pub fn from_params(params :CertificateParams) -> Self {
		let system_random = SystemRandom::new();
		// TODO is this the right algorithm?
		let key_pair_doc = EcdsaKeyPair::generate_pkcs8(&KALG, &system_random).unwrap();
		let key_pair_serialized = key_pair_doc.as_ref().to_vec();

		let key_pair = EcdsaKeyPair::from_pkcs8(&KALG, Input::from(&&key_pair_doc.as_ref())).unwrap();

		Certificate {
			params,
			key_pair,
			key_pair_serialized,
		}
	}
	fn write_name(&self, writer :DERWriter) {
		writer.write_sequence(|writer| {
			writer.next().write_set(|writer| {
				// Country name
				writer.next().write_sequence(|writer| {
					let oid = ObjectIdentifier::from_slice(OID_COUNTRY_NAME);
					writer.next().write_oid(&oid);
					writer.next().write_utf8_string("US");
				});
				// Organization name
				writer.next().write_sequence(|writer| {
					let oid = ObjectIdentifier::from_slice(OID_ORG_NAME);
					writer.next().write_oid(&oid);
					writer.next().write_utf8_string("Crab widgits pty ltd");
				});
				// Common name
				writer.next().write_sequence(|writer| {
					let oid = ObjectIdentifier::from_slice(OID_COMMON_NAME);
					writer.next().write_oid(&oid);
					writer.next().write_utf8_string("Mastery master crab cert");
				});
			});
		});
	}
	fn write_cert(&self, writer :DERWriter) {
		writer.write_sequence(|writer| {
			// Write version
			writer.next().write_tagged(Tag::context(0), |writer| {
				writer.write_u8(3);
			});
			// Write serialNumber
			let serial = self.params.serial_number.unwrap_or(42);
			writer.next().write_u64(serial);
			// Write signature
			writer.next().write_sequence(|writer| {
				writer.next().write_oid(&self.params.alg.oid());
				writer.next().write_null();
			});
			// Write issuer
			self.write_name(writer.next());
			// Write validity
			writer.next().write_sequence(|writer| {
				// Not before
				writer.next().write_generalized_time(&self.params.not_before);
				// Not after
				writer.next().write_generalized_time(&self.params.not_after);
			});
			// Write subject
			self.write_name(writer.next());
			// Write subjectPublicKeyInfo
			writer.next().write_sequence(|writer| {
				writer.next().write_sequence(|writer| {
					let oid = ObjectIdentifier::from_slice(OID_EC_PUBLIC_KEY);
					writer.next().write_oid(&oid);
					let oid = ObjectIdentifier::from_slice(OID_EC_SECP_256_R1);
					writer.next().write_oid(&oid);
				});
				let public_key = &self.key_pair.public_key().as_ref();
				writer.next().write_bit_string(0, public_key);
			});
			// TODO write extensions
		})
	}
	/// Serializes the certificate to the binary DER format
	pub fn serialize_der(&self) -> Vec<u8> {
		yasna::construct_der(|writer| {
			writer.write_sequence(|writer| {

				// Write tbsCertList
				self.write_cert(writer.next());

				// Write signatureAlgorithm
				writer.next().write_sequence(|writer| {
					writer.next().write_oid(&self.params.alg.oid());
				});

				// Write signature
				let tbs_cert_list_serialized = yasna::construct_der(|writer| {
					self.write_cert(writer);
				});
				let cl_input = Input::from(&tbs_cert_list_serialized);
				let system_random = SystemRandom::new();
				let signature = self.key_pair.sign(&system_random, cl_input).unwrap();
				writer.next().write_bit_string(0, &signature.as_ref());
			})
		})
	}
	/// Serializes the certificate to the ASCII PEM format
	pub fn serialize_pem(&self) -> String {
		let p = Pem {
			tag : "CERTIFICATE".to_string(),
			contents : self.serialize_der(),
		};
		pem::encode(&p)
	}
	/// Serializes the private key in PKCS#8 format
	pub fn serialize_private_key_der(&self) -> Vec<u8> {
		self.key_pair_serialized.clone()
	}
	/// Serializes the private key in PKCS#8 format
	pub fn serialize_private_key_pem(&self) -> String {
		let p = Pem {
			tag : "PRIVATE KEY".to_string(),
			contents : self.serialize_private_key_der(),
		};
		pem::encode(&p)
	}
}

pub struct SignatureAlgorithm {
	oid_components : &'static [u64],
}

/*
pub const PKCS_WITH_SHA256_WITH_RSA_ENCRYPTION :SignatureAlgorithm = SignatureAlgorithm {
	/// sha256WithRSAEncryption in RFC 4055
	oid_components : &[1, 2, 840, 113549, 1, 1, 11],
};
*/

/// Signature algorithm ID as per [RFC 5758](https://tools.ietf.org/html/rfc5758#section-3.2)
pub const PKCS_WITH_SHA256_WITH_ECDSA_ENCRYPTION :SignatureAlgorithm = SignatureAlgorithm {
	/// ecdsa-with-SHA256 in RFC 5758
	oid_components : &[1, 2, 840, 10045, 4, 3, 2],
};

// Signature algorithm IDs as per https://tools.ietf.org/html/rfc4055
impl SignatureAlgorithm {
	fn oid(&self) -> ObjectIdentifier {
		ObjectIdentifier::from_slice(self.oid_components)
	}
}
