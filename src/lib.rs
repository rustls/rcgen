/*!
Rust X.509 certificate generation utility

This crate provides a way to generate self signed X.509 certificates.

The most simple way of using this crate is by calling the
`generate_simple_self_signed` function.
For more customization abilities, we provide the lower level
`Certificate::from_params` function.

## Example

```
extern crate rcgen;
use rcgen::generate_simple_self_signed;
# fn main () {
// Generate a certificate that's valid for "localhost" and "hello.world.example"
let subject_alt_names = vec!["hello.world.example".to_string(),
	"localhost".to_string()];

let cert = generate_simple_self_signed(subject_alt_names);
println!("{}", cert.serialize_pem());
println!("{}", cert.serialize_private_key_pem());
# }
```
*/
extern crate yasna;
extern crate ring;
extern crate pem;
extern crate untrusted;
extern crate chrono;
extern crate bit_vec;

use yasna::Tag;
use yasna::models::ObjectIdentifier;
use pem::Pem;
use ring::signature::ECDSAKeyPair;
use ring::rand::SystemRandom;
use untrusted::Input;
use ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING as KALG;
use yasna::DERWriter;
use yasna::models::GeneralizedTime;
use chrono::{DateTime, Timelike};
use chrono::{NaiveDate, Utc};
use std::collections::HashMap;
use bit_vec::BitVec;

/// A self signed certificate together with signing keys
pub struct Certificate {
	params :CertificateParams,
	key_pair :ECDSAKeyPair,
	key_pair_serialized :Vec<u8>,
}


/**
KISS function to generate a self signed certificate

Given a set of domain names you want your certificate to be valid for,
this function fills in the other generation parameters with
reasonable defaults and generates a self signed certificate
as output.

## Example

```
extern crate rcgen;
use rcgen::generate_simple_self_signed;
# fn main () {
let subject_alt_names = vec!["hello.world.example".to_string(),
	"localhost".to_string()];

let cert = generate_simple_self_signed(subject_alt_names);
// The certificate is now valid for localhost and the domain "hello.world.example"
println!("{}", cert.serialize_pem());
println!("{}", cert.serialize_private_key_pem());
# }
```
*/
pub fn generate_simple_self_signed(subject_alt_names :Vec<String>) -> Certificate {
	// not_before and not_after set to reasonably long dates
	let not_before = date_time_ymd(1975, 01, 01);
	let not_after = date_time_ymd(4096, 01, 01);
	let mut distinguished_name = DistinguishedName::new();
	distinguished_name.push(DnType::CommonName, "rcgen self signed cert");
	let params = CertificateParams {
		alg : PKCS_WITH_SHA256_WITH_ECDSA_ENCRYPTION,
		not_before,
		not_after,
		serial_number : None,
		subject_alt_names,
		distinguished_name,
	};
	Certificate::from_params(params)
}

// https://tools.ietf.org/html/rfc5280#section-4.1.1

// Example certs usable as reference:
// Uses ECDSA: https://crt.sh/?asn1=607203242

/// id-at-countryName in RFC 5820
const OID_COUNTRY_NAME :&[u64] = &[2, 5, 4, 6];
/// id-at-organizationName in RFC 5820
const OID_ORG_NAME :&[u64] = &[2, 5, 4, 10];
/// id-at-commonName in RFC 5820
const OID_COMMON_NAME :&[u64] = &[2, 5, 4, 3];

// https://tools.ietf.org/html/rfc5480#section-2.1.1
const OID_EC_PUBLIC_KEY :&[u64] = &[1, 2, 840, 10045, 2, 1];
const OID_EC_SECP_256_R1 :&[u64] = &[1, 2, 840, 10045, 3, 1, 7];

// https://tools.ietf.org/html/rfc5280#appendix-A.2
// https://tools.ietf.org/html/rfc5280#section-4.2.1.6
const OID_SUBJECT_ALT_NAME :&[u64] = &[2, 5, 29, 17];

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum DnType {
	CountryName,
	OrganizationName,
	CommonName,
	#[doc(hidden)]
	_Nonexhaustive,
}

impl DnType {
	fn to_oid(&self) -> ObjectIdentifier {
		let sl = match self {
			DnType::CountryName => OID_COUNTRY_NAME,
			DnType::OrganizationName => OID_ORG_NAME,
			DnType::CommonName => OID_COMMON_NAME,
			DnType::_Nonexhaustive => unimplemented!(),
		};
		ObjectIdentifier::from_slice(sl)
	}
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DistinguishedName {
	entries :HashMap<DnType, String>,
}

impl DistinguishedName {
	pub fn new() -> Self {
		Self {
			entries : HashMap::new(),
		}
	}
	pub fn push(&mut self, ty :DnType, s :impl Into<String>) {
		self.entries.insert(ty, s.into());
	}
}

/// Parameters used for certificate generation
pub struct CertificateParams {
	pub alg :SignatureAlgorithm,
	pub not_before :DateTime<Utc>,
	pub not_after :DateTime<Utc>,
	pub serial_number :Option<u64>,
	pub subject_alt_names :Vec<String>,
	pub distinguished_name :DistinguishedName,
}

/// Helper to obtain a DateTime from year, month, day values
///
/// The year, month, day values are assumed to be in UTC.
///
/// This helper function serves two purposes: first, so that you don't
/// have to import the chrono crate yourself in order to specify date
/// information, second so that users don't have to type unproportionately
/// long code just to generate an instance of `DateTime<Utc>`.
pub fn date_time_ymd(year :i32, month :u32, day :u32) -> DateTime<Utc> {
	let naive_dt = NaiveDate::from_ymd(year, month, day).and_hms_milli(0, 0, 0, 0);
	DateTime::<Utc>::from_utc(naive_dt, Utc)
}

fn dt_to_generalized(dt :&DateTime<Utc>) -> GeneralizedTime {
	let mut date_time = *dt;
	// Set nanoseconds to zero (or to one leap second if there is a leap second)
	// This is needed because the GeneralizedTime serializer would otherwise
	// output fractional values which RFC 5820 explicitly forbode [1].
	// [1]: https://tools.ietf.org/html/rfc5280#section-4.1.2.5.2
	let nanos = if date_time.nanosecond() >= 1_000_000 {
		1_000_000
	} else {
		0
	};
	date_time = date_time.with_nanosecond(nanos).unwrap();
	GeneralizedTime::from_datetime::<Utc>(&date_time)
}

// Parses the DER formatted key pair to obtain the public key.
// TODO: replace this function with the newly arriving
// ring-provided functionality once we can use ring 0.14.0.
fn get_public_key_from_pair(pair_der :&[u8]) -> BitVec {
	yasna::parse_der(pair_der, |reader| {
		reader.read_sequence(|reader| {
			// Ignore the two first items.
			reader.next().read_u8()?;
			reader.next().read_sequence(|reader| {
				reader.next().read_oid()?;
				reader.next().read_oid()?;
				Ok(())
			})?;
			// ec_private_key formatted as ECPrivateKey as
			// specified in [1].
			// [1]: https://tools.ietf.org/html/rfc5915#section-3
			let ec_private_key = reader.next().read_bytes()?;
			yasna::parse_der(&ec_private_key, |reader| {
				reader.read_sequence(|reader| {
					reader.next().read_u8()?;
					reader.next().read_bytes()?;
					reader.next().read_tagged(Tag::context(1), |reader| {
						let bit_vec = reader.read_bitvec()?;
						Ok(bit_vec)
					})
				})
			})
		})
	}).unwrap()
}

impl Certificate {
	/// Generates a new self-signed certificate from the given parameters
	pub fn from_params(params :CertificateParams) -> Self {
		let system_random = SystemRandom::new();
		let key_pair_doc = ECDSAKeyPair::generate_pkcs8(&KALG, &system_random).unwrap();
		let key_pair_serialized = key_pair_doc.as_ref().to_vec();

		let key_pair = ECDSAKeyPair::from_pkcs8(&KALG, Input::from(&&key_pair_doc.as_ref())).unwrap();

		Certificate {
			params,
			key_pair,
			key_pair_serialized,
		}
	}
	fn write_name(&self, writer :DERWriter) {
		writer.write_sequence(|writer| {
			writer.next().write_set(|writer| {
				for (ty, content) in self.params.distinguished_name.entries.iter() {
					writer.next().write_sequence(|writer| {
						writer.next().write_oid(&ty.to_oid());
						writer.next().write_utf8_string(content);
					});
				}
			});
		});
	}
	fn write_cert(&self, writer :DERWriter) {
		writer.write_sequence(|writer| {
			// Write version
			writer.next().write_tagged(Tag::context(0), |writer| {
				writer.write_u8(2);
			});
			// Write serialNumber
			let serial = self.params.serial_number.unwrap_or(42);
			writer.next().write_u64(serial);
			// Write signature
			writer.next().write_sequence(|writer| {
				writer.next().write_oid(&self.params.alg.oid());
			});
			// Write issuer
			self.write_name(writer.next());
			// Write validity
			writer.next().write_sequence(|writer| {
				// Not before
				let nb_gt = dt_to_generalized(&self.params.not_before);
				writer.next().write_generalized_time(&nb_gt);
				// Not after
				let na_gt = dt_to_generalized(&self.params.not_after);
				writer.next().write_generalized_time(&na_gt);
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
				let public_key = get_public_key_from_pair(&self.key_pair_serialized);
				writer.next().write_bitvec(&public_key);
			});
			// write extensions
			writer.next().write_tagged(Tag::context(3), |writer| {
				writer.write_sequence(|writer| {
					// Write subject_alt_names
					writer.next().write_sequence(|writer| {
						let oid = ObjectIdentifier::from_slice(OID_SUBJECT_ALT_NAME);
						writer.next().write_oid(&oid);
						let bytes = yasna::construct_der(|writer| {
							writer.write_sequence(|writer|{
								for san in self.params.subject_alt_names.iter() {
									writer.next().write_tagged_implicit(Tag::context(2), |writer| {
										writer.write_utf8_string(san);
									});
								}
							});
						});
						writer.next().write_bytes(&bytes);
					});
				});
			});
		})
	}
	/// Serializes the certificate to the binary DER format
	pub fn serialize_der(&self) -> Vec<u8> {
		yasna::construct_der(|writer| {
			writer.write_sequence(|writer| {

				let tbs_cert_list_serialized = yasna::construct_der(|writer| {
					self.write_cert(writer);
				});
				// Write tbsCertList
				self.write_cert(writer.next());
				//writer.next().write_der(&tbs_cert_list_serialized);

				// Write signatureAlgorithm
				writer.next().write_sequence(|writer| {
					writer.next().write_oid(&self.params.alg.oid());
				});

				// Write signature
				let cl_input = Input::from(&tbs_cert_list_serialized);
				let system_random = SystemRandom::new();
				let signature = self.key_pair.sign(cl_input, &system_random).unwrap();
				let sig = BitVec::from_bytes(&signature.as_ref());
				writer.next().write_bitvec(&sig);
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
	/// Serializes the private key in PEM format
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
