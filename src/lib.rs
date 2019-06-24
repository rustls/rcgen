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

let cert = generate_simple_self_signed(subject_alt_names).unwrap();
println!("{}", cert.serialize_pem().unwrap());
println!("{}", cert.serialize_private_key_pem());
# }
```
*/

#![forbid(unsafe_code)]
#![deny(missing_docs)]

extern crate yasna;
extern crate ring;
#[cfg(feature = "pem")]
extern crate pem;
extern crate untrusted;
extern crate chrono;

use yasna::Tag;
use yasna::models::ObjectIdentifier;
#[cfg(feature = "pem")]
use pem::Pem;
#[cfg(feature = "pem")]
use std::convert::TryInto;
use ring::digest;
use ring::signature::{EcdsaKeyPair, Ed25519KeyPair, RsaKeyPair};
use ring::rand::SystemRandom;
use ring::signature::KeyPair as RingKeyPair;
use untrusted::Input;
use ring::signature::{self, EcdsaSigningAlgorithm, EdDSAParameters};
use yasna::DERWriter;
use yasna::models::GeneralizedTime;
use chrono::{DateTime, Timelike};
use chrono::{NaiveDate, Utc};
use std::collections::HashMap;
use std::fmt;
use std::convert::TryFrom;
use std::error::Error;

/// A self signed certificate together with signing keys
pub struct Certificate {
	params :CertificateParams,
	key_pair :KeyPair,
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
let subject_alt_names :&[_] = &["hello.world.example".to_string(),
	"localhost".to_string()];

let cert = generate_simple_self_signed(subject_alt_names).unwrap();
// The certificate is now valid for localhost and the domain "hello.world.example"
println!("{}", cert.serialize_pem().unwrap());
println!("{}", cert.serialize_private_key_pem());
# }
```
*/
pub fn generate_simple_self_signed(subject_alt_names :impl Into<Vec<String>>) -> Result<Certificate, RcgenError> {
	Certificate::from_params(CertificateParams::new(subject_alt_names))
}

// https://tools.ietf.org/html/rfc5280#section-4.1.1

// Example certs usable as reference:
// Uses ECDSA: https://crt.sh/?asn1=607203242

/// pkcs-9-at-extensionRequest in RFC 2985
const OID_PKCS_9_AT_EXTENSION_REQUEST :&[u64] = &[1, 2, 840, 113549, 1, 9, 14];

/// id-at-countryName in RFC 5820
const OID_COUNTRY_NAME :&[u64] = &[2, 5, 4, 6];
/// id-at-organizationName in RFC 5820
const OID_ORG_NAME :&[u64] = &[2, 5, 4, 10];
/// id-at-commonName in RFC 5820
const OID_COMMON_NAME :&[u64] = &[2, 5, 4, 3];

// https://tools.ietf.org/html/rfc5480#section-2.1.1
const OID_EC_PUBLIC_KEY :&[u64] = &[1, 2, 840, 10045, 2, 1];
const OID_EC_SECP_256_R1 :&[u64] = &[1, 2, 840, 10045, 3, 1, 7];
const OID_EC_SECP_384_R1 :&[u64] = &[1, 3, 132, 0, 34];

// rsaEncryption in RFC 4055
const OID_RSA_ENCRYPTION :&[u64] = &[1, 2, 840, 113549, 1, 1, 1];

// https://tools.ietf.org/html/rfc5280#appendix-A.2
// https://tools.ietf.org/html/rfc5280#section-4.2.1.6
const OID_SUBJECT_ALT_NAME :&[u64] = &[2, 5, 29, 17];

// https://tools.ietf.org/html/rfc5280#section-4.2.1.9
const OID_BASIC_CONSTRAINTS :&[u64] = &[2, 5, 29, 19];

// https://tools.ietf.org/html/rfc5280#section-4.2.1.2
const OID_SUBJECT_KEY_IDENTIFIER :&[u64] = &[2, 5, 29, 14];

// id-pe-acmeIdentifier in
// https://www.iana.org/assignments/smi-numbers/smi-numbers.xhtml#smi-numbers-1.3.6.1.5.5.7.1
const OID_PE_ACME :&[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 31];

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
#[allow(missing_docs)]
/// The attribute type of a distinguished name entry
pub enum DnType {
	CountryName,
	OrganizationName,
	CommonName,
	CustomDnType(Vec<u64>),
	#[doc(hidden)]
	_Nonexhaustive,
}

impl DnType {
	fn to_oid(&self) -> ObjectIdentifier {
		let sl = match self {
			DnType::CountryName => OID_COUNTRY_NAME,
			DnType::OrganizationName => OID_ORG_NAME,
			DnType::CommonName => OID_COMMON_NAME,
			DnType::CustomDnType(ref oid) => oid.as_slice(),
			DnType::_Nonexhaustive => unimplemented!(),
		};
		ObjectIdentifier::from_slice(sl)
	}

    /// Generate a DnType for the provided OID
	#[cfg(feature = "x509-parser")]
	pub fn from_oid(slice :&[u64]) -> Self {
		match slice {
			OID_COMMON_NAME => DnType::CommonName,
			OID_ORG_NAME => DnType::OrganizationName,
			OID_COUNTRY_NAME => DnType::CountryName,
			oid => DnType::CustomDnType(oid.into())
		}
	}
}

#[derive(Debug, PartialEq, Eq, Clone)]
/**
Distinguished name used e.g. for the issuer and subject fields of a certificate

A distinguished name is a set of (attribute type, attribute value) tuples.

See also the RFC 5280 sections on the [issuer](https://tools.ietf.org/html/rfc5280#section-4.1.2.4)
and [subject](https://tools.ietf.org/html/rfc5280#section-4.1.2.6) fields.
*/
pub struct DistinguishedName {
	entries :HashMap<DnType, String>,
	order :Vec<DnType>,
}

impl DistinguishedName {
	/// Creates a new, empty distinguished name
	pub fn new() -> Self {
		Self {
			entries : HashMap::new(),
			order : Vec::new(),
		}
	}
	/// Inserts a new attribute that consists of type and name
	pub fn push(&mut self, ty :DnType, s :impl Into<String>) {
		if !self.entries.contains_key(&ty) {
			self.order.push(ty.clone());
		}
		self.entries.insert(ty, s.into());
	}
	/// Iterate over the entries
	pub fn iter(&self) -> DistinguishedNameIterator<'_> {
		DistinguishedNameIterator {
			distinguished_name :self,
			iter :self.order.iter()
		}
	}
}

/**
Iterator over `DistinguishedName` entries
*/
pub struct DistinguishedNameIterator<'a> {
	distinguished_name :&'a DistinguishedName,
	iter :std::slice::Iter<'a, DnType>,
}

impl <'a> Iterator for DistinguishedNameIterator<'a> {
	type Item = (&'a DnType, &'a str);

	fn next(&mut self) -> Option<Self::Item> {
		self.iter.next()
			.and_then(|ty| {
				self.distinguished_name.entries.get(ty).map(|v| (ty, v.as_str()))
			})
	}
}

/// Parameters used for certificate generation
#[allow(missing_docs)]
pub struct CertificateParams {
	pub alg :&'static SignatureAlgorithm,
	pub not_before :DateTime<Utc>,
	pub not_after :DateTime<Utc>,
	pub serial_number :Option<u64>,
	pub subject_alt_names :Vec<String>,
	pub distinguished_name :DistinguishedName,
	pub is_ca :IsCa,
	pub custom_extensions :Vec<CustomExtension>,
	/// The certificate's key pair, a new random key pair will be generated if this is `None`
	pub key_pair :Option<KeyPair>,
	// To make the struct non-exhaustive
	_hidden :(),
}

impl Default for CertificateParams {
	fn default() -> Self {
		// not_before and not_after set to reasonably long dates
		let not_before = date_time_ymd(1975, 01, 01);
		let not_after = date_time_ymd(4096, 01, 01);
		let mut distinguished_name = DistinguishedName::new();
		distinguished_name.push(DnType::CommonName, "rcgen self signed cert");
		CertificateParams {
			alg : &PKCS_ECDSA_P256_SHA256,
			not_before,
			not_after,
			serial_number : None,
			subject_alt_names : Vec::new(),
			distinguished_name,
			is_ca : IsCa::SelfSignedOnly,
			custom_extensions : Vec::new(),
			key_pair : None,
			_hidden :(),
		}
	}
}

impl CertificateParams {
	/// Parses the ca certificate from the ASCII PEM format
	///
	/// See `from_ca_cert_der` for more details.
	#[cfg(all(feature = "pem", feature = "x509-parser"))]
	pub fn from_ca_cert_pem(pem_str :&str, key_pair :KeyPair) -> Result<Self, RcgenError> {
		let certificate = pem::parse(pem_str)
			.or(Err(RcgenError::CouldNotParseCertificate))?;
		Self::from_ca_cert_der(&certificate.contents, key_pair)
	}

	/// Parses the ca certificate from the DER format
	///
	/// This function is only of use if you have an existing ca certificate with which
	/// you want to sign a certificate newly generated by `rcgen` using the
	/// `serialize_der_with_signer()` or `serialize_pem_with_signer()` functions.
	///
	/// Will not check if certificate is a ca certificate!
	#[cfg(feature = "x509-parser")]
	pub fn from_ca_cert_der(ca_cert :&[u8], key_pair :KeyPair) -> Result<Self, RcgenError> {
		let (_remainder, x509) = x509_parser::parse_x509_der(ca_cert)
			.or(Err(RcgenError::CouldNotParseCertificate))?;

		let alg = SignatureAlgorithm::from_oid(x509.signature_algorithm.algorithm.iter().as_slice())?;

		let mut dn = DistinguishedName::new();
		for rdn in x509.tbs_certificate.subject.rdn_seq.iter() {
			assert!(rdn.set.len() != 0, "x509-parser distinguished name set is empty");

			let attr = if rdn.set.len() > 1 {
				// no support for distinguished names with more than one attribute
				return Err(RcgenError::CouldNotParseCertificate);
			} else {
				&rdn.set.as_slice()[0]
			};
			let value = attr.attr_value.as_slice()
				.or(Err(RcgenError::CouldNotParseCertificate))?;

			let dn_type = DnType::from_oid(attr.attr_type.iter().as_slice());
			let dn_value = String::from_utf8(value.into())
				.or(Err(RcgenError::CouldNotParseCertificate))?;
			dn.push(dn_type, dn_value);
		}

		Ok(
			CertificateParams {
				alg,
				distinguished_name : dn,
				key_pair : Some(key_pair),
				.. Default::default()
			}
		)
	}
}

/// Whether the certificate is allowed to sign other certificates
pub enum IsCa {
	/// The certificate can only sign itself
	SelfSignedOnly,
	/// The certificate may be used to sign other certificates
	Ca(BasicConstraints),
}

/// The path length constraint (only relevant for CA certificates)
///
/// Sets an optional upper limit on the length of the intermediate certificate chain
/// length allowed for this CA certificate (not including the end entity certificate).
pub enum BasicConstraints {
	/// No constraint
	Unconstrained,
	/// Constrain to the contained number of intermediate certificates
	Constrained(u8),
}

impl CertificateParams {
	/// Generate certificate parameters with reasonable defaults
	pub fn new(subject_alt_names :impl Into<Vec<String>>) -> Self {
		CertificateParams {
			subject_alt_names : subject_alt_names.into(),
			.. Default::default()
		}
	}
}

/// A custom extension of a certificate, as specified in
/// [RFC 5280](https://tools.ietf.org/html/rfc5280#section-4.2)
pub struct CustomExtension {
	oid :Vec<u64>,
	critical :bool,
	content :Vec<u8>,
}

impl CustomExtension {
	/// Creates a new acmeIdentifier extension for ACME TLS-ALPN-01
	/// as specified in [draft-ietf-acme-tls-alpn-05](https://tools.ietf.org/html/draft-ietf-acme-tls-alpn-05#section-3)
	///
	/// Panics if the passed `sha_digest` parameter doesn't hold 32 bytes (256 bits).
	pub fn new_acme_identifier(sha_digest :&[u8]) -> Self {
		assert_eq!(sha_digest.len(), 32, "wrong size of sha_digest");
		let content = yasna::construct_der(|writer| {
			writer.write_bytes(sha_digest);
		});
		Self {
			oid : OID_PE_ACME.to_owned(),
			critical : true,
			content,
		}
	}
	/// Create a new custom extension
	pub fn from_oid_content(oid :&[u64], content :Vec<u8>) -> Self {
		Self {
			oid : oid.to_owned(),
			critical : false,
			content,
		}
	}
	/// Sets the criticality flag of the extension.
	pub fn set_criticality(&mut self, criticality :bool) {
		self.critical = criticality;
	}
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

fn dt_to_generalized(dt :&DateTime<Utc>) -> Result<GeneralizedTime, RcgenError> {
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
	date_time = date_time.with_nanosecond(nanos).ok_or(RcgenError::Time)?;
	Ok(GeneralizedTime::from_datetime::<Utc>(&date_time))
}

impl Certificate {
	/// Generates a new certificate from the given parameters
	pub fn from_params(mut params :CertificateParams) -> Result<Self, RcgenError> {
		let key_pair = if let Some(key_pair) = params.key_pair.take() {
			if !key_pair.is_compatible(&params.alg) {
				return Err(RcgenError::CertificateKeyPairMismatch);
			}
			key_pair
		} else {
			KeyPair::generate(&params.alg)?
		};

		Ok(Certificate {
			params,
			key_pair,
		})
	}
	fn write_name(&self, writer :DERWriter, ca :&Certificate) {
		writer.write_sequence(|writer| {
			for (ty, content) in ca.params.distinguished_name.iter() {
				writer.next().write_set(|writer| {
					writer.next().write_sequence(|writer| {
						writer.next().write_oid(&ty.to_oid());
						writer.next().write_utf8_string(content);
					});
				});
			}
		});
	}
    fn write_request(&self, writer :DERWriter) {
		writer.write_sequence(|writer| {
			// Write version
			writer.next().write_u8(0);
			// Write issuer
			writer.next().write_sequence(|writer| {
				for (ty, content) in self.params.distinguished_name.iter() {
					writer.next().write_set(|writer| {
						writer.next().write_sequence(|writer| {
							writer.next().write_oid(&ty.to_oid());
							writer.next().write_utf8_string(content);
						});
					});
				}
			});
			// Write subjectPublicKeyInfo
			writer.next().write_sequence(|writer| {
				self.params.alg.write_oids_sign_alg(writer.next());
				let pk = self.key_pair.public_key();
				writer.next().write_bitvec_bytes(&pk, pk.len() * 8);
			});
			// Write extensions
			writer.next().write_tagged(Tag::context(0), |writer| {
				writer.write_sequence(|writer| {
					let oid = ObjectIdentifier::from_slice(OID_PKCS_9_AT_EXTENSION_REQUEST);
					writer.next().write_oid(&oid);
					writer.next().write_set(|writer| {
						writer.next().write_sequence(|writer| {
							// Write subject_alt_names
							writer.next().write_sequence(|writer| {
								let oid = ObjectIdentifier::from_slice(OID_SUBJECT_ALT_NAME);
								writer.next().write_oid(&oid);
								let bytes = yasna::construct_der(|writer| {
									writer.write_sequence(|writer| {
										for san in self.params.subject_alt_names.iter() {
											// All subject alt names are dNSName.
											const TAG_DNS_NAME :u64 = 2;
											writer.next().write_tagged_implicit(Tag::context(TAG_DNS_NAME), |writer| {
												writer.write_utf8_string(san);
											});
										}
									});
								});
								writer.next().write_bytes(&bytes);
							});
						});
					});
				});
			});
		});
	}
	fn write_cert(&self, writer :DERWriter, ca :&Certificate) -> Result<(), RcgenError> {
		writer.write_sequence(|writer| {
			// Write version
			writer.next().write_tagged(Tag::context(0), |writer| {
				writer.write_u8(2);
			});
			// Write serialNumber
			let serial = self.params.serial_number.unwrap_or(42);
			writer.next().write_u64(serial);
			// Write signature
			self.params.alg.write_alg_ident(writer.next());
			// Write issuer
			self.write_name(writer.next(), ca);
			// Write validity
			writer.next().write_sequence(|writer| {
				// Not before
				let nb_gt = dt_to_generalized(&self.params.not_before)?;
				writer.next().write_generalized_time(&nb_gt);
				// Not after
				let na_gt = dt_to_generalized(&self.params.not_after)?;
				writer.next().write_generalized_time(&na_gt);
				Ok::<(), RcgenError>(())
			})?;
			// Write subject
			self.write_name(writer.next(), self);
			// Write subjectPublicKeyInfo
			writer.next().write_sequence(|writer| {
				self.params.alg.write_oids_sign_alg(writer.next());
				let pk = self.key_pair.public_key();
				writer.next().write_bitvec_bytes(&pk, pk.len() * 8);
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
									// All subject alt names are dNSName.
									const TAG_DNS_NAME :u64 = 2;
									writer.next().write_tagged_implicit(Tag::context(TAG_DNS_NAME), |writer| {
										writer.write_utf8_string(san);
									});
								}
							});
						});
						writer.next().write_bytes(&bytes);
					});
					if let IsCa::Ca(ref constraint) = self.params.is_ca {
						// Write subject_key_identifier
						writer.next().write_sequence(|writer| {
							let oid = ObjectIdentifier::from_slice(OID_SUBJECT_KEY_IDENTIFIER);
							writer.next().write_oid(&oid);
							let digest = digest::digest(&self.params.alg.digest_alg, self.key_pair.public_key().as_ref());
							writer.next().write_bytes(&digest.as_ref());
						});
						// Write basic_constraints
						writer.next().write_sequence(|writer| {
							let oid = ObjectIdentifier::from_slice(OID_BASIC_CONSTRAINTS);
							writer.next().write_oid(&oid);
							let bytes = yasna::construct_der(|writer| {
								writer.write_sequence(|writer| {
									writer.next().write_bool(true); // cA flag
									if let BasicConstraints::Constrained(path_len_constraint) = constraint {
										writer.next().write_u8(*path_len_constraint);
									}
								});
							});
							writer.next().write_bytes(&bytes);
						});
					}
					// Write the custom extensions
					for ext in &self.params.custom_extensions {
						writer.next().write_sequence(|writer| {
							let oid = ObjectIdentifier::from_slice(&ext.oid);
							writer.next().write_oid(&oid);
							// If the extension is critical, we should signal this.
							// It's false by default so we don't need to write anything
							// if the extension is not critical.
							if ext.critical {
								writer.next().write_bool(true);
							}
							writer.next().write_bytes(&ext.content);
						});
					}
				});
			});
			Ok(())
		})
	}
	/// Serializes the certificate to the binary DER format
	pub fn serialize_der(&self) -> Result<Vec<u8>, RcgenError> {
		self.serialize_der_with_signer(&self)
	}
	/// Serializes the certificate, signed with another certificate's key, in binary DER format
	pub fn serialize_der_with_signer(&self, ca :&Certificate) -> Result<Vec<u8>, RcgenError> {
		yasna::try_construct_der(|writer| {
			writer.write_sequence(|writer| {

				let tbs_cert_list_serialized = yasna::try_construct_der(|writer| {
					self.write_cert(writer, ca)?;
					Ok::<(), RcgenError>(())
				})?;
				// Write tbsCertList
				writer.next().write_der(&tbs_cert_list_serialized);

				// Write signatureAlgorithm
				self.params.alg.write_alg_ident(writer.next());

				// Write signature
				ca.key_pair.sign(&tbs_cert_list_serialized, writer.next())?;

				Ok(())
			})
		})
	}
    /// Serializes a certificate signing request in binary DER format
    pub fn serialize_request_der(&self) -> Result<Vec<u8>, RcgenError> {
		yasna::try_construct_der(|writer| {
			writer.write_sequence(|writer| {
				let cert_data = yasna::construct_der(|writer| {
					self.write_request(writer);
				});
				writer.next().write_der(&cert_data);

				// Write signatureAlgorithm
				self.params.alg.write_alg_ident(writer.next());

				// Write signature
				self.key_pair.sign(&cert_data, writer.next())?;

				Ok(())
			})
		})
	}
	/// Serializes the certificate to the ASCII PEM format
	#[cfg(feature = "pem")]
	pub fn serialize_pem(&self) -> Result<String, RcgenError> {
		let p = Pem {
			tag : "CERTIFICATE".to_string(),
			contents : self.serialize_der()?,
		};
		Ok(pem::encode(&p))
	}
	/// Serializes the certificate, signed with another certificate's key, to the ASCII PEM format
	#[cfg(feature = "pem")]
	pub fn serialize_pem_with_signer(&self, ca :&Certificate) -> Result<String, RcgenError> {
		let p = Pem {
			tag : "CERTIFICATE".to_string(),
			contents : self.serialize_der_with_signer(ca)?,
		};
		Ok(pem::encode(&p))
	}
	/// Serializes the certificate signing request to the ASCII PEM format
	#[cfg(feature = "pem")]
	pub fn serialize_request_pem(&self) -> Result<String, RcgenError> {
		let p = Pem {
			tag : "CERTIFICATE REQUEST".to_string(),
			contents : self.serialize_request_der()?,
		};
		Ok(pem::encode(&p))
	}
	/// Serializes the private key in PKCS#8 format
	pub fn serialize_private_key_der(&self) -> Vec<u8> {
		self.key_pair.serialize_der()
	}
	/// Serializes the private key in PEM format
	#[cfg(feature = "pem")]
	pub fn serialize_private_key_pem(&self) -> String {
		self.key_pair.serialize_pem()
	}
}

enum SignAlgo {
	EcDsa(&'static EcdsaSigningAlgorithm),
	EdDsa(&'static EdDSAParameters),
	Rsa(),
}

/// A key pair vairant
enum KeyPairKind {
	/// A Ecdsa key pair
	Ec(EcdsaKeyPair),
	/// A Ed25519 key pair
	Ed(Ed25519KeyPair),
	/// A RSA key pair
	Rsa(RsaKeyPair),
}

/// A key pair used to sign certificates and CSRs
pub struct KeyPair {
	kind :KeyPairKind,
	serialized_der :Vec<u8>,
}

impl KeyPair {
	/// Parses the key pair from the ASCII PEM format
	#[cfg(feature = "pem")]
	pub fn from_pem(pem_str :&str) -> Result<Self, RcgenError> {
		let private_key = pem::parse(pem_str)?;
		let private_key_der :&[_] = &private_key.contents;
		Ok(private_key_der.try_into()?)
	}
}

#[derive(Debug)]
/// The error type of the rcgen crate
pub enum RcgenError {
	/// The given certificate couldn't be parsed
	CouldNotParseCertificate,
	/// The given key pair couldn't be parsed
	CouldNotParseKeyPair,
	/// There is no support for generating
	/// keys for the given algorithm
	KeyGenerationUnavailable,
	/// The requested signature algorithm is not supported
	UnsupportedSignatureAlgorithm,
	/// Unspecified ring error
	RingUnspecified,
	/// The provided certificate's signature algorithm
	/// is incompatible with the given key pair
	CertificateKeyPairMismatch,
	/// Time conversion related errors
	Time,
	#[cfg(feature = "pem")]
	/// Error from the pem crate
	PemError(pem::PemError),
	#[doc(hidden)]
	_Nonexhaustive,
}

impl fmt::Display for RcgenError {
	fn fmt(&self, f :&mut fmt::Formatter) -> fmt::Result {
		use self::RcgenError::*;
		match self {
			CouldNotParseCertificate => write!(f, "Could not parse certificate")?,
			CouldNotParseKeyPair => write!(f, "Could not parse key pair")?,
			KeyGenerationUnavailable => write!(f, "There is no support for generating \
				keys for the given algorithm")?,
			UnsupportedSignatureAlgorithm => write!(f, "The requested signature algorithm \
				is not supported")?,
			RingUnspecified => write!(f, "Unspecified ring error")?,
			CertificateKeyPairMismatch => write!(f, "The provided certificate's signature \
				algorithm is incompatible with the given key pair")?,
			Time => write!(f, "Time error")?,
			#[cfg(feature = "pem")]
			PemError(e) => write!(f, "PEM error: {}", e)?,
			_Nonexhaustive => panic!("Nonexhaustive error variant ought not be constructed"),
		};
		Ok(())
	}
}

impl Error for RcgenError {}

impl From<ring::error::Unspecified> for RcgenError {
	fn from(_unspecified :ring::error::Unspecified) -> Self {
		RcgenError::RingUnspecified
	}
}

#[cfg(feature = "pem")]
impl From<pem::PemError> for RcgenError {
	fn from(_pem_error :pem::PemError) -> Self {
		RcgenError::RingUnspecified
	}
}

impl TryFrom<&[u8]> for KeyPair {
	type Error = RcgenError;
	fn try_from(pkcs8 :&[u8]) -> Result<KeyPair, RcgenError> {
		let input = Input::from(pkcs8);
		let pkcs8_vec = std::iter::FromIterator::from_iter(pkcs8.iter().cloned());

		let kind = if let Ok(edkp) = Ed25519KeyPair::from_pkcs8_maybe_unchecked(input) {
			KeyPairKind::Ed(edkp)
		} else if let Ok(eckp) = EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, input) {
			KeyPairKind::Ec(eckp)
		} else if let Ok(eckp) = EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P384_SHA384_ASN1_SIGNING, input) {
			KeyPairKind::Ec(eckp)
		} else if let Ok(rsakp) = RsaKeyPair::from_pkcs8(input) {
			KeyPairKind::Rsa(rsakp)
		} else {
			return Err(RcgenError::CouldNotParseKeyPair);
		};

		Ok(KeyPair {
			kind,
			serialized_der : pkcs8_vec,
		})
	}
}

impl KeyPair {
	/// Generate a new random key pair for the specified signature algorithm
	pub fn generate(alg :&SignatureAlgorithm) -> Result<Self, RcgenError> {
		let system_random = SystemRandom::new();
		match alg.sign_alg {
			SignAlgo::EcDsa(sign_alg) => {
				let key_pair_doc = EcdsaKeyPair::generate_pkcs8(sign_alg, &system_random)?;
				let key_pair_serialized = key_pair_doc.as_ref().to_vec();

				let key_pair = EcdsaKeyPair::from_pkcs8(&sign_alg, Input::from(&&key_pair_doc.as_ref())).unwrap();
				Ok(KeyPair {
					kind : KeyPairKind::Ec(key_pair),
					serialized_der : key_pair_serialized,
				})
			},
			SignAlgo::EdDsa(_sign_alg) => {
				let key_pair_doc = Ed25519KeyPair::generate_pkcs8(&system_random)?;
				let key_pair_serialized = key_pair_doc.as_ref().to_vec();

				let key_pair = Ed25519KeyPair::from_pkcs8(Input::from(&&key_pair_doc.as_ref())).unwrap();
				Ok(KeyPair {
					kind : KeyPairKind::Ed(key_pair),
					serialized_der : key_pair_serialized,
				})
			},
			// Ring doesn't have RSA key generation yet:
			// https://github.com/briansmith/ring/issues/219
			// https://github.com/briansmith/ring/pull/733
			SignAlgo::Rsa() => Err(RcgenError::KeyGenerationUnavailable),
		}
	}
	fn public_key(&self) -> &[u8] {
		match &self.kind {
			KeyPairKind::Ec(kp) => kp.public_key().as_ref(),
			KeyPairKind::Ed(kp) => kp.public_key().as_ref(),
			KeyPairKind::Rsa(kp) => kp.public_key().as_ref(),
		}
	}
	fn is_compatible(&self, signature_algorithm :&SignatureAlgorithm) -> bool {
		match (&self.kind, &signature_algorithm.sign_alg) {
			(KeyPairKind::Ec(_), SignAlgo::EcDsa(_)) => true,
			(KeyPairKind::Ed(_), SignAlgo::EdDsa(_)) => true,
			(KeyPairKind::Rsa(_), SignAlgo::Rsa()) => true,
			_ => false,
		}
	}
	fn sign(&self, msg :&[u8], writer :DERWriter) -> Result<(), RcgenError> {
		match &self.kind {
			KeyPairKind::Ec(kp) => {
				let msg_input = Input::from(&msg);
				let system_random = SystemRandom::new();
				let signature = kp.sign(&system_random, msg_input)?;
				let sig = &signature.as_ref();
				writer.write_bitvec_bytes(&sig, &sig.len() * 8);
			},
			KeyPairKind::Ed(kp) => {
				let signature = kp.sign(msg);
				let sig = &signature.as_ref();
				writer.write_bitvec_bytes(&sig, &sig.len() * 8);
			},
			KeyPairKind::Rsa(kp) => {
				let system_random = SystemRandom::new();
				let mut signature = vec![0; kp.public_modulus_len()];
				kp.sign(&signature::RSA_PKCS1_SHA256, &system_random,
					msg, &mut signature)?;
				let sig = &signature.as_ref();
				writer.write_bitvec_bytes(&sig, &sig.len() * 8);
			},
		}
		Ok(())
	}
	/// Serializes the private key in PKCS#8 format
	pub fn serialize_der(&self) -> Vec<u8> {
		self.serialized_der.clone()
	}
	/// Serializes the private key in PEM format
	#[cfg(feature = "pem")]
	pub fn serialize_pem(&self) -> String {
		let p = Pem {
			tag : "PRIVATE KEY".to_string(),
			contents : self.serialize_der(),
		};
		pem::encode(&p)
	}
}

/// Signature algorithm type
pub struct SignatureAlgorithm {
	oids_sign_alg :&'static [&'static [u64]],
	sign_alg :SignAlgo,
	digest_alg :&'static ring::digest::Algorithm,
	oid_components :&'static [u64],
	write_null_params :bool,
}

impl SignatureAlgorithm {
	#[cfg(feature = "x509-parser")]
	fn iter() -> std::slice::Iter<'static, &'static SignatureAlgorithm> {
		static ALGORITHMS :&[&SignatureAlgorithm] = &[
			&PKCS_RSA_SHA256,
			&PKCS_ECDSA_P256_SHA256,
			&PKCS_ECDSA_P384_SHA384,
			&PKCS_ED25519
		];
		ALGORITHMS.iter()
	}

	/// Retrieve the SignatureAlgorithm for the provided OID
	#[cfg(feature = "x509-parser")]
	pub fn from_oid(oid :&[u64]) -> Result<&'static SignatureAlgorithm, RcgenError> {
		for algo in Self::iter() {
			if algo.oid_components == oid {
				return Ok(algo);
			}
		}
		Err(RcgenError::UnsupportedSignatureAlgorithm)
	}
}


/// RSA signing with PKCS#1 1.5 padding and SHA-256 hashing as per [RFC 4055](https://tools.ietf.org/html/rfc4055)
pub static PKCS_RSA_SHA256 :SignatureAlgorithm = SignatureAlgorithm {
	oids_sign_alg :&[&OID_RSA_ENCRYPTION],
	sign_alg :SignAlgo::Rsa(),
	digest_alg :&digest::SHA256,
	// sha256WithRSAEncryption in RFC 4055
	oid_components : &[1, 2, 840, 113549, 1, 1, 11],
	write_null_params : true,
};

/// ECDSA signing using the P-256 curves and SHA-256 hashing as per [RFC 5758](https://tools.ietf.org/html/rfc5758#section-3.2)
pub static PKCS_ECDSA_P256_SHA256 :SignatureAlgorithm = SignatureAlgorithm {
	oids_sign_alg :&[&OID_EC_PUBLIC_KEY, &OID_EC_SECP_256_R1],
	sign_alg :SignAlgo::EcDsa(&signature::ECDSA_P256_SHA256_ASN1_SIGNING),
	digest_alg :&digest::SHA256,
	/// ecdsa-with-SHA256 in RFC 5758
	oid_components : &[1, 2, 840, 10045, 4, 3, 2],
	write_null_params : false,
};

/// ECDSA signing using the P-384 curves and SHA-384 hashing as per [RFC 5758](https://tools.ietf.org/html/rfc5758#section-3.2)
pub static PKCS_ECDSA_P384_SHA384 :SignatureAlgorithm = SignatureAlgorithm {
	oids_sign_alg :&[&OID_EC_PUBLIC_KEY, &OID_EC_SECP_384_R1],
	sign_alg :SignAlgo::EcDsa(&signature::ECDSA_P384_SHA384_ASN1_SIGNING),
	digest_alg :&digest::SHA384,
	/// ecdsa-with-SHA384 in RFC 5758
	oid_components : &[1, 2, 840, 10045, 4, 3, 3],
	write_null_params : false,
};

// TODO PKCS_ECDSA_P521_SHA512 https://github.com/briansmith/ring/issues/824

/// ED25519 curve signing as per [RFC 8410](https://tools.ietf.org/html/rfc8410)
pub static PKCS_ED25519 :SignatureAlgorithm = SignatureAlgorithm {
	/// id-Ed25519 in RFC 8410
	oids_sign_alg :&[&[1, 3, 101, 112]],
	sign_alg :SignAlgo::EdDsa(&signature::ED25519),
	digest_alg :&digest::SHA512,
	/// id-Ed25519 in RFC 8410
	oid_components : &[1, 3, 101, 112],
	write_null_params : false,
};

// Signature algorithm IDs as per https://tools.ietf.org/html/rfc4055
impl SignatureAlgorithm {
	fn alg_ident_oid(&self) -> ObjectIdentifier {
		ObjectIdentifier::from_slice(self.oid_components)
	}
	fn write_alg_ident(&self, writer :DERWriter) {
		writer.write_sequence(|writer| {
			writer.next().write_oid(&self.alg_ident_oid());
			if self.write_null_params {
				writer.next().write_null();
			}
		});
	}
	fn write_oids_sign_alg(&self, writer :DERWriter) {
		writer.write_sequence(|writer| {
			for oid in self.oids_sign_alg {
				let oid = ObjectIdentifier::from_slice(oid);
				writer.next().write_oid(&oid);
			}
			if self.write_null_params {
				writer.next().write_null();
			}
		});
	}
}
