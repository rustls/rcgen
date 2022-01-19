/*!
Rust X.509 certificate generation utility

This crate provides a way to generate self signed X.509 certificates.

The most simple way of using this crate is by calling the
[`generate_simple_self_signed`] function.
For more customization abilities, we provide the lower level
[`Certificate::from_params`] function.

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
#![forbid(non_ascii_idents)]
#![deny(missing_docs)]
#![allow(clippy::complexity, clippy::style, clippy::pedantic)]

extern crate yasna;
extern crate ring;
#[cfg(feature = "pem")]
extern crate pem;
extern crate chrono;
#[cfg(feature = "x509-parser")]
extern crate x509_parser;

use yasna::Tag;
use yasna::models::ObjectIdentifier;
#[cfg(feature = "pem")]
use pem::Pem;
use std::convert::TryInto;
use ring::digest;
use ring::signature::{EcdsaKeyPair, Ed25519KeyPair, RsaKeyPair, RsaEncoding};
use ring::rand::SystemRandom;
use ring::signature::KeyPair as RingKeyPair;
use ring::signature::{self, EcdsaSigningAlgorithm, EdDSAParameters};
use yasna::DERWriter;
use yasna::models::{GeneralizedTime, UTCTime};
use yasna::tags::{TAG_BMPSTRING, TAG_TELETEXSTRING, TAG_UNIVERSALSTRING};
use chrono::{DateTime, Timelike, Datelike};
use chrono::{NaiveDate, Utc};
use std::collections::HashMap;
use std::fmt;
use std::convert::TryFrom;
use std::error::Error;
use std::net::IpAddr;
use std::str::FromStr;
use std::hash::{Hash, Hasher};

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

/// id-at-countryName in RFC 5280
const OID_COUNTRY_NAME :&[u64] = &[2, 5, 4, 6];
/// id-at-localityName in RFC 5280
const OID_LOCALITY_NAME :&[u64] = &[2, 5, 4, 7];
/// id-at-stateOrProvinceName in RFC 5280
const OID_STATE_OR_PROVINCE_NAME :&[u64] = &[2, 5, 4, 8];
/// id-at-organizationName in RFC 5280
const OID_ORG_NAME :&[u64] = &[2, 5, 4, 10];
/// id-at-organizationalUnitName in RFC 5280
const OID_ORG_UNIT_NAME :&[u64] = &[2, 5, 4, 11];
/// id-at-commonName in RFC 5280
const OID_COMMON_NAME :&[u64] = &[2, 5, 4, 3];

// https://tools.ietf.org/html/rfc5480#section-2.1.1
const OID_EC_PUBLIC_KEY :&[u64] = &[1, 2, 840, 10045, 2, 1];
const OID_EC_SECP_256_R1 :&[u64] = &[1, 2, 840, 10045, 3, 1, 7];
const OID_EC_SECP_384_R1 :&[u64] = &[1, 3, 132, 0, 34];

// rsaEncryption in RFC 4055
const OID_RSA_ENCRYPTION :&[u64] = &[1, 2, 840, 113549, 1, 1, 1];

// id-RSASSA-PSS in RFC 4055
const OID_RSASSA_PSS :&[u64] = &[1, 2, 840, 113549, 1, 1, 10];

// https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3
const OID_KEY_USAGE :&[u64] = &[2, 5, 29, 15];

// https://tools.ietf.org/html/rfc5280#appendix-A.2
// https://tools.ietf.org/html/rfc5280#section-4.2.1.6
const OID_SUBJECT_ALT_NAME :&[u64] = &[2, 5, 29, 17];

// https://tools.ietf.org/html/rfc5280#section-4.2.1.9
const OID_BASIC_CONSTRAINTS :&[u64] = &[2, 5, 29, 19];

// https://tools.ietf.org/html/rfc5280#section-4.2.1.2
const OID_SUBJECT_KEY_IDENTIFIER :&[u64] = &[2, 5, 29, 14];

// https://tools.ietf.org/html/rfc5280#section-4.2.1.1
const OID_AUTHORITY_KEY_IDENTIFIER :&[u64] = &[2, 5, 29, 35];

// id-ce-extKeyUsage in
// https://tools.ietf.org/html/rfc5280#section-4.2.1.12
const OID_EXT_KEY_USAGE :&[u64] = &[2, 5, 29, 37];

// id-ce-nameConstraints in
/// https://tools.ietf.org/html/rfc5280#section-4.2.1.10
const OID_NAME_CONSTRAINTS :&[u64] = &[2, 5, 29, 30];

// id-pe-acmeIdentifier in
// https://www.iana.org/assignments/smi-numbers/smi-numbers.xhtml#smi-numbers-1.3.6.1.5.5.7.1
const OID_PE_ACME :&[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 31];

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
#[allow(missing_docs)]
#[non_exhaustive]
/// The type of subject alt name
pub enum SanType {
	/// Also known as E-Mail address
	Rfc822Name(String),
	DnsName(String),
	IpAddress(IpAddr),
}

impl SanType {
	#[cfg(feature = "x509-parser")]
	fn try_from_general(name :&x509_parser::extensions::GeneralName<'_>) -> Result<Self, RcgenError> {
		Ok(match name {
			x509_parser::extensions::GeneralName::RFC822Name(name) => {
				SanType::Rfc822Name((*name).into())
			}
			x509_parser::extensions::GeneralName::DNSName(name) => {
				SanType::DnsName((*name).into())
			}
			_ => return Err(RcgenError::InvalidNameType),
		})
	}

	fn tag(&self) -> u64 {
		// Defined in the GeneralName list in
		// https://tools.ietf.org/html/rfc5280#page-38
		const TAG_RFC822_NAME :u64 = 1;
		const TAG_DNS_NAME :u64 = 2;
		const TAG_IP_ADDRESS :u64 = 7;

		match self {
			SanType::Rfc822Name(_name) => TAG_RFC822_NAME,
			SanType::DnsName(_name) => TAG_DNS_NAME,
			SanType::IpAddress(_addr) => TAG_IP_ADDRESS,
		}
	}
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[allow(missing_docs)]
#[non_exhaustive]
/// General Subtree type.
///
/// This type has similarities to the [`SanType`] enum but is not equal.
/// For example, `GeneralSubtree` has CIDR subnets for ip addresses
/// while [`SanType`] has IP addresses.
pub enum GeneralSubtree {
	/// Also known as E-Mail address
	Rfc822Name(String),
	DnsName(String),
	DirectoryName(DistinguishedName),
	IpAddress(CidrSubnet),
}

impl GeneralSubtree {
	fn tag(&self) -> u64 {
		// Defined in the GeneralName list in
		// https://tools.ietf.org/html/rfc5280#page-38
		const TAG_RFC822_NAME :u64 = 1;
		const TAG_DNS_NAME :u64 = 2;
		const TAG_DIRECTORY_NAME :u64 = 4;
		const TAG_IP_ADDRESS :u64 = 7;

		match self {
			GeneralSubtree::Rfc822Name(_name) => TAG_RFC822_NAME,
			GeneralSubtree::DnsName(_name) => TAG_DNS_NAME,
			GeneralSubtree::DirectoryName(_name) => TAG_DIRECTORY_NAME,
			GeneralSubtree::IpAddress(_addr) => TAG_IP_ADDRESS,
		}
	}
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
#[allow(missing_docs)]
/// CIDR subnet, as per [RFC 4632](https://tools.ietf.org/html/rfc4632)
///
/// You might know CIDR subnets better by their textual representation
/// where they consist of an ip address followed by a slash and a prefix
/// number, for example `192.168.99.0/24`.
///
/// The first field in the enum is the address, the second is the mask.
/// Both are specified in network byte order.
pub enum CidrSubnet {
	V4([u8; 4], [u8; 4]),
	V6([u8; 16], [u8; 16]),
}

macro_rules! mask {
	($t:ty, $d:expr) => {{
		let v = <$t>::max_value();
		let v = v.checked_shr($d as u32).unwrap_or(0);
		(!v).to_be_bytes()
	}};
}

impl CidrSubnet {
	/// Obtains the CidrSubnet from the well-known
	/// addr/prefix notation.
	/// ```
	/// # use std::str::FromStr;
	/// # use rcgen::CidrSubnet;
	/// // The "192.0.2.0/24" example from
	/// // https://tools.ietf.org/html/rfc5280#page-42
	/// let subnet = CidrSubnet::from_str("192.0.2.0/24").unwrap();
	/// assert_eq!(subnet, CidrSubnet::V4([0xC0, 0x00, 0x02, 0x00], [0xFF, 0xFF, 0xFF, 0x00]));
	/// ```
	pub fn from_str(s :&str) -> Result<Self, ()> {
		let mut iter = s.split('/');
		if let (Some(addr_s), Some(prefix_s)) = (iter.next(), iter.next()) {
			let addr = IpAddr::from_str(addr_s).map_err(|_| ())?;
			let prefix = u8::from_str(prefix_s).map_err(|_| ())?;
			Ok(Self::from_addr_prefix(addr, prefix))
		} else {
			Err(())
		}
	}
	/// Obtains the CidrSubnet from an ip address
	/// as well as the specified prefix number.
	///
	/// ```
	/// # use std::net::IpAddr;
	/// # use std::str::FromStr;
	/// # use rcgen::CidrSubnet;
	/// // The "192.0.2.0/24" example from
	/// // https://tools.ietf.org/html/rfc5280#page-42
	/// let addr = IpAddr::from_str("192.0.2.0").unwrap();
	/// let subnet = CidrSubnet::from_addr_prefix(addr, 24);
	/// assert_eq!(subnet, CidrSubnet::V4([0xC0, 0x00, 0x02, 0x00], [0xFF, 0xFF, 0xFF, 0x00]));
	/// ```
	pub fn from_addr_prefix(addr :IpAddr, prefix :u8) -> Self {
		match addr {
			IpAddr::V4(addr) => {
				Self::from_v4_prefix(addr.octets(), prefix)
			},
			IpAddr::V6(addr) => {
				Self::from_v6_prefix(addr.octets(), prefix)
			},
		}
	}
	/// Obtains the CidrSubnet from an IPv4 address in network byte order
	/// as well as the specified prefix.
	pub fn from_v4_prefix(addr :[u8; 4], prefix :u8) -> Self {
		CidrSubnet::V4(addr, mask!(u32, prefix))
	}
	/// Obtains the CidrSubnet from an IPv6 address in network byte order
	/// as well as the specified prefix.
	pub fn from_v6_prefix(addr :[u8; 16], prefix :u8) -> Self {
		CidrSubnet::V6(addr, mask!(u128, prefix))
	}
	fn to_bytes(&self) -> Vec<u8> {
		let mut res = Vec::new();
		match self {
			CidrSubnet::V4(addr, mask) => {
				res.extend_from_slice(addr);
				res.extend_from_slice(mask);
			},
			CidrSubnet::V6(addr, mask) => {
				res.extend_from_slice(addr);
				res.extend_from_slice(mask);
			},
		}
		res
	}
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
#[non_exhaustive]
/// The attribute type of a distinguished name entry
pub enum DnType {
	/// X520countryName
	CountryName,
	/// X520LocalityName
	LocalityName,
	/// X520StateOrProvinceName
	StateOrProvinceName,
	/// X520OrganizationName
	OrganizationName,
	/// X520OrganizationalUnitName
	OrganizationalUnitName,
	/// X520CommonName
	CommonName,
	/// Custom distinguished name type
	CustomDnType(Vec<u64>),
}

impl DnType {
	fn to_oid(&self) -> ObjectIdentifier {
		let sl = match self {
			DnType::CountryName => OID_COUNTRY_NAME,
			DnType::LocalityName => OID_LOCALITY_NAME,
			DnType::StateOrProvinceName => OID_STATE_OR_PROVINCE_NAME,
			DnType::OrganizationName => OID_ORG_NAME,
			DnType::OrganizationalUnitName => OID_ORG_UNIT_NAME,
			DnType::CommonName => OID_COMMON_NAME,
			DnType::CustomDnType(ref oid) => oid.as_slice(),
		};
		ObjectIdentifier::from_slice(sl)
	}

	/// Generate a DnType for the provided OID
	pub fn from_oid(slice :&[u64]) -> Self {
		match slice {
			OID_COUNTRY_NAME => DnType::CountryName,
			OID_LOCALITY_NAME => DnType::LocalityName,
			OID_STATE_OR_PROVINCE_NAME => DnType::StateOrProvinceName,
			OID_ORG_NAME => DnType::OrganizationName,
			OID_ORG_UNIT_NAME => DnType::OrganizationalUnitName,
			OID_COMMON_NAME => DnType::CommonName,
			oid => DnType::CustomDnType(oid.into())
		}
	}
}

/// A distinguished name entry
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
#[non_exhaustive]
pub enum DnValue {
	/// A string of characters from the T.61 character set
	TeletexString(Vec<u8>),
	/// An ASCII string containing only A-Z, a-z, 0-9, '()+,-./:=? and <SPACE>
	PrintableString(String),
	/// A string encoded using UTF-32
	UniversalString(Vec<u8>),
	/// A string encoded using UTF-8
	Utf8String(String),
	/// A string encoded using UCS-2
	BmpString(Vec<u8>),
}

impl<T> From<T> for DnValue
where
	T :Into<String>
{
	fn from(t :T) -> Self {
		DnValue::Utf8String(t.into())
	}
}

#[derive(Debug, PartialEq, Eq, Clone)]
/**
Distinguished name used e.g. for the issuer and subject fields of a certificate

A distinguished name is a set of (attribute type, attribute value) tuples.

This datastructure keeps them ordered by insertion order.

See also the RFC 5280 sections on the [issuer](https://tools.ietf.org/html/rfc5280#section-4.1.2.4)
and [subject](https://tools.ietf.org/html/rfc5280#section-4.1.2.6) fields.
*/
pub struct DistinguishedName {
	entries :HashMap<DnType, DnValue>,
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
	/// Obtains the attribute value for the given attribute type
	pub fn get(&self, ty :&DnType) -> Option<&DnValue> {
		self.entries.get(ty)
	}
	/// Removes the attribute with the specified DnType
	///
	/// Returns true when an actual removal happened, false
	/// when no attribute with the specified DnType was
	/// found.
	pub fn remove(&mut self, ty :DnType) -> bool {
		let removed = self.entries.remove(&ty).is_some();
		if removed {
			self.order.retain(|ty_o| &ty != ty_o);
		}
		removed
	}
	/// Inserts or updates an attribute that consists of type and name
	///
	/// ```
	/// # use rcgen::{DistinguishedName, DnType, DnValue};
	/// let mut dn = DistinguishedName::new();
	/// dn.push(DnType::OrganizationName, "Crab widgits SE");
	/// dn.push(DnType::CommonName, DnValue::PrintableString("Master Cert".to_string()));
	/// assert_eq!(dn.get(&DnType::OrganizationName), Some(&DnValue::Utf8String("Crab widgits SE".to_string())));
	/// assert_eq!(dn.get(&DnType::CommonName), Some(&DnValue::PrintableString("Master Cert".to_string())));
	/// ```
	pub fn push(&mut self, ty :DnType, s :impl Into<DnValue>) {
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

	#[cfg(feature = "x509-parser")]
	fn from_name(name :&x509_parser::x509::X509Name) -> Result<Self, RcgenError> {
		use x509_parser::der_parser::der::DerObjectContent;

		let mut dn = DistinguishedName::new();
		for rdn in name.iter() {
			let mut rdn_iter = rdn.iter();
			let dn_opt = rdn_iter.next();
			let attr = if let Some(dn) = dn_opt {
				if rdn_iter.next().is_some() {
					// no support for distinguished names with more than one attribute
					return Err(RcgenError::CouldNotParseCertificate);
				} else {
					dn
				}
			} else {
				panic!("x509-parser distinguished name set is empty");
			};

			let attr_type_oid = attr.attr_type().iter()
				.ok_or(RcgenError::CouldNotParseCertificate)?;
			let dn_type = DnType::from_oid(&attr_type_oid.collect::<Vec<_>>());
			let dn_value = match attr.attr_value().content {
				DerObjectContent::T61String(s) => DnValue::TeletexString(s.into()),
				DerObjectContent::PrintableString(s) => DnValue::PrintableString(s.into()),
				DerObjectContent::UniversalString(s) => DnValue::UniversalString(s.into()),
				DerObjectContent::UTF8String(s) => DnValue::Utf8String(s.into()),
				DerObjectContent::BmpString(s) => DnValue::BmpString(s.into()),
				_ => return Err(RcgenError::CouldNotParseCertificate),
			};

			dn.push(dn_type, dn_value);
		}
		Ok(dn)
	}
}

/**
Iterator over [`DistinguishedName`] entries
*/
pub struct DistinguishedNameIterator<'a> {
	distinguished_name :&'a DistinguishedName,
	iter :std::slice::Iter<'a, DnType>,
}

impl <'a> Iterator for DistinguishedNameIterator<'a> {
	type Item = (&'a DnType, &'a DnValue);

	fn next(&mut self) -> Option<Self::Item> {
		self.iter.next()
			.and_then(|ty| {
				self.distinguished_name.entries.get(ty).map(|v| (ty, v))
			})
	}
}


/// A public key, extracted from a CSR
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct PublicKey {
	raw: Vec<u8>,
	alg: &'static SignatureAlgorithm,
}

impl PublicKeyData for PublicKey {
	fn alg(&self) -> &SignatureAlgorithm {
		self.alg
	}

	fn raw_bytes(&self) -> &[u8] {
		&self.raw
	}
}

/// Data for a certificate signing request
#[allow(missing_docs)]
pub struct CertificateSigningRequest {
	pub params :CertificateParams,
	pub public_key :PublicKey,
}

impl CertificateSigningRequest {
	/// Parse a certificate signing request from the ASCII PEM format
	///
	/// See [`from_der`](Self::from_der) for more details.
	#[cfg(all(feature = "pem", feature = "x509-parser"))]
	pub fn from_pem(pem_str :&str) -> Result<Self, RcgenError> {
		let csr = pem::parse(pem_str)
			.or(Err(RcgenError::CouldNotParseCertificationRequest))?;
		Self::from_der(&csr.contents)
	}

	/// Parse a certificate signing request from DER-encoded bytes
	///
	/// Currently, this only supports the `Subject Alternative Name` extension.
	/// On encountering other extensions, this function will return an error.
	#[cfg(feature = "x509-parser")]
	pub fn from_der(csr :&[u8]) -> Result<Self, RcgenError> {
		use x509_parser::prelude::FromDer;
		let csr = x509_parser::certification_request::X509CertificationRequest::from_der(csr)
			.map_err(|_| RcgenError::CouldNotParseCertificationRequest)?.1;
		csr.verify_signature().map_err(|_| RcgenError::RingUnspecified)?;
		let alg_oid = csr.signature_algorithm.algorithm.iter()
			.ok_or(RcgenError::CouldNotParseCertificationRequest)?
			.collect::<Vec<_>>();
		let alg = SignatureAlgorithm::from_oid(&alg_oid)?;

		let info = &csr.certification_request_info;
		let mut params = CertificateParams::default();
		params.alg = alg;
		params.distinguished_name = DistinguishedName::from_name(&info.subject)?;
		let raw = info.subject_pki.subject_public_key.data.to_vec();

		if let Some(extensions) = csr.requested_extensions() {
			for ext in extensions {
				match ext {
					x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) => {
						for name in &san.general_names {
							params.subject_alt_names.push(SanType::try_from_general(name)?);
						}
					}
					_ => return Err(RcgenError::UnsupportedExtension),
				}
			}
		}

		// Not yet handled:
		// * is_ca
		// * extended_key_usages
		// * name_constraints
		// and any other extensions.

		Ok(Self {
			params,
			public_key: PublicKey { alg, raw },
		})
	}
	/// Serializes the requested certificate, signed with another certificate's key, in binary DER format
	pub fn serialize_der_with_signer(&self, ca :&Certificate) -> Result<Vec<u8>, RcgenError> {
		self.params.serialize_der_with_signer(&self.public_key, ca)
	}
	/// Serializes the requested certificate, signed with another certificate's key, to the ASCII PEM format
	///
	/// *This function is only available if rcgen is built with the "pem" feature*
	#[cfg(feature = "pem")]
	pub fn serialize_pem_with_signer(&self, ca :&Certificate) -> Result<String, RcgenError> {
		let p = Pem {
			tag : "CERTIFICATE".to_string(),
			contents : self.params.serialize_der_with_signer(&self.public_key, ca)?,
		};
		Ok(pem::encode(&p))
	}
}

/// Parameters used for certificate generation
#[allow(missing_docs)]
#[non_exhaustive]
pub struct CertificateParams {
	pub alg :&'static SignatureAlgorithm,
	pub not_before :DateTime<Utc>,
	pub not_after :DateTime<Utc>,
	pub serial_number :Option<u64>,
	pub subject_alt_names :Vec<SanType>,
	pub distinguished_name :DistinguishedName,
	pub is_ca :IsCa,
	pub key_usages :Vec<KeyUsagePurpose>,
	pub extended_key_usages :Vec<ExtendedKeyUsagePurpose>,
	pub name_constraints :Option<NameConstraints>,
	pub custom_extensions :Vec<CustomExtension>,
	/// The certificate's key pair, a new random key pair will be generated if this is `None`
	pub key_pair :Option<KeyPair>,
	/// If `true` (and not self-signed), the 'Authority Key Identifier' extension will be added to the generated cert
	pub use_authority_key_identifier_extension :bool,
	/// Method to generate key identifiers from public keys
	///
	/// Defaults to SHA-256.
	pub key_identifier_method :KeyIdMethod,
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
			key_usages : Vec::new(),
			extended_key_usages : Vec::new(),
			name_constraints : None,
			custom_extensions : Vec::new(),
			key_pair : None,
			use_authority_key_identifier_extension : false,
			key_identifier_method : KeyIdMethod::Sha256,
		}
	}
}

impl CertificateParams {
	/// Parses a ca certificate from the ASCII PEM format for signing
	///
	/// See [`from_ca_cert_der`](Self::from_ca_cert_der) for more details.
	///
	/// *This constructor is only available if rcgen is built with the "pem" and "x509-parser" features*
	#[cfg(all(feature = "pem", feature = "x509-parser"))]
	pub fn from_ca_cert_pem(pem_str :&str, key_pair :KeyPair) -> Result<Self, RcgenError> {
		let certificate = pem::parse(pem_str)
			.or(Err(RcgenError::CouldNotParseCertificate))?;
		Self::from_ca_cert_der(&certificate.contents, key_pair)
	}

	/// Parses a ca certificate from the DER format for signing
	///
	/// This function is only of use if you have an existing ca certificate with
	/// which you want to sign a certificate newly generated by `rcgen` using the
	/// [`serialize_der_with_signer`](Certificate::serialize_der_with_signer) or
	/// [`serialize_pem_with_signer`](Certificate::serialize_pem_with_signer)
	/// functions.
	///
	/// This function only extracts from the given ca cert the informations
	/// needed for signing. Any information beyond that is not extracted
	/// and left to defaults.
	///
	/// Will not check if certificate is a ca certificate!
	///
	/// *This constructor is only available if rcgen is built with the "x509-parser" feature*
	#[cfg(feature = "x509-parser")]
	pub fn from_ca_cert_der(ca_cert :&[u8], key_pair :KeyPair) -> Result<Self, RcgenError> {
		let (_remainder, x509) = x509_parser::parse_x509_certificate(ca_cert)
			.or(Err(RcgenError::CouldNotParseCertificate))?;

		let alg_oid = x509.signature_algorithm.algorithm.iter()
			.ok_or(RcgenError::CouldNotParseCertificate)?;
		let alg = SignatureAlgorithm::from_oid(&alg_oid.collect::<Vec<_>>())?;

		let dn = DistinguishedName::from_name(&x509.tbs_certificate.subject)?;
		Ok(
			CertificateParams {
				alg,
				distinguished_name : dn,
				key_pair : Some(key_pair),
				.. Default::default()
			}
		)
	}
	fn write_subject_alt_names(&self, writer :DERWriter) {
		Self::write_extension(writer, OID_SUBJECT_ALT_NAME, false, |writer| {
			writer.write_sequence(|writer| {
				for san in self.subject_alt_names.iter() {
					writer.next().write_tagged_implicit(Tag::context(san.tag()), |writer| {
						match san {
							SanType::Rfc822Name(name) |
							SanType::DnsName(name) => writer.write_utf8_string(name),
							SanType::IpAddress(IpAddr::V4(addr)) => writer.write_bytes(&addr.octets()),
							SanType::IpAddress(IpAddr::V6(addr)) => writer.write_bytes(&addr.octets()),
						}
					});
				}
			});
		});
	}
	fn write_request<K: PublicKeyData>(&self, pub_key: &K, writer :DERWriter) {
		writer.write_sequence(|writer| {
			// Write version
			writer.next().write_u8(0);
			// Write issuer
			writer.next().write_sequence(|writer| {
				for (ty, content) in self.distinguished_name.iter() {
					writer.next().write_set(|writer| {
						writer.next().write_sequence(|writer| {
							writer.next().write_oid(&ty.to_oid());
							match content {
								DnValue::TeletexString(s) => writer.next().write_tagged_implicit(TAG_TELETEXSTRING, |writer| {
									writer.write_bytes(s)
								}),
								DnValue::PrintableString(s) => writer.next().write_printable_string(s),
								DnValue::UniversalString(s) => writer.next().write_tagged_implicit(TAG_UNIVERSALSTRING, |writer| {
									writer.write_bytes(s)
								}),
								DnValue::Utf8String(s) => writer.next().write_utf8_string(s),
								DnValue::BmpString(s) => writer.next().write_tagged_implicit(TAG_BMPSTRING, |writer| {
									writer.write_bytes(s)
								}),
							}
						});
					});
				}
			});
			// Write subjectPublicKeyInfo
			pub_key.serialize_public_key_der(writer.next());
			// Write extensions
			// According to the spec in RFC 2986, even if attributes are empty we need the empty attribute tag
			writer.next().write_tagged(Tag::context(0), |writer| {
				if !self.subject_alt_names.is_empty() {
					writer.write_sequence(|writer| {
						let oid = ObjectIdentifier::from_slice(OID_PKCS_9_AT_EXTENSION_REQUEST);
						writer.next().write_oid(&oid);
						writer.next().write_set(|writer| {
							writer.next().write_sequence(|writer| {
								// Write subject_alt_names
								self.write_subject_alt_names(writer.next());
							});
						});
					});
				}
			});

		});
	}
	fn write_cert<K: PublicKeyData>(&self, writer :DERWriter, pub_key: &K, ca :&Certificate) -> Result<(), RcgenError> {
		writer.write_sequence(|writer| {
			// Write version
			writer.next().write_tagged(Tag::context(0), |writer| {
				writer.write_u8(2);
			});
			// Write serialNumber
			let serial = self.serial_number.unwrap_or_else(|| {
				let hash = digest::digest(&digest::SHA256, pub_key.raw_bytes());
				let bytes: [u8; 8] = hash.as_ref()[0..8].try_into().unwrap();
				u64::from_le_bytes(bytes)
			});
			writer.next().write_u64(serial);
			// Write signature
			ca.params.alg.write_alg_ident(writer.next());
			// Write issuer
			write_distinguished_name(writer.next(), &ca.params.distinguished_name);
			// Write validity
			writer.next().write_sequence(|writer| {
				// Not before
				write_dt_utc_or_generalized(writer.next(), &self.not_before)?;
				// Not after
				write_dt_utc_or_generalized(writer.next(), &self.not_after)?;
				Ok::<(), RcgenError>(())
			})?;
			// Write subject
			write_distinguished_name(writer.next(), &self.distinguished_name);
			// Write subjectPublicKeyInfo
			pub_key.serialize_public_key_der(writer.next());
			// write extensions
			let not_self_signed = ca.key_pair.public_key_raw() != pub_key.raw_bytes();
			let should_write_exts = (not_self_signed && self.use_authority_key_identifier_extension) ||
				!self.subject_alt_names.is_empty() ||
				!self.extended_key_usages.is_empty() ||
				self.name_constraints.iter().any(|c| !c.is_empty()) ||
				matches!(self.is_ca, IsCa::Ca(_)) ||
				!self.custom_extensions.is_empty();
			if should_write_exts {
				writer.next().write_tagged(Tag::context(3), |writer| {
					writer.write_sequence(|writer| {
						if not_self_signed && self.use_authority_key_identifier_extension {
							// Write Authority Key Identifier (when issued by a CA)
							// RFC 5280 states:
							//   'The keyIdentifier field of the authorityKeyIdentifier extension MUST
							//    be included in all certificates generated by conforming CAs to
							//    facilitate certification path construction.  There is one exception;
							//    where a CA distributes its public key in the form of a "self-signed"
							//    certificate, the authority key identifier MAY be omitted.'
							Self::write_extension(writer.next(), OID_AUTHORITY_KEY_IDENTIFIER, false, |writer| {
								writer.write_sequence(|writer| {
									writer.next().write_tagged_implicit(Tag::context(0), |writer| {
										writer.write_bytes(ca.get_key_identifier().as_ref())
									})
								});
							});
						}
						// Write subject_alt_names
						if !self.subject_alt_names.is_empty() {
							self.write_subject_alt_names(writer.next());
						}

						// Write standard key usage
						if !self.key_usages.is_empty() {
							writer.next().write_sequence(|writer| {

								let oid = ObjectIdentifier::from_slice(OID_KEY_USAGE);
								writer.next().write_oid(&oid);
								writer.next().write_bool(true);

								let mut bits :u16 = 0;

								for entry in self.key_usages.iter() {
									// Map the index to a value
									let index = match entry {
										KeyUsagePurpose::DigitalSignature => 0,
										KeyUsagePurpose::ContentCommitment => 1,
										KeyUsagePurpose::KeyEncipherment => 2,
										KeyUsagePurpose::DataEncipherment => 3,
										KeyUsagePurpose::KeyAgreement => 4,
										KeyUsagePurpose::KeyCertSign => 5,
										KeyUsagePurpose::CrlSign => 6,
										KeyUsagePurpose::EncipherOnly => 7,
										KeyUsagePurpose::DecipherOnly => 8,
									};

									bits |= 1 << index;
								}

								// Compute the 1-based most significant bit
								let msb = 16 - bits.leading_zeros();
								let nb = if msb <= 8 {
									1
								} else {
									2
								};

								let bits = bits.reverse_bits().to_be_bytes();

								// Finally take only the bytes != 0
								let bits = &bits[..nb];

								let der = yasna::construct_der(|writer| {
									writer.write_bitvec_bytes(&bits, msb as usize)
								});

								// Write them
								writer.next().write_bytes(&der);

							});
						}

						// Write extended key usage
						if !self.extended_key_usages.is_empty() {
							Self::write_extension(writer.next(), OID_EXT_KEY_USAGE, false, |writer| {
								writer.write_sequence(|writer| {
									for usage in self.extended_key_usages.iter() {
										let oid = ObjectIdentifier::from_slice(usage.oid());
										writer.next().write_oid(&oid);
									}
								});
							});
						}
						if let Some(name_constraints) = &self.name_constraints {
							// If both trees are empty, the extension must be omitted.
							if !name_constraints.is_empty() {
								Self::write_extension(writer.next(), OID_NAME_CONSTRAINTS, true, |writer| {
									writer.write_sequence(|writer| {
										if !name_constraints.permitted_subtrees.is_empty() {
											write_general_subtrees(writer.next(), 0, &name_constraints.permitted_subtrees);
										}
										if !name_constraints.excluded_subtrees.is_empty() {
											write_general_subtrees(writer.next(), 1, &name_constraints.excluded_subtrees);
										}
									});
								});
							}
						}
						if let IsCa::Ca(ref constraint) = self.is_ca {
							// Write subject_key_identifier
							Self::write_extension(writer.next(), OID_SUBJECT_KEY_IDENTIFIER, false, |writer| {
								let key_identifier = self.key_identifier(pub_key);
								writer.write_bytes(key_identifier.as_ref());
							});
							// Write basic_constraints
							Self::write_extension(writer.next(), OID_BASIC_CONSTRAINTS, true, |writer| {
								writer.write_sequence(|writer| {
									writer.next().write_bool(true); // cA flag
									if let BasicConstraints::Constrained(path_len_constraint) = constraint {
										writer.next().write_u8(*path_len_constraint);
									}
								});
							});
						}
						// Write the custom extensions
						for ext in &self.custom_extensions {
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
			}
			Ok(())
		})
	}
	/// Serializes an X.509v3 extension according to RFC 5280
	fn write_extension(writer :DERWriter, extension_oid :&[u64], is_critical :bool, value_serializer :impl FnOnce(DERWriter)) {
		// Extension specification:
		//    Extension  ::=  SEQUENCE  {
		//         extnID      OBJECT IDENTIFIER,
		//         critical    BOOLEAN DEFAULT FALSE,
		//         extnValue   OCTET STRING
		//                     -- contains the DER encoding of an ASN.1 value
		//                     -- corresponding to the extension type identified
		//                     -- by extnID
		//         }

		writer.write_sequence(|writer| {
			let oid = ObjectIdentifier::from_slice(extension_oid);
			writer.next().write_oid(&oid);
			if is_critical {
				writer.next().write_bool(true);
			}
			let bytes = yasna::construct_der(value_serializer);
			writer.next().write_bytes(&bytes);
		})
	}
	/// Calculates a subject key identifier for the certificate subject's public key.
	/// This key identifier is used in the SubjectKeyIdentifier X.509v3 extension.
	fn key_identifier<K: PublicKeyData>(&self, pub_key: &K) -> Vec<u8> {
		// Decide which method from RFC 7093 to use
		let digest_method = match self.key_identifier_method {
			KeyIdMethod::Sha256 => &digest::SHA256,
			KeyIdMethod::Sha384 => &digest::SHA384,
			KeyIdMethod::Sha512 => &digest::SHA512,
		};
		let digest = digest::digest(digest_method, pub_key.raw_bytes());
		let truncated_digest = &digest.as_ref()[0..20];
		truncated_digest.to_vec()
	}
	fn serialize_der_with_signer<K: PublicKeyData>(&self, pub_key: &K, ca :&Certificate) -> Result<Vec<u8>, RcgenError> {
		yasna::try_construct_der(|writer| {
			writer.write_sequence(|writer| {

				let tbs_cert_list_serialized = yasna::try_construct_der(|writer| {
					self.write_cert(writer, pub_key, ca)?;
					Ok::<(), RcgenError>(())
				})?;
				// Write tbsCertList
				writer.next().write_der(&tbs_cert_list_serialized);

				// Write signatureAlgorithm
				ca.params.alg.write_alg_ident(writer.next());

				// Write signature
				ca.key_pair.sign(&tbs_cert_list_serialized, writer.next())?;

				Ok(())
			})
		})
	}
}

/// Whether the certificate is allowed to sign other certificates
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
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
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum BasicConstraints {
	/// No constraint
	Unconstrained,
	/// Constrain to the contained number of intermediate certificates
	Constrained(u8),
}

impl CertificateParams {
	/// Generate certificate parameters with reasonable defaults
	pub fn new(subject_alt_names :impl Into<Vec<String>>) -> Self {
		let subject_alt_names = subject_alt_names.into()
			.into_iter()
			.map(|s| SanType::DnsName(s))
			.collect::<Vec<_>>();
		CertificateParams {
			subject_alt_names,
			.. Default::default()
		}
	}
}

/// The [NameConstraints extension](https://tools.ietf.org/html/rfc5280#section-4.2.1.10)
/// (only relevant for CA certificates)
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NameConstraints {
	/// If non-empty, a whitelist of subtrees that the
	/// domain has to match.
	pub permitted_subtrees :Vec<GeneralSubtree>,
	/// A list of excluded subtrees.
	///
	/// Any name matching an excluded subtree is invalid
	/// even if it also matches a permitted subtree.
	pub excluded_subtrees :Vec<GeneralSubtree>,
}

impl NameConstraints {
	fn is_empty(&self) -> bool {
		self.permitted_subtrees.is_empty() && self.excluded_subtrees.is_empty()
	}
}

/// One of the purposes contained in the [key usage](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3) extension
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum KeyUsagePurpose {
	/// digitalSignature
	DigitalSignature,
	/// contentCommitment / nonRepudiation
	ContentCommitment,
	/// keyEncipherment
	KeyEncipherment,
	/// dataEncipherment
	DataEncipherment,
	/// keyAgreement
	KeyAgreement,
	/// keyCertSign
	KeyCertSign,
	/// cRLSign
	CrlSign,
	/// encipherOnly
	EncipherOnly,
	/// decipherOnly
	DecipherOnly,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
/// One of the purposes contained in the [extended key usage extension](https://tools.ietf.org/html/rfc5280#section-4.2.1.12)
pub enum ExtendedKeyUsagePurpose {
	/// anyExtendedKeyUsage
	Any,
	/// id-kp-serverAuth
	ServerAuth,
	/// id-kp-clientAuth
	ClientAuth,
	/// id-kp-codeSigning
	CodeSigning,
	/// id-kp-emailProtection
	EmailProtection,
	/// id-kp-timeStamping
	TimeStamping,
	/// id-kp-OCSPSigning
	OcspSigning,
}

impl ExtendedKeyUsagePurpose {
	fn oid(&self) -> &'static [u64] {
		use ExtendedKeyUsagePurpose::*;
		match self {
			// anyExtendedKeyUsage
			Any => &[2, 5, 29, 37],
			// id-kp-*
			ServerAuth => &[1, 3, 6, 1, 5, 5, 7, 3, 1],
			ClientAuth => &[1, 3, 6, 1, 5, 5, 7, 3, 2],
			CodeSigning => &[1, 3, 6, 1, 5, 5, 7, 3, 3],
			EmailProtection => &[1, 3, 6, 1, 5, 5, 7, 3, 4],
			TimeStamping => &[1, 3, 6, 1, 5, 5, 7, 3, 8],
			OcspSigning => &[1, 3, 6, 1, 5, 5, 7, 3, 9],
		}
	}
}

/// A custom extension of a certificate, as specified in
/// [RFC 5280](https://tools.ietf.org/html/rfc5280#section-4.2)
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct CustomExtension {
	oid :Vec<u64>,
	critical :bool,

	/// The content must be DER-encoded
	content :Vec<u8>,
}

impl CustomExtension {
	/// Creates a new acmeIdentifier extension for ACME TLS-ALPN-01
	/// as specified in [RFC 8737](https://tools.ietf.org/html/rfc8737#section-3)
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
	/// Create a new custom extension with the specified content
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
	/// Obtains the criticality flag of the extension.
	pub fn criticality(&self) -> bool {
		self.critical
	}
	/// Obtains the content of the extension.
	pub fn content(&self) -> &[u8] {
		&self.content
	}
	/// Obtains the OID components of the extensions, as u64 pieces
	pub fn oid_components(&self) -> impl Iterator<Item = u64> + '_ {
		self.oid.iter().copied()
	}
}

/// Method to generate key identifiers from public keys.
///
/// This allows choice over methods to generate key identifiers
/// as specified in RFC 7093 section 2.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
#[non_exhaustive]
pub enum KeyIdMethod {
	/// RFC 7093 method 1
	Sha256,
	/// RFC 7093 method 2
	Sha384,
	/// RFC 7093 method 3
	Sha512,
}

/// Helper to obtain a DateTime from year, month, day values
///
/// The year, month, day values are assumed to be in UTC.
///
/// This helper function serves two purposes: first, so that you don't
/// have to import the chrono crate yourself in order to specify date
/// information, second so that users don't have to type unproportionately
/// long code just to generate an instance of [`DateTime<Utc>`].
pub fn date_time_ymd(year :i32, month :u32, day :u32) -> DateTime<Utc> {
	let naive_dt = NaiveDate::from_ymd(year, month, day).and_hms_milli(0, 0, 0, 0);
	DateTime::<Utc>::from_utc(naive_dt, Utc)
}

fn dt_strip_nanos(dt :&DateTime<Utc>, allow_leap: bool) -> Result<DateTime<Utc>, RcgenError> {
	// Set nanoseconds to zero (or to one leap second if there is a leap second)
	// This is needed because the GeneralizedTime serializer would otherwise
	// output fractional values which RFC 5280 explicitly forbode [1].
	// UTCTime cannot express fractional seconds or leap seconds
	// therefore, it needs to be stripped of nanoseconds fully.
	// [1]: https://tools.ietf.org/html/rfc5280#section-4.1.2.5.2
	let nanos = if dt.nanosecond() >= 1_000_000_000 && allow_leap {
		1_000_000_000
	} else {
		0
	};
	dt.with_nanosecond(nanos).ok_or(RcgenError::Time)
}

fn dt_to_generalized(dt :&DateTime<Utc>) -> Result<GeneralizedTime, RcgenError> {
	let date_time = dt_strip_nanos(dt, true)?;
	Ok(GeneralizedTime::from_datetime::<Utc>(&date_time))
}

fn write_dt_utc_or_generalized(writer :DERWriter, dt :&DateTime<Utc>) -> Result<(), RcgenError> {
	// RFC 5280 requires CAs to write certificate validity dates
	// below 2050 as UTCTime, and anything starting from 2050
	// as GeneralizedTime [1]. The RFC doesn't say anything
	// about dates before 1950, but as UTCTime can't represent
	// them, we have to use GeneralizedTime if we want to or not.
	// [1]: https://tools.ietf.org/html/rfc5280#section-4.1.2.5
	if (1950..2050).contains(&dt.year()) {
		let date_time = dt_strip_nanos(dt, false)?;
		let ut = UTCTime::from_datetime::<Utc>(&date_time);
		writer.write_utctime(&ut);
	} else {
		let gt = dt_to_generalized(dt)?;
		writer.write_generalized_time(&gt);
	}
	Ok(())
}

fn write_distinguished_name(writer :DERWriter, dn :&DistinguishedName) {
		writer.write_sequence(|writer| {
			for (ty, content) in dn.iter() {
				writer.next().write_set(|writer| {
					writer.next().write_sequence(|writer| {
						writer.next().write_oid(&ty.to_oid());
						match content {
							DnValue::TeletexString(s) => writer.next().write_tagged_implicit(TAG_TELETEXSTRING, |writer| {
								writer.write_bytes(s)
							}),
							DnValue::PrintableString(s) => writer.next().write_printable_string(s),
							DnValue::UniversalString(s) => writer.next().write_tagged_implicit(TAG_UNIVERSALSTRING, |writer| {
								writer.write_bytes(s)
							}),
							DnValue::Utf8String(s) => writer.next().write_utf8_string(s),
							DnValue::BmpString(s) => writer.next().write_tagged_implicit(TAG_BMPSTRING, |writer| {
								writer.write_bytes(s)
							}),
						}
					});
				});
			}
		});
}

fn write_general_subtrees(writer :DERWriter, tag :u64, general_subtrees :&[GeneralSubtree]) {
	writer.write_tagged_implicit(Tag::context(tag), |writer| {
		writer.write_sequence(|writer| {
			for subtree in general_subtrees.iter() {
				writer.next().write_sequence(|writer| {
					writer.next().write_tagged_implicit(Tag::context(subtree.tag()), |writer| {
						match subtree {
							GeneralSubtree::Rfc822Name(name) |
							GeneralSubtree::DnsName(name) => writer.write_utf8_string(name),
							GeneralSubtree::DirectoryName(name) => write_distinguished_name(writer, name),
							GeneralSubtree::IpAddress(subnet) => writer.write_bytes(&subnet.to_bytes()),
						}
					});
					// minimum must be 0 (the default) and maximum must be absent
				});
			}
		});
	});
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
	/// Calculates a subject key identifier for the certificate subject's public key.
	/// This key identifier is used in the SubjectKeyIdentifier X.509v3 extension.
	pub fn get_key_identifier(&self) -> Vec<u8> {
		self.params.key_identifier(&self.key_pair)
	}
	/// Serializes the certificate to the binary DER format
	pub fn serialize_der(&self) -> Result<Vec<u8>, RcgenError> {
		self.serialize_der_with_signer(&self)
	}
	/// Serializes the certificate, signed with another certificate's key, in binary DER format
	pub fn serialize_der_with_signer(&self, ca :&Certificate) -> Result<Vec<u8>, RcgenError> {
		self.params.serialize_der_with_signer(&self.key_pair, ca)
	}
	/// Serializes a certificate signing request in binary DER format
	pub fn serialize_request_der(&self) -> Result<Vec<u8>, RcgenError> {
		yasna::try_construct_der(|writer| {
			writer.write_sequence(|writer| {
				let cert_data = yasna::construct_der(|writer| {
					self.params.write_request(&self.key_pair, writer);
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
	/// Return the certificate's key pair
	pub fn get_key_pair(&self) -> &KeyPair {
		&self.key_pair
	}
	/// Serializes the certificate to the ASCII PEM format
	///
	/// *This function is only available if rcgen is built with the "pem" feature*
	#[cfg(feature = "pem")]
	pub fn serialize_pem(&self) -> Result<String, RcgenError> {
		let p = Pem {
			tag : "CERTIFICATE".to_string(),
			contents : self.serialize_der()?,
		};
		Ok(pem::encode(&p))
	}
	/// Serializes the certificate, signed with another certificate's key, to the ASCII PEM format
	///
	/// *This function is only available if rcgen is built with the "pem" feature*
	#[cfg(feature = "pem")]
	pub fn serialize_pem_with_signer(&self, ca :&Certificate) -> Result<String, RcgenError> {
		let p = Pem {
			tag : "CERTIFICATE".to_string(),
			contents : self.serialize_der_with_signer(ca)?,
		};
		Ok(pem::encode(&p))
	}
	/// Serializes the certificate signing request to the ASCII PEM format
	///
	/// *This function is only available if rcgen is built with the "pem" feature*
	#[cfg(feature = "pem")]
	pub fn serialize_request_pem(&self) -> Result<String, RcgenError> {
		let p = Pem {
			tag : "CERTIFICATE REQUEST".to_string(),
			contents : self.serialize_request_der()?,
		};
		Ok(pem::encode(&p))
	}
	/// Serializes the private key in PKCS#8 format
	///
	/// Panics if called on a remote key pair.
	pub fn serialize_private_key_der(&self) -> Vec<u8> {
		self.key_pair.serialize_der()
	}
	/// Serializes the private key in PEM format
	///
	/// Panics if called on a remote key pair.
	///
	/// *This function is only available if rcgen is built with the "pem" feature*
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
	Rsa(RsaKeyPair, &'static dyn RsaEncoding),
	/// A remote key pair
	Remote(Box<dyn RemoteKeyPair + Send + Sync>),
}

impl fmt::Debug for KeyPairKind {
	fn fmt(&self, f :&mut fmt::Formatter) -> fmt::Result {
		match self {
			Self::Ec(key_pair) => write!(f, "{:?}", key_pair),
			Self::Ed(key_pair) => write!(f, "{:?}", key_pair),
			Self::Rsa(key_pair, _) => write!(f, "{:?}", key_pair),
			Self::Remote(_) => write!(f, "Box<dyn RemotePrivateKey>"),
		}
	}
}

/// A key pair used to sign certificates and CSRs
///
/// Note that ring, the underlying library to handle RSA keys
/// requires them to be in a special format, meaning that
/// `openssl genrsa` doesn't work. See ring's [documentation](ring::signature::RsaKeyPair::from_pkcs8)
/// for how to generate RSA keys in the wanted format
/// and conversion between the formats.
#[derive(Debug)]
pub struct KeyPair {
	kind :KeyPairKind,
	alg :&'static SignatureAlgorithm,
	serialized_der :Vec<u8>,
}

impl KeyPair {
	/// Parses the key pair from the DER format
	///
	/// Equivalent to using the [`TryFrom`] implementation.
	pub fn from_der(der :&[u8]) -> Result<Self, RcgenError> {
		Ok(der.try_into()?)
	}
	/// Parses the key pair from the ASCII PEM format
	///
	/// *This constructor is only available if rcgen is built with the "pem" feature*
	#[cfg(feature = "pem")]
	pub fn from_pem(pem_str :&str) -> Result<Self, RcgenError> {
		let private_key = pem::parse(pem_str)?;
		let private_key_der :&[_] = &private_key.contents;
		Ok(private_key_der.try_into()?)
	}

	/// Obtains the key pair from a raw public key and a remote private key
	pub fn from_remote(key_pair :Box<dyn RemoteKeyPair + Send + Sync>) -> Result<Self, RcgenError> {
		Ok(Self {
			alg : key_pair.algorithm(),
			kind : KeyPairKind::Remote(key_pair),
			serialized_der : Vec::new(),
		})
	}


	/// Obtains the key pair from a DER formatted key
	/// using the specified [`SignatureAlgorithm`](SignatureAlgorithm)
	///
	/// Same as [from_pem_and_sign_algo](Self::from_pem_and_sign_algo).
	///
	/// *This constructor is only available if rcgen is built with the "pem" feature*
	#[cfg(feature = "pem")]
	pub fn from_pem_and_sign_algo(pem_str :&str, alg :&'static SignatureAlgorithm) -> Result<Self, RcgenError> {
		let private_key = pem::parse(pem_str)?;
		let private_key_der :&[_] = &private_key.contents;
		Ok(Self::from_der_and_sign_algo(private_key_der, alg)?)
	}

	/// Obtains the key pair from a DER formatted key
	/// using the specified [`SignatureAlgorithm`](SignatureAlgorithm)
	///
	/// Usually, calling this function is not neccessary and you can just call
	/// [`from_der`](Self::from_der) instead. That function will try to figure
	/// out a fitting [`SignatureAlgorithm`](SignatureAlgorithm) for the given
	/// key pair. However sometimes multiple signature algorithms fit for the
	/// same der key. In that instance, you can use this function to precisely
	/// specify the `SignatureAlgorithm`.
	pub fn from_der_and_sign_algo(pkcs8 :&[u8], alg :&'static SignatureAlgorithm) -> Result<Self, RcgenError> {
		let pkcs8_vec = pkcs8.to_vec();

		let kind = if alg == &PKCS_ED25519 {
			KeyPairKind::Ed(Ed25519KeyPair::from_pkcs8_maybe_unchecked(pkcs8)?)
		} else if alg == &PKCS_ECDSA_P256_SHA256 {
			KeyPairKind::Ec(EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8)?)
		} else if alg == &PKCS_ECDSA_P384_SHA384 {
			KeyPairKind::Ec(EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P384_SHA384_ASN1_SIGNING, pkcs8)?)
		} else if alg == &PKCS_RSA_SHA256 {
			let rsakp = RsaKeyPair::from_pkcs8(pkcs8)?;
			KeyPairKind::Rsa(rsakp, &signature::RSA_PKCS1_SHA256)
		} else if alg == &PKCS_RSA_SHA384 {
			let rsakp = RsaKeyPair::from_pkcs8(pkcs8)?;
			KeyPairKind::Rsa(rsakp, &signature::RSA_PKCS1_SHA384)
		} else if alg == &PKCS_RSA_SHA512 {
			let rsakp = RsaKeyPair::from_pkcs8(pkcs8)?;
			KeyPairKind::Rsa(rsakp, &signature::RSA_PKCS1_SHA512)
		} else if alg == &PKCS_RSA_PSS_SHA256 {
			let rsakp = RsaKeyPair::from_pkcs8(pkcs8)?;
			KeyPairKind::Rsa(rsakp, &signature::RSA_PSS_SHA256)
		} else {
			panic!("Unknown SignatureAlgorithm specified!");
		};

		Ok(KeyPair {
			kind,
			alg,
			serialized_der : pkcs8_vec,
		})
	}

	fn from_raw(pkcs8: &[u8]) -> Result<(KeyPairKind, &'static SignatureAlgorithm), RcgenError> {
		let (kind, alg) = if let Ok(edkp) = Ed25519KeyPair::from_pkcs8_maybe_unchecked(pkcs8) {
			(KeyPairKind::Ed(edkp), &PKCS_ED25519)
		} else if let Ok(eckp) = EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8) {
			(KeyPairKind::Ec(eckp), &PKCS_ECDSA_P256_SHA256)
		} else if let Ok(eckp) = EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P384_SHA384_ASN1_SIGNING, pkcs8) {
			(KeyPairKind::Ec(eckp), &PKCS_ECDSA_P384_SHA384)
		} else if let Ok(rsakp) = RsaKeyPair::from_pkcs8(pkcs8) {
			(KeyPairKind::Rsa(rsakp, &signature::RSA_PKCS1_SHA256), &PKCS_RSA_SHA256)
		} else {
			return Err(RcgenError::CouldNotParseKeyPair);
		};
		Ok((kind, alg))
	}
}

/// A private key that is not directly accessible, but can be used to sign messages
///
/// Trait objects based on this trait can be passed to the [`KeyPair::from_remote`] function to generating certificates
/// from a remote and raw private key, for example an HSM.
pub trait RemoteKeyPair {
	/// Returns the public key of this key pair in DER format
	fn public_key(&self) -> &[u8];

	/// Signs `msg` using the selected algorithm
	fn sign(&self, msg :&[u8]) -> Result<Vec<u8>, RcgenError>;

	/// Reveals which algorithm will be used when you call `sign()`
	fn algorithm(&self) -> &'static SignatureAlgorithm;
}

#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
/// The error type of the rcgen crate
pub enum RcgenError {
	/// The given certificate couldn't be parsed
	CouldNotParseCertificate,
	/// The given certificate signing request couldn't be parsed
	CouldNotParseCertificationRequest,
	/// The given key pair couldn't be parsed
	CouldNotParseKeyPair,
	#[cfg(feature = "x509-parser")]
	/// Invalid subject alternative name type
	InvalidNameType,
	/// There is no support for generating
	/// keys for the given algorithm
	KeyGenerationUnavailable,
	#[cfg(feature = "x509-parser")]
	/// Unsupported extension requested in CSR
	UnsupportedExtension,
	/// The requested signature algorithm is not supported
	UnsupportedSignatureAlgorithm,
	/// Unspecified `ring` error
	RingUnspecified,
	/// The `ring` library rejected the key upon loading
	RingKeyRejected(&'static str),
	/// The provided certificate's signature algorithm
	/// is incompatible with the given key pair
	CertificateKeyPairMismatch,
	/// Time conversion related errors
	Time,
	#[cfg(feature = "pem")]
	/// Error from the pem crate
	///
	/// *This variant is only available if rcgen is built with the "pem" feature*
	PemError(pem::PemError),
	/// Error generated by a remote key operation
	RemoteKeyError,
}

impl fmt::Display for RcgenError {
	fn fmt(&self, f :&mut fmt::Formatter) -> fmt::Result {
		use self::RcgenError::*;
		match self {
			CouldNotParseCertificate => write!(f, "Could not parse certificate")?,
			CouldNotParseCertificationRequest => write!(f, "Could not parse certificate signing \
				request")?,
			CouldNotParseKeyPair => write!(f, "Could not parse key pair")?,
			#[cfg(feature = "x509-parser")]
			InvalidNameType => write!(f, "Invalid subject alternative name type")?,
			KeyGenerationUnavailable => write!(f, "There is no support for generating \
				keys for the given algorithm")?,
			UnsupportedSignatureAlgorithm => write!(f, "The requested signature algorithm \
				is not supported")?,
			#[cfg(feature = "x509-parser")]
			UnsupportedExtension => write!(f, "Unsupported extension requested in CSR")?,
			RingUnspecified => write!(f, "Unspecified ring error")?,
			RingKeyRejected(e) => write!(f, "Key rejected by ring: {}", e)?,
			CertificateKeyPairMismatch => write!(f, "The provided certificate's signature \
				algorithm is incompatible with the given key pair")?,

			Time => write!(f, "Time error")?,
			RemoteKeyError => write!(f, "Remote key error")?,
			#[cfg(feature = "pem")]
			PemError(e) => write!(f, "PEM error: {}", e)?,
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

impl From<ring::error::KeyRejected> for RcgenError {
	fn from(err :ring::error::KeyRejected) -> Self {
		RcgenError::RingKeyRejected(err.description_())
	}
}

#[cfg(feature = "pem")]
impl From<pem::PemError> for RcgenError {
	fn from(e :pem::PemError) -> Self {
		RcgenError::PemError(e)
	}
}

impl TryFrom<&[u8]> for KeyPair {
	type Error = RcgenError;

	fn try_from(pkcs8: &[u8]) -> Result<KeyPair, RcgenError> {
		let (kind, alg) = KeyPair::from_raw(pkcs8)?;
		Ok(KeyPair {
			kind,
			alg,
			serialized_der: pkcs8.to_vec(),
		})
	}
}

impl TryFrom<Vec<u8>> for KeyPair {
	type Error = RcgenError;

	fn try_from(pkcs8: Vec<u8>) -> Result<KeyPair, RcgenError> {
		let (kind, alg) = KeyPair::from_raw(pkcs8.as_slice())?;
		Ok(KeyPair {
			kind,
			alg,
			serialized_der: pkcs8,
		})
	}
}

impl KeyPair {
	/// Generate a new random key pair for the specified signature algorithm
	pub fn generate(alg :&'static SignatureAlgorithm) -> Result<Self, RcgenError> {
		let system_random = SystemRandom::new();
		match alg.sign_alg {
			SignAlgo::EcDsa(sign_alg) => {
				let key_pair_doc = EcdsaKeyPair::generate_pkcs8(sign_alg, &system_random)?;
				let key_pair_serialized = key_pair_doc.as_ref().to_vec();

				let key_pair = EcdsaKeyPair::from_pkcs8(&sign_alg, &&key_pair_doc.as_ref()).unwrap();
				Ok(KeyPair {
					kind : KeyPairKind::Ec(key_pair),
					alg,
					serialized_der : key_pair_serialized,
				})
			},
			SignAlgo::EdDsa(_sign_alg) => {
				let key_pair_doc = Ed25519KeyPair::generate_pkcs8(&system_random)?;
				let key_pair_serialized = key_pair_doc.as_ref().to_vec();

				let key_pair = Ed25519KeyPair::from_pkcs8(&&key_pair_doc.as_ref()).unwrap();
				Ok(KeyPair {
					kind : KeyPairKind::Ed(key_pair),
					alg,
					serialized_der : key_pair_serialized,
				})
			},
			// Ring doesn't have RSA key generation yet:
			// https://github.com/briansmith/ring/issues/219
			// https://github.com/briansmith/ring/pull/733
			SignAlgo::Rsa() => Err(RcgenError::KeyGenerationUnavailable),
		}
	}
	/// Get the raw public key of this key pair
	///
	/// The key is in raw format, as how [`ring::signature::KeyPair::public_key`]
	/// would output, and how [`ring::signature::UnparsedPublicKey::verify`]
	/// would accept.
	pub fn public_key_raw(&self) -> &[u8] {
		self.raw_bytes()
	}
	/// Check if this key pair can be used with the given signature algorithm
	pub fn is_compatible(&self, signature_algorithm :&SignatureAlgorithm) -> bool {
		self.alg == signature_algorithm
	}
	/// Returns (possibly multiple) compatible [`SignatureAlgorithm`]'s
	/// that the key can be used with
	pub fn compatible_algs(&self)
			-> impl Iterator<Item=&'static SignatureAlgorithm> {
		std::iter::once(self.alg)
	}
	fn sign(&self, msg :&[u8], writer :DERWriter) -> Result<(), RcgenError> {
		match &self.kind {
			KeyPairKind::Ec(kp) => {
				let system_random = SystemRandom::new();
				let signature = kp.sign(&system_random, msg)?;
				let sig = &signature.as_ref();
				writer.write_bitvec_bytes(&sig, &sig.len() * 8);
			},
			KeyPairKind::Ed(kp) => {
				let signature = kp.sign(msg);
				let sig = &signature.as_ref();
				writer.write_bitvec_bytes(&sig, &sig.len() * 8);
			},
			KeyPairKind::Rsa(kp, padding_alg) => {
				let system_random = SystemRandom::new();
				let mut signature = vec![0; kp.public_modulus_len()];
				kp.sign(*padding_alg, &system_random,
					msg, &mut signature)?;
				let sig = &signature.as_ref();
				writer.write_bitvec_bytes(&sig, &sig.len() * 8);
			},
			KeyPairKind::Remote(kp) => {
				let signature = kp.sign(msg)?;
				writer.write_bitvec_bytes(&signature, &signature.len() * 8);
			},
		}
		Ok(())
	}
	/// Return the key pair's public key in DER format
	///
	/// The key is formatted according to the SubjectPublicKeyInfo struct of
	/// X.509.
	/// See [RFC 5280 section 4.1](https://tools.ietf.org/html/rfc5280#section-4.1).
	pub fn public_key_der(&self) -> Vec<u8> {
		yasna::construct_der(|writer| self.serialize_public_key_der(writer))
	}
	/// Return the key pair's public key in PEM format
	///
	/// The returned string can be interpreted with `openssl pkey --inform PEM -pubout -pubin -text`
	///
	/// *This function is only available if rcgen is built with the "pem" feature*
	#[cfg(feature = "pem")]
	pub fn public_key_pem(&self) -> String {
		let p = Pem {
			tag : "PUBLIC KEY".to_string(),
			contents : self.public_key_der(),
		};
		pem::encode(&p)
	}
	/// Serializes the key pair (including the private key) in PKCS#8 format in DER
	///
	/// Panics if called on a remote key pair.
	pub fn serialize_der(&self) -> Vec<u8> {
		if let KeyPairKind::Remote(_) = self.kind {
			panic!("Serializing a remote key pair is not supported")
		}

		self.serialized_der.clone()
	}
	/// Serializes the key pair (including the private key) in PKCS#8 format in PEM
	///
	/// *This function is only available if rcgen is built with the "pem" feature*
	#[cfg(feature = "pem")]
	pub fn serialize_pem(&self) -> String {
		let p = Pem {
			tag : "PRIVATE KEY".to_string(),
			contents : self.serialize_der(),
		};
		pem::encode(&p)
	}
}

impl PublicKeyData for KeyPair {
	fn alg(&self) -> &SignatureAlgorithm {
		self.alg
	}
	fn raw_bytes(&self) -> &[u8] {
		match &self.kind {
			KeyPairKind::Ec(kp) => kp.public_key().as_ref(),
			KeyPairKind::Ed(kp) => kp.public_key().as_ref(),
			KeyPairKind::Rsa(kp, _) => kp.public_key().as_ref(),
			KeyPairKind::Remote(kp) => kp.public_key(),
		}
	}
}

trait PublicKeyData {
	fn alg(&self) -> &SignatureAlgorithm;
	fn raw_bytes(&self) -> &[u8];
	fn serialize_public_key_der(&self, writer :DERWriter) {
		writer.write_sequence(|writer| {
			self.alg().write_oids_sign_alg(writer.next());
			let pk = self.raw_bytes();
			writer.next().write_bitvec_bytes(&pk, pk.len() * 8);
		})
	}
}

#[derive(PartialEq, Eq)]
enum SignatureAlgorithmParams {
	/// Omit the parameters
	None,
	/// Write null parameters
	Null,
	/// RSASSA-PSS-params as per RFC 4055
	RsaPss {
		hash_algorithm :&'static [u64],
		salt_length :u64,
	},
}

/// Signature algorithm type
pub struct SignatureAlgorithm {
	oids_sign_alg :&'static [&'static [u64]],
	sign_alg :SignAlgo,
	oid_components :&'static [u64],
	params :SignatureAlgorithmParams,
}

impl fmt::Debug for SignatureAlgorithm {
	fn fmt(&self, f :&mut fmt::Formatter) -> fmt::Result {
		if self == &PKCS_RSA_SHA256 {
			write!(f, "PKCS_RSA_SHA256")
		} else if self == &PKCS_RSA_SHA384 {
			write!(f, "PKCS_RSA_SHA384")
		} else if self == &PKCS_RSA_SHA512 {
			write!(f, "PKCS_RSA_SHA512")
		} else if self == &PKCS_RSA_PSS_SHA256 {
			write!(f, "PKCS_RSA_PSS_SHA256")
		} else if self == &PKCS_ECDSA_P256_SHA256 {
			write!(f, "PKCS_ECDSA_P256_SHA256")
		} else if self == &PKCS_ECDSA_P384_SHA384 {
			write!(f, "PKCS_ECDSA_P384_SHA384")
		} else if self == &PKCS_ED25519 {
			write!(f, "PKCS_ED25519")
		} else {
			write!(f, "Unknown")
		}
	}
}

impl PartialEq for SignatureAlgorithm {
	fn eq(&self, other :&Self) -> bool {
		(self.oids_sign_alg, self.oid_components) == (other.oids_sign_alg, other.oid_components)
	}
}

impl Eq for SignatureAlgorithm {}

/// The `Hash` trait is not derived, but implemented according to impl of the `PartialEq` trait
impl Hash for SignatureAlgorithm {
	fn hash<H: Hasher>(&self, state: &mut H) {
		// see SignatureAlgorithm::eq(), just this field is compared
		self.oids_sign_alg.hash(state);
	}
}

impl SignatureAlgorithm {
	fn iter() -> std::slice::Iter<'static, &'static SignatureAlgorithm> {
		static ALGORITHMS :&[&SignatureAlgorithm] = &[
			&PKCS_RSA_SHA256,
			&PKCS_RSA_SHA384,
			&PKCS_RSA_SHA512,
			//&PKCS_RSA_PSS_SHA256,
			&PKCS_ECDSA_P256_SHA256,
			&PKCS_ECDSA_P384_SHA384,
			&PKCS_ED25519
		];
		ALGORITHMS.iter()
	}

	/// Retrieve the SignatureAlgorithm for the provided OID
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
	// sha256WithRSAEncryption in RFC 4055
	oid_components : &[1, 2, 840, 113549, 1, 1, 11],
	params : SignatureAlgorithmParams::Null,
};

/// RSA signing with PKCS#1 1.5 padding and SHA-256 hashing as per [RFC 4055](https://tools.ietf.org/html/rfc4055)
pub static PKCS_RSA_SHA384 :SignatureAlgorithm = SignatureAlgorithm {
	oids_sign_alg :&[&OID_RSA_ENCRYPTION],
	sign_alg :SignAlgo::Rsa(),
	// sha384WithRSAEncryption in RFC 4055
	oid_components : &[1, 2, 840, 113549, 1, 1, 12],
	params : SignatureAlgorithmParams::Null,
};

/// RSA signing with PKCS#1 1.5 padding and SHA-512 hashing as per [RFC 4055](https://tools.ietf.org/html/rfc4055)
pub static PKCS_RSA_SHA512 :SignatureAlgorithm = SignatureAlgorithm {
	oids_sign_alg :&[&OID_RSA_ENCRYPTION],
	sign_alg :SignAlgo::Rsa(),
	// sha512WithRSAEncryption in RFC 4055
	oid_components : &[1, 2, 840, 113549, 1, 1, 13],
	params : SignatureAlgorithmParams::Null,
};

// TODO: not really sure whether the certs we generate actually work.
// Both openssl and webpki reject them. It *might* be possible that openssl
// accepts the certificate if the key is a proper RSA-PSS key, but ring doesn't
// support those: https://github.com/briansmith/ring/issues/1353
//
/// RSA signing with PKCS#1 2.1 RSASSA-PSS padding and SHA-256 hashing as per [RFC 4055](https://tools.ietf.org/html/rfc4055)
static PKCS_RSA_PSS_SHA256 :SignatureAlgorithm = SignatureAlgorithm {
	// We could also use OID_RSA_ENCRYPTION here, but it's recommended
	// to use ID-RSASSA-PSS if possible.
	oids_sign_alg :&[&OID_RSASSA_PSS],
	sign_alg :SignAlgo::Rsa(),
	oid_components : &OID_RSASSA_PSS,//&[1, 2, 840, 113549, 1, 1, 13],
	// rSASSA-PSS-SHA256-Params in RFC 4055
	params : SignatureAlgorithmParams::RsaPss {
		// id-sha256 in https://datatracker.ietf.org/doc/html/rfc4055#section-2.1
		hash_algorithm : &[2, 16, 840, 1, 101, 3, 4, 2, 1],
		salt_length : 20,
	},
};

/// ECDSA signing using the P-256 curves and SHA-256 hashing as per [RFC 5758](https://tools.ietf.org/html/rfc5758#section-3.2)
pub static PKCS_ECDSA_P256_SHA256 :SignatureAlgorithm = SignatureAlgorithm {
	oids_sign_alg :&[&OID_EC_PUBLIC_KEY, &OID_EC_SECP_256_R1],
	sign_alg :SignAlgo::EcDsa(&signature::ECDSA_P256_SHA256_ASN1_SIGNING),
	/// ecdsa-with-SHA256 in RFC 5758
	oid_components : &[1, 2, 840, 10045, 4, 3, 2],
	params : SignatureAlgorithmParams::None,
};

/// ECDSA signing using the P-384 curves and SHA-384 hashing as per [RFC 5758](https://tools.ietf.org/html/rfc5758#section-3.2)
pub static PKCS_ECDSA_P384_SHA384 :SignatureAlgorithm = SignatureAlgorithm {
	oids_sign_alg :&[&OID_EC_PUBLIC_KEY, &OID_EC_SECP_384_R1],
	sign_alg :SignAlgo::EcDsa(&signature::ECDSA_P384_SHA384_ASN1_SIGNING),
	/// ecdsa-with-SHA384 in RFC 5758
	oid_components : &[1, 2, 840, 10045, 4, 3, 3],
	params : SignatureAlgorithmParams::None,
};

// TODO PKCS_ECDSA_P521_SHA512 https://github.com/briansmith/ring/issues/824

/// ED25519 curve signing as per [RFC 8410](https://tools.ietf.org/html/rfc8410)
pub static PKCS_ED25519 :SignatureAlgorithm = SignatureAlgorithm {
	/// id-Ed25519 in RFC 8410
	oids_sign_alg :&[&[1, 3, 101, 112]],
	sign_alg :SignAlgo::EdDsa(&signature::ED25519),
	/// id-Ed25519 in RFC 8410
	oid_components : &[1, 3, 101, 112],
	params : SignatureAlgorithmParams::None,
};

// Signature algorithm IDs as per https://tools.ietf.org/html/rfc4055
impl SignatureAlgorithm {
	fn alg_ident_oid(&self) -> ObjectIdentifier {
		ObjectIdentifier::from_slice(self.oid_components)
	}
	fn write_params(&self, writer :&mut yasna::DERWriterSeq) {
		match self.params {
			SignatureAlgorithmParams::None => (),
			SignatureAlgorithmParams::Null => {
				writer.next().write_null();
			},
			SignatureAlgorithmParams::RsaPss {
				hash_algorithm, salt_length,
			} => {
				writer.next().write_sequence(|writer| {
					// https://datatracker.ietf.org/doc/html/rfc4055#section-3.1

					let oid = ObjectIdentifier::from_slice(hash_algorithm);
					// hashAlgorithm
					writer.next().write_tagged(Tag::context(0), |writer| {
						writer.write_sequence(|writer| {
							writer.next().write_oid(&oid);
						});
					});
					// maskGenAlgorithm
					writer.next().write_tagged(Tag::context(1), |writer| {
						writer.write_sequence(|writer| {
							// id-mgf1 in RFC 4055
							const ID_MGF1 :&[u64] = &[1, 2, 840, 113549, 1, 1, 8];
							let oid = ObjectIdentifier::from_slice(ID_MGF1);
							writer.next().write_oid(&oid);
							writer.next().write_sequence(|writer| {
								let oid = ObjectIdentifier::from_slice(hash_algorithm);
								writer.next().write_oid(&oid);
								writer.next().write_null();
							});
						});
					});
					// saltLength
					writer.next().write_tagged(Tag::context(2), |writer| {
						writer.write_u64(salt_length);
					});
					// We *must* omit the trailerField element as per RFC 4055 section 3.1
				})
			},
		}
	}
	/// Writes the algorithm identifier as it appears inside a signature
	fn write_alg_ident(&self, writer :DERWriter) {
		writer.write_sequence(|writer| {
			writer.next().write_oid(&self.alg_ident_oid());
			self.write_params(writer);
		});
	}
	/// Writes the algorithm identifier as it appears inside subjectPublicKeyInfo
	fn write_oids_sign_alg(&self, writer :DERWriter) {
		writer.write_sequence(|writer| {
			for oid in self.oids_sign_alg {
				let oid = ObjectIdentifier::from_slice(oid);
				writer.next().write_oid(&oid);
			}
			self.write_params(writer);
		});
	}
}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for KeyPair {
	fn zeroize(&mut self) {
		self.serialized_der.zeroize();
	}
}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for Certificate {
	fn zeroize(&mut self) {
		self.params.zeroize();
		self.key_pair.zeroize();
	}
}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for CertificateSigningRequest {
	fn zeroize(&mut self) {
		self.params.zeroize();
	}
}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for CertificateParams {
	fn zeroize(&mut self) {
		self.key_pair.zeroize();
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use std::panic::catch_unwind;
	use chrono::TimeZone;

	fn get_times() -> [DateTime<Utc>; 3] {
		let dt_nanos = Utc.ymd(2020, 12, 3).and_hms_nano(0, 0, 1, 444);
		let dt_leap = Utc.ymd(2020, 12, 3).and_hms_nano(0, 0, 1, 1_000_000_001);
		let dt_zero = Utc.ymd(2020, 12, 3).and_hms_nano(0, 0, 1, 0);
		[dt_nanos, dt_leap, dt_zero]
	}

	#[test]
	fn test_dt_utc_strip_nanos() {
		let times = get_times();

		// No stripping - DateTime with nanos
		let res = catch_unwind(|| UTCTime::from_datetime::<Utc>(&times[0]));
		assert!(res.is_err());

		// Stripping
		for dt in times.iter() {
			let date_time = dt_strip_nanos(&dt, false);
			assert!(date_time.is_ok());
			let _ut = UTCTime::from_datetime::<Utc>(&date_time.unwrap());
		}
	}

	#[test]
	fn test_dt_to_generalized() {
		let times = get_times();

		for dt in times.iter() {
			assert!(dt_to_generalized(&dt).is_ok());
		}
	}

	#[test]
	fn test_with_key_usages() {
		let mut params: CertificateParams = Default::default();

		// Set key_usages
		params.key_usages = vec![
			KeyUsagePurpose::DigitalSignature,
			KeyUsagePurpose::KeyEncipherment,
			KeyUsagePurpose::ContentCommitment,
		];

		// This can sign things!
		params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));

		// Make the cert
		let cert = Certificate::from_params(params).unwrap();

		// Serialize it
		let der = cert.serialize_der().unwrap();

		// Parse it
		let (_rem, cert) = x509_parser::parse_x509_certificate(&der).unwrap();

		// Check oid
		let key_usage_oid_str= "2.5.29.15";

		// Found flag
		let mut found = false;

		for ext in cert.extensions() {
			if key_usage_oid_str == ext.oid.to_id_string() {
				match ext.parsed_extension() {
					x509_parser::extensions::ParsedExtension::KeyUsage(usage) =>{
						assert!(usage.flags == 7);
						found = true;
					}
					_ => {}
				}
			}
		}

		assert!(found);
	}

	#[test]
	fn test_with_key_usages_decipheronly_only() {
		let mut params: CertificateParams = Default::default();

		// Set key_usages
		params.key_usages = vec![KeyUsagePurpose::DecipherOnly];

		// This can sign things!
		params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));

		// Make the cert
		let cert = Certificate::from_params(params).unwrap();

		// Serialize it
		let der = cert.serialize_der().unwrap();

		// Parse it
		let (_rem, cert) = x509_parser::parse_x509_certificate(&der).unwrap();

		// Check oid
		let key_usage_oid_str= "2.5.29.15";

		// Found flag
		let mut found = false;

		for ext in cert.extensions() {
			if key_usage_oid_str == ext.oid.to_id_string() {
				match ext.parsed_extension() {
					x509_parser::extensions::ParsedExtension::KeyUsage(usage) =>{
						assert!(usage.flags == 256);
						found = true;
					}
					_ => {}
				}
			}
		}

		assert!(found);
	}

	#[test]
	fn signature_algos_different() {
		// TODO unify this with test_key_params_mismatch.
		// Note that that test doesn't have a full list of signature
		// algorithms, as it has no access to the iter function.
		for (i, alg_i) in SignatureAlgorithm::iter().enumerate() {
			for (j, alg_j) in SignatureAlgorithm::iter().enumerate() {
				assert_eq!(alg_i == alg_j, i == j,
					"Algorighm relationship mismatch for algorithm index pair {} and {}", i, j);
			}
		}
	}
}
