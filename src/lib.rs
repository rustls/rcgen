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

use yasna::Tag;
use yasna::models::ObjectIdentifier;
#[cfg(feature = "pem")]
use pem::Pem;
use ring::digest;
use yasna::DERWriter;
use yasna::models::{GeneralizedTime, UTCTime};
use yasna::tags::{TAG_BMPSTRING, TAG_TELETEXSTRING, TAG_UNIVERSALSTRING};
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};
use std::collections::HashMap;
use std::fmt;
use std::convert::TryFrom;
use std::net::IpAddr;
#[cfg(feature = "x509-parser")]
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::hash::Hash;

pub use crate::error::RcgenError;
use crate::oid::*;
use crate::key_pair::PublicKeyData;
pub use crate::key_pair::{KeyPair, RemoteKeyPair};
pub use crate::csr::{PublicKey, CertificateSigningRequest};
pub use crate::sign_algo::SignatureAlgorithm;
pub use crate::sign_algo::algo::*;

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

mod csr;
mod error;
mod key_pair;
mod oid;
mod sign_algo;

// Example certs usable as reference:
// Uses ECDSA: https://crt.sh/?asn1=607203242

#[cfg(feature = "pem")]
const ENCODE_CONFIG: pem::EncodeConfig = match cfg!(target_family = "windows") {
	true => pem::EncodeConfig { line_ending: pem::LineEnding::CRLF },
	false => pem::EncodeConfig { line_ending: pem::LineEnding::LF },
};

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
#[allow(missing_docs)]
#[non_exhaustive]
/// The type of subject alt name
pub enum SanType {
	/// Also known as E-Mail address
	Rfc822Name(String),
	DnsName(String),
	URI(String),
	IpAddress(IpAddr),
}

#[cfg(feature = "x509-parser")]
fn ip_addr_from_octets(octets: &[u8]) -> Result<IpAddr, RcgenError> {
	if let Ok(ipv6_octets) = <&[u8; 16]>::try_from(octets) {
		Ok(Ipv6Addr::from(*ipv6_octets).into())
	} else if let Ok(ipv4_octets) = <&[u8; 4]>::try_from(octets) {
		Ok(Ipv4Addr::from(*ipv4_octets).into())
	} else {
		Err(RcgenError::InvalidIpAddressOctetLength(octets.len()))
	}
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
			x509_parser::extensions::GeneralName::URI(name) => {
				SanType::URI((*name).into())
			}
			x509_parser::extensions::GeneralName::IPAddress(octets) => {
				SanType::IpAddress(ip_addr_from_octets(octets)?)
			}
			_ => return Err(RcgenError::InvalidNameType),
		})
	}

	fn tag(&self) -> u64 {
		// Defined in the GeneralName list in
		// https://tools.ietf.org/html/rfc5280#page-38
		const TAG_RFC822_NAME :u64 = 1;
		const TAG_DNS_NAME :u64 = 2;
		const TAG_URI :u64 = 6;
		const TAG_IP_ADDRESS :u64 = 7;

		match self {
			SanType::Rfc822Name(_name) => TAG_RFC822_NAME,
			SanType::DnsName(_name) => TAG_DNS_NAME,
			SanType::URI(_name) => TAG_URI,
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
		use x509_parser::der_parser::asn1_rs::Tag;

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
			let data = attr.attr_value().data;
			let dn_value = match attr.attr_value().header.tag() {
				Tag::T61String => DnValue::TeletexString(data.into()),
				Tag::PrintableString => {
					let data = std::str::from_utf8(data)
						.map_err(|_| RcgenError::CouldNotParseCertificate)?;
					DnValue::PrintableString(data.to_owned())
				},
				Tag::UniversalString => DnValue::UniversalString(data.into()),
				Tag::Utf8String => {
					let data = std::str::from_utf8(data)
						.map_err(|_| RcgenError::CouldNotParseCertificate)?;
					DnValue::Utf8String(data.to_owned())
				},
				Tag::BmpString => DnValue::BmpString(data.into()),
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

/// A certificate revocation list (CRL)
///
/// ## Example
///
/// ```
/// extern crate rcgen;
/// use rcgen::*;
///
/// # fn main () {
/// // Generate a CRL issuer.
/// let mut issuer_params = CertificateParams::new(vec!["crl.issuer.example.com".to_string()]);
/// issuer_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
/// issuer_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::CrlSign];
/// let issuer = Certificate::from_params(issuer_params).unwrap();
/// // Describe a revoked certificate.
/// let revoked_cert = RevokedCertParams{
///   serial_number: SerialNumber::from(9999),
///   revocation_time: date_time_ymd(2024, 06, 17),
///   reason_code: Some(RevocationReason::KeyCompromise),
///   invalidity_date: None,
/// };
/// // Create a CRL signed by the issuer, revoking revoked_cert.
/// let crl = CertificateRevocationListParams{
///   this_update: date_time_ymd(2023, 06, 17),
///   next_update: date_time_ymd(2024, 06, 17),
///   crl_number: SerialNumber::from(1234),
///   issuing_distribution_point: None,
///   revoked_certs: vec![revoked_cert],
///   alg: &PKCS_ECDSA_P256_SHA256,
///   key_identifier_method: KeyIdMethod::Sha256,
/// };
/// let crl = CertificateRevocationList::from_params(crl).unwrap();
/// println!("{}", crl.serialize_pem_with_signer(&issuer).unwrap());
///# }
pub struct CertificateRevocationList {
	params :CertificateRevocationListParams,
}

impl CertificateRevocationList {
	/// Generates a new certificate revocation list (CRL) from the given parameters.
	pub fn from_params(params :CertificateRevocationListParams) -> Result<Self, RcgenError> {
		if params.next_update.le(&params.this_update) {
			return Err(RcgenError::InvalidCrlNextUpdate);
		}
		Ok(Self { params })
	}
	/// Returns the certificate revocation list (CRL) parameters.
	pub fn get_params(&self) -> &CertificateRevocationListParams {
		&self.params
	}
	/// Serializes the certificate revocation list (CRL) in binary DER format, signed with
	/// the issuing certificate authority's key.
	pub fn serialize_der_with_signer(&self, ca :&Certificate) -> Result<Vec<u8>, RcgenError> {
		if !ca.params.key_usages.is_empty() && !ca.params.key_usages.contains(&KeyUsagePurpose::CrlSign) {
			return Err(RcgenError::IssuerNotCrlSigner);
		}
		self.params.serialize_der_with_signer(ca)
	}
	/// Serializes the certificate revocation list (CRL) in ASCII PEM format, signed with
	/// the issuing certificate authority's key.
	///
	/// *This function is only available if rcgen is built with the "pem" feature*
	#[cfg(feature = "pem")]
	pub fn serialize_pem_with_signer(&self, ca :&Certificate) -> Result<String, RcgenError> {
		let contents = self.serialize_der_with_signer(ca)?;
		let p = Pem::new("X509 CRL", contents);
		Ok(pem::encode_config(&p, ENCODE_CONFIG))
	}
}

/// Parameters used for certificate generation
#[allow(missing_docs)]
#[non_exhaustive]
pub struct CertificateParams {
	pub alg :&'static SignatureAlgorithm,
	pub not_before :OffsetDateTime,
	pub not_after :OffsetDateTime,
	pub serial_number :Option<SerialNumber>,
	pub subject_alt_names :Vec<SanType>,
	pub distinguished_name :DistinguishedName,
	pub is_ca :IsCa,
	pub key_usages :Vec<KeyUsagePurpose>,
	pub extended_key_usages :Vec<ExtendedKeyUsagePurpose>,
	pub name_constraints :Option<NameConstraints>,
	/// An optional list of certificate revocation list (CRL) distribution points as described
	/// in RFC 5280 Section 4.2.1.13[^1]. Each distribution point contains one or more URIs where
	/// an up-to-date CRL with scope including this certificate can be retrieved.
	///
	/// [^1]: <https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.13>
	pub crl_distribution_points :Vec<CrlDistributionPoint>,
	pub custom_extensions :Vec<CustomExtension>,
	/// The certificate's key pair, a new random key pair will be generated if this is `None`
	pub key_pair :Option<KeyPair>,
	/// If `true`, the 'Authority Key Identifier' extension will be added to the generated cert
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
			is_ca : IsCa::NoCa,
			key_usages : Vec::new(),
			extended_key_usages : Vec::new(),
			name_constraints : None,
			crl_distribution_points : Vec::new(),
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
		Self::from_ca_cert_der(certificate.contents(), key_pair)
	}

	/// Parses a ca certificate from the DER format for signing
	///
	/// This function is only of use if you have an existing ca certificate with
	/// which you want to sign a certificate newly generated by `rcgen` using the
	/// [`serialize_der_with_signer`](Certificate::serialize_der_with_signer) or
	/// [`serialize_pem_with_signer`](Certificate::serialize_pem_with_signer)
	/// functions.
	///
	/// This function only extracts from the given ca cert the information
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
		let is_ca = Self::convert_x509_is_ca(&x509)?;
		let validity = x509.validity();
		let subject_alt_names = Self::convert_x509_subject_alternative_name(&x509)?;
		let key_usages = Self::convert_x509_key_usages(&x509)?;
		let extended_key_usages = Self::convert_x509_extended_key_usages(&x509)?;
		let name_constraints = Self::convert_x509_name_constraints(&x509)?;
		let serial_number = Some(x509.serial.to_bytes_be().into());

		Ok(
			CertificateParams {
				alg,
				is_ca,
				subject_alt_names,
				key_usages,
				extended_key_usages,
				name_constraints,
				serial_number,
				distinguished_name : dn,
				key_pair : Some(key_pair),
				not_before : validity.not_before.to_datetime(),
				not_after : validity.not_after.to_datetime(),
				.. Default::default()
			}
		)
	}
	#[cfg(feature = "x509-parser")]
	fn convert_x509_is_ca(x509 :&x509_parser::certificate::X509Certificate<'_>) -> Result<IsCa, RcgenError> {
		use x509_parser::extensions::BasicConstraints as B;

		let basic_constraints = x509.basic_constraints()
			.or(Err(RcgenError::CouldNotParseCertificate))?.map(|ext| ext.value);

		let is_ca = match basic_constraints {
			Some(B { ca: true, path_len_constraint: Some(n) }) if *n <= u8::MAX as u32 => IsCa::Ca(BasicConstraints::Constrained(*n as u8)),
			Some(B { ca: true, path_len_constraint: Some(_) }) => return Err(RcgenError::CouldNotParseCertificate),
			Some(B { ca: true, path_len_constraint: None }) => IsCa::Ca(BasicConstraints::Unconstrained),
			Some(B { ca: false, .. }) => IsCa::ExplicitNoCa,
			None => IsCa::NoCa,
		};

		Ok(is_ca)
	}
	#[cfg(feature = "x509-parser")]
	fn convert_x509_subject_alternative_name(x509 :&x509_parser::certificate::X509Certificate<'_>) -> Result<Vec<SanType>, RcgenError> {
		let sans = x509.subject_alternative_name()
			.or(Err(RcgenError::CouldNotParseCertificate))?
			.map(|ext| &ext.value.general_names);

		if let Some(sans) = sans {
			let mut subject_alt_names = Vec::with_capacity(sans.len());
			for san in sans {
				subject_alt_names.push(SanType::try_from_general(san)?);
			}
			Ok(subject_alt_names)
		} else {
			Ok(Vec::new())
		}
	}
	#[cfg(feature = "x509-parser")]
	fn convert_x509_key_usages(x509 :&x509_parser::certificate::X509Certificate<'_>) -> Result<Vec<KeyUsagePurpose>, RcgenError> {
		let key_usage = x509.key_usage()
			.or(Err(RcgenError::CouldNotParseCertificate))?
			.map(|ext| ext.value);

		let mut key_usages = Vec::new();
		if let Some(key_usage) = key_usage {
			if key_usage.digital_signature() {
				key_usages.push(KeyUsagePurpose::DigitalSignature);
			}
			if key_usage.non_repudiation() {
				key_usages.push(KeyUsagePurpose::ContentCommitment);
			}
			if key_usage.key_encipherment() {
				key_usages.push(KeyUsagePurpose::KeyEncipherment);
			}
			if key_usage.data_encipherment() {
				key_usages.push(KeyUsagePurpose::DataEncipherment);
			}
			if key_usage.key_agreement() {
				key_usages.push(KeyUsagePurpose::KeyAgreement);
			}
			if key_usage.key_cert_sign() {
				key_usages.push(KeyUsagePurpose::KeyCertSign);
			}
			if key_usage.crl_sign() {
				key_usages.push(KeyUsagePurpose::CrlSign);
			}
			if key_usage.encipher_only() {
				key_usages.push(KeyUsagePurpose::EncipherOnly);
			}
			if key_usage.decipher_only() {
				key_usages.push(KeyUsagePurpose::DecipherOnly);
			}
		}
		Ok(key_usages)
	}
	#[cfg(feature = "x509-parser")]
	fn convert_x509_extended_key_usages(x509 :&x509_parser::certificate::X509Certificate<'_>) -> Result<Vec<ExtendedKeyUsagePurpose>, RcgenError> {
		let extended_key_usage = x509.extended_key_usage()
			.or(Err(RcgenError::CouldNotParseCertificate))?
			.map(|ext| ext.value);

		let mut extended_key_usages = Vec::new();
		if let Some(extended_key_usage) = extended_key_usage {
			if extended_key_usage.any {
				extended_key_usages.push(ExtendedKeyUsagePurpose::Any);
			}
			if extended_key_usage.server_auth {
				extended_key_usages.push(ExtendedKeyUsagePurpose::ServerAuth);
			}
			if extended_key_usage.client_auth {
				extended_key_usages.push(ExtendedKeyUsagePurpose::ClientAuth);
			}
			if extended_key_usage.code_signing {
				extended_key_usages.push(ExtendedKeyUsagePurpose::CodeSigning);
			}
			if extended_key_usage.email_protection {
				extended_key_usages.push(ExtendedKeyUsagePurpose::EmailProtection);
			}
			if extended_key_usage.time_stamping {
				extended_key_usages.push(ExtendedKeyUsagePurpose::TimeStamping);
			}
			if extended_key_usage.ocsp_signing {
				extended_key_usages.push(ExtendedKeyUsagePurpose::OcspSigning);
			}
		}
		Ok(extended_key_usages)
	}
	#[cfg(feature = "x509-parser")]
	fn convert_x509_name_constraints(x509 :&x509_parser::certificate::X509Certificate<'_>) -> Result<Option<NameConstraints>, RcgenError> {
		let constraints = x509.name_constraints()
			.or(Err(RcgenError::CouldNotParseCertificate))?
			.map(|ext| ext.value);

		if let Some(constraints) = constraints {
			let permitted_subtrees = if let Some(permitted) = &constraints.permitted_subtrees {
				Self::convert_x509_general_subtrees(&permitted)?
			} else {
				Vec::new()
			};

			let excluded_subtrees = if let Some(excluded) = &constraints.excluded_subtrees {
				Self::convert_x509_general_subtrees(&excluded)?
			} else {
				Vec::new()
			};

			let name_constraints = NameConstraints { permitted_subtrees, excluded_subtrees };

			Ok(Some(name_constraints))
		} else {
			Ok(None)
		}
	}
	#[cfg(feature = "x509-parser")]
	fn convert_x509_general_subtrees(subtrees :&[x509_parser::extensions::GeneralSubtree<'_>]) -> Result<Vec<GeneralSubtree>, RcgenError> {
		use x509_parser::extensions::GeneralName;

		let mut result = Vec::new();
		for subtree in subtrees {
			let subtree = match &subtree.base {
				GeneralName::RFC822Name(s) => GeneralSubtree::Rfc822Name(s.to_string()),
				GeneralName::DNSName(s) => GeneralSubtree::DnsName(s.to_string()),
				GeneralName::DirectoryName(n) => GeneralSubtree::DirectoryName(DistinguishedName::from_name(&n)?),
				GeneralName::IPAddress(bytes) if bytes.len() == 8 => {
					let addr: [u8; 4] = bytes[..4].try_into().unwrap();
					let mask: [u8; 4] = bytes[4..].try_into().unwrap();
					GeneralSubtree::IpAddress(CidrSubnet::V4(addr, mask))
				}
				GeneralName::IPAddress(bytes) if bytes.len() == 32 => {
					let addr: [u8; 16] = bytes[..16].try_into().unwrap();
					let mask: [u8; 16] = bytes[16..].try_into().unwrap();
					GeneralSubtree::IpAddress(CidrSubnet::V6(addr, mask))
				}
				_ => continue,
			};
			result.push(subtree);
		}
		Ok(result)
	}
	fn write_subject_alt_names(&self, writer :DERWriter) {
		write_x509_extension(writer, OID_SUBJECT_ALT_NAME, false, |writer| {
			writer.write_sequence(|writer| {
				for san in self.subject_alt_names.iter() {
					writer.next().write_tagged_implicit(Tag::context(san.tag()), |writer| {
						match san {
							SanType::Rfc822Name(name) |
							SanType::DnsName(name) |
							SanType::URI(name) => writer.write_ia5_string(name),
							SanType::IpAddress(IpAddr::V4(addr)) => writer.write_bytes(&addr.octets()),
							SanType::IpAddress(IpAddr::V6(addr)) => writer.write_bytes(&addr.octets()),
						}
					});
				}
			});
		});
	}
	fn write_request<K: PublicKeyData>(&self, pub_key: &K, writer :DERWriter)
	 -> Result<(), RcgenError> {
		// No .. pattern, we use this to ensure every field is used
		#[deny(unused)]
		let Self {
			alg,
			not_before,
			not_after,
			serial_number,
			subject_alt_names,
			distinguished_name,
			is_ca,
			key_usages,
			extended_key_usages,
			name_constraints,
			crl_distribution_points,
			custom_extensions,
			key_pair,
			use_authority_key_identifier_extension,
			key_identifier_method,
		} = self;
		// - alg and key_pair will be used by the caller
		// - not_before and not_after cannot be put in a CSR
		// - There might be a use case for specifying the key identifier
		// in the CSR, but in the current API it can't be distinguished
		// from the defaults so this is left for a later version if
		// needed.
		let _ = (alg, key_pair, not_before, not_after, key_identifier_method);
		if serial_number.is_some()
			|| *is_ca != IsCa::NoCa
			|| !key_usages.is_empty()
			|| !extended_key_usages.is_empty()
			|| name_constraints.is_some()
			|| !crl_distribution_points.is_empty()
			|| *use_authority_key_identifier_extension
		{
			return Err(RcgenError::UnsupportedInCsr);
		}
		writer.write_sequence(|writer| {
			// Write version
			writer.next().write_u8(0);
			// Write issuer
			writer.next().write_sequence(|writer| {
				for (ty, content) in distinguished_name.iter() {
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
				if !subject_alt_names.is_empty() {
					writer.write_sequence(|writer| {
						let oid = ObjectIdentifier::from_slice(OID_PKCS_9_AT_EXTENSION_REQUEST);
						writer.next().write_oid(&oid);
						writer.next().write_set(|writer| {
							writer.next().write_sequence(|writer| {
								// Write subject_alt_names
								self.write_subject_alt_names(writer.next());

								// Write custom extensions
								for ext in custom_extensions {
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
					});
				}
			});

		});
		Ok(())
	}
	fn write_cert<K: PublicKeyData>(&self, writer :DERWriter, pub_key: &K, ca :&Certificate) -> Result<(), RcgenError> {
		writer.write_sequence(|writer| {
			// Write version
			writer.next().write_tagged(Tag::context(0), |writer| {
				writer.write_u8(2);
			});
			// Write serialNumber
			if let Some(ref serial) = self.serial_number {
				writer.next().write_bigint_bytes(serial.as_ref(), true);
			} else {
				let hash = digest::digest(&digest::SHA256, pub_key.raw_bytes());
				// RFC 5280 specifies at most 20 bytes for a serial number
				let sl = &hash.as_ref()[0..20];
				writer.next().write_bigint_bytes(sl, true);
			};
			// Write signature
			ca.params.alg.write_alg_ident(writer.next());
			// Write issuer
			write_distinguished_name(writer.next(), &ca.params.distinguished_name);
			// Write validity
			writer.next().write_sequence(|writer| {
				// Not before
				write_dt_utc_or_generalized(writer.next(), self.not_before);
				// Not after
				write_dt_utc_or_generalized(writer.next(), self.not_after);
				Ok::<(), RcgenError>(())
			})?;
			// Write subject
			write_distinguished_name(writer.next(), &self.distinguished_name);
			// Write subjectPublicKeyInfo
			pub_key.serialize_public_key_der(writer.next());
			// write extensions
			let should_write_exts = self.use_authority_key_identifier_extension ||
				!self.subject_alt_names.is_empty() ||
				!self.extended_key_usages.is_empty() ||
				self.name_constraints.iter().any(|c| !c.is_empty()) ||
				matches!(self.is_ca, IsCa::ExplicitNoCa) ||
				matches!(self.is_ca, IsCa::Ca(_)) ||
				!self.custom_extensions.is_empty();
			if should_write_exts {
				writer.next().write_tagged(Tag::context(3), |writer| {
					writer.write_sequence(|writer| {
						if self.use_authority_key_identifier_extension {
							write_x509_authority_key_identifier(writer.next(), ca)
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
							write_x509_extension(writer.next(), OID_EXT_KEY_USAGE, false, |writer| {
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
								write_x509_extension(writer.next(), OID_NAME_CONSTRAINTS, true, |writer| {
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
						if !self.crl_distribution_points.is_empty() {
							write_x509_extension(writer.next(), OID_CRL_DISTRIBUTION_POINTS, false, |writer| {
								writer.write_sequence(|writer| {
									for distribution_point in &self.crl_distribution_points {
										distribution_point.write_der(writer.next());
									}
								})
							});
						}
						match self.is_ca {
							IsCa::Ca(ref constraint) => {
								// Write subject_key_identifier
								write_x509_extension(writer.next(), OID_SUBJECT_KEY_IDENTIFIER, false, |writer| {
									let key_identifier = self.key_identifier(pub_key);
									writer.write_bytes(key_identifier.as_ref());
								});
								// Write basic_constraints
								write_x509_extension(writer.next(), OID_BASIC_CONSTRAINTS, true, |writer| {
									writer.write_sequence(|writer| {
										writer.next().write_bool(true); // cA flag
										if let BasicConstraints::Constrained(path_len_constraint) = constraint {
											writer.next().write_u8(*path_len_constraint);
										}
									});
								});
							}
							IsCa::ExplicitNoCa => {
								// Write subject_key_identifier
								write_x509_extension(writer.next(), OID_SUBJECT_KEY_IDENTIFIER, false, |writer| {
									let key_identifier = self.key_identifier(pub_key);
									writer.write_bytes(key_identifier.as_ref());
								});
								// Write basic_constraints
								write_x509_extension(writer.next(), OID_BASIC_CONSTRAINTS, true, |writer| {
									writer.write_sequence(|writer| {
										writer.next().write_bool(false); // cA flag
									});
								});
							}
							IsCa::NoCa => {}
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
	NoCa,
	/// The certificate can only sign itself, adding the extension and `CA:FALSE`
	ExplicitNoCa,
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
			.map(|s| {
				match s.parse() {
					Ok(ip) => SanType::IpAddress(ip),
					Err(_) => SanType::DnsName(s)
				}
			})
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

/// A certificate revocation list (CRL) distribution point, to be included in a certificate's
/// [distribution points extension](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.13) or
/// a CRL's [issuing distribution point extension](https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.5)
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct CrlDistributionPoint {
	/// One or more URI distribution point names, indicating a place the current CRL can
	/// be retrieved. When present, SHOULD include at least one LDAP or HTTP URI.
	pub uris :Vec<String>,
}

impl CrlDistributionPoint {
	fn write_der(&self, writer :DERWriter) {
		// DistributionPoint SEQUENCE
		writer.write_sequence(|writer| {
			write_distribution_point_name_uris(writer.next(), &self.uris);
		});
	}
}

fn write_distribution_point_name_uris<'a>(writer :DERWriter, uris: impl IntoIterator<Item = &'a String>) {
	// distributionPoint DistributionPointName
	writer.write_tagged_implicit(Tag::context(0), |writer| {
		writer.write_sequence(|writer| {
			// fullName GeneralNames
			writer.next().write_tagged_implicit(Tag::context(0), | writer| {
				// GeneralNames
				writer.write_sequence(|writer| {
					for uri in uris.into_iter() {
						// uniformResourceIdentifier [6] IA5String,
						writer.next().write_tagged_implicit(Tag::context(6), |writer| {
							writer.write_ia5_string(uri)
						});
					}
				})
			});
		});
	});
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
			Any => &[2, 5, 29, 37, 0],
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

/// Identifies the reason a certificate was revoked.
/// See RFC 5280 §5.3.1[^1]
///
/// [^1] <https://www.rfc-editor.org/rfc/rfc5280#section-5.3.1>
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[allow(missing_docs)] // Not much to add above the code name.
pub enum RevocationReason {
	Unspecified = 0,
	KeyCompromise = 1,
	CaCompromise = 2,
	AffiliationChanged = 3,
	Superseded = 4,
	CessationOfOperation = 5,
	CertificateHold = 6,
	// 7 is not defined.
	RemoveFromCrl = 8,
	PrivilegeWithdrawn = 9,
	AaCompromise = 10,
}

/// Parameters used for certificate revocation list (CRL) generation
pub struct CertificateRevocationListParams {
	/// Issue date of the CRL.
	pub this_update :OffsetDateTime,
	/// The date by which the next CRL will be issued.
	pub next_update :OffsetDateTime,
	/// A monotonically increasing sequence number for a given CRL scope and issuer.
	pub crl_number :SerialNumber,
	/// An optional CRL extension identifying the CRL distribution point and scope for a
	/// particular CRL as described in RFC 5280 Section 5.2.5[^1].
	///
	/// [^1]: <https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.5>
	pub issuing_distribution_point :Option<CrlIssuingDistributionPoint>,
	/// A list of zero or more parameters describing revoked certificates included in the CRL.
	pub revoked_certs :Vec<RevokedCertParams>,
	/// Signature algorithm to use when signing the serialized CRL.
	pub alg :&'static SignatureAlgorithm,
	/// Method to generate key identifiers from public keys
	///
	/// Defaults to SHA-256.
	pub key_identifier_method :KeyIdMethod,
}

impl CertificateRevocationListParams {
	fn serialize_der_with_signer(&self, ca :&Certificate) -> Result<Vec<u8>, RcgenError> {
		yasna::try_construct_der(|writer| {
			// https://www.rfc-editor.org/rfc/rfc5280#section-5.1
			writer.write_sequence(|writer| {
				let tbs_cert_list_serialized = yasna::try_construct_der(|writer| {
					self.write_crl(writer, ca)?;
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
	fn write_crl(&self, writer :DERWriter, ca :&Certificate) -> Result<(), RcgenError> {
		writer.write_sequence(|writer| {
			// Write CRL version.
			// RFC 5280 §5.1.2.1:
			//   This optional field describes the version of the encoded CRL.  When
			//   extensions are used, as required by this profile, this field MUST be
			//   present and MUST specify version 2 (the integer value is 1).
			// RFC 5280 §5.2:
			//   Conforming CRL issuers are REQUIRED to include the authority key
			//   identifier (Section 5.2.1) and the CRL number (Section 5.2.3)
			//   extensions in all CRLs issued.
			writer.next().write_u8(1);

			// Write algorithm identifier.
			// RFC 5280 §5.1.2.2:
			//   This field MUST contain the same algorithm identifier as the
			//   signatureAlgorithm field in the sequence CertificateList
			ca.params.alg.write_alg_ident(writer.next());

			// Write issuer.
			// RFC 5280 §5.1.2.3:
			//   The issuer field MUST contain a non-empty X.500 distinguished name (DN).
			write_distinguished_name(writer.next(), &ca.params.distinguished_name);

			// Write thisUpdate date.
			// RFC 5280 §5.1.2.4:
			//    This field indicates the issue date of this CRL.  thisUpdate may be
			//    encoded as UTCTime or GeneralizedTime.
			write_dt_utc_or_generalized(writer.next(), self.this_update);

			// Write nextUpdate date.
			// While OPTIONAL in the ASN.1 module, RFC 5280 §5.1.2.5 says:
			//   Conforming CRL issuers MUST include the nextUpdate field in all CRLs.
			write_dt_utc_or_generalized(writer.next(), self.next_update);

			// Write revokedCertificates.
			// RFC 5280 §5.1.2.6:
			//   When there are no revoked certificates, the revoked certificates list
			//   MUST be absent
			if !self.revoked_certs.is_empty() {
				writer.next().write_sequence(|writer| {
					for revoked_cert in &self.revoked_certs {
						revoked_cert.write_der(writer.next());
					}
				});
			}

			// Write crlExtensions.
			// RFC 5280 §5.1.2.7:
			//   This field may only appear if the version is 2 (Section 5.1.2.1).  If
			//   present, this field is a sequence of one or more CRL extensions.
			// RFC 5280 §5.2:
			//   Conforming CRL issuers are REQUIRED to include the authority key
			//   identifier (Section 5.2.1) and the CRL number (Section 5.2.3)
			//   extensions in all CRLs issued.
			writer.next().write_tagged(Tag::context(0), |writer| {
				writer.write_sequence(|writer| {
					// Write authority key identifier.
					write_x509_authority_key_identifier(writer.next(), ca);

					// Write CRL number.
					write_x509_extension(writer.next(), OID_CRL_NUMBER, false, |writer| {
						writer.write_bigint_bytes(self.crl_number.as_ref(), true);
					});

					// Write issuing distribution point (if present).
					if let Some(issuing_distribution_point) = &self.issuing_distribution_point {
						write_x509_extension(writer.next(), OID_CRL_ISSUING_DISTRIBUTION_POINT, true, |writer| {
							issuing_distribution_point.write_der(writer);
						});
					}
				});
			});

			Ok(())
		})
	}
}

/// A certificate revocation list (CRL) issuing distribution point, to be included in a CRL's
/// [issuing distribution point extension](https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.5).
pub struct CrlIssuingDistributionPoint {
	/// The CRL's distribution point, containing a sequence of URIs the CRL can be retrieved from.
	pub distribution_point :CrlDistributionPoint,
	/// An optional description of the CRL's scope. If omitted, the CRL may contain
	/// both user certs and CA certs.
	pub scope :Option<CrlScope>,
}

impl CrlIssuingDistributionPoint {
	fn write_der(&self, writer :DERWriter) {
		// IssuingDistributionPoint SEQUENCE
		writer.write_sequence(|writer| {
			// distributionPoint [0] DistributionPointName OPTIONAL
			write_distribution_point_name_uris(writer.next(), &self.distribution_point.uris);

			// -- at most one of onlyContainsUserCerts, onlyContainsCACerts,
			// -- and onlyContainsAttributeCerts may be set to TRUE.
			if let Some(scope) = self.scope {
				let tag = match scope {
					// onlyContainsUserCerts [1] BOOLEAN DEFAULT FALSE,
					CrlScope::UserCertsOnly => Tag::context(1),
					// onlyContainsCACerts [2] BOOLEAN DEFAULT FALSE,
					CrlScope::CaCertsOnly => Tag::context(2),
				};
				writer.next().write_tagged_implicit(tag, |writer| {
					writer.write_bool(true);
				});
			}
		});
	}
}

/// Describes the scope of a CRL for an issuing distribution point extension.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CrlScope {
	/// The CRL contains only end-entity user certificates.
	UserCertsOnly,
	/// The CRL contains only CA certificates.
	CaCertsOnly,
}

/// Parameters used for describing a revoked certificate included in a [`CertificateRevocationList`].
pub struct RevokedCertParams {
	/// Serial number identifying the revoked certificate.
	pub serial_number :SerialNumber,
	/// The date at which the CA processed the revocation.
	pub revocation_time :OffsetDateTime,
	/// An optional reason code identifying why the certificate was revoked.
	pub reason_code :Option<RevocationReason>,
	/// An optional field describing the date on which it was known or suspected that the
	/// private key was compromised or the certificate otherwise became invalid. This date
	/// may be earlier than the [`RevokedCertParams::revocation_time`].
	pub invalidity_date :Option<OffsetDateTime>,
}

impl RevokedCertParams {
	fn write_der(&self, writer :DERWriter) {
		writer.write_sequence(|writer| {
			// Write serial number.
			// RFC 5280 §4.1.2.2:
			//    Certificate users MUST be able to handle serialNumber values up to 20 octets.
			//    Conforming CAs MUST NOT use serialNumber values longer than 20 octets.
			//
			//    Note: Non-conforming CAs may issue certificates with serial numbers
			//    that are negative or zero.  Certificate users SHOULD be prepared to
			//    gracefully handle such certificates.
			writer.next().write_bigint_bytes(self.serial_number.as_ref(), true);

			// Write revocation date.
			write_dt_utc_or_generalized(writer.next(), self.revocation_time);

			// Write extensions if applicable.
			// RFC 5280 §5.3:
			//   Support for the CRL entry extensions defined in this specification is
			//   optional for conforming CRL issuers and applications.  However, CRL
			//   issuers SHOULD include reason codes (Section 5.3.1) and invalidity
			//   dates (Section 5.3.2) whenever this information is available.
			let has_reason_code = matches!(self.reason_code, Some(reason) if reason != RevocationReason::Unspecified);
			let has_invalidity_date = self.invalidity_date.is_some();
			if has_reason_code || has_invalidity_date {
				writer.next().write_sequence(|writer| {
					// Write reason code if present.
					self.reason_code.map(|reason_code| {
						write_x509_extension(writer.next(), OID_CRL_REASONS, false, |writer| {
							writer.write_enum(reason_code as i64);
						});
					});

					// Write invalidity date if present.
					self.invalidity_date.map(|invalidity_date| {
						write_x509_extension(writer.next(), OID_CRL_INVALIDITY_DATE, false, |writer| {
							write_dt_utc_or_generalized(writer, invalidity_date);
						})
					});
				});
			}
		})
	}
}

/// Helper to obtain an `OffsetDateTime` from year, month, day values
///
/// The year, month, day values are assumed to be in UTC.
///
/// This helper function serves two purposes: first, so that you don't
/// have to import the time crate yourself in order to specify date
/// information, second so that users don't have to type unproportionately
/// long code just to generate an instance of [`OffsetDateTime`].
pub fn date_time_ymd(year :i32, month :u8, day :u8) -> OffsetDateTime {
	let month = Month::try_from(month).expect("out-of-range month");
	let primitive_dt = PrimitiveDateTime::new(
		Date::from_calendar_date(year, month, day).expect("invalid or out-of-range date"),
		Time::MIDNIGHT
	);
	primitive_dt.assume_utc()
}

fn dt_strip_nanos(dt :OffsetDateTime) -> OffsetDateTime {
	// Set nanoseconds to zero
	// This is needed because the GeneralizedTime serializer would otherwise
	// output fractional values which RFC 5280 explicitly forbode [1].
	// UTCTime cannot express fractional seconds or leap seconds
	// therefore, it needs to be stripped of nanoseconds fully.
	// [1]: https://tools.ietf.org/html/rfc5280#section-4.1.2.5.2
	// TODO: handle leap seconds if dt becomes leap second aware
	let time = Time::from_hms(dt.hour(), dt.minute(), dt.second())
		.expect("invalid or out-of-range time");
	dt.replace_time(time)
}

fn dt_to_generalized(dt :OffsetDateTime) -> GeneralizedTime {
	let date_time = dt_strip_nanos(dt);
	GeneralizedTime::from_datetime(date_time)
}

fn write_dt_utc_or_generalized(writer :DERWriter, dt :OffsetDateTime) {
	// RFC 5280 requires CAs to write certificate validity dates
	// below 2050 as UTCTime, and anything starting from 2050
	// as GeneralizedTime [1]. The RFC doesn't say anything
	// about dates before 1950, but as UTCTime can't represent
	// them, we have to use GeneralizedTime if we want to or not.
	// [1]: https://tools.ietf.org/html/rfc5280#section-4.1.2.5
	if (1950..2050).contains(&dt.year()) {
		let date_time = dt_strip_nanos(dt);
		let ut = UTCTime::from_datetime(date_time);
		writer.write_utctime(&ut);
	} else {
		let gt = dt_to_generalized(dt);
		writer.write_generalized_time(&gt);
	}
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
							GeneralSubtree::DnsName(name) => writer.write_ia5_string(name),
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
	/// Generates a new certificate from the given parameters.
	///
	/// If there is no key pair included, then a new key pair will be generated and used.
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
	/// Returns the certificate parameters
	pub fn get_params(&self) -> &CertificateParams {
			&self.params
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
				let cert_data = yasna::try_construct_der(|writer| {
					self.params.write_request(&self.key_pair, writer)
				})?;
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
		let contents =  self.serialize_der()?;
		let p = Pem::new("CERTIFICATE", contents);
		Ok(pem::encode_config(&p, ENCODE_CONFIG))
	}
	/// Serializes the certificate, signed with another certificate's key, to the ASCII PEM format
	///
	/// *This function is only available if rcgen is built with the "pem" feature*
	#[cfg(feature = "pem")]
	pub fn serialize_pem_with_signer(&self, ca :&Certificate) -> Result<String, RcgenError> {
		let contents = self.serialize_der_with_signer(ca)?;
		let p = Pem::new("CERTIFICATE", contents);
		Ok(pem::encode_config(&p, ENCODE_CONFIG))
	}
	/// Serializes the certificate signing request to the ASCII PEM format
	///
	/// *This function is only available if rcgen is built with the "pem" feature*
	#[cfg(feature = "pem")]
	pub fn serialize_request_pem(&self) -> Result<String, RcgenError> {
		let contents = self.serialize_request_der()?;
		let p = Pem::new("CERTIFICATE REQUEST", contents);
		Ok(pem::encode_config(&p, ENCODE_CONFIG))
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

/// Serializes an X.509v3 extension according to RFC 5280
fn write_x509_extension(writer :DERWriter, extension_oid :&[u64], is_critical :bool, value_serializer :impl FnOnce(DERWriter)) {
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

/// Serializes an X.509v3 authority key identifier extension according to RFC 5280.
fn write_x509_authority_key_identifier(writer :DERWriter, ca :&Certificate) {
	// Write Authority Key Identifier
	// RFC 5280 states:
	//   'The keyIdentifier field of the authorityKeyIdentifier extension MUST
	//    be included in all certificates generated by conforming CAs to
	//    facilitate certification path construction.  There is one exception;
	//    where a CA distributes its public key in the form of a "self-signed"
	//    certificate, the authority key identifier MAY be omitted.'
	// In addition, for CRLs:
	//    'Conforming CRL issuers MUST use the key identifier method, and MUST
	//     include this extension in all CRLs issued.'
	write_x509_extension(writer, OID_AUTHORITY_KEY_IDENTIFIER, false, |writer| {
		writer.write_sequence(|writer| {
			writer.next().write_tagged_implicit(Tag::context(0), |writer| {
				writer.write_bytes(ca.get_key_identifier().as_ref())
			})
		});
	});
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

/// A certificate serial number.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct SerialNumber {
	inner :Vec<u8>,
}

impl SerialNumber {
		/// Create a serial number from the given byte slice.
		pub fn from_slice(bytes :&[u8]) -> SerialNumber {
				let inner = bytes.to_vec();
				SerialNumber { inner }
		}

		/// Return the byte representation of the serial number.
		pub fn to_bytes(&self) -> Vec<u8> {
				self.inner.clone()
		}

		/// Return the length of the serial number in bytes.
		pub fn len(&self) -> usize {
				self.inner.len()
		}
}

impl fmt::Display for SerialNumber {
		fn fmt(&self, f :&mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
				let hex :Vec<_> = self.inner.iter().map(|b| format!("{:02x}", b)).collect();
				write!(f, "{}", hex.join(":"))
		}
}

impl From<Vec<u8>> for SerialNumber {
		fn from(inner :Vec<u8>) -> SerialNumber {
				SerialNumber { inner }
		}
}

impl From<u64> for SerialNumber {
		fn from(u :u64) -> SerialNumber {
				let inner = u.to_be_bytes().into();
				SerialNumber { inner }
		}
}

impl AsRef<[u8]> for SerialNumber {
		fn as_ref(&self) -> &[u8] {
				&self.inner
		}
}

#[cfg(test)]
mod tests {
	use super::*;

	use std::panic::catch_unwind;

	fn get_times() -> [OffsetDateTime; 2] {
		let dt_nanos = {
			let date = Date::from_calendar_date(2020, Month::December, 3).unwrap();
			let time = Time::from_hms_nano(0, 0, 1, 444).unwrap();
			PrimitiveDateTime::new(date, time).assume_utc()
		};
		let dt_zero = {
			let date = Date::from_calendar_date(2020, Month::December, 3).unwrap();
			let time = Time::from_hms_nano(0, 0, 1, 0).unwrap();
			PrimitiveDateTime::new(date, time).assume_utc()
		};
		// TODO: include leap seconds if time becomes leap second aware
		[dt_nanos, dt_zero]
	}

	#[test]
	fn test_dt_utc_strip_nanos() {
		let times = get_times();

		// No stripping - OffsetDateTime with nanos
		let res = catch_unwind(|| UTCTime::from_datetime(times[0]));
		assert!(res.is_err());

		// Stripping
		for dt in times {
			let date_time = dt_strip_nanos(dt);
			assert_eq!(date_time.time().nanosecond(), 0);
			let _ut = UTCTime::from_datetime(date_time);
		}
	}

	#[test]
	fn test_dt_to_generalized() {
		let times = get_times();

		for dt in times {
			let _gt = dt_to_generalized(dt);
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
	fn test_with_extended_key_usages_any() {
		let mut params: CertificateParams = Default::default();

		// Set extended_key_usages
		params.extended_key_usages = vec![ExtendedKeyUsagePurpose::Any];

		// Make the cert
		let cert = Certificate::from_params(params).unwrap();

		// Serialize it
		let der = cert.serialize_der().unwrap();

		// Parse it
		let (_rem, cert) = x509_parser::parse_x509_certificate(&der).unwrap();

		// Ensure we found it.
		let maybe_extension = cert.extended_key_usage().unwrap();
		let extension = maybe_extension.unwrap();
		assert!(extension.value.any);
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

	#[cfg(feature = "pem")]
	mod test_pem_serialization {
    use crate::CertificateParams;
    use crate::Certificate;

		#[test]
		#[cfg(windows)]
		fn test_windows_line_endings() {
			let cert = Certificate::from_params(CertificateParams::default()).unwrap();
			let pem = cert.serialize_pem().expect("Failed to serialize pem");
			assert!(pem.contains("\r\n"));
		}

		#[test]
		#[cfg(not(windows))]
		fn test_not_windows_line_endings() {
			let cert = Certificate::from_params(CertificateParams::default()).unwrap();
			let pem = cert.serialize_pem().expect("Failed to serialize pem");
			assert!(!pem.contains("\r"));
		}
	}

	#[cfg(feature = "x509-parser")]
	mod test_ip_address_from_octets {
		use std::net::IpAddr;
		use super::super::ip_addr_from_octets;
		use super::super::RcgenError;

		#[test]
		fn ipv4() {
			let octets = [10, 20, 30, 40];

			let actual = ip_addr_from_octets(&octets)
				.unwrap();

			assert_eq!(IpAddr::from(octets), actual)
		}

		#[test]
		fn ipv6() {
			let octets = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

			let actual = ip_addr_from_octets(&octets)
				.unwrap();

			assert_eq!(IpAddr::from(octets), actual)
		}

		#[test]
		fn mismatch() {
			let incorrect: Vec<u8> = (0..10).into_iter().collect();
			let actual = ip_addr_from_octets(&incorrect)
				.unwrap_err();

			assert_eq!(RcgenError::InvalidIpAddressOctetLength(10), actual);
		}

		#[test]
		fn none() {
			let actual = ip_addr_from_octets(&[])
				.unwrap_err();

			assert_eq!(RcgenError::InvalidIpAddressOctetLength(0), actual);
		}

		#[test]
		fn too_many() {
			let incorrect: Vec<u8> = (0..20).into_iter().collect();
			let actual = ip_addr_from_octets(&incorrect)
				.unwrap_err();

			assert_eq!(RcgenError::InvalidIpAddressOctetLength(20), actual);
		}
	}

	#[cfg(feature = "x509-parser")]
	mod test_san_type_from_general_name {
		use std::net::IpAddr;
		use x509_parser::extensions::GeneralName;
		use crate::SanType;

		#[test]
		fn with_ipv4() {
			let octets = [1, 2, 3, 4];
			let value = GeneralName::IPAddress(&octets);
			let actual = SanType::try_from_general(&value)
				.unwrap();

			assert_eq!(SanType::IpAddress(IpAddr::from(octets)), actual);
		}
	}
}
