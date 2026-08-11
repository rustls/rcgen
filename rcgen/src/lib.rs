/*!
Rust X.509 certificate generation utility

This crate provides a way to generate self signed X.509 certificates.

The most simple way of using this crate is by calling the
[`generate_simple_self_signed`] function.
For more customization abilities, construct a [`CertificateParams`] and
a key pair to call [`CertificateParams::signed_by()`] or [`CertificateParams::self_signed()`].
*/
#![cfg_attr(
	feature = "pem",
	doc = r##"
## Example

```
use rcgen::{generate_simple_self_signed, CertifiedKey};
# fn main () {
// Generate a certificate that's valid for "localhost" and "hello.world.example"
let subject_alt_names = vec!["hello.world.example".to_string(),
	"localhost".to_string()];

let CertifiedKey { cert, signing_key } = generate_simple_self_signed(subject_alt_names).unwrap();
println!("{}", cert.pem());
println!("{}", signing_key.serialize_pem());
# }
```"##
)]
#![forbid(unsafe_code)]
#![forbid(non_ascii_idents)]
#![deny(missing_docs)]
#![cfg_attr(rcgen_docsrs, feature(doc_cfg))]
#![warn(unreachable_pub)]

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::hash::Hash;
use std::ops::Deref;

pub use certificate::{
	date_time_ymd, Attribute, BasicConstraints, Certificate, CertificateParams, CustomExtension,
	DnType, IsCa,
};
pub use crl::{
	CertificateRevocationList, CertificateRevocationListParams, CrlIssuingDistributionPoint,
	CrlScope, RevocationReason, RevokedCertParams,
};
pub use csr::{CertificateSigningRequest, CertificateSigningRequestParams, PublicKey};
pub use error::{Error, InvalidAsn1String};
pub use ext::{
	CidrSubnet, CrlDistributionPoint, ExtendedKeyUsagePurpose, GeneralSubtree, KeyIdMethod,
	KeyUsagePurpose, NameConstraints, OtherNameValue, SanType,
};
#[cfg(feature = "crypto")]
pub use key_pair::KeyPair;
#[cfg(all(feature = "crypto", feature = "aws_lc_rs"))]
pub use key_pair::RsaKeySize;
pub use key_pair::{PublicKeyData, SigningKey, SubjectPublicKeyInfo};
#[cfg(feature = "pem")]
use pem::Pem;
use pki_types::CertificateDer;
pub use sign_algo::algo::*;
pub use sign_algo::SignatureAlgorithm;
use time::{OffsetDateTime, Time};
use yasna::models::{GeneralizedTime, ObjectIdentifier, UTCTime};
use yasna::tags::{TAG_BMPSTRING, TAG_TELETEXSTRING, TAG_UNIVERSALSTRING};
use yasna::DERWriter;

use crate::string::{BmpString, Ia5String, PrintableString, TeletexString, UniversalString};

mod certificate;
mod crl;
mod csr;
mod error;
mod ext;
mod key_pair;
mod oid;
mod ring_like;
mod sign_algo;
pub mod string;

/// Type-alias for the old name of [`Error`].
#[deprecated(
	note = "Renamed to `Error`. We recommend to refer to it by fully-qualifying the crate: `rcgen::Error`."
)]
pub type RcgenError = Error;

/// An issued certificate, together with the subject keypair.
#[derive(PartialEq, Eq)]
pub struct CertifiedKey<S: SigningKey> {
	/// An issued certificate.
	pub cert: Certificate,
	/// The certificate's subject signing key.
	pub signing_key: S,
}

/**
KISS function to generate a self signed certificate

Given a set of domain names you want your certificate to be valid for,
this function fills in the other generation parameters with
reasonable defaults and generates a self signed certificate
and key pair as output.
*/
#[cfg(feature = "crypto")]
#[cfg_attr(
	feature = "pem",
	doc = r##"
## Example

```
use rcgen::{generate_simple_self_signed, CertifiedKey};
# fn main () {
// Generate a certificate that's valid for "localhost" and "hello.world.example"
let subject_alt_names = vec!["hello.world.example".to_string(),
	"localhost".to_string()];

let CertifiedKey { cert, signing_key } = generate_simple_self_signed(subject_alt_names).unwrap();

// The certificate is now valid for localhost and the domain "hello.world.example"
println!("{}", cert.pem());
println!("{}", signing_key.serialize_pem());
# }
```
"##
)]
pub fn generate_simple_self_signed(
	subject_alt_names: impl Into<Vec<String>>,
) -> Result<CertifiedKey<KeyPair>, Error> {
	let signing_key = KeyPair::generate()?;
	let cert = CertificateParams::new(subject_alt_names)?.self_signed(&signing_key)?;
	Ok(CertifiedKey { cert, signing_key })
}

/// An [`Issuer`] wrapper that also contains the issuer's [`Certificate`].
#[derive(Debug)]
pub struct CertifiedIssuer<'a, S> {
	certificate: Certificate,
	issuer: Issuer<'a, S>,
}

impl<'a, S: SigningKey> CertifiedIssuer<'a, S> {
	/// Create a new issuer from the given parameters and key, with a self-signed certificate.
	pub fn self_signed(params: CertificateParams, signing_key: S) -> Result<Self, Error> {
		Ok(Self {
			certificate: params.self_signed(&signing_key)?,
			issuer: Issuer::new(params, signing_key),
		})
	}

	/// Create a new issuer from the given parameters and key, signed by the given `issuer`.
	pub fn signed_by(
		params: CertificateParams,
		signing_key: S,
		issuer: &Issuer<'_, impl SigningKey>,
	) -> Result<Self, Error> {
		Ok(Self {
			certificate: params.signed_by(&signing_key, issuer)?,
			issuer: Issuer::new(params, signing_key),
		})
	}

	/// Get the certificate in PEM encoded format.
	#[cfg(feature = "pem")]
	pub fn pem(&self) -> String {
		pem::encode_config(&Pem::new("CERTIFICATE", self.der().to_vec()), ENCODE_CONFIG)
	}

	/// Get the certificate in DER encoded format.
	///
	/// See also [`Certificate::der()`]
	pub fn der(&self) -> &CertificateDer<'static> {
		self.certificate.der()
	}
}

impl<'a, S> Deref for CertifiedIssuer<'a, S> {
	type Target = Issuer<'a, S>;

	fn deref(&self) -> &Self::Target {
		&self.issuer
	}
}

impl<'a, S> AsRef<Certificate> for CertifiedIssuer<'a, S> {
	fn as_ref(&self) -> &Certificate {
		&self.certificate
	}
}

/// An issuer that can sign certificates.
///
/// Encapsulates the distinguished name, key identifier method, key usages and signing key
/// of the issuing certificate.
pub struct Issuer<'a, S> {
	distinguished_name: Cow<'a, DistinguishedName>,
	key_identifier_method: Cow<'a, KeyIdMethod>,
	key_usages: Cow<'a, [KeyUsagePurpose]>,
	signing_key: S,
}

impl<'a, S: SigningKey> Issuer<'a, S> {
	/// Create a new issuer from the given parameters and signing key.
	pub fn new(params: CertificateParams, signing_key: S) -> Self {
		Self {
			distinguished_name: Cow::Owned(params.distinguished_name),
			key_identifier_method: Cow::Owned(params.key_identifier_method),
			key_usages: Cow::Owned(params.key_usages),
			signing_key,
		}
	}

	/// Create a new issuer from the given parameters and signing key references.
	///
	/// Use [`Issuer::new`] instead if you want to obtain an [`Issuer`] that owns
	/// its parameters.
	pub fn from_params(params: &'a CertificateParams, signing_key: S) -> Self {
		Self {
			distinguished_name: Cow::Borrowed(&params.distinguished_name),
			key_identifier_method: Cow::Borrowed(&params.key_identifier_method),
			key_usages: Cow::Borrowed(&params.key_usages),
			signing_key,
		}
	}

	/// Parses an existing CA certificate from the ASCII PEM format.
	///
	/// See [`from_ca_cert_der`](Self::from_ca_cert_der) for more details.
	#[cfg(all(feature = "pem", feature = "x509-parser"))]
	pub fn from_ca_cert_pem(pem_str: &str, signing_key: S) -> Result<Self, Error> {
		let certificate = pem::parse(pem_str).map_err(|_| Error::CouldNotParseCertificate)?;
		Self::from_ca_cert_der(&certificate.contents().into(), signing_key)
	}

	/// Parses an existing CA certificate from the DER format.
	///
	/// This function assumes the provided certificate is a CA. It will not check
	/// for the presence of the `BasicConstraints` extension, or perform any other
	/// validation.
	///
	/// If you already have a byte slice containing DER, it can trivially be converted into
	/// [`CertificateDer`] using the [`Into`] trait.
	#[cfg(feature = "x509-parser")]
	pub fn from_ca_cert_der(ca_cert: &CertificateDer<'_>, signing_key: S) -> Result<Self, Error> {
		let (_remainder, x509) = x509_parser::parse_x509_certificate(ca_cert)
			.map_err(|_| Error::CouldNotParseCertificate)?;

		Ok(Self {
			key_usages: Cow::Owned(KeyUsagePurpose::from_x509(&x509)?),
			key_identifier_method: Cow::Owned(KeyIdMethod::from_x509(&x509)?),
			distinguished_name: Cow::Owned(DistinguishedName::from_name(
				&x509.tbs_certificate.subject,
			)?),
			signing_key,
		})
	}

	/// Allowed key usages for this issuer.
	pub fn key_usages(&self) -> &[KeyUsagePurpose] {
		&self.key_usages
	}

	/// Yield a reference to the signing key.
	pub fn key(&self) -> &S {
		&self.signing_key
	}
}

impl<'a, S> fmt::Debug for Issuer<'a, S> {
	/// Formats the issuer information without revealing the key pair.
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		// The key pair is omitted from the debug output as it contains secret information.
		let Issuer {
			distinguished_name,
			key_identifier_method,
			key_usages,
			signing_key: _,
		} = self;

		f.debug_struct("Issuer")
			.field("distinguished_name", distinguished_name)
			.field("key_identifier_method", key_identifier_method)
			.field("key_usages", key_usages)
			.field("signing_key", &"[elided]")
			.finish()
	}
}

// https://tools.ietf.org/html/rfc5280#section-4.1.1

// Example certs usable as reference:
// Uses ECDSA: https://crt.sh/?asn1=607203242

#[cfg(feature = "pem")]
const ENCODE_CONFIG: pem::EncodeConfig = {
	let line_ending = match cfg!(target_family = "windows") {
		true => pem::LineEnding::CRLF,
		false => pem::LineEnding::LF,
	};
	pem::EncodeConfig::new().set_line_ending(line_ending)
};

/// A distinguished name entry
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
#[non_exhaustive]
pub enum DnValue {
	/// A string encoded using UCS-2
	BmpString(BmpString),
	/// An ASCII string.
	Ia5String(Ia5String),
	/// An ASCII string containing only A-Z, a-z, 0-9, '()+,-./:=? and `<SPACE>`
	PrintableString(PrintableString),
	/// A string of characters from the T.61 character set
	TeletexString(TeletexString),
	/// A string encoded using UTF-32
	UniversalString(UniversalString),
	/// A string encoded using UTF-8
	Utf8String(String),
}

impl<T> From<T> for DnValue
where
	T: Into<String>,
{
	fn from(t: T) -> Self {
		DnValue::Utf8String(t.into())
	}
}

#[derive(Debug, Default, PartialEq, Eq, Clone)]
/**
Distinguished name used e.g. for the issuer and subject fields of a certificate

A distinguished name is a set of (attribute type, attribute value) tuples.

This datastructure keeps them ordered by insertion order.

See also the RFC 5280 sections on the [issuer](https://tools.ietf.org/html/rfc5280#section-4.1.2.4)
and [subject](https://tools.ietf.org/html/rfc5280#section-4.1.2.6) fields.
*/
pub struct DistinguishedName {
	entries: HashMap<DnType, DnValue>,
	order: Vec<DnType>,
}

impl DistinguishedName {
	/// Creates a new, empty distinguished name
	pub fn new() -> Self {
		Self::default()
	}
	/// Obtains the attribute value for the given attribute type
	pub fn get(&self, ty: &DnType) -> Option<&DnValue> {
		self.entries.get(ty)
	}
	/// Removes the attribute with the specified DnType
	///
	/// Returns true when an actual removal happened, false
	/// when no attribute with the specified DnType was
	/// found.
	pub fn remove(&mut self, ty: DnType) -> bool {
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
	/// dn.push(DnType::CommonName, DnValue::PrintableString("Master Cert".try_into().unwrap()));
	/// assert_eq!(dn.get(&DnType::OrganizationName), Some(&DnValue::Utf8String("Crab widgits SE".to_string())));
	/// assert_eq!(dn.get(&DnType::CommonName), Some(&DnValue::PrintableString("Master Cert".try_into().unwrap())));
	/// ```
	pub fn push(&mut self, ty: DnType, s: impl Into<DnValue>) {
		if !self.entries.contains_key(&ty) {
			self.order.push(ty.clone());
		}
		self.entries.insert(ty, s.into());
	}
	/// Iterate over the entries
	pub fn iter(&self) -> DistinguishedNameIterator<'_> {
		DistinguishedNameIterator {
			distinguished_name: self,
			iter: self.order.iter(),
		}
	}

	#[cfg(feature = "x509-parser")]
	fn from_name(name: &x509_parser::x509::X509Name) -> Result<Self, Error> {
		use x509_parser::der_parser::asn1_rs::Tag;

		let mut dn = DistinguishedName::new();
		for rdn in name.iter() {
			let mut rdn_iter = rdn.iter();
			let dn_opt = rdn_iter.next();
			let attr = if let Some(dn) = dn_opt {
				if rdn_iter.next().is_some() {
					// no support for distinguished names with more than one attribute
					return Err(Error::CouldNotParseCertificate);
				} else {
					dn
				}
			} else {
				panic!("x509-parser distinguished name set is empty");
			};

			let attr_type_oid = attr
				.attr_type()
				.iter()
				.ok_or(Error::CouldNotParseCertificate)?;
			let dn_type = DnType::from_oid(&attr_type_oid.collect::<Vec<_>>());
			let data = attr.attr_value().data;
			let try_str =
				|data| std::str::from_utf8(data).map_err(|_| Error::CouldNotParseCertificate);
			let dn_value = match attr.attr_value().header.tag() {
				Tag::BmpString => DnValue::BmpString(BmpString::from_utf16be(data.to_vec())?),
				Tag::Ia5String => DnValue::Ia5String(try_str(data)?.try_into()?),
				Tag::PrintableString => DnValue::PrintableString(try_str(data)?.try_into()?),
				Tag::T61String => DnValue::TeletexString(try_str(data)?.try_into()?),
				Tag::UniversalString => {
					DnValue::UniversalString(UniversalString::from_utf32be(data.to_vec())?)
				},
				Tag::Utf8String => DnValue::Utf8String(try_str(data)?.to_owned()),
				_ => return Err(Error::CouldNotParseCertificate),
			};

			dn.push(dn_type, dn_value);
		}
		Ok(dn)
	}
}

/**
Iterator over [`DistinguishedName`] entries
*/
#[derive(Clone, Debug)]
pub struct DistinguishedNameIterator<'a> {
	distinguished_name: &'a DistinguishedName,
	iter: std::slice::Iter<'a, DnType>,
}

impl<'a> Iterator for DistinguishedNameIterator<'a> {
	type Item = (&'a DnType, &'a DnValue);

	fn next(&mut self) -> Option<Self::Item> {
		self.iter
			.next()
			.and_then(|ty| self.distinguished_name.entries.get(ty).map(|v| (ty, v)))
	}
}

fn dt_strip_nanos(dt: OffsetDateTime) -> OffsetDateTime {
	// Set nanoseconds to zero
	// This is needed because the GeneralizedTime serializer would otherwise
	// output fractional values which RFC 5280 explicitly forbode [1].
	// UTCTime cannot express fractional seconds or leap seconds
	// therefore, it needs to be stripped of nanoseconds fully.
	// [1]: https://tools.ietf.org/html/rfc5280#section-4.1.2.5.2
	// TODO: handle leap seconds if dt becomes leap second aware
	let time =
		Time::from_hms(dt.hour(), dt.minute(), dt.second()).expect("invalid or out-of-range time");
	dt.replace_time(time)
}

fn dt_to_generalized(dt: OffsetDateTime) -> GeneralizedTime {
	let date_time = dt_strip_nanos(dt);
	GeneralizedTime::from_datetime(date_time)
}

fn write_dt_utc_or_generalized(writer: DERWriter, dt: OffsetDateTime) {
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

fn write_distinguished_name(writer: DERWriter, dn: &DistinguishedName) {
	writer.write_sequence(|writer| {
		for (ty, content) in dn.iter() {
			writer.next().write_set(|writer| {
				writer.next().write_sequence(|writer| {
					writer.next().write_oid(&ty.to_oid());
					match content {
						DnValue::BmpString(s) => writer
							.next()
							.write_tagged_implicit(TAG_BMPSTRING, |writer| {
								writer.write_bytes(s.as_bytes())
							}),

						DnValue::Ia5String(s) => writer.next().write_ia5_string(s.as_str()),

						DnValue::PrintableString(s) => {
							writer.next().write_printable_string(s.as_str())
						},
						DnValue::TeletexString(s) => writer
							.next()
							.write_tagged_implicit(TAG_TELETEXSTRING, |writer| {
								writer.write_bytes(s.as_bytes())
							}),
						DnValue::UniversalString(s) => writer
							.next()
							.write_tagged_implicit(TAG_UNIVERSALSTRING, |writer| {
								writer.write_bytes(s.as_bytes())
							}),
						DnValue::Utf8String(s) => writer.next().write_utf8_string(s),
					}
				});
			});
		}
	});
}

/// Serializes an X.509v3 extension according to RFC 5280
fn write_x509_extension(
	writer: DERWriter,
	extension_oid: &[u64],
	is_critical: bool,
	value_serializer: impl FnOnce(DERWriter),
) {
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

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for KeyPair {
	fn zeroize(&mut self) {
		self.serialized_der.zeroize();
	}
}

/// A certificate serial number.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct SerialNumber {
	inner: Vec<u8>,
}

#[allow(clippy::len_without_is_empty)]
impl SerialNumber {
	/// Create a serial number from the given byte slice.
	pub fn from_slice(bytes: &[u8]) -> SerialNumber {
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
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
		let hex: Vec<_> = self.inner.iter().map(|b| format!("{b:02x}")).collect();
		write!(f, "{}", hex.join(":"))
	}
}

impl From<Vec<u8>> for SerialNumber {
	fn from(inner: Vec<u8>) -> SerialNumber {
		SerialNumber { inner }
	}
}

impl From<u64> for SerialNumber {
	fn from(u: u64) -> SerialNumber {
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
	use std::panic::catch_unwind;

	use time::{Date, Month, PrimitiveDateTime};

	use super::*;

	fn times() -> [OffsetDateTime; 2] {
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
		let times = times();

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
		let times = times();

		for dt in times {
			let _gt = dt_to_generalized(dt);
		}
	}

	#[test]
	fn signature_algos_different() {
		// TODO unify this with test_key_params_mismatch.
		// Note that that test doesn't have a full list of signature
		// algorithms, as it has no access to the iter function.
		for (i, alg_i) in SignatureAlgorithm::iter().enumerate() {
			for (j, alg_j) in SignatureAlgorithm::iter().enumerate() {
				assert_eq!(
					alg_i == alg_j,
					i == j,
					"Algorithm relationship mismatch for algorithm index pair {i} and {j}"
				);
			}
		}
	}
}
