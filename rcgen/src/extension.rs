use std::fmt::Debug;
use std::net::IpAddr;
#[cfg(feature = "x509-parser")]
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use yasna::models::ObjectIdentifier;
use yasna::{DERWriter, Tag};

#[cfg(feature = "crypto")]
use crate::ring_like::digest;
use crate::string::Ia5String;
#[cfg(feature = "x509-parser")]
use crate::Error;
use crate::{
	oid, write_distinguished_name, CertificateParams, DistinguishedName, Issuer, SigningKey,
};

/// An X.509v3 subject alternative name extension according to [RFC 5280 §4.2.1.6].
///
/// [RFC 5280 §4.2.1.6]: <https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.6>
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SubjectAlternativeName<'params> {
	criticality: Criticality,
	names: &'params [SanType],
}

impl<'params> SubjectAlternativeName<'params> {
	pub(crate) fn from_params(params: &'params CertificateParams) -> Option<Self> {
		// GeneralNames ::= SEQUENCE SIZE (1..MAX): an empty SAN can't be encoded,
		// so the extension is omitted (RFC 5280 §4.2.1.6).
		if params.subject_alt_names.is_empty() {
			return None;
		}

		Some(Self {
			// Per RFC 5280 §4.1.2.6, SAN must be marked critical if the subject
			// is an empty sequence, and SHOULD be non-critical otherwise.
			criticality: params.distinguished_name.entries.is_empty().into(),
			names: &params.subject_alt_names,
		})
	}

	fn write_name(writer: DERWriter, san: &SanType) {
		writer.write_tagged_implicit(Tag::context(san.tag()), |writer| match san {
			SanType::Rfc822Name(name) | SanType::DnsName(name) | SanType::URI(name) => {
				writer.write_ia5_string(name.as_str())
			},
			SanType::IpAddress(IpAddr::V4(addr)) => writer.write_bytes(&addr.octets()),
			SanType::IpAddress(IpAddr::V6(addr)) => writer.write_bytes(&addr.octets()),
			SanType::OtherName((oid, value)) => {
				// otherName SEQUENCE { OID, [0] explicit any defined by oid }
				// https://datatracker.ietf.org/doc/html/rfc5280#page-38
				writer.write_sequence(|writer| {
					writer.next().write_oid(&ObjectIdentifier::from_slice(oid));
					value.write_der(writer.next());
				});
			},
		})
	}
}

impl Extension for SubjectAlternativeName<'_> {
	fn write_value(&self, writer: DERWriter) {
		/*
		   SubjectAltName ::= GeneralNames
		   GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
		*/
		writer.write_sequence(|writer| {
			for san in self.names.iter() {
				Self::write_name(writer.next(), san);
			}
		});
	}

	fn criticality(&self) -> Criticality {
		self.criticality
	}

	fn oid(&self) -> &[u64] {
		oid::SUBJECT_ALT_NAME
	}
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
#[allow(missing_docs)]
#[non_exhaustive]
/// The type of subject alt name
pub enum SanType {
	/// Also known as E-Mail address
	Rfc822Name(Ia5String),
	DnsName(Ia5String),
	URI(Ia5String),
	IpAddress(IpAddr),
	OtherName((Vec<u64>, OtherNameValue)),
}

impl SanType {
	#[cfg(all(test, feature = "x509-parser"))]
	pub(crate) fn from_x509(
		x509: &x509_parser::certificate::X509Certificate<'_>,
	) -> Result<Vec<Self>, Error> {
		let sans = x509
			.subject_alternative_name()
			.map_err(|_| Error::CouldNotParseCertificate)?
			.map(|ext| &ext.value.general_names);

		let Some(sans) = sans else {
			return Ok(Vec::new());
		};

		let mut subject_alt_names = Vec::with_capacity(sans.len());
		for san in sans {
			subject_alt_names.push(Self::try_from_general(san)?);
		}
		Ok(subject_alt_names)
	}

	#[cfg(feature = "x509-parser")]
	pub(crate) fn try_from_general(
		name: &x509_parser::extensions::GeneralName<'_>,
	) -> Result<Self, Error> {
		use x509_parser::der_parser::asn1_rs::{self, FromDer, Tag, TaggedExplicit};
		Ok(match name {
			x509_parser::extensions::GeneralName::RFC822Name(name) => {
				SanType::Rfc822Name((*name).try_into()?)
			},
			x509_parser::extensions::GeneralName::DNSName(name) => {
				SanType::DnsName((*name).try_into()?)
			},
			x509_parser::extensions::GeneralName::URI(name) => SanType::URI((*name).try_into()?),
			x509_parser::extensions::GeneralName::IPAddress(octets) => {
				SanType::IpAddress(ip_addr_from_octets(octets)?)
			},
			x509_parser::extensions::GeneralName::OtherName(oid, value) => {
				let oid = oid.iter().ok_or(Error::CouldNotParseCertificate)?;
				// We first remove the explicit tag ([0] EXPLICIT)
				let (_, other_name) = TaggedExplicit::<asn1_rs::Any, _, 0>::from_der(value)
					.map_err(|_| Error::CouldNotParseCertificate)?;
				let other_name = other_name.into_inner();

				let other_name_value = match other_name.tag() {
					Tag::Utf8String => OtherNameValue::Utf8String(
						std::str::from_utf8(other_name.data)
							.map_err(|_| Error::CouldNotParseCertificate)?
							.to_owned(),
					),
					_ => return Err(Error::CouldNotParseCertificate),
				};
				SanType::OtherName((oid.collect(), other_name_value))
			},
			_ => return Err(Error::InvalidNameType),
		})
	}

	fn tag(&self) -> u64 {
		// Defined in the GeneralName list in
		// https://tools.ietf.org/html/rfc5280#page-38
		const TAG_OTHER_NAME: u64 = 0;
		const TAG_RFC822_NAME: u64 = 1;
		const TAG_DNS_NAME: u64 = 2;
		const TAG_URI: u64 = 6;
		const TAG_IP_ADDRESS: u64 = 7;

		match self {
			SanType::Rfc822Name(_name) => TAG_RFC822_NAME,
			SanType::DnsName(_name) => TAG_DNS_NAME,
			SanType::URI(_name) => TAG_URI,
			SanType::IpAddress(_addr) => TAG_IP_ADDRESS,
			Self::OtherName(_oid) => TAG_OTHER_NAME,
		}
	}
}

/// An `OtherName` value, defined in [RFC 5280§4.1.2.4].
///
/// While the standard specifies this could be any ASN.1 type rcgen limits
/// the value to a UTF-8 encoded string as this will cover the most common
/// use cases, for instance smart card user principal names (UPN).
///
/// [RFC 5280§4.1.2.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
#[non_exhaustive]
pub enum OtherNameValue {
	/// A string encoded using UTF-8
	Utf8String(String),
}

impl OtherNameValue {
	fn write_der(&self, writer: DERWriter) {
		writer.write_tagged(Tag::context(0), |writer| match self {
			OtherNameValue::Utf8String(s) => writer.write_utf8_string(s),
		});
	}
}

impl<T> From<T> for OtherNameValue
where
	T: Into<String>,
{
	fn from(t: T) -> Self {
		OtherNameValue::Utf8String(t.into())
	}
}

#[cfg(feature = "x509-parser")]
fn ip_addr_from_octets(octets: &[u8]) -> Result<IpAddr, Error> {
	if let Ok(ipv6_octets) = <&[u8; 16]>::try_from(octets) {
		Ok(Ipv6Addr::from(*ipv6_octets).into())
	} else if let Ok(ipv4_octets) = <&[u8; 4]>::try_from(octets) {
		Ok(Ipv4Addr::from(*ipv4_octets).into())
	} else {
		Err(Error::InvalidIpAddressOctetLength(octets.len()))
	}
}

/// An X.509v3 key usage extension according to [RFC 5280 §4.2.1.3].
///
/// [RFC 5280 §4.2.1.3]: <https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.3>
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct KeyUsage<'params>(&'params [KeyUsagePurpose]);

impl<'params> KeyUsage<'params> {
	pub(crate) fn from_params(params: &'params CertificateParams) -> Option<Self> {
		if params.key_usages.is_empty() {
			return None;
		}

		Some(Self(&params.key_usages))
	}
}

impl StaticExtension for KeyUsage<'_> {
	fn write_value(&self, writer: DERWriter) {
		/*
		   KeyUsage ::= BIT STRING {
			  digitalSignature        (0),
			  nonRepudiation          (1), -- recent editions of X.509 have
										   -- renamed this bit to contentCommitment
			  keyEncipherment         (2),
			  dataEncipherment        (3),
			  keyAgreement            (4),
			  keyCertSign             (5),
			  cRLSign                 (6),
			  encipherOnly            (7),
			  decipherOnly            (8) }
		*/
		// u16 is large enough to encode the largest possible key usage (two-bytes)
		let bit_string = self.0.iter().fold(0u16, |bit_string, key_usage| {
			bit_string | key_usage.to_u16()
		});

		match u16::BITS - bit_string.trailing_zeros() {
			bits @ 0..=8 => {
				writer.write_bitvec_bytes(&bit_string.to_be_bytes()[..1], bits as usize)
			},
			bits @ 9..=16 => writer.write_bitvec_bytes(&bit_string.to_be_bytes(), bits as usize),
			_ => unreachable!(),
		}
	}

	// RFC 5280 §4.2.1.3: "When present, conforming CAs SHOULD mark this extension
	// as critical."
	const CRITICALITY: Criticality = Criticality::Critical;

	const OID: &'static [u64] = oid::KEY_USAGE;
}

/// One of the purposes contained in the [key usage](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3) extension
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
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

impl KeyUsagePurpose {
	#[cfg(feature = "x509-parser")]
	pub(crate) fn from_x509(
		x509: &x509_parser::certificate::X509Certificate<'_>,
	) -> Result<Vec<Self>, Error> {
		let key_usage = x509
			.key_usage()
			.map_err(|_| Error::CouldNotParseCertificate)?
			.map(|ext| ext.value);
		// This x509 parser stores flags in reversed bit BIT STRING order
		let flags = key_usage.map_or(0u16, |k| k.flags).reverse_bits();
		Ok(Self::from_u16(flags))
	}

	/// Encode a key usage as the value of a BIT STRING as defined by RFC 5280.
	/// [`u16`] is sufficient to encode the largest possible key usage value (two bytes).
	fn to_u16(self) -> u16 {
		const FLAG: u16 = 0b1000_0000_0000_0000;
		FLAG >> match self {
			KeyUsagePurpose::DigitalSignature => 0,
			KeyUsagePurpose::ContentCommitment => 1,
			KeyUsagePurpose::KeyEncipherment => 2,
			KeyUsagePurpose::DataEncipherment => 3,
			KeyUsagePurpose::KeyAgreement => 4,
			KeyUsagePurpose::KeyCertSign => 5,
			KeyUsagePurpose::CrlSign => 6,
			KeyUsagePurpose::EncipherOnly => 7,
			KeyUsagePurpose::DecipherOnly => 8,
		}
	}

	/// Parse a collection of key usages from a [`u16`] representing the value
	/// of a KeyUsage BIT STRING as defined by RFC 5280.
	#[cfg(feature = "x509-parser")]
	pub(crate) fn from_u16(value: u16) -> Vec<Self> {
		[
			KeyUsagePurpose::DigitalSignature,
			KeyUsagePurpose::ContentCommitment,
			KeyUsagePurpose::KeyEncipherment,
			KeyUsagePurpose::DataEncipherment,
			KeyUsagePurpose::KeyAgreement,
			KeyUsagePurpose::KeyCertSign,
			KeyUsagePurpose::CrlSign,
			KeyUsagePurpose::EncipherOnly,
			KeyUsagePurpose::DecipherOnly,
		]
		.iter()
		.filter_map(|key_usage| {
			let present = key_usage.to_u16() & value != 0;
			present.then_some(*key_usage)
		})
		.collect()
	}
}

/// An X.509v3 extended key usage extension according to [RFC 5280 §4.2.1.12].
///
/// [RFC 5280 §4.2.1.12]: <https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.12>
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExtendedKeyUsage<'params>(&'params [ExtendedKeyUsagePurpose]);

impl<'params> ExtendedKeyUsage<'params> {
	pub(crate) fn from_params(params: &'params CertificateParams) -> Option<Self> {
		if params.extended_key_usages.is_empty() {
			return None;
		}

		Some(Self(&params.extended_key_usages))
	}
}

impl StaticExtension for ExtendedKeyUsage<'_> {
	fn write_value(&self, writer: DERWriter) {
		/*
		   ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
		   KeyPurposeId ::= OBJECT IDENTIFIER
		*/
		writer.write_sequence(|writer| {
			for usage in self.0.iter() {
				writer
					.next()
					.write_oid(&ObjectIdentifier::from_slice(usage.oid()));
			}
		});
	}

	// RFC 5280 §4.2.1.12: "This extension MAY, at the option of the certificate
	// issuer, be either critical or non-critical."
	// TODO(XXX): make this configurable?
	const CRITICALITY: Criticality = Criticality::NonCritical;

	const OID: &'static [u64] = oid::EXT_KEY_USAGE;
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
	/// A custom purpose not from the pre-specified list of purposes
	Other(Vec<u64>),
}

impl ExtendedKeyUsagePurpose {
	#[cfg(all(test, feature = "x509-parser"))]
	pub(crate) fn from_x509(
		x509: &x509_parser::certificate::X509Certificate<'_>,
	) -> Result<Vec<Self>, Error> {
		let extended_key_usage = x509
			.extended_key_usage()
			.map_err(|_| Error::CouldNotParseCertificate)?
			.map(|ext| ext.value);

		let mut extended_key_usages = Vec::new();
		if let Some(extended_key_usage) = extended_key_usage {
			if extended_key_usage.any {
				extended_key_usages.push(Self::Any);
			}
			if extended_key_usage.server_auth {
				extended_key_usages.push(Self::ServerAuth);
			}
			if extended_key_usage.client_auth {
				extended_key_usages.push(Self::ClientAuth);
			}
			if extended_key_usage.code_signing {
				extended_key_usages.push(Self::CodeSigning);
			}
			if extended_key_usage.email_protection {
				extended_key_usages.push(Self::EmailProtection);
			}
			if extended_key_usage.time_stamping {
				extended_key_usages.push(Self::TimeStamping);
			}
			if extended_key_usage.ocsp_signing {
				extended_key_usages.push(Self::OcspSigning);
			}
		}

		Ok(extended_key_usages)
	}

	pub(crate) fn oid(&self) -> &[u64] {
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
			Other(oid) => oid,
		}
	}
}

/// An X.509v3 basic constraints extension according to [RFC 5280 §4.2.1.9].
///
/// [RFC 5280 §4.2.1.9]: <https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.9>
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BasicConstraints(IsCa);

impl BasicConstraints {
	pub(crate) fn from_params(params: &CertificateParams) -> Option<Self> {
		// For IsCa::NoCa the extension is omitted entirely: absence implies the
		// certificate is not a CA. Use IsCa::ExplicitNoCa to emit the extension
		// with cA absent (FALSE).
		if params.is_ca == IsCa::NoCa {
			return None;
		}

		Some(Self(params.is_ca))
	}
}

impl StaticExtension for BasicConstraints {
	fn write_value(&self, writer: DERWriter) {
		/*
		   BasicConstraints ::= SEQUENCE {
				cA                      BOOLEAN DEFAULT FALSE,
				pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
		*/
		writer.write_sequence(|writer| {
			let IsCa::Ca(constraints) = &self.0 else {
				// The cA flag is DEFAULT FALSE, so DER (X.690 §11.5) requires it
				// to be omitted when false: the extension value is an empty
				// SEQUENCE.
				return;
			};

			writer.next().write_bool(true); // cA flag
			if let PathLenConstraint::Constrained(path_len_constraint) = constraints {
				writer.next().write_u8(*path_len_constraint); // pathLenConstraint integer
			}
		});
	}

	// RFC 5280 §4.2.1.9: "Conforming CAs MUST include this extension in all CA
	// certificates that contain public keys used to validate digital signatures
	// on certificates and MUST mark the extension as critical in such
	// certificates."
	const CRITICALITY: Criticality = Criticality::Critical;

	const OID: &'static [u64] = oid::BASIC_CONSTRAINTS;
}

/// Whether the certificate is allowed to sign other certificates
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IsCa {
	/// The certificate can only sign itself
	NoCa,
	/// The certificate can only sign itself, adding the extension and `CA:FALSE`
	ExplicitNoCa,
	/// The certificate may be used to sign other certificates
	Ca(PathLenConstraint),
}

impl IsCa {
	#[cfg(all(test, feature = "x509-parser"))]
	pub(crate) fn from_x509(
		x509: &x509_parser::certificate::X509Certificate<'_>,
	) -> Result<Self, Error> {
		let basic_constraints = x509
			.basic_constraints()
			.map_err(|_| Error::CouldNotParseCertificate)?
			.map(|ext| ext.value);

		match basic_constraints {
			Some(bc) => Self::from_basic_constraints(bc),
			None => Ok(Self::NoCa),
		}
	}

	#[cfg(feature = "x509-parser")]
	pub(crate) fn from_basic_constraints(
		basic_constraints: &x509_parser::extensions::BasicConstraints,
	) -> Result<Self, Error> {
		use x509_parser::extensions::BasicConstraints as B;

		Ok(match basic_constraints {
			B {
				ca: true,
				path_len_constraint: Some(n),
			} if *n <= u8::MAX as u32 => Self::Ca(PathLenConstraint::Constrained(*n as u8)),
			B {
				ca: true,
				path_len_constraint: Some(_),
			} => return Err(Error::CouldNotParseCertificate),
			B {
				ca: true,
				path_len_constraint: None,
			} => Self::Ca(PathLenConstraint::Unconstrained),
			B { ca: false, .. } => Self::ExplicitNoCa,
		})
	}
}

/// The path length constraint (only relevant for CA certificates)
///
/// Sets an optional upper limit on the length of the intermediate certificate chain
/// length allowed for this CA certificate (not including the end entity certificate).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PathLenConstraint {
	/// No constraint
	Unconstrained,
	/// Constrain to the contained number of intermediate certificates
	Constrained(u8),
}

/// An X.509v3 name constraints extension according to [RFC 5280 §4.2.1.10].
///
/// [RFC 5280 §4.2.1.10]: <https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.10>
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NameConstraintsExt<'params> {
	permitted_subtrees: &'params [GeneralSubtree],
	excluded_subtrees: &'params [GeneralSubtree],
}

impl<'params> NameConstraintsExt<'params> {
	pub(crate) fn from_params(params: &'params CertificateParams) -> Option<Self> {
		match &params.name_constraints {
			// If both subtrees are empty, the extension must be omitted.
			Some(nc) if !nc.is_empty() => Some(Self {
				permitted_subtrees: &nc.permitted_subtrees,
				excluded_subtrees: &nc.excluded_subtrees,
			}),
			_ => None,
		}
	}

	fn write_general_subtrees(writer: DERWriter, tag: u64, general_subtrees: &[GeneralSubtree]) {
		/*
		   GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
		   GeneralSubtree ::= SEQUENCE {
				base                    GeneralName,
				minimum         [0]     BaseDistance DEFAULT 0,
				maximum         [1]     BaseDistance OPTIONAL }
		   BaseDistance ::= INTEGER (0..MAX)
		*/
		writer.write_tagged_implicit(Tag::context(tag), |writer| {
			writer.write_sequence(|writer| {
				for subtree in general_subtrees.iter() {
					writer.next().write_sequence(|writer| {
						let writer = writer.next();
						let tag = Tag::context(subtree.tag());
						match subtree {
							GeneralSubtree::Rfc822Name(name) | GeneralSubtree::DnsName(name) => {
								writer.write_tagged_implicit(tag, |writer| {
									writer.write_ia5_string(name)
								})
							},
							// `Name` is a CHOICE, so X.680 §31.2.7 requires explicit tagging.
							GeneralSubtree::DirectoryName(name) => writer
								.write_tagged(tag, |writer| write_distinguished_name(writer, name)),
							GeneralSubtree::IpAddress(subnet) => writer
								.write_tagged_implicit(tag, |writer| {
									writer.write_bytes(&subnet.to_bytes())
								}),
						}
						// minimum must be 0 (the default) and maximum must be absent
					});
				}
			});
		});
	}
}

impl StaticExtension for NameConstraintsExt<'_> {
	fn write_value(&self, writer: DERWriter) {
		/*
		   NameConstraints ::= SEQUENCE {
				permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
				excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }
		*/
		writer.write_sequence(|writer| {
			if !self.permitted_subtrees.is_empty() {
				Self::write_general_subtrees(writer.next(), 0, self.permitted_subtrees);
			}
			if !self.excluded_subtrees.is_empty() {
				Self::write_general_subtrees(writer.next(), 1, self.excluded_subtrees);
			}
		});
	}

	// RFC 5280 §4.2.1.10: "Conforming CAs MUST mark this extension as critical."
	const CRITICALITY: Criticality = Criticality::Critical;

	const OID: &'static [u64] = oid::NAME_CONSTRAINTS;
}

/// The [NameConstraints extension](https://tools.ietf.org/html/rfc5280#section-4.2.1.10)
/// (only relevant for CA certificates)
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NameConstraints {
	/// A list of subtrees that the domain has to match.
	pub permitted_subtrees: Vec<GeneralSubtree>,
	/// A list of subtrees that the domain must not match.
	///
	/// Any name matching an excluded subtree is invalid even if it also matches a permitted subtree.
	pub excluded_subtrees: Vec<GeneralSubtree>,
}

impl NameConstraints {
	#[cfg(all(test, feature = "x509-parser"))]
	pub(crate) fn from_x509(
		x509: &x509_parser::certificate::X509Certificate<'_>,
	) -> Result<Option<Self>, Error> {
		let constraints = x509
			.name_constraints()
			.map_err(|_| Error::CouldNotParseCertificate)?
			.map(|ext| ext.value);

		let Some(constraints) = constraints else {
			return Ok(None);
		};

		let permitted_subtrees = if let Some(permitted) = &constraints.permitted_subtrees {
			GeneralSubtree::from_x509(permitted)?
		} else {
			Vec::new()
		};

		let excluded_subtrees = if let Some(excluded) = &constraints.excluded_subtrees {
			GeneralSubtree::from_x509(excluded)?
		} else {
			Vec::new()
		};

		Ok(Some(Self {
			permitted_subtrees,
			excluded_subtrees,
		}))
	}

	pub(crate) fn is_empty(&self) -> bool {
		self.permitted_subtrees.is_empty() && self.excluded_subtrees.is_empty()
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
	#[cfg(all(test, feature = "x509-parser"))]
	fn from_x509(
		subtrees: &[x509_parser::extensions::GeneralSubtree<'_>],
	) -> Result<Vec<Self>, Error> {
		use x509_parser::extensions::GeneralName;

		let mut result = Vec::new();
		for subtree in subtrees {
			let subtree = match &subtree.base {
				GeneralName::RFC822Name(s) => Self::Rfc822Name(s.to_string()),
				GeneralName::DNSName(s) => Self::DnsName(s.to_string()),
				GeneralName::DirectoryName(n) => {
					Self::DirectoryName(DistinguishedName::from_name(n)?)
				},
				GeneralName::IPAddress(bytes) if bytes.len() == 8 => {
					let addr: [u8; 4] = bytes[..4].try_into().unwrap();
					let mask: [u8; 4] = bytes[4..].try_into().unwrap();
					Self::IpAddress(CidrSubnet::V4(addr, mask))
				},
				GeneralName::IPAddress(bytes) if bytes.len() == 32 => {
					let addr: [u8; 16] = bytes[..16].try_into().unwrap();
					let mask: [u8; 16] = bytes[16..].try_into().unwrap();
					Self::IpAddress(CidrSubnet::V6(addr, mask))
				},
				_ => continue,
			};
			result.push(subtree);
		}

		Ok(result)
	}

	fn tag(&self) -> u64 {
		// Defined in the GeneralName list in
		// https://tools.ietf.org/html/rfc5280#page-38
		const TAG_RFC822_NAME: u64 = 1;
		const TAG_DNS_NAME: u64 = 2;
		const TAG_DIRECTORY_NAME: u64 = 4;
		const TAG_IP_ADDRESS: u64 = 7;

		match self {
			GeneralSubtree::Rfc822Name(_name) => TAG_RFC822_NAME,
			GeneralSubtree::DnsName(_name) => TAG_DNS_NAME,
			GeneralSubtree::DirectoryName(_name) => TAG_DIRECTORY_NAME,
			GeneralSubtree::IpAddress(_addr) => TAG_IP_ADDRESS,
		}
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
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
		let v = <$t>::MAX;
		let v = v.checked_shr($d as u32).unwrap_or(0);
		(!v).to_be_bytes()
	}};
}

impl CidrSubnet {
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
	pub fn from_addr_prefix(addr: IpAddr, prefix: u8) -> Self {
		match addr {
			IpAddr::V4(addr) => Self::from_v4_prefix(addr.octets(), prefix),
			IpAddr::V6(addr) => Self::from_v6_prefix(addr.octets(), prefix),
		}
	}

	/// Obtains the CidrSubnet from an IPv4 address in network byte order
	/// as well as the specified prefix.
	pub fn from_v4_prefix(addr: [u8; 4], prefix: u8) -> Self {
		CidrSubnet::V4(addr, mask!(u32, prefix))
	}

	/// Obtains the CidrSubnet from an IPv6 address in network byte order
	/// as well as the specified prefix.
	pub fn from_v6_prefix(addr: [u8; 16], prefix: u8) -> Self {
		CidrSubnet::V6(addr, mask!(u128, prefix))
	}

	fn to_bytes(self) -> Vec<u8> {
		let mut res = Vec::new();
		match self {
			CidrSubnet::V4(addr, mask) => {
				res.extend_from_slice(&addr);
				res.extend_from_slice(&mask);
			},
			CidrSubnet::V6(addr, mask) => {
				res.extend_from_slice(&addr);
				res.extend_from_slice(&mask);
			},
		}
		res
	}
}

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
impl FromStr for CidrSubnet {
	type Err = ();

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let mut iter = s.split('/');
		if let (Some(addr_s), Some(prefix_s)) = (iter.next(), iter.next()) {
			let addr = IpAddr::from_str(addr_s).map_err(|_| ())?;
			let prefix = u8::from_str(prefix_s).map_err(|_| ())?;
			Ok(Self::from_addr_prefix(addr, prefix))
		} else {
			Err(())
		}
	}
}

/// An X.509v3 CRL distribution points extension according to [RFC 5280 §4.2.1.13].
///
/// [RFC 5280 §4.2.1.13]: <https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.13>
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CrlDistributionPoints<'params>(&'params [CrlDistributionPoint]);

impl<'params> CrlDistributionPoints<'params> {
	pub(crate) fn from_params(params: &'params CertificateParams) -> Option<Self> {
		if params.crl_distribution_points.is_empty() {
			return None;
		}

		Some(Self(&params.crl_distribution_points))
	}
}

impl StaticExtension for CrlDistributionPoints<'_> {
	fn write_value(&self, writer: DERWriter) {
		// CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
		writer.write_sequence(|writer| {
			for distribution_point in self.0 {
				distribution_point.write_der(writer.next());
			}
		})
	}

	// RFC 5280 §4.2.1.13: "The extension SHOULD be non-critical".
	const CRITICALITY: Criticality = Criticality::NonCritical;

	const OID: &'static [u64] = oid::CRL_DISTRIBUTION_POINTS;
}

/// A certificate revocation list (CRL) distribution point, to be included in a certificate's
/// [distribution points extension](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.13) or
/// a CRL's [issuing distribution point extension](https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.5)
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct CrlDistributionPoint {
	/// One or more URI distribution point names, indicating a place the current CRL can
	/// be retrieved. When present, SHOULD include at least one LDAP or HTTP URI.
	pub uris: Vec<String>,
}

impl CrlDistributionPoint {
	fn write_der(&self, writer: DERWriter) {
		// DistributionPoint SEQUENCE
		writer.write_sequence(|writer| {
			write_distribution_point_name_uris(writer.next(), &self.uris);
		});
	}
}

pub(crate) fn write_distribution_point_name_uris<'a>(
	writer: DERWriter,
	uris: impl IntoIterator<Item = &'a String>,
) {
	// distributionPoint DistributionPointName
	writer.write_tagged_implicit(Tag::context(0), |writer| {
		writer.write_sequence(|writer| {
			// fullName GeneralNames
			writer
				.next()
				.write_tagged_implicit(Tag::context(0), |writer| {
					// GeneralNames
					writer.write_sequence(|writer| {
						for uri in uris.into_iter() {
							// uniformResourceIdentifier [6] IA5String,
							writer
								.next()
								.write_tagged_implicit(Tag::context(6), |writer| {
									writer.write_ia5_string(uri)
								});
						}
					})
				});
		});
	});
}

/// An X.509v3 subject key identifier extension according to [RFC 5280 §4.2.1.2].
///
/// [RFC 5280 §4.2.1.2]: <https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.2>
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SubjectKeyIdentifier(Vec<u8>);

impl SubjectKeyIdentifier {
	pub(crate) fn new(key_identifier_method: &KeyIdMethod, pub_key_spki: &[u8]) -> Self {
		Self(key_identifier_method.derive(pub_key_spki))
	}
}

impl StaticExtension for SubjectKeyIdentifier {
	fn write_value(&self, writer: DERWriter) {
		/*
		   SubjectKeyIdentifier ::= KeyIdentifier
		   KeyIdentifier ::= OCTET STRING
		*/
		writer.write_bytes(&self.0)
	}

	// RFC 5280 §4.2.1.2: "Conforming CAs MUST mark this extension as non-critical."
	const CRITICALITY: Criticality = Criticality::NonCritical;

	const OID: &'static [u64] = oid::SUBJECT_KEY_IDENTIFIER;
}

/// An X.509v3 authority key identifier extension according to [RFC 5280 §4.2.1.1].
///
/// RFC 5280 states:
///   'The keyIdentifier field of the authorityKeyIdentifier extension MUST
///    be included in all certificates generated by conforming CAs to
///    facilitate certification path construction.  There is one exception;
///    where a CA distributes its public key in the form of a "self-signed"
///    certificate, the authority key identifier MAY be omitted.'
/// In addition, for CRLs:
///    'Conforming CRL issuers MUST use the key identifier method, and MUST
///     include this extension in all CRLs issued.'
///
/// [RFC 5280 §4.2.1.1]: <https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.1>
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AuthorityKeyIdentifier(pub(crate) Vec<u8>);

impl<S: SigningKey> From<&Issuer<'_, S>> for AuthorityKeyIdentifier {
	fn from(issuer: &Issuer<'_, S>) -> Self {
		Self(match issuer.key_identifier_method.as_ref() {
			KeyIdMethod::PreSpecified(aki) => aki.clone(),
			#[cfg(feature = "crypto")]
			_ => issuer
				.key_identifier_method
				.derive(issuer.signing_key.subject_public_key_info()),
		})
	}
}

impl StaticExtension for AuthorityKeyIdentifier {
	fn write_value(&self, writer: DERWriter) {
		/*
			AuthorityKeyIdentifier ::= SEQUENCE {
				   keyIdentifier             [0] KeyIdentifier           OPTIONAL,
				   authorityCertIssuer       [1] GeneralNames            OPTIONAL,
				   authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
			KeyIdentifier ::= OCTET STRING
		*/
		writer.write_sequence(|writer| {
			writer
				.next()
				.write_tagged_implicit(Tag::context(0), |writer| writer.write_bytes(&self.0))
		});
	}

	// RFC 5280 §4.2.1.1: "Conforming CAs MUST mark this extension as non-critical."
	const CRITICALITY: Criticality = Criticality::NonCritical;

	const OID: &'static [u64] = oid::AUTHORITY_KEY_IDENTIFIER;
}

/// Method to generate key identifiers from public keys.
///
/// Key identifiers should be derived from the public key data. [RFC 7093] defines
/// three methods to do so using a choice of SHA256 (method 1), SHA384 (method 2), or SHA512
/// (method 3). In each case the first 160 bits of the hash are used as the key identifier
/// to match the output length that would be produced were SHA1 used (a legacy option defined
/// in RFC 5280).
///
/// In addition to the RFC 7093 mechanisms, rcgen supports using a pre-specified key identifier.
/// This can be helpful when working with an existing `Certificate`.
///
/// [RFC 7093]: https://www.rfc-editor.org/rfc/rfc7093
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
#[non_exhaustive]
pub enum KeyIdMethod {
	/// RFC 7093 method 1 - a truncated SHA256 digest.
	#[cfg(feature = "crypto")]
	Sha256,
	/// RFC 7093 method 2 - a truncated SHA384 digest.
	#[cfg(feature = "crypto")]
	Sha384,
	/// RFC 7093 method 3 - a truncated SHA512 digest.
	#[cfg(feature = "crypto")]
	Sha512,
	/// Pre-specified identifier. The exact given value is used as the key identifier.
	PreSpecified(Vec<u8>),
}

impl KeyIdMethod {
	#[cfg(feature = "x509-parser")]
	pub(crate) fn from_x509(
		x509: &x509_parser::certificate::X509Certificate<'_>,
	) -> Result<Self, Error> {
		let key_identifier_method =
			x509.iter_extensions()
				.find_map(|ext| match ext.parsed_extension() {
					x509_parser::extensions::ParsedExtension::SubjectKeyIdentifier(key_id) => {
						Some(KeyIdMethod::PreSpecified(key_id.0.into()))
					},
					_ => None,
				});

		Ok(match key_identifier_method {
			Some(method) => method,
			None => {
				#[cfg(not(feature = "crypto"))]
				return Err(Error::UnsupportedSignatureAlgorithm);
				#[cfg(feature = "crypto")]
				KeyIdMethod::Sha256
			},
		})
	}

	/// Derive a key identifier for the provided subject public key info using the key ID method.
	///
	/// Typically this is a truncated hash over the raw subject public key info, but may
	/// be a pre-specified value.
	///
	/// This key identifier is used in the SubjectKeyIdentifier and AuthorityKeyIdentifier
	/// X.509v3 extensions.
	#[allow(unused_variables)]
	pub(crate) fn derive(&self, subject_public_key_info: impl AsRef<[u8]>) -> Vec<u8> {
		#[cfg_attr(not(feature = "crypto"), expect(clippy::let_unit_value))]
		let digest_method = match &self {
			#[cfg(feature = "crypto")]
			Self::Sha256 => &digest::SHA256,
			#[cfg(feature = "crypto")]
			Self::Sha384 => &digest::SHA384,
			#[cfg(feature = "crypto")]
			Self::Sha512 => &digest::SHA512,
			Self::PreSpecified(b) => {
				return b.to_vec();
			},
		};
		#[cfg(feature = "crypto")]
		{
			let digest = digest::digest(digest_method, subject_public_key_info.as_ref());
			digest.as_ref()[0..20].to_vec()
		}
	}
}

impl<T: StaticExtension> Extension for T {
	fn write_value(&self, writer: DERWriter) {
		// Calling with fully qualified syntax to disambiguate.
		StaticExtension::write_value(self, writer)
	}

	fn criticality(&self) -> Criticality {
		T::CRITICALITY
	}

	fn oid(&self) -> &[u64] {
		T::OID
	}
}

/// An X.509 extension whose OID and criticality are fixed by the profile
/// defining it.
///
/// Implementors receive [`Extension`] through a blanket impl. Extensions that
/// decide criticality (or OID) at runtime implement [`Extension`] directly
/// instead.
pub(crate) trait StaticExtension: Debug {
	/// Write the extension's value (the content of the extnValue OCTET STRING).
	fn write_value(&self, writer: DERWriter);

	/// The criticality of the extension.
	const CRITICALITY: Criticality;

	/// The OID components of the extension.
	const OID: &'static [u64];
}

/// An X.509 extension.
///
/// All extensions have an OID, a criticality, and a DER encoded value for inclusion in
/// an X.509 extension SEQUENCE.
pub(crate) trait Extension: Debug {
	/// Serialize the extension according to RFC 5280.
	fn write(&self, writer: DERWriter) {
		/*
		   Extension  ::=  SEQUENCE  {
				extnID      OBJECT IDENTIFIER,
				critical    BOOLEAN DEFAULT FALSE,
				extnValue   OCTET STRING
							-- contains the DER encoding of an ASN.1 value
							-- corresponding to the extension type identified
							-- by extnID
				}
		*/
		writer.write_sequence(|writer| {
			writer
				.next()
				.write_oid(&ObjectIdentifier::from_slice(self.oid()));
			// DER requires that DEFAULT values be omitted (X.690 §11.5): the critical
			// flag may only be encoded when it is TRUE.
			if self.criticality() == Criticality::Critical {
				writer.next().write_bool(true);
			}
			writer
				.next()
				.write_bytes(&yasna::construct_der(|writer| self.write_value(writer)));
		})
	}

	/// Write the extension's value (the content of the extnValue OCTET STRING).
	fn write_value(&self, writer: DERWriter);

	/// Return the criticality of the extension.
	fn criticality(&self) -> Criticality;

	/// Return the OID components of the extension.
	fn oid(&self) -> &[u64];
}

/// The criticality of an X.509 extension.
///
/// This controls how consumers should handle an unrecognized extension.
///
/// See [RFC 5280 §4.2] for more information.
///
/// [RFC 5280 §4.2]: <https://www.rfc-editor.org/rfc/rfc5280#section-4.2>
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Criticality {
	/// The extension MUST be recognized and parsed correctly.
	Critical,

	/// The extension MAY be ignored if it is not recognized.
	NonCritical,
}

impl From<bool> for Criticality {
	fn from(critical: bool) -> Self {
		match critical {
			true => Self::Critical,
			false => Self::NonCritical,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn critical_flag_omitted_when_false() {
		// The critical flag is DEFAULT FALSE, so DER (X.690 §11.5) requires that a
		// non-critical extension omit it entirely rather than encode FALSE.
		// See https://github.com/rustls/rcgen/pull/444 for a past instance of this
		// bug class.
		let ext = DummyExt(Criticality::NonCritical);
		let der = yasna::construct_der(|writer| ext.write(writer));
		assert_eq!(
			der,
			yasna::construct_der(|writer| {
				writer.write_sequence(|writer| {
					writer
						.next()
						.write_oid(&ObjectIdentifier::from_slice(ext.oid()));
					// No BOOLEAN between the OID and the value: the critical
					// flag must be absent, not encoded as FALSE.
					writer
						.next()
						.write_bytes(&yasna::construct_der(|writer| ext.write_value(writer)));
				})
			})
		);
	}

	#[test]
	fn critical_flag_written_when_true() {
		let ext = DummyExt(Criticality::Critical);
		let der = yasna::construct_der(|writer| ext.write(writer));
		assert_eq!(
			der,
			yasna::construct_der(|writer| {
				writer.write_sequence(|writer| {
					writer
						.next()
						.write_oid(&ObjectIdentifier::from_slice(ext.oid()));
					writer.next().write_bool(true); // critical TRUE
					writer
						.next()
						.write_bytes(&yasna::construct_der(|writer| ext.write_value(writer)));
				})
			})
		);
	}

	#[test]
	fn aki_encoding() {
		let ext = AuthorityKeyIdentifier(vec![0xDE, 0xAD]);
		let der = yasna::construct_der(|writer| ext.write(writer));
		assert_eq!(
			der,
			yasna::construct_der(|writer| {
				writer.write_sequence(|writer| {
					writer
						.next()
						.write_oid(&ObjectIdentifier::from_slice(oid::AUTHORITY_KEY_IDENTIFIER));
					// Non-critical: the critical flag must be absent.
					writer.next().write_bytes(&yasna::construct_der(|writer| {
						// AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] OCTET STRING }
						writer.write_sequence(|writer| {
							writer
								.next()
								.write_tagged_implicit(Tag::context(0), |writer| {
									writer.write_bytes(&[0xDE, 0xAD])
								})
						})
					}));
				})
			})
		);
	}

	#[test]
	fn basic_constraints_absent_for_no_ca() {
		// IsCa::NoCa means no BasicConstraints extension at all.
		assert!(BasicConstraints::from_params(&CertificateParams::default()).is_none());
	}

	#[test]
	fn basic_constraints_encoding() {
		// The cA flag is DEFAULT FALSE, so DER (X.690 §11.5) requires that
		// ExplicitNoCa encode as an empty SEQUENCE with the flag omitted.
		// See https://github.com/rustls/rcgen/pull/444.
		for (is_ca, expected) in [
			(
				// cA absent (FALSE): an empty SEQUENCE.
				IsCa::ExplicitNoCa,
				yasna::construct_der(|writer| writer.write_sequence(|_writer| {})),
			),
			(
				IsCa::Ca(PathLenConstraint::Unconstrained),
				yasna::construct_der(|writer| {
					writer.write_sequence(|writer| writer.next().write_bool(true))
				}),
			),
			(
				IsCa::Ca(PathLenConstraint::Constrained(5)),
				yasna::construct_der(|writer| {
					writer.write_sequence(|writer| {
						writer.next().write_bool(true);
						writer.next().write_u8(5);
					})
				}),
			),
		] {
			let params = CertificateParams {
				is_ca,
				..CertificateParams::default()
			};
			let bc = BasicConstraints::from_params(&params).unwrap();
			let value = yasna::construct_der(|writer| StaticExtension::write_value(&bc, writer));
			assert_eq!(value, expected, "unexpected encoding for {is_ca:?}");
		}
	}

	#[test]
	fn name_constraints_absent_when_subtrees_empty() {
		// A name constraints extension with no permitted or excluded subtrees
		// would violate SEQUENCE SIZE (1..MAX) and must be omitted.
		let params = CertificateParams {
			name_constraints: Some(crate::NameConstraints {
				permitted_subtrees: Vec::new(),
				excluded_subtrees: Vec::new(),
			}),
			..CertificateParams::default()
		};
		assert!(NameConstraintsExt::from_params(&params).is_none());
	}

	#[test]
	fn san_absent_when_no_names() {
		assert!(SubjectAlternativeName::from_params(&CertificateParams::default()).is_none());
	}

	#[test]
	fn san_critical_when_subject_empty() {
		// RFC 5280 §4.1.2.6: SAN must be critical if the subject is an empty sequence.
		let mut params = CertificateParams {
			subject_alt_names: vec![SanType::DnsName("example.com".try_into().unwrap())],
			..CertificateParams::default()
		};
		assert_eq!(
			SubjectAlternativeName::from_params(&params)
				.unwrap()
				.criticality(),
			Criticality::NonCritical
		);

		params.distinguished_name = crate::DistinguishedName::new();
		assert_eq!(
			SubjectAlternativeName::from_params(&params)
				.unwrap()
				.criticality(),
			Criticality::Critical
		);
	}

	#[cfg(feature = "x509-parser")]
	mod test_ip_address_from_octets {
		use super::*;

		#[test]
		fn ipv4() {
			let octets = [10, 20, 30, 40];
			let actual = ip_addr_from_octets(&octets).unwrap();
			assert_eq!(IpAddr::from(octets), actual)
		}

		#[test]
		fn ipv6() {
			let octets = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
			let actual = ip_addr_from_octets(&octets).unwrap();
			assert_eq!(IpAddr::from(octets), actual)
		}

		#[test]
		fn mismatch() {
			let incorrect = Vec::from_iter(0..10);
			let actual = ip_addr_from_octets(&incorrect).unwrap_err();
			assert_eq!(Error::InvalidIpAddressOctetLength(10), actual);
		}

		#[test]
		fn none() {
			let actual = ip_addr_from_octets(&[]).unwrap_err();
			assert_eq!(Error::InvalidIpAddressOctetLength(0), actual);
		}

		#[test]
		fn too_many() {
			let incorrect = Vec::from_iter(0..20);
			let actual = ip_addr_from_octets(&incorrect).unwrap_err();
			assert_eq!(Error::InvalidIpAddressOctetLength(20), actual);
		}
	}

	#[cfg(feature = "x509-parser")]
	#[test]
	fn san_type_from_general_name_with_ipv4() {
		use x509_parser::extensions::GeneralName;

		let octets = [1, 2, 3, 4];
		let value = GeneralName::IPAddress(&octets);
		let actual = SanType::try_from_general(&value).unwrap();

		assert_eq!(SanType::IpAddress(IpAddr::from(octets)), actual);
	}

	#[derive(Debug)]
	struct DummyExt(Criticality);

	impl Extension for DummyExt {
		fn write_value(&self, writer: DERWriter) {
			writer.write_null()
		}

		fn criticality(&self) -> Criticality {
			self.0
		}

		fn oid(&self) -> &[u64] {
			&[1, 3, 6, 1, 4, 1, 99]
		}
	}
}
