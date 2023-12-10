use std::collections::HashSet;
use std::fmt::Debug;
use std::net::IpAddr;
use time::OffsetDateTime;

use yasna::models::ObjectIdentifier;
use yasna::{DERWriter, DERWriterSeq, Tag};

use crate::key_pair::PublicKeyData;
use crate::oid::{OID_PE_ACME, OID_PKCS_9_AT_EXTENSION_REQUEST};
use crate::{
	crl, oid, write_distinguished_name, write_dt_utc_or_generalized, Certificate,
	CertificateParams, CertificateRevocationListParams, CrlIssuingDistributionPoint, Error,
	ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, KeyUsagePurpose, RevokedCertParams, SanType,
	SerialNumber,
};

/// The criticality of an extension.
///
/// This controls how a certificate-using system should handle an unrecognized or un-parsable
/// extension.
///
/// See [RFC 5280 Section 4.2] for more information.
///
/// [RFC 5280 Section 4.2]: <https://www.rfc-editor.org/rfc/rfc5280#section-4.2>
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Criticality {
	/// The extension MUST be recognized and parsed correctly.
	///
	/// A certificate-using system MUST reject the certificate if it encounters a critical
	/// extension it does not recognize or a critical extension that contains information that it
	/// cannot process.
	Critical,

	/// The extension MAY be ignored if it is not recognized or parsed correctly.
	///
	/// A non-critical extension MAY be ignored if it is not recognized, but MUST be
	/// processed if it is recognized
	NonCritical,
}

/// A custom extension of a certificate, as specified in
/// [RFC 5280](https://tools.ietf.org/html/rfc5280#section-4.2)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomExtension {
	/// OID identifying the extension.
	///
	/// Only one extension with a given OID may appear within a certificate.
	pub oid: ObjectIdentifier,

	/// Criticality of the extension.
	///
	/// See [Criticality] for more information.
	pub criticality: Criticality,

	/// The raw DER encoded value of the extension.
	///
	/// This should not contain the OID, criticality, OCTET STRING, or the outer extension SEQUENCE
	/// of the extension itself: it should only be the DER encoded bytes that will be found
	/// within the extensions' OCTET STRING value.
	pub der_value: Vec<u8>,
}

impl CustomExtension {
	/// Create a new custom extension with the specified content
	pub fn from_oid_content(oid: &[u64], criticality: Criticality, der_value: Vec<u8>) -> Self {
		Self {
			oid: ObjectIdentifier::from_slice(oid),
			criticality,
			der_value,
		}
	}

	/// Obtains the OID components of the extensions, as u64 pieces
	pub fn oid_components(&self) -> impl Iterator<Item = u64> + '_ {
		self.oid.components().iter().copied()
	}

	#[cfg(feature = "x509-parser")]
	pub(crate) fn from_parsed(
		parsed: &x509_parser::prelude::X509Extension<'_>,
	) -> Result<Self, Error> {
		Ok(CustomExtension {
			oid: ObjectIdentifier::from_slice(
				&parsed
					.oid
					.iter()
					.ok_or(Error::UnsupportedExtension)?
					.collect::<Vec<_>>(),
			),
			criticality: if parsed.critical {
				Criticality::Critical
			} else {
				Criticality::NonCritical
			},
			der_value: parsed.value.to_vec(),
		})
	}
}

impl Extension for CustomExtension {
	fn oid(&self) -> ObjectIdentifier {
		self.oid.clone()
	}

	fn criticality(&self) -> Criticality {
		self.criticality
	}

	fn write_value(&self, writer: DERWriter) {
		writer.write_der(&self.der_value)
	}
}

/// An ACME TLS-ALPN-01 challenge response certificate extension.
///
/// See [RFC 8737 Section 3] for more information.
///
/// [RFC 8737 Section 3]: <https://tools.ietf.org/html/rfc8737#section-3>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcmeIdentifier {
	// The SHA256 digest of the RFC 8555 key authorization for a TLS-ALPN-01 challenge
	// issued by the CA.
	key_auth_digest: [u8; 32],
}

impl AcmeIdentifier {
	/// Construct an ACME TLS-ALPN-01 challenge response certificate extension.
	///
	/// `key_auth_digest` should be the SHA-256 digest of the key authorization for the
	/// TLS-ALPN-01 challenge issued by the CA.
	///
	/// If you have a `Vec` or `&[u8]` use `try_from` and handle the potential error
	/// if the input length is not 32 bytes.
	pub fn new(key_auth_digest: [u8; 32]) -> Self {
		Self {
			key_auth_digest: key_auth_digest,
		}
	}
}

impl TryFrom<&[u8]> for AcmeIdentifier {
	type Error = Error;

	fn try_from(key_auth_digest: &[u8]) -> Result<Self, Self::Error> {
		// All TLS-ALPN-01 challenge response digests are 32 bytes long,
		// matching the output of the SHA256 digest algorithm.
		if key_auth_digest.len() != 32 {
			return Err(Error::InvalidAcmeIdentifierLength);
		}

		let mut sha_digest = [0u8; 32];
		sha_digest.copy_from_slice(&key_auth_digest);
		Ok(Self {
			key_auth_digest: sha_digest,
		})
	}
}

impl Extension for AcmeIdentifier {
	fn oid(&self) -> ObjectIdentifier {
		ObjectIdentifier::from_slice(OID_PE_ACME)
	}

	fn criticality(&self) -> Criticality {
		// The acmeIdentifier extension MUST be critical so that the certificate isn't inadvertently
		// used by non-ACME software.
		Criticality::Critical
	}

	fn write_value(&self, writer: DERWriter) {
		// Authorization ::= OCTET STRING (SIZE (32))
		writer.write_bytes(&self.key_auth_digest);
	}
}

/// A trait describing an X.509 Extension.
///
/// All extensions have an OID, an indicator of whether they are critical or not, and can be
/// encoded to a DER value for inclusion in an X.509 certificate extension SEQUENCE.
pub(crate) trait Extension: Debug {
	/// Return the OID of the extension.  
	fn oid(&self) -> ObjectIdentifier;

	/// Return the criticality of the extension.  
	fn criticality(&self) -> Criticality;

	/// Write the extension's value to the DER writer.  
	fn write_value(&self, writer: DERWriter);
}

/// A collection of X.509 extensions.
///
/// Preserves the order that extensions were added and maintains the invariant that
/// there are no duplicate extension OIDs.
#[derive(Debug, Default)]
pub(crate) struct Extensions {
	exts: Vec<Box<dyn Extension>>,
	oids: HashSet<ObjectIdentifier>,
}

impl Extensions {
	/// Construct a set of extensions from an iterator of extensions.
	///
	/// # Errors
	///
	/// Returns [Error::DuplicateExtension] if any of the extensions have the same OID.
	pub(crate) fn new(
		extensions: impl IntoIterator<Item = Box<dyn Extension>>,
	) -> Result<Self, Error> {
		let mut result = Self::default();
		result.add_extensions(extensions)?;
		Ok(result)
	}

	/// Add an extension to the collection.
	///
	/// # Errors
	///
	/// Returns [Error::DuplicateExtension] if the extension's OID is already present in the collection.
	pub(crate) fn add_extension(&mut self, extension: Box<dyn Extension>) -> Result<(), Error> {
		if self.oids.get(&extension.oid()).is_some() {
			return Err(Error::DuplicateExtension(extension.oid().to_string()));
		}

		self.oids.insert(extension.oid());
		self.exts.push(extension);
		Ok(())
	}

	pub(crate) fn add_extensions(
		&mut self,
		extensions: impl IntoIterator<Item = Box<dyn Extension>>,
	) -> Result<(), Error> {
		for ext in extensions {
			self.add_extension(ext)?
		}
		Ok(())
	}

	/// Write the SEQUENCE of extensions to the DER writer, wrapped in the context tag for
	/// an optional X.509 V3 certificate extensions field.
	///
	/// Nothing will be written to the writer if there were no extensions.
	pub(crate) fn write_exts_der(&self, writer: DERWriter) {
		// Avoid writing an empty tagged extensions sequence.
		if self.exts.is_empty() {
			return;
		}

		// extensions [3] Extensions OPTIONAL
		writer.write_tagged(Tag::context(3), |writer| self.write_der(writer));
	}

	/// Write the SEQUENCE of extensions to the DER writer, wrapped in the PKCS 9 attribute
	/// extension request OID and set for a CSR.
	///
	/// Nothing will be written to the writer if there were no extensions.
	pub(crate) fn write_csr_der(&self, writer: DERWriter) {
		// Avoid writing an empty attribute requests sequence.
		if self.exts.is_empty() {
			return;
		}

		writer.write_sequence(|writer| {
			writer.next().write_oid(&ObjectIdentifier::from_slice(
				OID_PKCS_9_AT_EXTENSION_REQUEST,
			));
			writer.next().write_set(|writer| {
				self.write_der(writer.next());
			});
		});
	}

	pub(crate) fn write_crl_der(&self, writer: DERWriter) {
		// Avoid writing an empty tagged extensions sequence.
		if self.exts.is_empty() {
			return;
		}

		// crlExtensions [0] Extensions OPTIONAL
		writer.write_tagged(Tag::context(0), |writer| self.write_der(writer));
	}

	/// Write the SEQUENCE of extensions to the DER writer.
	fn write_der(&self, writer: DERWriter) {
		debug_assert_eq!(self.exts.len(), self.oids.len());

		// Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension
		writer.write_sequence(|writer| {
			for extension in &self.exts {
				Self::write_extension(writer, extension);
			}
		})
	}

	pub(crate) fn iter(&self) -> impl Iterator<Item = &Box<dyn Extension>> {
		self.exts.iter()
	}

	/// Write a single extension SEQUENCE to the DER writer.
	pub(crate) fn write_extension(writer: &mut DERWriterSeq, extension: &Box<dyn Extension>) {
		//  Extension ::= SEQUENCE {
		//    extnID    OBJECT IDENTIFIER,
		//    critical  BOOLEAN DEFAULT FALSE,
		//    extnValue OCTET STRING
		//      -- contains the DER encoding of an ASN.1 value
		//      -- corresponding to the extension type identified
		//      -- by extnID
		//  }
		writer.next().write_sequence(|writer| {
			writer.next().write_oid(&extension.oid());
			writer
				.next()
				.write_bool(matches!(extension.criticality(), Criticality::Critical));
			writer.next().write_bytes(&yasna::construct_der(|writer| {
				extension.write_value(writer)
			}));
		});
	}
}

/// An X.509v3 authority key identifier extension according to
/// [RFC 5280 4.2.1.1](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.1).
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord)]
pub(crate) struct AuthorityKeyIdentifier {
	key_identifier: Vec<u8>,
}

impl Extension for AuthorityKeyIdentifier {
	fn oid(&self) -> ObjectIdentifier {
		ObjectIdentifier::from_slice(oid::OID_AUTHORITY_KEY_IDENTIFIER)
	}

	fn criticality(&self) -> Criticality {
		// Conforming CAs MUST mark this extension as non-critical.
		Criticality::NonCritical
	}

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
				.write_tagged_implicit(Tag::context(0), |writer| {
					writer.write_bytes(&self.key_identifier)
				})
		});
	}
}

impl From<&Certificate> for AuthorityKeyIdentifier {
	fn from(cert: &Certificate) -> Self {
		Self {
			key_identifier: cert.get_key_identifier(),
		}
	}
}

/// An X.509v3 subject alternative name extension according to
/// [RFC 5280 4.2.1.6](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.6).
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct SubjectAlternativeName {
	criticality: Criticality,
	names: Vec<SanType>,
}

impl SubjectAlternativeName {
	pub(crate) fn from_params(params: &CertificateParams) -> Option<Self> {
		match params.subject_alt_names.is_empty() {
			true => None,
			false => Some(Self {
				// TODO(XXX): For now we mark the SAN extension as non-critical, matching the pre-existing
				//   handling, however per 5280 this extension's criticality is determined based
				// 	 on whether or not the subject contains an empty sequence.
				criticality: Criticality::NonCritical,
				names: params.subject_alt_names.clone(),
			}),
		}
	}

	#[cfg(feature = "x509-parser")]
	pub(crate) fn from_parsed(
		params: &mut CertificateParams,
		ext: &x509_parser::extensions::ParsedExtension,
	) -> Result<bool, Error> {
		Ok(match ext {
			x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) => {
				for name in &san.general_names {
					params
						.subject_alt_names
						.push(SanType::try_from_general(name)?);
				}
				true
			},
			_ => false,
		})
	}

	fn write_name(writer: DERWriter, san: &SanType) {
		writer.write_tagged_implicit(Tag::context(san.tag()), |writer| match san {
			SanType::Rfc822Name(name) | SanType::DnsName(name) | SanType::URI(name) => {
				writer.write_ia5_string(&name)
			},
			SanType::IpAddress(IpAddr::V4(addr)) => writer.write_bytes(&addr.octets()),
			SanType::IpAddress(IpAddr::V6(addr)) => writer.write_bytes(&addr.octets()),
		})
	}
}

impl Extension for SubjectAlternativeName {
	fn oid(&self) -> ObjectIdentifier {
		ObjectIdentifier::from_slice(oid::OID_SUBJECT_ALT_NAME)
	}

	fn criticality(&self) -> Criticality {
		// this extension's criticality is determined based on whether or not the subject contains
		// an empty sequence. If it does, the SAN MUST be critical. If it has a non-empty subject
		// distinguished name, the SAN SHOULD be non-critical.
		self.criticality
	}

	fn write_value(&self, writer: DERWriter) {
		/*
		   SubjectAltName ::= GeneralNames
		   GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
		*/
		writer.write_sequence(|writer| {
			self.names
				.iter()
				.for_each(|san| Self::write_name(writer.next(), san));
		});
	}
}

/// An X.509v3 key usage extension according to
/// [RFC 5280 4.2.1.3](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.3).
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct KeyUsage {
	usages: Vec<KeyUsagePurpose>,
}

impl KeyUsage {
	pub(crate) fn from_params(params: &CertificateParams) -> Option<Self> {
		match params.key_usages.is_empty() {
			true => None,
			false => Some(Self {
				usages: params.key_usages.clone(),
			}),
		}
	}

	#[cfg(feature = "x509-parser")]
	pub(crate) fn from_parsed(
		params: &mut CertificateParams,
		ext: &x509_parser::extensions::ParsedExtension,
	) -> Result<bool, Error> {
		match ext {
			x509_parser::extensions::ParsedExtension::KeyUsage(ku) => {
				let mut usages = Vec::new();
				if ku.digital_signature() {
					usages.push(KeyUsagePurpose::DigitalSignature);
				}
				// Note: previous editions of X.509 called ContentCommitment "Non repudiation"
				if ku.non_repudiation() {
					usages.push(KeyUsagePurpose::ContentCommitment);
				}
				if ku.key_encipherment() {
					usages.push(KeyUsagePurpose::KeyEncipherment);
				}
				if ku.key_cert_sign() {
					usages.push(KeyUsagePurpose::KeyCertSign);
				}
				if ku.crl_sign() {
					usages.push(KeyUsagePurpose::CrlSign);
				}
				if ku.encipher_only() {
					usages.push(KeyUsagePurpose::EncipherOnly);
				}
				if ku.decipher_only() {
					usages.push(KeyUsagePurpose::DecipherOnly);
				}
				params.key_usages = usages;
				Ok(true)
			},
			_ => Ok(false),
		}
	}
}

impl Extension for KeyUsage {
	fn oid(&self) -> ObjectIdentifier {
		ObjectIdentifier::from_slice(oid::OID_KEY_USAGE)
	}

	fn criticality(&self) -> Criticality {
		// When present, conforming CAs SHOULD mark this extension as critical.
		Criticality::Critical
	}

	fn write_value(&self, writer: DERWriter) {
		use KeyUsagePurpose::*;

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
		let mut bits: u16 = 0;

		for entry in &self.usages {
			// Map the index to a value
			let index = match entry {
				DigitalSignature => 0,
				ContentCommitment => 1,
				KeyEncipherment => 2,
				DataEncipherment => 3,
				KeyAgreement => 4,
				KeyCertSign => 5,
				CrlSign => 6,
				EncipherOnly => 7,
				DecipherOnly => 8,
			};

			bits |= 1 << index;
		}

		// Compute the 1-based most significant bit
		let msb = 16 - bits.leading_zeros();
		let nb = if msb <= 8 { 1 } else { 2 };
		let bits = bits.reverse_bits().to_be_bytes();

		// Finally take only the bytes != 0
		let bits = &bits[..nb];
		writer.write_bitvec_bytes(&bits, msb as usize)
	}
}

/// An X.509v3 extended key usage extension according to
/// [RFC 5280 4.2.1.12](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.12).
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct ExtendedKeyUsage {
	usages: Vec<ExtendedKeyUsagePurpose>,
	// This extension MAY, at the option of the certificate issuer, be
	// either critical or non-critical.
	critical: Criticality,
}

impl ExtendedKeyUsage {
	pub(crate) fn from_params(params: &CertificateParams) -> Option<Self> {
		match params.extended_key_usages.is_empty() {
			true => None,
			false => Some(Self {
				usages: params.extended_key_usages.clone(),
				// TODO(xxx): Consider making EKU criticality configurable through params.
				critical: Criticality::NonCritical,
			}),
		}
	}

	#[cfg(feature = "x509-parser")]
	pub(crate) fn from_parsed(
		params: &mut CertificateParams,
		ext: &x509_parser::extensions::ParsedExtension,
	) -> Result<bool, Error> {
		match ext {
			x509_parser::extensions::ParsedExtension::ExtendedKeyUsage(eku) => {
				use ExtendedKeyUsagePurpose::*;

				let mut usages = Vec::new();
				if eku.any {
					usages.push(Any);
				}
				if eku.server_auth {
					usages.push(ServerAuth);
				}
				if eku.client_auth {
					usages.push(ClientAuth);
				}
				if eku.code_signing {
					usages.push(CodeSigning);
				}
				if eku.email_protection {
					usages.push(EmailProtection);
				}
				if eku.time_stamping {
					usages.push(TimeStamping);
				}
				if eku.ocsp_signing {
					usages.push(OcspSigning);
				}
				params.extended_key_usages = usages;
				Ok(true)
			},
			_ => Ok(false),
		}
	}
}

impl Extension for ExtendedKeyUsage {
	fn oid(&self) -> ObjectIdentifier {
		ObjectIdentifier::from_slice(oid::OID_EXT_KEY_USAGE)
	}

	fn criticality(&self) -> Criticality {
		self.critical
	}

	fn write_value(&self, writer: DERWriter) {
		/*
		  ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
		  KeyPurposeId ::= OBJECT IDENTIFIER
		*/
		writer.write_sequence(|writer| {
			for usage in self.usages.iter() {
				writer
					.next()
					.write_oid(&ObjectIdentifier::from_slice(usage.oid()));
			}
		});
	}
}

/// An X.509v3 name constraints extension according to
/// [RFC 5280 4.2.1.10](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.10).
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct NameConstraints {
	permitted_subtrees: Vec<GeneralSubtree>,
	excluded_subtrees: Vec<GeneralSubtree>,
}

impl NameConstraints {
	pub(crate) fn from_params(params: &CertificateParams) -> Option<Self> {
		match &params.name_constraints {
			Some(nc) if nc.permitted_subtrees.is_empty() && nc.excluded_subtrees.is_empty() => {
				return None; // Avoid writing an empty name constraints extension.
			},
			Some(nc) => Some(Self {
				permitted_subtrees: nc.permitted_subtrees.clone(),
				excluded_subtrees: nc.excluded_subtrees.clone(),
			}),
			_ => None,
		}
	}

	#[cfg(feature = "x509-parser")]
	pub(crate) fn from_parsed(
		params: &mut CertificateParams,
		ext: &x509_parser::extensions::ParsedExtension,
	) -> Result<bool, Error> {
		Ok(match ext {
			x509_parser::extensions::ParsedExtension::NameConstraints(ncs) => {
				let mut permitted_subtrees = Vec::default();
				if let Some(ncs_permitted) = &ncs.permitted_subtrees {
					permitted_subtrees = ncs_permitted
						.iter()
						.map(GeneralSubtree::from_x509_general_subtree)
						.collect::<Result<Vec<_>, _>>()?;
				}
				let mut excluded_subtrees = Vec::default();
				if let Some(ncs_excluded) = &ncs.excluded_subtrees {
					excluded_subtrees = ncs_excluded
						.iter()
						.map(GeneralSubtree::from_x509_general_subtree)
						.collect::<Result<Vec<_>, _>>()?;
				}
				if !permitted_subtrees.is_empty() || !excluded_subtrees.is_empty() {
					params.name_constraints = Some(crate::NameConstraints {
						permitted_subtrees,
						excluded_subtrees,
					});
				}
				true
			},
			_ => false,
		})
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
						writer.next().write_tagged_implicit(
							Tag::context(subtree.tag()),
							|writer| match subtree {
								GeneralSubtree::Rfc822Name(name)
								| GeneralSubtree::DnsName(name) => writer.write_ia5_string(name),
								GeneralSubtree::DirectoryName(name) => {
									write_distinguished_name(writer, name)
								},
								GeneralSubtree::IpAddress(subnet) => {
									writer.write_bytes(&subnet.to_bytes())
								},
							},
						);
						// minimum must be 0 (the default) and maximum must be absent
					});
				}
			});
		});
	}
}

impl Extension for NameConstraints {
	fn oid(&self) -> ObjectIdentifier {
		ObjectIdentifier::from_slice(oid::OID_NAME_CONSTRAINTS)
	}

	fn criticality(&self) -> Criticality {
		// Conforming CAs MUST mark this extension as critical
		Criticality::Critical
	}

	fn write_value(&self, writer: DERWriter) {
		/*
			NameConstraints ::= SEQUENCE {
				  permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
				  excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }
		*/
		writer.write_sequence(|writer| {
			if !self.permitted_subtrees.is_empty() {
				Self::write_general_subtrees(writer.next(), 0, &self.permitted_subtrees);
			}
			if !self.excluded_subtrees.is_empty() {
				Self::write_general_subtrees(writer.next(), 1, &self.excluded_subtrees);
			}
		});
	}
}

/// An X.509v3 CRL distribution points extension according to
/// [RFC 5280 4.2.1.13](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.13).
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct CrlDistributionPoints {
	distribution_points: Vec<crate::CrlDistributionPoint>,
}

impl CrlDistributionPoints {
	pub(crate) fn from_params(params: &CertificateParams) -> Option<Self> {
		match params.crl_distribution_points.is_empty() {
			true => return None, // Avoid writing an empty CRL distribution points extension.
			false => Some(Self {
				distribution_points: params.crl_distribution_points.clone(),
			}),
		}
	}

	#[cfg(feature = "x509-parser")]
	pub(crate) fn from_parsed(
		params: &mut CertificateParams,
		ext: &x509_parser::extensions::ParsedExtension,
	) -> Result<bool, Error> {
		Ok(match ext {
			x509_parser::extensions::ParsedExtension::CRLDistributionPoints(crl_dps) => {
				let dps = crl_dps
					.points
					.iter()
					.map(|dp| {
						// Rcgen does not support CRL DPs with specific reasons, or an indirect issuer.
						if dp.reasons.is_some() || dp.crl_issuer.is_some() {
							return Err(Error::UnsupportedCrlDistributionPoint);
						}
						let general_names = match &dp.distribution_point {
							Some(x509_parser::extensions::DistributionPointName::FullName(
								general_names,
							)) => Ok(general_names),
							// Rcgen does not support CRL DPs missing a distribution point,
							// or that specific a distribution point with a name relative
							// to an issuer.
							_ => Err(Error::UnsupportedCrlDistributionPoint),
						}?;
						let uris = general_names
							.iter()
							.map(|general_name| match general_name {
								x509_parser::extensions::GeneralName::URI(uri) => {
									Ok(uri.to_string())
								},
								// Rcgen does not support CRL DP general names other than URI.
								_ => Err(Error::UnsupportedGeneralName),
							})
							.collect::<Result<Vec<_>, _>>()?;
						Ok(crate::CrlDistributionPoint { uris })
					})
					.collect::<Result<Vec<_>, _>>()?;
				params.crl_distribution_points = dps;
				true
			},
			_ => false,
		})
	}
}

impl Extension for CrlDistributionPoints {
	fn oid(&self) -> ObjectIdentifier {
		ObjectIdentifier::from_slice(oid::OID_CRL_DISTRIBUTION_POINTS)
	}

	fn criticality(&self) -> Criticality {
		// The extension SHOULD be non-critical
		Criticality::NonCritical
	}

	fn write_value(&self, writer: DERWriter) {
		writer.write_sequence(|writer| {
			for distribution_point in &self.distribution_points {
				distribution_point.write_der(writer.next());
			}
		})
	}
}

/// An X.509v3 subject key identifier extension according to
/// [RFC 5280 4.2.1.2](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.2).
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct SubjectKeyIdentifier {
	key_identifier: Vec<u8>,
}

impl SubjectKeyIdentifier {
	pub(crate) fn from_params<K: PublicKeyData>(params: &CertificateParams, pub_key: &K) -> Self {
		Self {
			key_identifier: params.key_identifier(pub_key),
		}
	}

	#[cfg(feature = "x509-parser")]
	pub(crate) fn from_parsed(
		params: &mut CertificateParams,
		ext: &x509_parser::extensions::ParsedExtension,
	) -> Result<bool, Error> {
		Ok(match ext {
			x509_parser::extensions::ParsedExtension::SubjectKeyIdentifier(ski) => {
				params.key_identifier_method = crate::KeyIdMethod::PreSpecified(ski.0.to_vec());
				true
			},
			_ => false,
		})
	}
}

impl Extension for SubjectKeyIdentifier {
	fn oid(&self) -> ObjectIdentifier {
		ObjectIdentifier::from_slice(oid::OID_SUBJECT_KEY_IDENTIFIER)
	}

	fn criticality(&self) -> Criticality {
		// Conforming CAs MUST mark this extension as non-critical.
		Criticality::NonCritical
	}

	fn write_value(&self, writer: DERWriter) {
		// SubjectKeyIdentifier ::= KeyIdentifier
		// KeyIdentifier ::= OCTET STRING
		writer.write_bytes(&self.key_identifier)
	}
}

/// An X.509v3 basic constraints extension according to
/// [RFC 5280 4.2.1.9](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.9).
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct BasicConstraints {
	is_ca: IsCa,
}

impl BasicConstraints {
	pub(crate) fn from_params(params: &CertificateParams) -> Option<Self> {
		// For NoCa we don't emit the extension, it is implied not a CA.
		// Use ExplicitNoCa when you want the false cA ext emitted.
		match params.is_ca {
			IsCa::NoCa => None,
			_ => Some(Self {
				is_ca: params.is_ca.clone(),
			}),
		}
	}

	#[cfg(feature = "x509-parser")]
	pub(crate) fn from_parsed(
		params: &mut CertificateParams,
		ext: &x509_parser::extensions::ParsedExtension,
	) -> Result<bool, Error> {
		Ok(match ext {
			x509_parser::extensions::ParsedExtension::BasicConstraints(bc) => {
				match (bc.ca, bc.path_len_constraint) {
					(true, Some(len)) => {
						params.is_ca = IsCa::Ca(crate::BasicConstraints::Constrained(
							u8::try_from(len)
								.map_err(|_| Error::UnsupportedBasicConstraintsPathLen)?,
						));
					},
					(true, None) => {
						params.is_ca = IsCa::Ca(crate::BasicConstraints::Unconstrained);
					},
					(false, _) => {
						params.is_ca = IsCa::ExplicitNoCa;
					},
				}
				true
			},
			_ => false,
		})
	}
}

impl Extension for BasicConstraints {
	fn oid(&self) -> ObjectIdentifier {
		ObjectIdentifier::from_slice(oid::OID_BASIC_CONSTRAINTS)
	}

	fn criticality(&self) -> Criticality {
		// Conforming CAs MUST include this extension in all CA certificates
		// that contain public keys used to validate digital signatures on
		// certificates and MUST mark the extension as critical in such
		// certificates
		Criticality::Critical
	}

	fn write_value(&self, writer: DERWriter) {
		/*
			BasicConstraints ::= SEQUENCE {
			  cA                      BOOLEAN DEFAULT FALSE,
			  pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
		*/
		writer.write_sequence(|writer| {
			writer.next().write_bool(matches!(self.is_ca, IsCa::Ca(_)));
			if let IsCa::Ca(crate::BasicConstraints::Constrained(path_len_constraint)) = self.is_ca
			{
				writer.next().write_u8(path_len_constraint);
			}
		});
	}
}

/// An X.509v3 CRL number extension according to
/// [RFC 5280 5.2.3](https://www.rfc-editor.org/rfc/rfc5280#section-5.2.3)
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct CrlNumber {
	number: SerialNumber,
}

impl CrlNumber {
	pub(crate) fn from_params(params: &CertificateRevocationListParams) -> Self {
		Self {
			number: params.crl_number.clone(),
		}
	}
}

impl Extension for CrlNumber {
	fn oid(&self) -> ObjectIdentifier {
		ObjectIdentifier::from_slice(oid::OID_CRL_NUMBER)
	}

	fn criticality(&self) -> Criticality {
		// CRL issuers conforming to this profile MUST include this extension in all
		// CRLs and MUST mark this extension as non-critical.
		Criticality::NonCritical
	}

	fn write_value(&self, writer: DERWriter) {
		// CRLNumber ::= INTEGER (0..MAX)
		writer.write_bigint_bytes(self.number.as_ref(), true);
	}
}

/// An X.509v3 issuing distribution point extension according to
/// [RFC 5280 5.2.5](https://www.rfc-editor.org/rfc/rfc5280#section-5.2.5)
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct IssuingDistributionPoint {
	point: CrlIssuingDistributionPoint,
}

impl IssuingDistributionPoint {
	pub(crate) fn from_params(params: &CertificateRevocationListParams) -> Option<Self> {
		match &params.issuing_distribution_point {
			Some(idp) => Some(Self { point: idp.clone() }),
			None => None,
		}
	}
}

impl Extension for IssuingDistributionPoint {
	fn oid(&self) -> ObjectIdentifier {
		ObjectIdentifier::from_slice(oid::OID_CRL_ISSUING_DISTRIBUTION_POINT)
	}

	fn criticality(&self) -> Criticality {
		// Although the extension is critical, conforming implementations are not required to support this
		// extension.
		Criticality::Critical
	}

	fn write_value(&self, writer: DERWriter) {
		self.point.write_der(writer);
	}
}

/// An X.509v3 reason code extension according to
/// [RFC 5280 5.3.1](https://www.rfc-editor.org/rfc/rfc5280#section-5.3.1).
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct ReasonCode {
	reason: crl::RevocationReason,
}

impl ReasonCode {
	pub(crate) fn from_params(params: &RevokedCertParams) -> Option<Self> {
		match &params.reason_code {
			Some(reason) => Some(Self { reason: *reason }),
			None => None,
		}
	}
}

impl Extension for ReasonCode {
	fn oid(&self) -> ObjectIdentifier {
		ObjectIdentifier::from_slice(oid::OID_CRL_REASONS)
	}

	fn criticality(&self) -> Criticality {
		// The reasonCode is a non-critical CRL entry extension
		Criticality::NonCritical
	}

	fn write_value(&self, writer: DERWriter) {
		/*
		   CRLReason ::= ENUMERATED {
			   unspecified             (0),
			   keyCompromise           (1),
			   cACompromise            (2),
			   affiliationChanged      (3),
			   superseded              (4),
			   cessationOfOperation    (5),
			   certificateHold         (6),
					-- value 7 is not used
			   removeFromCRL           (8),
			   privilegeWithdrawn      (9),
			   aACompromise           (10) }
		*/
		writer.write_enum(self.reason as i64);
	}
}

/// An X.509v3 invalidity date extension according to
/// [RFC 5280 5.3.2](https://www.rfc-editor.org/rfc/rfc5280#section-5.3.2).
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct InvalidityDate {
	date: OffsetDateTime,
}

impl InvalidityDate {
	pub(crate) fn from_params(params: &RevokedCertParams) -> Option<Self> {
		match &params.invalidity_date {
			Some(date) => Some(Self { date: date.clone() }),
			None => None,
		}
	}
}

impl Extension for InvalidityDate {
	fn oid(&self) -> ObjectIdentifier {
		ObjectIdentifier::from_slice(oid::OID_CRL_INVALIDITY_DATE)
	}

	fn criticality(&self) -> Criticality {
		// The invalidity date is a non-critical CRL entry extension
		Criticality::NonCritical
	}

	fn write_value(&self, writer: DERWriter) {
		// InvalidityDate ::= GeneralizedTime
		write_dt_utc_or_generalized(writer, self.date);
	}
}

#[cfg(test)]
mod extensions_tests {
	use crate::oid;

	use super::Criticality::*;
	use super::*;

	#[test]
	fn test_no_duplicates() {
		let oid = ObjectIdentifier::from_slice(oid::OID_SUBJECT_ALT_NAME);
		let ext = Box::new(DummyExt {
			oid: oid.clone(),
			critical: NonCritical,
			der: Vec::default(),
		});

		// It should be an error to add two extensions with the same OID.
		let mut exts = Extensions::default();
		exts.add_extension(ext.clone()).unwrap();
		assert_eq!(
			exts.add_extension(ext.clone()),
			Err(Error::DuplicateExtension(oid.to_string())),
		);

		// Or to construct an extensions set from an iterator containing two extensions with the
		// same OID.
		assert_eq!(
			Extensions::new(vec![
				ext.clone() as Box<dyn Extension>,
				ext.clone() as Box<dyn Extension>
			])
			.unwrap_err(),
			Error::DuplicateExtension(oid.to_string()),
		);
	}

	#[test]
	fn test_write_der() {
		use yasna::construct_der;

		// Construct three dummy extensions.
		let ext_a = Box::new(DummyExt {
			oid: ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 3]),
			critical: Critical,
			der: b"a".to_vec(),
		});

		let ext_b = Box::new(DummyExt {
			oid: ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 2]),
			critical: NonCritical,
			der: b"b".to_vec(),
		});

		let ext_c = Box::new(DummyExt {
			oid: ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1]),
			critical: Critical,
			der: b"c".to_vec(),
		});

		// Items of note:
		// - We expect the extensions to be written in the order they were added.
		// - The ext_b criticality is elided because it is non-critical - it would be a mis-encoding
		//   to write a value for a FALSE BOOLEAN in DER.
		// - Each extension DER value should have been written unmodified, with no extra tags
		//   or length bytes.
		let expected_der = vec![
			0x30, 0x2D, // exts SEQUENCE
			0x30, 0xD, // ext_a SEQUENCE
			0x6, 0x5, 0x2B, 0x6, 0x1, 0x4, 0x3, 0x1, 0x1,  // ext_a OID
			0xFF, // ext_A CRITICAL = true
			0x4, 0x1, 0x61, // ext_A OCTET SEQUENCE "A" (0x61)
			0x30, 0xD, // ext_b SEQUENCE
			0x6, 0x5, 0x2B, 0x6, 0x1, 0x4, 0x2, 0x1, 0x1, 0x0, // ext_b OID
			// ext_b criticality elided
			0x4, 0x1, 0x62, // ext_b OCTET SEQUENCE "B" (0x62)
			0x30, 0xD, // ext_b SEQUENCE
			0x6, 0x5, 0x2B, 0x6, 0x1, 0x4, 0x1, 0x1, 0x1,  // ext_c OID
			0xFF, // ext_b CRITICAL = true
			0x4, 0x1, 0x63, // ext_c OCTET SEQUENCE "C" (0x63)
		];

		// Building the extensions and encoding to DER should result in the expected DER.
		let test_exts: Vec<Box<dyn Extension>> = vec![ext_a.clone(), ext_b.clone(), ext_c.clone()];
		let exts = Extensions::new(test_exts).unwrap();
		assert_eq!(construct_der(|writer| exts.write_der(writer)), expected_der);
	}

	/// Mock extension for testing.
	#[derive(Debug, Clone)]
	struct DummyExt {
		oid: ObjectIdentifier,
		critical: Criticality,
		der: Vec<u8>,
	}

	impl Extension for DummyExt {
		fn oid(&self) -> ObjectIdentifier {
			self.oid.clone()
		}

		fn criticality(&self) -> Criticality {
			self.critical
		}

		fn write_value(&self, writer: DERWriter) {
			writer.write_der(&self.der);
		}
	}
}

#[cfg(test)]
mod san_ext_tests {
	#[cfg(feature = "x509-parser")]
	use x509_parser::prelude::FromDer;

	use super::*;
	use crate::CertificateParams;

	#[test]
	fn test_from_params() {
		let domain_a = "test.example.com".to_string();
		let domain_b = "example.com".to_string();
		let ip = IpAddr::try_from([127, 0, 0, 1]).unwrap();
		let mut params = CertificateParams::new(vec![domain_a.clone(), domain_b.clone()]);
		params
			.subject_alt_names
			.push(SanType::IpAddress(ip.clone()));

		let ext = SubjectAlternativeName::from_params(&params).unwrap();
		let expected_names = vec![
			SanType::DnsName(domain_a),
			SanType::DnsName(domain_b),
			SanType::IpAddress(ip),
		];
		assert_eq!(ext.names, expected_names);
	}

	#[test]
	fn test_from_empty_san() {
		assert!(SubjectAlternativeName::from_params(&CertificateParams::default()).is_none());
	}

	#[test]
	#[cfg(feature = "x509-parser")]
	fn test_from_parsed() {
		let domain_a = "test.example.com".to_string();
		let domain_b = "example.com".to_string();
		let ip = IpAddr::try_from([127, 0, 0, 1]).unwrap();
		let mut params = CertificateParams::new(vec![domain_a.clone(), domain_b.clone()]);
		params
			.subject_alt_names
			.push(SanType::IpAddress(ip.clone()));

		let der = yasna::construct_der(|writer| {
			SubjectAlternativeName::from_params(&params)
				.unwrap()
				.write_value(writer)
		});

		let parsed_ext = x509_parser::extensions::ParsedExtension::SubjectAlternativeName(
			x509_parser::extensions::SubjectAlternativeName::from_der(&der)
				.unwrap()
				.1,
		);

		let mut recovered_params = CertificateParams::default();
		SubjectAlternativeName::from_parsed(&mut recovered_params, &parsed_ext).unwrap();
		assert_eq!(recovered_params.subject_alt_names, params.subject_alt_names);
	}
}

#[cfg(test)]
mod ku_ext_tests {
	#[cfg(feature = "x509-parser")]
	use x509_parser::prelude::FromDer;

	use super::*;
	use crate::CertificateParams;

	#[test]
	fn test_from_params() {
		let mut params = CertificateParams::default();
		params.key_usages = vec![
			KeyUsagePurpose::DigitalSignature,
			KeyUsagePurpose::ContentCommitment,
			KeyUsagePurpose::KeyEncipherment,
			KeyUsagePurpose::DataEncipherment,
			KeyUsagePurpose::KeyAgreement,
			KeyUsagePurpose::KeyCertSign,
			KeyUsagePurpose::CrlSign,
			KeyUsagePurpose::EncipherOnly,
			KeyUsagePurpose::DecipherOnly,
		];

		let ext = KeyUsage::from_params(&params).unwrap();
		assert_eq!(ext.usages, params.key_usages);
	}

	#[test]
	#[cfg(feature = "x509-parser")]
	fn test_from_parsed() {
		let mut params = CertificateParams::default();
		params.key_usages = vec![
			KeyUsagePurpose::ContentCommitment,
			KeyUsagePurpose::KeyEncipherment,
		];

		let der = yasna::construct_der(|writer| {
			KeyUsage::from_params(&params).unwrap().write_value(writer)
		});

		let parsed_ext = x509_parser::extensions::ParsedExtension::KeyUsage(
			x509_parser::extensions::KeyUsage::from_der(&der).unwrap().1,
		);

		let mut recovered_params = CertificateParams::default();
		KeyUsage::from_parsed(&mut recovered_params, &parsed_ext).unwrap();
		assert_eq!(recovered_params.key_usages, params.key_usages);
	}
}

#[cfg(test)]
mod eku_ext_tests {
	#[cfg(feature = "x509-parser")]
	use x509_parser::prelude::FromDer;

	use super::*;
	use crate::CertificateParams;

	#[test]
	fn test_from_params() {
		let mut params = CertificateParams::default();
		params.extended_key_usages = vec![
			ExtendedKeyUsagePurpose::Any,
			ExtendedKeyUsagePurpose::ServerAuth,
			ExtendedKeyUsagePurpose::ClientAuth,
			ExtendedKeyUsagePurpose::CodeSigning,
			ExtendedKeyUsagePurpose::EmailProtection,
			ExtendedKeyUsagePurpose::TimeStamping,
			ExtendedKeyUsagePurpose::OcspSigning,
		];

		let ext = ExtendedKeyUsage::from_params(&params).unwrap();
		assert_eq!(ext.usages, params.extended_key_usages);
	}

	#[test]
	#[cfg(feature = "x509-parser")]
	fn test_from_parsed() {
		let mut params = CertificateParams::default();
		params.extended_key_usages = vec![
			ExtendedKeyUsagePurpose::CodeSigning,
			ExtendedKeyUsagePurpose::EmailProtection,
		];

		let der = yasna::construct_der(|writer| {
			ExtendedKeyUsage::from_params(&params)
				.unwrap()
				.write_value(writer)
		});

		let parsed_ext = x509_parser::extensions::ParsedExtension::ExtendedKeyUsage(
			x509_parser::extensions::ExtendedKeyUsage::from_der(&der)
				.unwrap()
				.1,
		);

		let mut recovered_params = CertificateParams::default();
		ExtendedKeyUsage::from_parsed(&mut recovered_params, &parsed_ext).unwrap();
		assert_eq!(
			recovered_params.extended_key_usages,
			params.extended_key_usages
		);
	}
}

#[cfg(test)]
mod name_constraints_tests {
	#[cfg(feature = "x509-parser")]
	use x509_parser::prelude::FromDer;

	use super::*;
	use crate::CertificateParams;

	#[test]
	fn test_from_params() {
		let constraints = crate::NameConstraints {
			permitted_subtrees: vec![GeneralSubtree::DnsName("com".into())],
			excluded_subtrees: vec![GeneralSubtree::DnsName("org".into())],
		};
		let mut params = CertificateParams::default();
		params.name_constraints = Some(constraints.clone());

		let ext = NameConstraints::from_params(&params).unwrap();
		assert_eq!(ext.permitted_subtrees, constraints.permitted_subtrees);
		assert_eq!(ext.excluded_subtrees, constraints.excluded_subtrees);
	}

	#[test]
	#[cfg(feature = "x509-parser")]
	fn test_from_parsed() {
		let mut params = CertificateParams::default();
		let constraints = crate::NameConstraints {
			permitted_subtrees: vec![GeneralSubtree::DnsName("com".into())],
			excluded_subtrees: Vec::default(),
		};
		params.name_constraints = Some(constraints.clone());

		let der = yasna::construct_der(|writer| {
			NameConstraints::from_params(&params)
				.unwrap()
				.write_value(writer)
		});

		let parsed_ext = x509_parser::extensions::ParsedExtension::NameConstraints(
			x509_parser::extensions::NameConstraints::from_der(&der)
				.unwrap()
				.1,
		);

		let mut recovered_params = CertificateParams::default();
		NameConstraints::from_parsed(&mut recovered_params, &parsed_ext).unwrap();
		assert!(recovered_params.name_constraints.is_some());
		assert_eq!(
			recovered_params
				.name_constraints
				.as_ref()
				.unwrap()
				.permitted_subtrees,
			constraints.permitted_subtrees,
		);
		assert_eq!(
			recovered_params.name_constraints.unwrap().excluded_subtrees,
			constraints.excluded_subtrees,
		);
	}
}

#[cfg(test)]
mod crl_dps_test {
	#[cfg(feature = "x509-parser")]
	use x509_parser::prelude::FromDer;

	use super::*;
	use crate::CertificateParams;

	#[test]
	fn test_from_params() {
		let crl_dps = vec![
			crate::CrlDistributionPoint {
				uris: vec!["http://example.com".into()],
			},
			crate::CrlDistributionPoint {
				uris: vec!["http://example.org".into(), "ldap://example.com".into()],
			},
		];
		let mut params = CertificateParams::default();
		params.crl_distribution_points = crl_dps.clone();

		let ext = CrlDistributionPoints::from_params(&params).unwrap();
		assert_eq!(ext.distribution_points, crl_dps);
	}

	#[test]
	#[cfg(feature = "x509-parser")]
	fn test_from_parsed() {
		let mut params = CertificateParams::default();
		let crl_dps = vec![crate::CrlDistributionPoint {
			uris: vec!["http://example.com".into()],
		}];
		params.crl_distribution_points = crl_dps.clone();

		let der = yasna::construct_der(|writer| {
			CrlDistributionPoints::from_params(&params)
				.unwrap()
				.write_value(writer)
		});

		let parsed_ext = x509_parser::extensions::ParsedExtension::CRLDistributionPoints(
			x509_parser::extensions::CRLDistributionPoints::from_der(&der)
				.unwrap()
				.1,
		);

		let mut recovered_params = CertificateParams::default();
		CrlDistributionPoints::from_parsed(&mut recovered_params, &parsed_ext).unwrap();
		assert_eq!(recovered_params.crl_distribution_points, crl_dps,);
	}
}

#[cfg(test)]
mod ski_ext_tests {
	#[cfg(feature = "x509-parser")]
	use x509_parser::prelude::FromDer;

	use super::*;
	use crate::{CertificateParams, KeyIdMethod, KeyPair};

	#[test]
	fn test_from_params() {
		let ski = vec![1, 2, 3, 4];
		let mut params = CertificateParams::default();
		params.key_identifier_method = KeyIdMethod::PreSpecified(ski.clone());

		let keypair = KeyPair::generate(&crate::PKCS_ECDSA_P256_SHA256).unwrap();
		let ext = SubjectKeyIdentifier::from_params(&params, &keypair);
		assert_eq!(ext.key_identifier, ski);

		let keypair = KeyPair::generate(&crate::PKCS_ECDSA_P256_SHA256).unwrap();
		let mut params = CertificateParams::default();
		params.key_pair = Some(keypair);

		let keypair = params.key_pair.as_ref().unwrap();
		let ext = SubjectKeyIdentifier::from_params(&params, keypair);
		assert_ne!(ext.key_identifier, ski);
		assert_eq!(ext.key_identifier.len(), 20); // SHA-256 digest truncated to SHA-1 length
	}

	#[test]
	#[cfg(feature = "x509-parser")]
	fn test_from_parsed() {
		let ski = vec![1, 2, 3, 4];
		let keypair = KeyPair::generate(&crate::PKCS_ECDSA_P256_SHA256).unwrap();

		let mut params = CertificateParams::default();
		params.key_pair = Some(keypair);
		params.key_identifier_method = KeyIdMethod::PreSpecified(ski.clone());

		let keypair = params.key_pair.as_ref().unwrap();
		let der = yasna::construct_der(|writer| {
			SubjectKeyIdentifier::from_params(&params, keypair).write_value(writer)
		});

		let parsed_ext = x509_parser::extensions::ParsedExtension::SubjectKeyIdentifier(
			x509_parser::extensions::KeyIdentifier::from_der(&der)
				.unwrap()
				.1,
		);

		let mut recovered_params = CertificateParams::default();
		SubjectKeyIdentifier::from_parsed(&mut recovered_params, &parsed_ext).unwrap();
		assert_eq!(
			recovered_params.key_identifier_method,
			KeyIdMethod::PreSpecified(ski)
		);
	}
}

#[cfg(test)]
mod bc_ext_tests {
	#[cfg(feature = "x509-parser")]
	use x509_parser::prelude::FromDer;

	use super::*;
	use crate::CertificateParams;

	#[test]
	fn test_from_params() {
		// NoCA
		let params = CertificateParams::default();
		let ext = BasicConstraints::from_params(&params);
		assert!(ext.is_none()); // No ext for NoCA.

		// Explicit NoCA
		let mut params = CertificateParams::default();
		params.is_ca = IsCa::ExplicitNoCa;
		let ext = BasicConstraints::from_params(&params);
		assert_eq!(ext.unwrap().is_ca, IsCa::ExplicitNoCa);

		// CA unconstrained
		let mut params = CertificateParams::default();
		params.is_ca = IsCa::Ca(crate::BasicConstraints::Unconstrained);
		let ext = BasicConstraints::from_params(&params);
		assert_eq!(
			ext.unwrap().is_ca,
			IsCa::Ca(crate::BasicConstraints::Unconstrained)
		);

		// CA constrained
		let mut params = CertificateParams::default();
		params.is_ca = IsCa::Ca(crate::BasicConstraints::Constrained(1));
		let ext = BasicConstraints::from_params(&params);
		assert_eq!(
			ext.unwrap().is_ca,
			IsCa::Ca(crate::BasicConstraints::Constrained(1))
		);
	}

	#[test]
	#[cfg(feature = "x509-parser")]
	fn test_from_parsed_explicit_no_ca() {
		let mut params = CertificateParams::default();
		params.is_ca = IsCa::ExplicitNoCa;

		let der = yasna::construct_der(|writer| {
			BasicConstraints::from_params(&params)
				.unwrap()
				.write_value(writer)
		});

		let parsed_ext = x509_parser::extensions::ParsedExtension::BasicConstraints(
			x509_parser::extensions::BasicConstraints::from_der(&der)
				.unwrap()
				.1,
		);

		let mut recovered_params = CertificateParams::default();
		BasicConstraints::from_parsed(&mut recovered_params, &parsed_ext).unwrap();
		assert_eq!(recovered_params.is_ca, IsCa::ExplicitNoCa);
	}

	#[test]
	#[cfg(feature = "x509-parser")]
	fn test_from_parsed_unconstrained() {
		let mut params = CertificateParams::default();
		params.is_ca = IsCa::Ca(crate::BasicConstraints::Unconstrained);

		let der = yasna::construct_der(|writer| {
			BasicConstraints::from_params(&params)
				.unwrap()
				.write_value(writer)
		});

		let parsed_ext = x509_parser::extensions::ParsedExtension::BasicConstraints(
			x509_parser::extensions::BasicConstraints::from_der(&der)
				.unwrap()
				.1,
		);

		let mut recovered_params = CertificateParams::default();
		BasicConstraints::from_parsed(&mut recovered_params, &parsed_ext).unwrap();
		assert_eq!(
			recovered_params.is_ca,
			IsCa::Ca(crate::BasicConstraints::Unconstrained)
		);
	}

	#[test]
	#[cfg(feature = "x509-parser")]
	fn test_from_parsed_constrained() {
		let mut params = CertificateParams::default();
		let path_len = 5;
		params.is_ca = IsCa::Ca(crate::BasicConstraints::Constrained(path_len));

		let der = yasna::construct_der(|writer| {
			BasicConstraints::from_params(&params)
				.unwrap()
				.write_value(writer)
		});

		let parsed_ext = x509_parser::extensions::ParsedExtension::BasicConstraints(
			x509_parser::extensions::BasicConstraints::from_der(&der)
				.unwrap()
				.1,
		);

		let mut recovered_params = CertificateParams::default();
		BasicConstraints::from_parsed(&mut recovered_params, &parsed_ext).unwrap();
		assert_eq!(
			recovered_params.is_ca,
			IsCa::Ca(crate::BasicConstraints::Constrained(path_len))
		);
	}
}
