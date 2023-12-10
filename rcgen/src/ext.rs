use std::collections::HashSet;
use std::fmt::Debug;
use std::net::IpAddr;

use yasna::models::ObjectIdentifier;
use yasna::{DERWriter, DERWriterSeq, Tag};

use crate::{
	oid, Certificate, CertificateParams, Error, ExtendedKeyUsagePurpose, KeyUsagePurpose, SanType,
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
pub(crate) enum Criticality {
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

	/// Write the SEQUENCE of extensions to the DER writer.
	///
	/// This will return without writing anything if there are no extensions in the collection.
	pub(crate) fn write_der(&self, writer: DERWriter) {
		debug_assert_eq!(self.exts.len(), self.oids.len());

		// Avoid writing an empty extensions sequence.
		if self.exts.is_empty() {
			return;
		}

		// Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension
		writer.write_sequence(|writer| {
			for extension in &self.exts {
				Self::write_extension(writer, extension);
			}
		})
	}

	/// TODO(@cpu): Remove once `Extensions::write_der` is being used.
	pub(crate) fn iter(&self) -> impl Iterator<Item = &Box<dyn Extension>> {
		self.exts.iter()
	}

	/// TODO(@cpu): Reduce visibility once `Extensions::write_der` is being used.
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
