use std::collections::HashSet;
use std::fmt::Debug;

use yasna::models::ObjectIdentifier;
use yasna::{DERWriter, DERWriterSeq};

use crate::{CertificateParams, Error};

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
