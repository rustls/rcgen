use std::fmt::Debug;
use std::net::IpAddr;

use time::OffsetDateTime;
use yasna::models::ObjectIdentifier;
use yasna::{DERWriter, DERWriterSet, Tag};

use crate::crl::{CrlDistributionPoint, RevocationReason, RevokedCertParams};
use crate::{
	dt_to_generalized, oid, write_distinguished_name, CertificateParams, CustomExtension, Error,
	ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, Issuer, KeyIdMethod, KeyUsagePurpose,
	PathLenConstraint, SanType, SerialNumber, SigningKey,
};

/// A collection of X.509 extensions.
///
/// Preserves the order that extensions were added and maintains the invariant that
/// there are no duplicate extension OIDs. The extensions borrow from the params
/// they were built from for the duration of one serialization.
#[derive(Debug, Default)]
pub(crate) struct Extensions<'params> {
	exts: Vec<Box<dyn Extension + 'params>>,
}

impl<'params> Extensions<'params> {
	/// Add an extension to the collection.
	///
	/// Returns [`Error::DuplicateExtension`] if the extension's OID is already present
	/// in the collection.
	pub(crate) fn add_extension(
		&mut self,
		extension: Box<dyn Extension + 'params>,
	) -> Result<(), Error> {
		let oid = extension.oid();
		// A linear scan is plenty: no profile puts more than a handful of
		// extensions in one certificate.
		if self.exts.iter().any(|existing| existing.oid() == oid) {
			return Err(Error::DuplicateExtension(
				ObjectIdentifier::from_slice(oid).to_string(),
			));
		}

		self.exts.push(extension);
		Ok(())
	}

	/// Write the certificate's optional extensions field.
	///
	/// Nothing is written when the collection is empty: presence is decided by the
	/// built collection, not predicted from the params, so an empty extensions
	/// field is never emitted and requested extensions can never be silently
	/// dropped.
	pub(crate) fn write_exts_der(&self, writer: DERWriter) {
		if self.exts.is_empty() {
			return;
		}

		writer.write_tagged(Tag::context(3), |writer| self.write_der(writer));
	}

	/// Write the PKCS #9 extensionRequest attribute for a CSR into the
	/// attributes SET, containing the collection as its single `Extensions`
	/// value.
	///
	/// Nothing is written when the collection is empty: attribute values are a
	/// SET SIZE(1..MAX), so an empty extension request can't be encoded and the
	/// attribute is elided entirely. The attribute's slot in the SET is only
	/// claimed when there is something to write: yasna rejects set elements
	/// that produce no output.
	pub(crate) fn write_csr_attribute(&self, writer: &mut DERWriterSet<'_>) {
		if self.exts.is_empty() {
			return;
		}

		/*
		   Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
				type   ATTRIBUTE.&id({IOSet}),
				values SET SIZE(1..MAX) OF ATTRIBUTE.&Type({IOSet}{@type})
		   }
		   ExtensionRequest ::= Extensions
		*/
		writer.next().write_sequence(|writer| {
			writer.next().write_oid(&ObjectIdentifier::from_slice(
				oid::PKCS_9_AT_EXTENSION_REQUEST,
			));
			writer.next().write_set(|writer| {
				self.write_der(writer.next());
			});
		});
	}

	/// Write the `crlExtensions [0] EXPLICIT Extensions OPTIONAL` field of a CRL.
	///
	/// Nothing is written when the collection is empty.
	pub(crate) fn write_crl_der(&self, writer: DERWriter) {
		if self.exts.is_empty() {
			return;
		}

		writer.write_tagged(Tag::context(0), |writer| self.write_der(writer));
	}

	/// Write `Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension`, e.g. for the
	/// untagged `crlEntryExtensions` field of a CRL entry.
	///
	/// Nothing is written when the collection is empty.
	pub(crate) fn write_der(&self, writer: DERWriter) {
		if self.exts.is_empty() {
			return;
		}

		writer.write_sequence(|writer| {
			for extension in &self.exts {
				write_extension(writer.next(), extension.as_ref());
			}
		})
	}
}

/// An X.509 extension whose OID and criticality are fixed by the profile
/// defining it.
///
/// Implementors receive [`Extension`] through a blanket impl. Extensions that
/// decide criticality (or OID) at runtime implement [`Extension`] directly
/// instead.
pub(crate) trait StaticExtension: Debug {
	/// The OID components of the extension.
	const OID: &'static [u64];

	/// The criticality of the extension.
	const CRITICALITY: Criticality;

	/// Write the extension's value (the content of the extnValue OCTET STRING).
	fn write_value(&self, writer: DERWriter);
}

impl<T: StaticExtension> Extension for T {
	fn oid(&self) -> &[u64] {
		T::OID
	}

	fn criticality(&self) -> Criticality {
		T::CRITICALITY
	}

	fn write_value(&self, writer: DERWriter) {
		// Calling with fully qualified syntax to disambiguate.
		StaticExtension::write_value(self, writer)
	}
}

/// An X.509 extension.
///
/// All extensions have an OID, a criticality, and a DER encoded value for inclusion in
/// an X.509 extension SEQUENCE.
pub(crate) trait Extension: Debug {
	/// Return the OID components of the extension.
	fn oid(&self) -> &[u64];

	/// Return the criticality of the extension.
	fn criticality(&self) -> Criticality;

	/// Write the extension's value (the content of the extnValue OCTET STRING).
	fn write_value(&self, writer: DERWriter);
}

/// The criticality of an X.509 extension.
///
/// This controls how consumers should handle an unrecognized extension.
///
/// See [RFC 5280 §4.2] for more information.
///
/// [RFC 5280 §4.2]: <https://www.rfc-editor.org/rfc/rfc5280#section-4.2>
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
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

/// Serializes an X.509v3 extension according to RFC 5280.
fn write_extension(writer: DERWriter, extension: &dyn Extension) {
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
			.write_oid(&ObjectIdentifier::from_slice(extension.oid()));
		// DER requires that DEFAULT values be omitted (X.690 §11.5): the critical
		// flag may only be encoded when it is TRUE.
		if extension.criticality() == Criticality::Critical {
			writer.next().write_bool(true);
		}
		writer.next().write_bytes(&yasna::construct_der(|writer| {
			extension.write_value(writer)
		}));
	})
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
	const OID: &'static [u64] = oid::AUTHORITY_KEY_IDENTIFIER;

	// RFC 5280 §4.2.1.1: "Conforming CAs MUST mark this extension as non-critical."
	const CRITICALITY: Criticality = Criticality::NonCritical;

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
}

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
	fn oid(&self) -> &[u64] {
		oid::SUBJECT_ALT_NAME
	}

	fn criticality(&self) -> Criticality {
		self.criticality
	}

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
	const OID: &'static [u64] = oid::KEY_USAGE;

	// RFC 5280 §4.2.1.3: "When present, conforming CAs SHOULD mark this extension
	// as critical."
	const CRITICALITY: Criticality = Criticality::Critical;

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
	const OID: &'static [u64] = oid::EXT_KEY_USAGE;

	// RFC 5280 §4.2.1.12: "This extension MAY, at the option of the certificate
	// issuer, be either critical or non-critical."
	// TODO(XXX): make this configurable?
	const CRITICALITY: Criticality = Criticality::NonCritical;

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
}

/// An X.509v3 name constraints extension according to [RFC 5280 §4.2.1.10].
///
/// [RFC 5280 §4.2.1.10]: <https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.10>
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NameConstraints<'params> {
	permitted_subtrees: &'params [GeneralSubtree],
	excluded_subtrees: &'params [GeneralSubtree],
}

impl<'params> NameConstraints<'params> {
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

impl StaticExtension for NameConstraints<'_> {
	const OID: &'static [u64] = oid::NAME_CONSTRAINTS;

	// RFC 5280 §4.2.1.10: "Conforming CAs MUST mark this extension as critical."
	const CRITICALITY: Criticality = Criticality::Critical;

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
	const OID: &'static [u64] = oid::CRL_DISTRIBUTION_POINTS;

	// RFC 5280 §4.2.1.13: "The extension SHOULD be non-critical".
	const CRITICALITY: Criticality = Criticality::NonCritical;

	fn write_value(&self, writer: DERWriter) {
		// CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
		writer.write_sequence(|writer| {
			for distribution_point in self.0 {
				distribution_point.write_der(writer.next());
			}
		})
	}
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
	const OID: &'static [u64] = oid::SUBJECT_KEY_IDENTIFIER;

	// RFC 5280 §4.2.1.2: "Conforming CAs MUST mark this extension as non-critical."
	const CRITICALITY: Criticality = Criticality::NonCritical;

	fn write_value(&self, writer: DERWriter) {
		/*
		   SubjectKeyIdentifier ::= KeyIdentifier
		   KeyIdentifier ::= OCTET STRING
		*/
		writer.write_bytes(&self.0)
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
	const OID: &'static [u64] = oid::BASIC_CONSTRAINTS;

	// RFC 5280 §4.2.1.9: "Conforming CAs MUST include this extension in all CA
	// certificates that contain public keys used to validate digital signatures
	// on certificates and MUST mark the extension as critical in such
	// certificates."
	const CRITICALITY: Criticality = Criticality::Critical;

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
}

impl Extension for &CustomExtension {
	fn oid(&self) -> &[u64] {
		&self.oid
	}

	fn criticality(&self) -> Criticality {
		self.criticality
	}

	fn write_value(&self, writer: DERWriter) {
		writer.write_der(&self.content)
	}
}

/// An X.509v3 CRL number extension according to [RFC 5280 §5.2.3].
///
/// [RFC 5280 §5.2.3]: <https://www.rfc-editor.org/rfc/rfc5280#section-5.2.3>
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CrlNumber<'params>(&'params SerialNumber);

impl<'params> From<&'params SerialNumber> for CrlNumber<'params> {
	fn from(number: &'params SerialNumber) -> Self {
		Self(number)
	}
}

impl StaticExtension for CrlNumber<'_> {
	const OID: &'static [u64] = oid::CRL_NUMBER;

	// RFC 5280 §5.2.3: "CRL issuers conforming to this profile MUST include this
	// extension in all CRLs and MUST mark this extension as non-critical."
	const CRITICALITY: Criticality = Criticality::NonCritical;

	fn write_value(&self, writer: DERWriter) {
		// CRLNumber ::= INTEGER (0..MAX)
		writer.write_bigint_bytes(self.0.as_ref(), true);
	}
}

/// An X.509v3 CRL reason code entry extension according to [RFC 5280 §5.3.1].
///
/// [RFC 5280 §5.3.1]: <https://www.rfc-editor.org/rfc/rfc5280#section-5.3.1>
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReasonCode(RevocationReason);

impl ReasonCode {
	pub(crate) fn from_params(params: &RevokedCertParams) -> Option<Self> {
		// RFC 5280 §5.3.1: "The reason code CRL entry extension SHOULD be absent
		// instead of using the unspecified (0) reasonCode value."
		params
			.reason_code
			.filter(|reason| *reason != RevocationReason::Unspecified)
			.map(Self)
	}
}

impl StaticExtension for ReasonCode {
	const OID: &'static [u64] = oid::CRL_REASONS;

	// RFC 5280 §5.3.1: "The reasonCode is a non-critical CRL entry extension".
	const CRITICALITY: Criticality = Criticality::NonCritical;

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
		writer.write_enum(self.0 as i64);
	}
}

/// An X.509v3 CRL invalidity date entry extension according to [RFC 5280 §5.3.2].
///
/// [RFC 5280 §5.3.2]: <https://www.rfc-editor.org/rfc/rfc5280#section-5.3.2>
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InvalidityDate(OffsetDateTime);

impl InvalidityDate {
	pub(crate) fn from_params(params: &RevokedCertParams) -> Option<Self> {
		params.invalidity_date.map(Self)
	}
}

impl StaticExtension for InvalidityDate {
	const OID: &'static [u64] = oid::CRL_INVALIDITY_DATE;

	// RFC 5280 §5.3.2: "The invalidity date is a non-critical CRL entry extension".
	const CRITICALITY: Criticality = Criticality::NonCritical;

	fn write_value(&self, writer: DERWriter) {
		// RFC 5280 §5.3.2: InvalidityDate ::= GeneralizedTime. Unlike the Time
		// CHOICE used elsewhere, dates in the UTCTime range (1950-2049) must still
		// be encoded as GeneralizedTime.
		writer.write_generalized_time(&dt_to_generalized(self.0));
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn extensions_reject_duplicate_oids() {
		let mut exts = Extensions::default();
		exts.add_extension(Box::new(DummyExt {
			oid: TEST_OID,
			criticality: Criticality::NonCritical,
		}))
		.unwrap();
		assert_eq!(
			exts.add_extension(Box::new(DummyExt {
				oid: TEST_OID,
				criticality: Criticality::Critical,
			})),
			Err(Error::DuplicateExtension(
				ObjectIdentifier::from_slice(TEST_OID).to_string()
			)),
		);
	}

	#[test]
	fn extensions_preserve_insertion_order() {
		let mut exts = Extensions::default();
		// Add an extension with a lexicographically larger OID first: the encoded
		// SEQUENCE must preserve insertion order, not sort.
		exts.add_extension(Box::new(DummyExt {
			oid: &[1, 3, 6, 1, 4, 1, 98],
			criticality: Criticality::NonCritical,
		}))
		.unwrap();
		exts.add_extension(Box::new(DummyExt {
			oid: &[1, 3, 6, 1, 4, 1, 97],
			criticality: Criticality::NonCritical,
		}))
		.unwrap();

		let der = yasna::construct_der(|writer| exts.write_exts_der(writer));
		assert_eq!(
			der,
			yasna::construct_der(|writer| {
				writer.write_tagged(Tag::context(3), |writer| {
					writer.write_sequence(|writer| {
						// Insertion order, not OID order: 98 first, then 97.
						for oid in [&[1, 3, 6, 1, 4, 1, 98], &[1, 3, 6, 1, 4, 1, 97]] {
							writer.next().write_sequence(|writer| {
								writer.next().write_oid(&ObjectIdentifier::from_slice(oid));
								writer.next().write_bytes(&yasna::construct_der(|writer| {
									writer.write_null()
								}));
							});
						}
					})
				})
			})
		);
	}

	#[test]
	fn extensions_elided_when_empty() {
		// An empty collection writes nothing at all: no extensions field, no
		// empty SEQUENCE.
		let exts = Extensions::default();
		let der = yasna::construct_der(|writer| {
			writer.write_sequence(|writer| exts.write_exts_der(writer.next()))
		});
		assert_eq!(
			der,
			yasna::construct_der(|writer| writer.write_sequence(|_writer| {}))
		);
	}

	#[test]
	fn csr_attribute_elided_when_empty() {
		// An empty collection must not claim a slot in the attributes SET at
		// all: yasna rejects set elements that produce no output.
		let exts = Extensions::default();
		let der = yasna::construct_der(|writer| {
			writer.write_set_of(|writer| exts.write_csr_attribute(writer))
		});
		assert_eq!(
			der,
			yasna::construct_der(|writer| writer.write_set_of(|_writer| {}))
		);
	}

	#[test]
	fn critical_flag_omitted_when_false() {
		// The critical flag is DEFAULT FALSE, so DER (X.690 §11.5) requires that a
		// non-critical extension omit it entirely rather than encode FALSE.
		// See https://github.com/rustls/rcgen/pull/444 for a past instance of this
		// bug class.
		let ext = DummyExt {
			oid: TEST_OID,
			criticality: Criticality::NonCritical,
		};
		let der = yasna::construct_der(|writer| write_extension(writer, &ext));
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
		let ext = DummyExt {
			oid: TEST_OID,
			criticality: Criticality::Critical,
		};
		let der = yasna::construct_der(|writer| write_extension(writer, &ext));
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
		let der = yasna::construct_der(|writer| write_extension(writer, &ext));
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
		assert!(NameConstraints::from_params(&params).is_none());
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

	#[derive(Debug)]
	struct DummyExt {
		oid: &'static [u64],
		criticality: Criticality,
	}

	impl Extension for DummyExt {
		fn oid(&self) -> &[u64] {
			self.oid
		}

		fn criticality(&self) -> Criticality {
			self.criticality
		}

		fn write_value(&self, writer: DERWriter) {
			writer.write_null()
		}
	}

	const TEST_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 99];
}
