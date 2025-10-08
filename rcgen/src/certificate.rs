use std::net::IpAddr;
use std::str::FromStr;

#[cfg(feature = "pem")]
use pem::Pem;
use pki_types::pem::PemObject;
use pki_types::{CertificateDer, CertificateSigningRequestDer};
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};
use yasna::models::ObjectIdentifier;
use yasna::{DERWriter, DERWriterSeq, Tag};

use crate::crl::CrlDistributionPoint;
use crate::csr::CertificateSigningRequest;
use crate::key_pair::{serialize_public_key_der, sign_der, PublicKeyData};
#[cfg(feature = "crypto")]
use crate::ring_like::digest;
#[cfg(feature = "pem")]
use crate::ENCODE_CONFIG;
use crate::{
	oid, write_distinguished_name, write_dt_utc_or_generalized,
	write_x509_authority_key_identifier, write_x509_extension, DistinguishedName, Error, Issuer,
	KeyIdMethod, KeyUsagePurpose, SanType, SerialNumber, SigningKey,
};

/// An issued certificate
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
	pub(crate) der: CertificateDer<'static>,
}

impl Certificate {
	/// Get the certificate in DER encoded format.
	///
	/// [`CertificateDer`] implements `Deref<Target = [u8]>` and `AsRef<[u8]>`, so you can easily
	/// extract the DER bytes from the return value.
	pub fn der(&self) -> &CertificateDer<'static> {
		&self.der
	}

	/// Get the certificate in PEM encoded format.
	#[cfg(feature = "pem")]
	pub fn pem(&self) -> String {
		pem::encode_config(&Pem::new("CERTIFICATE", self.der().to_vec()), ENCODE_CONFIG)
	}
	/// Deserialize a cert from PEM format
	#[cfg(feature = "pem")]
	pub fn from_pem(pem_bytes:&[u8]) -> Result<Self,Error>{
		let cert_der = match CertificateDer::from_pem_slice(&pem_bytes){
			Ok(val) => val,
			Err(_) => return Err(Error::CouldNotParseCertificate)
		};
		return Ok(Self { der: cert_der })
	}

	/// Deserialize a cert from DER format
	pub fn from_der(der_bytes:&[u8]) -> Self{

		let owned_bytes = der_bytes.to_vec();
		return Certificate{der: owned_bytes.into()};
	}
}

impl From<Certificate> for CertificateDer<'static> {
	fn from(cert: Certificate) -> Self {
		cert.der
	}
}

/// Parameters used for certificate generation
#[allow(missing_docs)]
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct CertificateParams {
	pub not_before: OffsetDateTime,
	pub not_after: OffsetDateTime,
	pub serial_number: Option<SerialNumber>,
	pub subject_alt_names: Vec<SanType>,
	pub distinguished_name: DistinguishedName,
	pub is_ca: IsCa,
	pub key_usages: Vec<KeyUsagePurpose>,
	pub extended_key_usages: Vec<ExtendedKeyUsagePurpose>,
	pub name_constraints: Option<NameConstraints>,
	/// An optional list of certificate revocation list (CRL) distribution points as described
	/// in RFC 5280 Section 4.2.1.13[^1]. Each distribution point contains one or more URIs where
	/// an up-to-date CRL with scope including this certificate can be retrieved.
	///
	/// [^1]: <https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.13>
	pub crl_distribution_points: Vec<CrlDistributionPoint>,
	pub custom_extensions: Vec<CustomExtension>,
	/// If `true`, the 'Authority Key Identifier' extension will be added to the generated cert
	pub use_authority_key_identifier_extension: bool,
	/// Method to generate key identifiers from public keys
	///
	/// Defaults to a truncated SHA-256 digest. See [`KeyIdMethod`] for more information.
	pub key_identifier_method: KeyIdMethod,
}

impl Default for CertificateParams {
	fn default() -> Self {
		// not_before and not_after set to reasonably long dates
		let not_before = date_time_ymd(1975, 1, 1);
		let not_after = date_time_ymd(4096, 1, 1);
		let mut distinguished_name = DistinguishedName::new();
		distinguished_name.push(DnType::CommonName, "rcgen self signed cert");
		CertificateParams {
			not_before,
			not_after,
			serial_number: None,
			subject_alt_names: Vec::new(),
			distinguished_name,
			is_ca: IsCa::NoCa,
			key_usages: Vec::new(),
			extended_key_usages: Vec::new(),
			name_constraints: None,
			crl_distribution_points: Vec::new(),
			custom_extensions: Vec::new(),
			use_authority_key_identifier_extension: false,
			#[cfg(feature = "crypto")]
			key_identifier_method: KeyIdMethod::Sha256,
			#[cfg(not(feature = "crypto"))]
			key_identifier_method: KeyIdMethod::PreSpecified(Vec::new()),
		}
	}
}

impl CertificateParams {
	/// Generate certificate parameters with reasonable defaults
	pub fn new(subject_alt_names: impl Into<Vec<String>>) -> Result<Self, Error> {
		let subject_alt_names = subject_alt_names
			.into()
			.into_iter()
			.map(|s| {
				Ok(match IpAddr::from_str(&s) {
					Ok(ip) => SanType::IpAddress(ip),
					Err(_) => SanType::DnsName(s.try_into()?),
				})
			})
			.collect::<Result<Vec<_>, _>>()?;
		Ok(CertificateParams {
			subject_alt_names,
			..Default::default()
		})
	}

	/// Generate a new certificate from the given parameters, signed by the provided issuer.
	///
	/// The returned certificate will have its issuer field set to the subject of the
	/// provided `issuer`, and the authority key identifier extension will be populated using
	/// the subject public key of `issuer` (typically either a [`CertificateParams`] or
	/// [`Certificate`]). It will be signed by `issuer_key`.
	///
	/// Note that no validation of the `issuer` certificate is performed. Rcgen will not require
	/// the certificate to be a CA certificate, or have key usage extensions that allow signing.
	///
	/// The returned [`Certificate`] may be serialized using [`Certificate::der`] and
	/// [`Certificate::pem`].
	pub fn signed_by(
		&self,
		public_key: &impl PublicKeyData,
		issuer: &Issuer<'_, impl SigningKey>,
	) -> Result<Certificate, Error> {
		Ok(Certificate {
			der: self.serialize_der_with_signer(public_key, issuer)?,
		})
	}

	/// Generates a new self-signed certificate from the given parameters.
	///
	/// The returned [`Certificate`] may be serialized using [`Certificate::der`] and
	/// [`Certificate::pem`].
	pub fn self_signed(&self, signing_key: &impl SigningKey) -> Result<Certificate, Error> {
		let issuer = Issuer::from_params(self, signing_key);
		Ok(Certificate {
			der: self.serialize_der_with_signer(signing_key, &issuer)?,
		})
	}

	/// Calculates a subject key identifier for the certificate subject's public key.
	/// This key identifier is used in the SubjectKeyIdentifier X.509v3 extension.
	pub fn key_identifier(&self, key: &impl PublicKeyData) -> Vec<u8> {
		self.key_identifier_method
			.derive(key.subject_public_key_info())
	}

	#[cfg(all(test, feature = "x509-parser"))]
	pub(crate) fn from_ca_cert_der(ca_cert: &CertificateDer<'_>) -> Result<Self, Error> {
		let (_remainder, x509) = x509_parser::parse_x509_certificate(ca_cert)
			.map_err(|_| Error::CouldNotParseCertificate)?;

		Ok(CertificateParams {
			is_ca: IsCa::from_x509(&x509)?,
			subject_alt_names: SanType::from_x509(&x509)?,
			key_usages: KeyUsagePurpose::from_x509(&x509)?,
			extended_key_usages: ExtendedKeyUsagePurpose::from_x509(&x509)?,
			name_constraints: NameConstraints::from_x509(&x509)?,
			serial_number: Some(x509.serial.to_bytes_be().into()),
			key_identifier_method: KeyIdMethod::from_x509(&x509)?,
			distinguished_name: DistinguishedName::from_name(&x509.tbs_certificate.subject)?,
			not_before: x509.validity().not_before.to_datetime(),
			not_after: x509.validity().not_after.to_datetime(),
			..Default::default()
		})
	}

	/// Write a CSR extension request attribute as defined in [RFC 2985].
	///
	/// [RFC 2985]: <https://datatracker.ietf.org/doc/html/rfc2985>
	fn write_extension_request_attribute(&self, writer: DERWriter) {
		writer.write_sequence(|writer| {
			writer.next().write_oid(&ObjectIdentifier::from_slice(
				oid::PKCS_9_AT_EXTENSION_REQUEST,
			));
			writer.next().write_set(|writer| {
				writer.next().write_sequence(|writer| {
					// Write key_usage
					self.write_key_usage(writer.next());
					// Write subject_alt_names
					self.write_subject_alt_names(writer.next());
					self.write_extended_key_usage(writer.next());

					// Write custom extensions
					for ext in &self.custom_extensions {
						write_x509_extension(writer.next(), &ext.oid, ext.critical, |writer| {
							writer.write_der(ext.content())
						});
					}
				});
			});
		});
	}

	/// Write a certificate's KeyUsage as defined in RFC 5280.
	fn write_key_usage(&self, writer: DERWriter) {
		if self.key_usages.is_empty() {
			return;
		}

		// "When present, conforming CAs SHOULD mark this extension as critical."
		write_x509_extension(writer, oid::KEY_USAGE, true, |writer| {
			// u16 is large enough to encode the largest possible key usage (two-bytes)
			let bit_string = self.key_usages.iter().fold(0u16, |bit_string, key_usage| {
				bit_string | key_usage.to_u16()
			});

			match u16::BITS - bit_string.trailing_zeros() {
				bits @ 0..=8 => {
					writer.write_bitvec_bytes(&bit_string.to_be_bytes()[..1], bits as usize)
				},
				bits @ 9..=16 => {
					writer.write_bitvec_bytes(&bit_string.to_be_bytes(), bits as usize)
				},
				_ => unreachable!(),
			}
		});
	}

	fn write_extended_key_usage(&self, writer: DERWriter) {
		if !self.extended_key_usages.is_empty() {
			write_x509_extension(writer, oid::EXT_KEY_USAGE, false, |writer| {
				writer.write_sequence(|writer| {
					for usage in &self.extended_key_usages {
						writer
							.next()
							.write_oid(&ObjectIdentifier::from_slice(usage.oid()));
					}
				});
			});
		}
	}

	fn write_subject_alt_names(&self, writer: DERWriter) {
		if self.subject_alt_names.is_empty() {
			return;
		}

		// Per https://tools.ietf.org/html/rfc5280#section-4.1.2.6, SAN must be marked
		// as critical if subject is empty.
		let critical = self.distinguished_name.entries.is_empty();
		write_x509_extension(writer, oid::SUBJECT_ALT_NAME, critical, |writer| {
			writer.write_sequence(|writer| {
				for san in self.subject_alt_names.iter() {
					writer.next().write_tagged_implicit(
						Tag::context(san.tag()),
						|writer| match san {
							SanType::Rfc822Name(name)
							| SanType::DnsName(name)
							| SanType::URI(name) => writer.write_ia5_string(name.as_str()),
							SanType::IpAddress(IpAddr::V4(addr)) => {
								writer.write_bytes(&addr.octets())
							},
							SanType::IpAddress(IpAddr::V6(addr)) => {
								writer.write_bytes(&addr.octets())
							},
							SanType::OtherName((oid, value)) => {
								// otherName SEQUENCE { OID, [0] explicit any defined by oid }
								// https://datatracker.ietf.org/doc/html/rfc5280#page-38
								writer.write_sequence(|writer| {
									writer.next().write_oid(&ObjectIdentifier::from_slice(oid));
									value.write_der(writer.next());
								});
							},
						},
					);
				}
			});
		});
	}

	/// Generate and serialize a certificate signing request (CSR).
	///
	/// The constructed CSR will contain attributes based on the certificate parameters,
	/// and include the subject public key information from `subject_key`. Additionally,
	/// the CSR will be signed using the subject key.
	///
	/// Note that subsequent invocations of `serialize_request()` will not produce the exact
	/// same output.
	pub fn serialize_request(
		&self,
		subject_key: &impl SigningKey,
	) -> Result<CertificateSigningRequest, Error> {
		self.serialize_request_with_attributes(subject_key, Vec::new())
	}

	/// Generate and serialize a certificate signing request (CSR) with custom PKCS #10 attributes.
	/// as defined in [RFC 2986].
	///
	/// The constructed CSR will contain attributes based on the certificate parameters,
	/// and include the subject public key information from `subject_key`. Additionally,
	/// the CSR will be self-signed using the subject key.
	///
	/// Note that subsequent invocations of `serialize_request_with_attributes()` will not produce the exact
	/// same output.
	///
	/// [RFC 2986]: <https://datatracker.ietf.org/doc/html/rfc2986#section-4>
	pub fn serialize_request_with_attributes(
		&self,
		subject_key: &impl SigningKey,
		attrs: Vec<Attribute>,
	) -> Result<CertificateSigningRequest, Error> {
		// No .. pattern, we use this to ensure every field is used
		#[deny(unused)]
		let Self {
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
			use_authority_key_identifier_extension,
			key_identifier_method,
		} = self;
		// - subject_key will be used by the caller
		// - not_before and not_after cannot be put in a CSR
		// - key_identifier_method is here because self.write_extended_key_usage uses it
		// - There might be a use case for specifying the key identifier
		// in the CSR, but in the current API it can't be distinguished
		// from the defaults so this is left for a later version if
		// needed.
		let _ = (
			not_before,
			not_after,
			key_identifier_method,
			extended_key_usages,
		);
		if serial_number.is_some()
			|| *is_ca != IsCa::NoCa
			|| name_constraints.is_some()
			|| !crl_distribution_points.is_empty()
			|| *use_authority_key_identifier_extension
		{
			return Err(Error::UnsupportedInCsr);
		}

		// Whether or not to write an extension request attribute
		let write_extension_request = !key_usages.is_empty()
			|| !subject_alt_names.is_empty()
			|| !extended_key_usages.is_empty()
			|| !custom_extensions.is_empty();

		let der = sign_der(subject_key, |writer| {
			// Write version
			writer.next().write_u8(0);
			write_distinguished_name(writer.next(), distinguished_name);
			serialize_public_key_der(subject_key, writer.next());

			// According to the spec in RFC 2986, even if attributes are empty we need the empty attribute tag
			writer
				.next()
				.write_tagged_implicit(Tag::context(0), |writer| {
					// RFC 2986 specifies that attributes are a SET OF Attribute
					writer.write_set_of(|writer| {
						if write_extension_request {
							self.write_extension_request_attribute(writer.next());
						}

						for Attribute { oid, values } in attrs {
							writer.next().write_sequence(|writer| {
								writer.next().write_oid(&ObjectIdentifier::from_slice(oid));
								writer.next().write_der(&values);
							});
						}
					});
				});

			Ok(())
		})?;

		Ok(CertificateSigningRequest {
			der: CertificateSigningRequestDer::from(der),
		})
	}

	pub(crate) fn serialize_der_with_signer<K: PublicKeyData>(
		&self,
		pub_key: &K,
		issuer: &Issuer<'_, impl SigningKey>,
	) -> Result<CertificateDer<'static>, Error> {
		let der = sign_der(&issuer.signing_key, |writer| {
			let pub_key_spki = pub_key.subject_public_key_info();
			// Write version
			writer.next().write_tagged(Tag::context(0), |writer| {
				writer.write_u8(2);
			});
			// Write serialNumber
			if let Some(ref serial) = self.serial_number {
				writer.next().write_bigint_bytes(serial.as_ref(), true);
			} else {
				#[cfg(feature = "crypto")]
				{
					let hash = digest::digest(&digest::SHA256, pub_key.der_bytes());
					// RFC 5280 specifies at most 20 bytes for a serial number
					let mut sl = hash.as_ref()[0..20].to_vec();
					sl[0] &= 0x7f; // MSB must be 0 to ensure encoding bignum in 20 bytes
					writer.next().write_bigint_bytes(&sl, true);
				}
				#[cfg(not(feature = "crypto"))]
				if self.serial_number.is_none() {
					return Err(Error::MissingSerialNumber);
				}
			};
			// Write signature algorithm
			issuer
				.signing_key
				.algorithm()
				.write_alg_ident(writer.next());
			// Write issuer name
			write_distinguished_name(writer.next(), issuer.distinguished_name.as_ref());
			// Write validity
			writer.next().write_sequence(|writer| {
				// Not before
				write_dt_utc_or_generalized(writer.next(), self.not_before);
				// Not after
				write_dt_utc_or_generalized(writer.next(), self.not_after);
				Ok::<(), Error>(())
			})?;
			// Write subject
			write_distinguished_name(writer.next(), &self.distinguished_name);
			// Write subjectPublicKeyInfo
			serialize_public_key_der(pub_key, writer.next());
			// write extensions
			let should_write_exts = self.use_authority_key_identifier_extension
				|| !self.subject_alt_names.is_empty()
				|| !self.extended_key_usages.is_empty()
				|| self.name_constraints.iter().any(|c| !c.is_empty())
				|| matches!(self.is_ca, IsCa::ExplicitNoCa)
				|| matches!(self.is_ca, IsCa::Ca(_))
				|| !self.custom_extensions.is_empty();
			if !should_write_exts {
				return Ok(());
			}

			writer.next().write_tagged(Tag::context(3), |writer| {
				writer.write_sequence(|writer| self.write_extensions(writer, &pub_key_spki, issuer))
			})?;

			Ok(())
		})?;

		Ok(der.into())
	}

	fn write_extensions(
		&self,
		writer: &mut DERWriterSeq,
		pub_key_spki: &[u8],
		issuer: &Issuer<'_, impl SigningKey>,
	) -> Result<(), Error> {
		if self.use_authority_key_identifier_extension {
			write_x509_authority_key_identifier(
				writer.next(),
				match issuer.key_identifier_method.as_ref() {
					KeyIdMethod::PreSpecified(aki) => aki.clone(),
					#[cfg(feature = "crypto")]
					_ => issuer
						.key_identifier_method
						.derive(issuer.signing_key.subject_public_key_info()),
				},
			);
		}

		// Write subject_alt_names
		self.write_subject_alt_names(writer.next());

		// Write standard key usage
		self.write_key_usage(writer.next());

		// Write extended key usage
		if !self.extended_key_usages.is_empty() {
			write_x509_extension(writer.next(), oid::EXT_KEY_USAGE, false, |writer| {
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
				write_x509_extension(writer.next(), oid::NAME_CONSTRAINTS, true, |writer| {
					writer.write_sequence(|writer| {
						if !name_constraints.permitted_subtrees.is_empty() {
							write_general_subtrees(
								writer.next(),
								0,
								&name_constraints.permitted_subtrees,
							);
						}
						if !name_constraints.excluded_subtrees.is_empty() {
							write_general_subtrees(
								writer.next(),
								1,
								&name_constraints.excluded_subtrees,
							);
						}
					});
				});
			}
		}

		if !self.crl_distribution_points.is_empty() {
			write_x509_extension(
				writer.next(),
				oid::CRL_DISTRIBUTION_POINTS,
				false,
				|writer| {
					writer.write_sequence(|writer| {
						for distribution_point in &self.crl_distribution_points {
							distribution_point.write_der(writer.next());
						}
					})
				},
			);
		}

		match self.is_ca {
			IsCa::Ca(ref constraint) => {
				// Write subject_key_identifier
				write_x509_extension(
					writer.next(),
					oid::SUBJECT_KEY_IDENTIFIER,
					false,
					|writer| {
						writer.write_bytes(&self.key_identifier_method.derive(pub_key_spki));
					},
				);
				// Write basic_constraints
				write_x509_extension(writer.next(), oid::BASIC_CONSTRAINTS, true, |writer| {
					writer.write_sequence(|writer| {
						writer.next().write_bool(true); // cA flag
						if let BasicConstraints::Constrained(path_len_constraint) = constraint {
							writer.next().write_u8(*path_len_constraint);
						}
					});
				});
			},
			IsCa::ExplicitNoCa => {
				// Write subject_key_identifier
				write_x509_extension(
					writer.next(),
					oid::SUBJECT_KEY_IDENTIFIER,
					false,
					|writer| {
						writer.write_bytes(&self.key_identifier_method.derive(pub_key_spki));
					},
				);
				// Write basic_constraints
				write_x509_extension(writer.next(), oid::BASIC_CONSTRAINTS, true, |writer| {
					writer.write_sequence(|writer| {
						writer.next().write_bool(false); // cA flag
					});
				});
			},
			IsCa::NoCa => {},
		}

		// Write the custom extensions
		for ext in &self.custom_extensions {
			write_x509_extension(writer.next(), &ext.oid, ext.critical, |writer| {
				writer.write_der(ext.content())
			});
		}

		Ok(())
	}

	/// Insert an extended key usage (EKU) into the parameters if it does not already exist
	pub fn insert_extended_key_usage(&mut self, eku: ExtendedKeyUsagePurpose) {
		if !self.extended_key_usages.contains(&eku) {
			self.extended_key_usages.push(eku);
		}
	}
}

impl AsRef<CertificateParams> for CertificateParams {
	fn as_ref(&self) -> &CertificateParams {
		self
	}
}

fn write_general_subtrees(writer: DERWriter, tag: u64, general_subtrees: &[GeneralSubtree]) {
	writer.write_tagged_implicit(Tag::context(tag), |writer| {
		writer.write_sequence(|writer| {
			for subtree in general_subtrees.iter() {
				writer.next().write_sequence(|writer| {
					writer
						.next()
						.write_tagged_implicit(
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

/// A PKCS #10 CSR attribute, as defined in [RFC 5280] and constrained
/// by [RFC 2986].
///
/// [RFC 5280]: <https://datatracker.ietf.org/doc/html/rfc5280#appendix-A.1>
/// [RFC 2986]: <https://datatracker.ietf.org/doc/html/rfc2986#section-4>
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Attribute {
	/// `AttributeType` of the `Attribute`, defined as an `OBJECT IDENTIFIER`.
	pub oid: &'static [u64],
	/// DER-encoded values of the `Attribute`, defined by [RFC 2986] as:
	///
	/// ```text
	/// SET SIZE(1..MAX) OF ATTRIBUTE.&Type({IOSet}{@type})
	/// ```
	///
	/// [RFC 2986]: https://datatracker.ietf.org/doc/html/rfc2986#section-4
	pub values: Vec<u8>,
}

/// A custom extension of a certificate, as specified in
/// [RFC 5280](https://tools.ietf.org/html/rfc5280#section-4.2)
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct CustomExtension {
	oid: Vec<u64>,
	critical: bool,

	/// The content must be DER-encoded
	content: Vec<u8>,
}

impl CustomExtension {
	/// Creates a new acmeIdentifier extension for ACME TLS-ALPN-01
	/// as specified in [RFC 8737](https://tools.ietf.org/html/rfc8737#section-3)
	///
	/// Panics if the passed `sha_digest` parameter doesn't hold 32 bytes (256 bits).
	pub fn new_acme_identifier(sha_digest: &[u8]) -> Self {
		assert_eq!(sha_digest.len(), 32, "wrong size of sha_digest");
		let content = yasna::construct_der(|writer| {
			writer.write_bytes(sha_digest);
		});
		Self {
			oid: oid::PE_ACME.to_owned(),
			critical: true,
			content,
		}
	}
	/// Create a new custom extension with the specified content
	pub fn from_oid_content(oid: &[u64], content: Vec<u8>) -> Self {
		Self {
			oid: oid.to_owned(),
			critical: false,
			content,
		}
	}
	/// Sets the criticality flag of the extension.
	pub fn set_criticality(&mut self, criticality: bool) {
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
	pub(crate) fn to_oid(&self) -> ObjectIdentifier {
		let sl = match self {
			DnType::CountryName => oid::COUNTRY_NAME,
			DnType::LocalityName => oid::LOCALITY_NAME,
			DnType::StateOrProvinceName => oid::STATE_OR_PROVINCE_NAME,
			DnType::OrganizationName => oid::ORG_NAME,
			DnType::OrganizationalUnitName => oid::ORG_UNIT_NAME,
			DnType::CommonName => oid::COMMON_NAME,
			DnType::CustomDnType(ref oid) => oid.as_slice(),
		};
		ObjectIdentifier::from_slice(sl)
	}

	/// Generate a DnType for the provided OID
	pub fn from_oid(slice: &[u64]) -> Self {
		match slice {
			oid::COUNTRY_NAME => DnType::CountryName,
			oid::LOCALITY_NAME => DnType::LocalityName,
			oid::STATE_OR_PROVINCE_NAME => DnType::StateOrProvinceName,
			oid::ORG_NAME => DnType::OrganizationName,
			oid::ORG_UNIT_NAME => DnType::OrganizationalUnitName,
			oid::COMMON_NAME => DnType::CommonName,
			oid => DnType::CustomDnType(oid.into()),
		}
	}
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
	fn from_x509(x509: &x509_parser::certificate::X509Certificate<'_>) -> Result<Vec<Self>, Error> {
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

	fn oid(&self) -> &[u64] {
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
	fn from_x509(
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

	fn is_empty(&self) -> bool {
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

/// Helper to obtain an `OffsetDateTime` from year, month, day values
///
/// The year, month, day values are assumed to be in UTC.
///
/// This helper function serves two purposes: first, so that you don't
/// have to import the time crate yourself in order to specify date
/// information, second so that users don't have to type unproportionately
/// long code just to generate an instance of [`OffsetDateTime`].
pub fn date_time_ymd(year: i32, month: u8, day: u8) -> OffsetDateTime {
	let month = Month::try_from(month).expect("out-of-range month");
	let primitive_dt = PrimitiveDateTime::new(
		Date::from_calendar_date(year, month, day).expect("invalid or out-of-range date"),
		Time::MIDNIGHT,
	);
	primitive_dt.assume_utc()
}

/// Whether the certificate is allowed to sign other certificates
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IsCa {
	/// The certificate can only sign itself
	NoCa,
	/// The certificate can only sign itself, adding the extension and `CA:FALSE`
	ExplicitNoCa,
	/// The certificate may be used to sign other certificates
	Ca(BasicConstraints),
}

impl IsCa {
	#[cfg(all(test, feature = "x509-parser"))]
	fn from_x509(x509: &x509_parser::certificate::X509Certificate<'_>) -> Result<Self, Error> {
		use x509_parser::extensions::BasicConstraints as B;

		let basic_constraints = x509
			.basic_constraints()
			.map_err(|_| Error::CouldNotParseCertificate)?
			.map(|ext| ext.value);

		Ok(match basic_constraints {
			Some(B {
				ca: true,
				path_len_constraint: Some(n),
			}) if *n <= u8::MAX as u32 => Self::Ca(BasicConstraints::Constrained(*n as u8)),
			Some(B {
				ca: true,
				path_len_constraint: Some(_),
			}) => return Err(Error::CouldNotParseCertificate),
			Some(B {
				ca: true,
				path_len_constraint: None,
			}) => Self::Ca(BasicConstraints::Unconstrained),
			Some(B { ca: false, .. }) => Self::ExplicitNoCa,
			None => Self::NoCa,
		})
	}
}

/// The path length constraint (only relevant for CA certificates)
///
/// Sets an optional upper limit on the length of the intermediate certificate chain
/// length allowed for this CA certificate (not including the end entity certificate).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BasicConstraints {
	/// No constraint
	Unconstrained,
	/// Constrain to the contained number of intermediate certificates
	Constrained(u8),
}

#[cfg(test)]
mod tests {
	#[cfg(feature = "x509-parser")]
	use std::net::Ipv4Addr;

	#[cfg(feature = "x509-parser")]
	use pki_types::pem::PemObject;

	#[cfg(feature = "pem")]
	use super::*;
	#[cfg(feature = "x509-parser")]
	use crate::DnValue;
	#[cfg(feature = "crypto")]
	use crate::KeyPair;

	#[cfg(feature = "crypto")]
	#[test]
	fn test_with_key_usages() {
		let params = CertificateParams {
			// Set key usages
			key_usages: vec![
				KeyUsagePurpose::DigitalSignature,
				KeyUsagePurpose::KeyEncipherment,
				KeyUsagePurpose::ContentCommitment,
			],
			// This can sign things!
			is_ca: IsCa::Ca(BasicConstraints::Constrained(0)),
			..CertificateParams::default()
		};

		// Make the cert
		let key_pair = KeyPair::generate().unwrap();
		let cert = params.self_signed(&key_pair).unwrap();

		// Parse it
		let (_rem, cert) = x509_parser::parse_x509_certificate(cert.der()).unwrap();

		// Check oid
		let key_usage_oid_str = "2.5.29.15";

		// Found flag
		let mut found = false;

		for ext in cert.extensions() {
			if key_usage_oid_str == ext.oid.to_id_string() {
				// should have the minimal number of octets, and no extra trailing zero bytes
				// ref. https://github.com/rustls/rcgen/issues/368
				assert_eq!(ext.value, vec![0x03, 0x02, 0x05, 0xe0]);
				if let x509_parser::extensions::ParsedExtension::KeyUsage(usage) =
					ext.parsed_extension()
				{
					assert!(usage.flags == 7);
					found = true;
				}
			}
		}

		assert!(found);
	}

	#[cfg(feature = "crypto")]
	#[test]
	fn test_with_key_usages_decipheronly_only() {
		let params = CertificateParams {
			// Set key usages
			key_usages: vec![KeyUsagePurpose::DecipherOnly],
			// This can sign things!
			is_ca: IsCa::Ca(BasicConstraints::Constrained(0)),
			..CertificateParams::default()
		};

		// Make the cert
		let key_pair = KeyPair::generate().unwrap();
		let cert = params.self_signed(&key_pair).unwrap();

		// Parse it
		let (_rem, cert) = x509_parser::parse_x509_certificate(cert.der()).unwrap();

		// Check oid
		let key_usage_oid_str = "2.5.29.15";

		// Found flag
		let mut found = false;

		for ext in cert.extensions() {
			if key_usage_oid_str == ext.oid.to_id_string() {
				if let x509_parser::extensions::ParsedExtension::KeyUsage(usage) =
					ext.parsed_extension()
				{
					assert!(usage.flags == 256);
					found = true;
				}
			}
		}

		assert!(found);
	}

	#[cfg(feature = "crypto")]
	#[test]
	fn test_with_extended_key_usages_any() {
		let params = CertificateParams {
			extended_key_usages: vec![ExtendedKeyUsagePurpose::Any],
			..CertificateParams::default()
		};

		// Make the cert
		let key_pair = KeyPair::generate().unwrap();
		let cert = params.self_signed(&key_pair).unwrap();

		// Parse it
		let (_rem, cert) = x509_parser::parse_x509_certificate(cert.der()).unwrap();

		// Ensure we found it.
		let maybe_extension = cert.extended_key_usage().unwrap();
		let extension = maybe_extension.unwrap();
		assert!(extension.value.any);
	}

	#[cfg(feature = "crypto")]
	#[test]
	fn test_with_extended_key_usages_other() {
		use x509_parser::der_parser::asn1_rs::Oid;
		const OID_1: &[u64] = &[1, 2, 3, 4];
		const OID_2: &[u64] = &[1, 2, 3, 4, 5, 6];

		let params = CertificateParams {
			extended_key_usages: vec![
				ExtendedKeyUsagePurpose::Other(Vec::from(OID_1)),
				ExtendedKeyUsagePurpose::Other(Vec::from(OID_2)),
			],
			..CertificateParams::default()
		};

		// Make the cert
		let key_pair = KeyPair::generate().unwrap();
		let cert = params.self_signed(&key_pair).unwrap();

		// Parse it
		let (_rem, cert) = x509_parser::parse_x509_certificate(cert.der()).unwrap();

		// Ensure we found it.
		let maybe_extension = cert.extended_key_usage().unwrap();
		let extension = maybe_extension.unwrap();

		let expected_oids = vec![Oid::from(OID_1).unwrap(), Oid::from(OID_2).unwrap()];
		assert_eq!(extension.value.other, expected_oids);
	}

	#[cfg(feature = "pem")]
	mod test_pem_serialization {
		use super::*;

		#[test]
		#[cfg(windows)]
		fn test_windows_line_endings() {
			let key_pair = KeyPair::generate().unwrap();
			let cert = CertificateParams::default().self_signed(&key_pair).unwrap();
			assert!(cert.pem().contains("\r\n"));
		}

		#[test]
		#[cfg(not(windows))]
		fn test_not_windows_line_endings() {
			let key_pair = KeyPair::generate().unwrap();
			let cert = CertificateParams::default().self_signed(&key_pair).unwrap();
			assert!(!cert.pem().contains('\r'));
		}
	}

	#[cfg(feature = "x509-parser")]
	#[test]
	fn parse_other_name_alt_name() {
		// Create and serialize a certificate with an alternative name containing an "OtherName".
		let mut params = CertificateParams::default();
		let other_name = SanType::OtherName((vec![1, 2, 3, 4], "Foo".into()));
		params.subject_alt_names.push(other_name.clone());
		let key_pair = KeyPair::generate().unwrap();
		let cert = params.self_signed(&key_pair).unwrap();

		// We should be able to parse the certificate with x509-parser.
		assert!(x509_parser::parse_x509_certificate(cert.der()).is_ok());

		// We should be able to reconstitute params from the DER using x509-parser.
		let params_from_cert = CertificateParams::from_ca_cert_der(cert.der()).unwrap();

		// We should find the expected distinguished name in the reconstituted params.
		let expected_alt_names = &[&other_name];
		let subject_alt_names = params_from_cert
			.subject_alt_names
			.iter()
			.collect::<Vec<_>>();
		assert_eq!(subject_alt_names, expected_alt_names);
	}

	#[cfg(feature = "x509-parser")]
	#[test]
	fn parse_ia5string_subject() {
		// Create and serialize a certificate with a subject containing an IA5String email address.
		let email_address_dn_type = DnType::CustomDnType(vec![1, 2, 840, 113549, 1, 9, 1]); // id-emailAddress
		let email_address_dn_value = DnValue::Ia5String("foo@bar.com".try_into().unwrap());
		let mut params = CertificateParams::new(vec!["crabs".to_owned()]).unwrap();
		params.distinguished_name = DistinguishedName::new();
		params.distinguished_name.push(
			email_address_dn_type.clone(),
			email_address_dn_value.clone(),
		);
		let key_pair = KeyPair::generate().unwrap();
		let cert = params.self_signed(&key_pair).unwrap();

		// We should be able to parse the certificate with x509-parser.
		assert!(x509_parser::parse_x509_certificate(cert.der()).is_ok());

		// We should be able to reconstitute params from the DER using x509-parser.
		let params_from_cert = CertificateParams::from_ca_cert_der(cert.der()).unwrap();

		// We should find the expected distinguished name in the reconstituted params.
		let expected_names = &[(&email_address_dn_type, &email_address_dn_value)];
		let names = params_from_cert
			.distinguished_name
			.iter()
			.collect::<Vec<(_, _)>>();
		assert_eq!(names, expected_names);
	}

	#[cfg(feature = "x509-parser")]
	#[test]
	fn converts_from_ip() {
		let ip = Ipv4Addr::new(2, 4, 6, 8);
		let ip_san = SanType::IpAddress(IpAddr::V4(ip));

		let mut params = CertificateParams::new(vec!["crabs".to_owned()]).unwrap();
		let ca_key = KeyPair::generate().unwrap();

		// Add the SAN we want to test the parsing for
		params.subject_alt_names.push(ip_san.clone());

		// Because we're using a function for CA certificates
		params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

		// Serialize our cert that has our chosen san, so we can testing parsing/deserializing it.
		let cert = params.self_signed(&ca_key).unwrap();

		let actual = CertificateParams::from_ca_cert_der(cert.der()).unwrap();
		assert!(actual.subject_alt_names.contains(&ip_san));
	}

	#[cfg(feature = "x509-parser")]
	mod test_key_identifier_from_ca {
		use super::*;

		#[test]
		fn load_ca_and_sign_cert() {
			let ca_cert = r#"-----BEGIN CERTIFICATE-----
MIIFDTCCAvWgAwIBAgIUVuDfDt/BUVfObGOHsM+L5/qPZfIwDQYJKoZIhvcNAQEL
BQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wHhcNMjMxMjA4MTAwOTI2WhcNMjQx
MTI4MTAwOTI2WjAWMRQwEgYDVQQDDAtleGFtcGxlLmNvbTCCAiIwDQYJKoZIhvcN
AQEBBQADggIPADCCAgoCggIBAKXyZsv7Zwek9yc54IXWjCkMwU4eDMz9Uw06WETF
hZtauwDo4usCeYJa/7x8RZbGcI99s/vOMHjIdVzY6g9p5c6qS+7EUBhXARYVB74z
XUGwgVGss7lgw+0dNxhQ8F0M2smBXUP9FlJJjJpbWeU+93iynGy+PTXFtYMnOoVI
4G7YKsG5lX0zBJUNYZslEz6Kp8eRYu7FAdccU0u5bmg02a1WiXOYJeN1+AifUbRN
zNInZCqMCFgoHczb0DvKU3QX/xrcBxfr/SNJPqxlecUvsozteUoAFAUF1uTxH31q
cVmCHf9I0r6JJoGxs+XMVbH2SJLdsq/+zpjeHz6gy0z4aRMBpaUWUQ9pEENeSq15
PXCuX3yPT2BII30mL86OWO6qgms70iALak6xZ/xAT7RT22E1bOF+XJsiUM3OgGF0
TPmDcpafEMH4kwzdaC7U5hqhYk9I2lfTMEghV86kUXClExuHEQD4GZLcd1HMD/Wg
qOZO4y/t/yzBPNq01FpeilFph/tW6pxr1X7Jloz1/yIuNFK0oXTB24J/TUi+/S1B
kavOBg3eNHHDXDjESKtnV+iwo1cFt6LVCrnKhKJ6m95+c+YKQGIrcwkR91OxZ9ZT
DEzySsPDpWrteZf3K1VA0Ut41aTKu8pYwxsnVdOiBGaJkOh/lrevI6U9Eg4vVq94
hyAZAgMBAAGjUzBRMB0GA1UdDgQWBBSX1HahmxpxNSrH9KGEElYGul1hhDAfBgNV
HSMEGDAWgBSX1HahmxpxNSrH9KGEElYGul1hhDAPBgNVHRMBAf8EBTADAQH/MA0G
CSqGSIb3DQEBCwUAA4ICAQAhtwt0OrHVITVOzoH3c+7SS/rGd9KGpHG4Z/N7ASs3
7A2PXFC5XbUuylky0+/nbkN6hhecj+Zwt5x5R8k4saXUZ8xkMfP8RaRxyZ3rUOIC
BZhZm1XbQzaWIQjpjyPUWDDa9P0lGsUyrEIQaLjg1J5jYPOD132bmdIuhZtzldTV
zeE/4sKdrkj6HZxe1jxAhx2IWm6W+pEAcq1Ld9SmJGOxBVRRKyGsMMw6hCdWfQHv
Z8qRIhn3FU6ZKW2jvTGJBIXoK4u454qi6DVxkFZ0OK9VwWVuDLvs2Es95TiZPTq+
KJmRHWHF/Ic78XFgxVq0tVaJAs7qoOMjDkehPG1V8eewanlpcaE6rPx0eiPq+nHE
gCf0KmKGVM8lQe63obzprkdLKL3T4UDN19K2wqscJcPKK++27OYx2hJaJKmYzF23
4WhIRzdALTs/2fbB68nVSz7kBtHvsHHS33Q57zEdQq5YeyUaTtCvJJobt70dy9vN
YolzLWoY/itEPFtbBAdnJxXlctI3bw4Mzw1d66Wt+//R45+cIe6cJdUIqMHDhsGf
U8EuffvDcTJuUzIkyzbyOI15r1TMbRt8vFR0jzagZBCG73lVacH/bYEb2j4Z1ORi
L2Fl4tgIQ5tyaTpu9gpJZvPU0VZ/j+1Jdk1c9PJ6xhCjof4nzI9YsLbI8lPtu8K/
Ng==
-----END CERTIFICATE-----"#;

			let ca_key = r#"-----BEGIN PRIVATE KEY-----
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
PITGdT9dgN88nHPCle0B1+OY+OZ5
-----END PRIVATE KEY-----"#;

			let ca_kp = KeyPair::from_pem(ca_key).unwrap();
			let ca = Issuer::from_ca_cert_pem(ca_cert, ca_kp).unwrap();
			let ca_ski = vec![
				0x97, 0xD4, 0x76, 0xA1, 0x9B, 0x1A, 0x71, 0x35, 0x2A, 0xC7, 0xF4, 0xA1, 0x84, 0x12,
				0x56, 0x06, 0xBA, 0x5D, 0x61, 0x84,
			];

			assert_eq!(
				&KeyIdMethod::PreSpecified(ca_ski.clone()),
				ca.key_identifier_method.as_ref()
			);

			let ca_cert_der = CertificateDer::from_pem_slice(ca_cert.as_bytes()).unwrap();
			let (_, x509_ca) = x509_parser::parse_x509_certificate(ca_cert_der.as_ref()).unwrap();
			assert_eq!(
				&ca_ski,
				&x509_ca
					.iter_extensions()
					.find_map(|ext| match ext.parsed_extension() {
						x509_parser::extensions::ParsedExtension::SubjectKeyIdentifier(key_id) => {
							Some(key_id.0.to_vec())
						},
						_ => None,
					})
					.unwrap()
			);

			let ee_key = KeyPair::generate().unwrap();
			let ee_params = CertificateParams {
				use_authority_key_identifier_extension: true,
				..CertificateParams::default()
			};
			let ee_cert = ee_params.signed_by(&ee_key, &ca).unwrap();

			let (_, x509_ee) = x509_parser::parse_x509_certificate(ee_cert.der()).unwrap();
			assert_eq!(
				&ca_ski,
				&x509_ee
					.iter_extensions()
					.find_map(|ext| match ext.parsed_extension() {
						x509_parser::extensions::ParsedExtension::AuthorityKeyIdentifier(aki) => {
							aki.key_identifier.as_ref().map(|ki| ki.0.to_vec())
						},
						_ => None,
					})
					.unwrap()
			);
		}
	}
}
