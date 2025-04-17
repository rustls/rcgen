use std::hash::Hash;

#[cfg(feature = "pem")]
use pem::Pem;
use pki_types::CertificateSigningRequestDer;
use yasna::{models::ObjectIdentifier, DERWriter, Tag};

#[cfg(feature = "pem")]
use crate::ENCODE_CONFIG;
use crate::{
	certificate::SignableCertificateParams, key_pair::serialize_public_key_der, oid,
	write_distinguished_name, write_x509_extension, Attribute, Certificate, CertificateParams,
	Error, IsCa, Issuer, PublicKeyData, SignatureAlgorithm, SigningKey, ToDer,
};
#[cfg(feature = "x509-parser")]
use crate::{DistinguishedName, SanType};

/// A public key, extracted from a CSR
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct PublicKey {
	raw: Vec<u8>,
	alg: &'static SignatureAlgorithm,
}

impl PublicKey {
	/// The algorithm used to generate the public key and sign the CSR.
	pub fn algorithm(&self) -> &SignatureAlgorithm {
		self.alg
	}
}

impl PublicKeyData for PublicKey {
	fn der_bytes(&self) -> &[u8] {
		&self.raw
	}

	fn algorithm(&self) -> &'static SignatureAlgorithm {
		self.alg
	}
}

/// A certificate signing request (CSR) that can be encoded to PEM or DER.
#[derive(Debug)]
pub struct CertificateSigningRequest {
	pub(crate) der: CertificateSigningRequestDer<'static>,
}

impl CertificateSigningRequest {
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
	pub fn new(
		params: &CertificateParams,
		subject_key: &impl SigningKey,
		attrs: Vec<Attribute>,
	) -> Result<Self, Error> {
		Ok(Self {
			der: SignableRequest {
				params,
				subject_key,
				attrs,
			}
			.signed(subject_key)?
			.into(),
		})
	}

	/// Get the PEM-encoded bytes of the certificate signing request.
	#[cfg(feature = "pem")]
	pub fn pem(&self) -> Result<String, Error> {
		let p = Pem::new("CERTIFICATE REQUEST", &*self.der);
		Ok(pem::encode_config(&p, ENCODE_CONFIG))
	}

	/// Get the DER-encoded bytes of the certificate signing request.
	///
	/// [`CertificateSigningRequestDer`] implements `Deref<Target = [u8]>` and `AsRef<[u8]>`,
	/// so you can easily extract the DER bytes from the return value.
	pub fn der(&self) -> &CertificateSigningRequestDer<'static> {
		&self.der
	}
}

impl From<CertificateSigningRequest> for CertificateSigningRequestDer<'static> {
	fn from(csr: CertificateSigningRequest) -> Self {
		csr.der
	}
}

struct SignableRequest<'a, S> {
	params: &'a CertificateParams,
	subject_key: &'a S,
	attrs: Vec<Attribute>,
}

impl<'a, S: SigningKey> ToDer for SignableRequest<'a, S> {
	fn write_der(&self, writer: &mut yasna::DERWriterSeq) -> Result<(), Error> {
		// No .. pattern, we use this to ensure every field is used
		#[deny(unused)]
		let CertificateParams {
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
		} = &self.params;
		// - alg and key_pair will be used by the caller
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

		// Write version
		writer.next().write_u8(0);
		write_distinguished_name(writer.next(), distinguished_name);
		serialize_public_key_der(self.subject_key, writer.next());

		// According to the spec in RFC 2986, even if attributes are empty we need the empty attribute tag
		writer
			.next()
			.write_tagged_implicit(Tag::context(0), |writer| {
				// RFC 2986 specifies that attributes are a SET OF Attribute
				writer.write_set_of(|writer| {
					if write_extension_request {
						write_extension_request_attribute(&self.params, writer.next());
					}

					for Attribute { oid, values } in &self.attrs {
						writer.next().write_sequence(|writer| {
							writer.next().write_oid(&ObjectIdentifier::from_slice(&oid));
							writer.next().write_der(&values);
						});
					}
				});
			});

		Ok(())
	}
}

/// Write a CSR extension request attribute as defined in [RFC 2985].
///
/// [RFC 2985]: <https://datatracker.ietf.org/doc/html/rfc2985>
pub(crate) fn write_extension_request_attribute(params: &CertificateParams, writer: DERWriter) {
	writer.write_sequence(|writer| {
		writer.next().write_oid(&ObjectIdentifier::from_slice(
			oid::PKCS_9_AT_EXTENSION_REQUEST,
		));
		writer.next().write_set(|writer| {
			writer.next().write_sequence(|writer| {
				// Write key_usage
				params.write_key_usage(writer.next());
				// Write subject_alt_names
				params.write_subject_alt_names(writer.next());
				params.write_extended_key_usage(writer.next());

				// Write custom extensions
				for ext in &params.custom_extensions {
					write_x509_extension(writer.next(), &ext.oid, ext.critical, |writer| {
						writer.write_der(ext.content())
					});
				}
			});
		});
	});
}

/// Parameters for a certificate signing request
#[derive(Debug)]
pub struct CertificateSigningRequestParams {
	/// Parameters for the certificate to be signed.
	pub params: CertificateParams,
	/// Public key to include in the certificate signing request.
	pub public_key: PublicKey,
}

impl CertificateSigningRequestParams {
	/// Parse a certificate signing request from the ASCII PEM format
	///
	/// See [`from_der`](Self::from_der) for more details.
	#[cfg(all(feature = "pem", feature = "x509-parser"))]
	pub fn from_pem(pem_str: &str) -> Result<Self, Error> {
		let csr = pem::parse(pem_str).or(Err(Error::CouldNotParseCertificationRequest))?;
		Self::from_der(&csr.contents().into())
	}

	/// Parse a certificate signing request from DER-encoded bytes
	///
	/// Currently, this only supports the `Subject Alternative Name` extension.
	/// On encountering other extensions, this function will return an error.
	///
	/// [`rustls_pemfile::csr()`] is often used to obtain a [`CertificateSigningRequestDer`] from
	/// PEM input. If you already have a byte slice containing DER, it can trivially be converted
	/// into [`CertificateSigningRequestDer`] using the [`Into`] trait.
	///
	/// [`rustls_pemfile::csr()`]: https://docs.rs/rustls-pemfile/latest/rustls_pemfile/fn.csr.html
	#[cfg(feature = "x509-parser")]
	pub fn from_der(csr: &CertificateSigningRequestDer<'_>) -> Result<Self, Error> {
		use crate::KeyUsagePurpose;
		use x509_parser::prelude::FromDer;

		let csr = x509_parser::certification_request::X509CertificationRequest::from_der(csr)
			.map_err(|_| Error::CouldNotParseCertificationRequest)?
			.1;
		csr.verify_signature().map_err(|_| Error::RingUnspecified)?;
		let alg_oid = csr
			.signature_algorithm
			.algorithm
			.iter()
			.ok_or(Error::CouldNotParseCertificationRequest)?
			.collect::<Vec<_>>();
		let alg = SignatureAlgorithm::from_oid(&alg_oid)?;

		let info = &csr.certification_request_info;
		let mut params = CertificateParams {
			distinguished_name: DistinguishedName::from_name(&info.subject)?,
			..CertificateParams::default()
		};
		let raw = info.subject_pki.subject_public_key.data.to_vec();

		if let Some(extensions) = csr.requested_extensions() {
			for ext in extensions {
				match ext {
					x509_parser::extensions::ParsedExtension::KeyUsage(key_usage) => {
						// This x509 parser stores flags in reversed bit BIT STRING order
						params.key_usages =
							KeyUsagePurpose::from_u16(key_usage.flags.reverse_bits());
					},
					x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) => {
						for name in &san.general_names {
							params
								.subject_alt_names
								.push(SanType::try_from_general(name)?);
						}
					},
					x509_parser::extensions::ParsedExtension::ExtendedKeyUsage(eku) => {
						if eku.any {
							params.insert_extended_key_usage(crate::ExtendedKeyUsagePurpose::Any);
						}
						if eku.server_auth {
							params.insert_extended_key_usage(
								crate::ExtendedKeyUsagePurpose::ServerAuth,
							);
						}
						if eku.client_auth {
							params.insert_extended_key_usage(
								crate::ExtendedKeyUsagePurpose::ClientAuth,
							);
						}
						if eku.code_signing {
							params.insert_extended_key_usage(
								crate::ExtendedKeyUsagePurpose::CodeSigning,
							);
						}
						if eku.email_protection {
							params.insert_extended_key_usage(
								crate::ExtendedKeyUsagePurpose::EmailProtection,
							);
						}
						if eku.time_stamping {
							params.insert_extended_key_usage(
								crate::ExtendedKeyUsagePurpose::TimeStamping,
							);
						}
						if eku.ocsp_signing {
							params.insert_extended_key_usage(
								crate::ExtendedKeyUsagePurpose::OcspSigning,
							);
						}
						if !eku.other.is_empty() {
							return Err(Error::UnsupportedExtension);
						}
					},
					_ => return Err(Error::UnsupportedExtension),
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

	/// Generate a new certificate based on the requested parameters, signed by the provided
	/// issuer.
	///
	/// The returned certificate will have its issuer field set to the subject of the provided
	/// `issuer`, and the authority key identifier extension will be populated using the subject
	/// public key of `issuer`. It will be signed by `issuer_key`.
	///
	/// Note that no validation of the `issuer` certificate is performed. Rcgen will not require
	/// the certificate to be a CA certificate, or have key usage extensions that allow signing.
	///
	/// The returned [`Certificate`] may be serialized using [`Certificate::der`] and
	/// [`Certificate::pem`].
	pub fn signed_by(
		&self,
		issuer: &CertificateParams,
		issuer_key: &impl SigningKey,
	) -> Result<Certificate, Error> {
		let issuer = Issuer::new(issuer, issuer_key);
		Ok(Certificate {
			der: SignableCertificateParams {
				params: &self.params,
				pub_key: &self.public_key,
				issuer: &issuer,
			}
			.signed(issuer.key_pair)?
			.into(),
		})
	}
}
