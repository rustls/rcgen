use crate::{Certificate, DistinguishedName, KeyIdMethod, KeyPair, KeyUsagePurpose};

/// Holds the information necessary for an issuer of a certificate to sign other certificates. Specifically, it must
/// have the distinguished name, key identifier method, key usages, and access to the private key.
///
/// Optionally, the issuer may also have the entire issuer's certificate, but for root certificates this cannot be
/// available, as the root certificate is self-signed.
pub struct Issuer<'a> {
	/// The distinguished name of the issuer. Used to construct the issuer field in the issued certificate.
	pub(crate) distinguished_name: &'a DistinguishedName,

	/// The method used to generate the key identifier for the issuer. Must match the method used to generate the
	/// subject key identifier in the issuer's certificate.
	pub(crate) key_identifier_method: &'a KeyIdMethod,

	/// The key usage purposes associated with the issuer.
	pub(crate) key_usages: &'a [KeyUsagePurpose],

	/// The key pair of the issuer which includes the private key, though it may be a RemoteKeyPair allowing for a key
	/// held in an HSM or other secure location to sign the certificate.
	pub(crate) key_pair: &'a KeyPair,

	/// The issuer's certificate, if available. This is typically `None` for root certificates.
	pub(crate) certificate: Option<Certificate>,
}
