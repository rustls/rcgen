use crate::{DistinguishedName, KeyIdMethod, KeyPair, KeyUsagePurpose};

/// Holds the information necessary for an issuer of a certificate to sign other certificates. Specifically, it must
/// have the distinguished name, key identifier method, key usages, and access to the private key.
///
/// Optionally, the issuer may also have the entire issuer's certificate, but for root certificates this cannot be
/// available, as the root certificate is self-signed.
pub struct Issuer<'a> {
	/// The distinguished name of the issuer.
	pub(crate) distinguished_name: &'a DistinguishedName,
	/// The method used to generate the key identifier for the issuer.
	pub(crate) key_identifier_method: &'a KeyIdMethod,
	/// The key usage purposes associated with the issuer.
	pub(crate) key_usages: &'a [KeyUsagePurpose],
	/// The key pair of the issuer.
	pub(crate) key_pair: &'a KeyPair,
}
