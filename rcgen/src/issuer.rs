use crate::{DistinguishedName, KeyIdMethod, KeyPair, KeyUsagePurpose};

/// TODO
pub struct Issuer<'a> {
	pub(crate) distinguished_name: &'a DistinguishedName,
	pub(crate) key_identifier_method: &'a KeyIdMethod,
	pub(crate) key_usages: &'a [KeyUsagePurpose],
	pub(crate) key_pair: &'a KeyPair,
}

impl<'a> Issuer<'a> {}
