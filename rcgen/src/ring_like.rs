#[cfg(all(feature = "crypto", feature = "_aws_lc_like"))]
pub(crate) use aws_lc_rs::*;
#[cfg(all(feature = "crypto", feature = "ring", not(feature = "_aws_lc_like")))]
pub(crate) use ring::*;

#[cfg(feature = "crypto")]
use crate::error::ExternalError;
#[cfg(feature = "crypto")]
use crate::Error;

#[cfg(feature = "crypto")]
pub(crate) fn ecdsa_from_pkcs8(
	alg: &'static signature::EcdsaSigningAlgorithm,
	pkcs8: &[u8],
	_rng: &dyn rand::SecureRandom,
) -> Result<signature::EcdsaKeyPair, Error> {
	#[cfg(all(feature = "ring", not(feature = "_aws_lc_like")))]
	{
		signature::EcdsaKeyPair::from_pkcs8(alg, pkcs8, _rng)._err()
	}

	#[cfg(feature = "_aws_lc_like")]
	{
		signature::EcdsaKeyPair::from_pkcs8(alg, pkcs8)._err()
	}
}

#[cfg(all(feature = "crypto", feature = "_aws_lc_like"))]
pub(crate) fn ecdsa_from_private_key_der(
	alg: &'static signature::EcdsaSigningAlgorithm,
	key: &[u8],
) -> Result<signature::EcdsaKeyPair, Error> {
	signature::EcdsaKeyPair::from_private_key_der(alg, key)._err()
}

#[cfg(feature = "crypto")]
pub(crate) fn rsa_key_pair_public_modulus_len(kp: &signature::RsaKeyPair) -> usize {
	#[cfg(all(feature = "ring", not(feature = "_aws_lc_like")))]
	{
		kp.public().modulus_len()
	}

	#[cfg(feature = "_aws_lc_like")]
	{
		kp.public_modulus_len()
	}
}

#[cfg(all(
	feature = "crypto",
	not(any(feature = "ring", feature = "_aws_lc_like"))
))]
compile_error!("At least one of the 'ring' or 'aws_lc_rs' features must be activated when the 'crypto' feature is enabled");
