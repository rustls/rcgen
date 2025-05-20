#![warn(missing_docs)]
//! This library wraps [rcgen] to provide a simple API to generate TLS
//! certificate-chains. Its primary intent is to ease development of
//! applications that verify chains of trust. It can be used for
//! whatever purpose you may need a TLS certificate-chain.

#![warn(unreachable_pub)]

mod cert;
pub use cert::{Ca, CaBuilder, CertificateBuilder, EndEntity, EndEntityBuilder};
