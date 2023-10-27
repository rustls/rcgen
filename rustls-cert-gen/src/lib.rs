#![warn(missing_docs)]
//! This library wraps [rcgen] to provide a simple API to generate TLS
//! certificate-chains. Its primary intent is to ease development of
//! applications that verify chain of trust. It can be used for
//! whatever purpose you may need a TLS certificate-chain.

mod cert;
pub use cert::CertificateBuilder;

/// A specialized `Result` type.
pub type Result<T> = std::result::Result<T, Error>;
/// This is defined as a convenience.
pub type Error = Box<dyn std::error::Error + Send + Sync>;
