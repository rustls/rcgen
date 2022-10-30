//! Auto-generate a CA certificate and a server certificate signed
//! by that CA, and start a TLS server and client using them.
//!
//! Run with:
//!
//!     $ cargo run --example auto-gen-ca-and-server-nativetls --features=x509-parser
//!
//! This doesn't start a network service (not even on localhost).
//! Instead, it creates an in-memory TLS server and an in-memory
//! TLS client in two separate threads in the same process.

use std::error::Error;
use std::io::{BufRead, BufReader, Read, Write};
use std::thread;

use native_tls::{HandshakeError, Identity, TlsAcceptor, TlsConnector, TlsStream};
use rcgen::{BasicConstraints, CertificateSigningRequest, DnType, IsCa, SanType, KeyUsagePurpose, DistinguishedName, CertificateParams, Certificate, RcgenError};

const SAN: &str = "example-server";

fn read_line<A: BufRead>(reader: &mut A) -> Result<String, std::io::Error> {
	let mut buffer = String::new();

	reader.read_line(&mut buffer)?;

	Ok(buffer.trim_end().into())
}

fn main() -> Result<(), Box<dyn Error>> {
    let ca = gen_cert_for_ca()?;

    println!("CA private key:\n{}", ca.serialize_private_key_pem());
    println!();
    println!("CA certificate:\n{}", ca.serialize_pem()?);

    let host_cert = gen_cert_for_server(&ca)?;

    println!("Preparing to verify with tls");

    let leaf_then_ca = format!("{}{}", host_cert.signed_certificate_pem, ca.serialize_pem()?);

    println!();
    println!("Server private key:\n{}", host_cert.private_key_pem);
    println!("Server chain:\n{}\n", leaf_then_ca);

    // For use by server
    let server_id = Identity::from_pkcs8(
        leaf_then_ca.as_bytes(),
        host_cert.private_key_pem.as_bytes()
    )?;

    // For use by client
    let native_ca_cert = native_tls::Certificate::from_pem(ca.serialize_pem()?.as_bytes())?;

	// We can use either bipipe or bipipe_buffered when one side reads before it writes, but
	// we cannot use either if both sides write before they read - both sides will block on write.
    let (p_client, p_server) = pipe::bipipe();

    let t_client = thread::spawn(move || -> Result<(), String> {
        println!("Client creating");

        let test_client = TlsConnector::builder()
            .add_root_certificate(native_ca_cert)
            .build()
            .map_err(|e| e.to_string())?;

        println!("Client connecting");

        let mut stream = map_tls_io_error(test_client.connect(SAN, p_client))?;

        println!("Client connected");

		println!("Client sending message");

		let message = "Hello from client.\n".as_bytes();
		stream.write_all(message)
			.unwrap();

		stream.flush().unwrap();

		println!("Client sent message");

		let mut reader = BufReader::new(stream);
		println!("Client received message: {}", read_line(&mut reader).unwrap());

        Ok(())
    });

    let t_server = thread::spawn(move || -> Result<(), String> {
        println!("Server creating");

        let test_server = TlsAcceptor::new(server_id)
            .map_err(|e| e.to_string())?;

        println!("Server accepting");

        let mut stream = map_tls_io_error(test_server.accept(p_server))?;

        println!("Server accepted");

		let mut reader = BufReader::new(&mut stream);
		println!("Server received message: {}", read_line(&mut reader).unwrap());

		println!("Server sending message");

		let message = "Hello from server.\n".as_bytes();
		stream.write_all(message)
			.unwrap();

		println!("Server sent message");

        Ok(())
    });

    println!("Joining client");
    t_client.join()
        .map_err(|e| format!("{:?}", e))??;

    println!("Joining server");
    t_server.join()
        .map_err(|e| format!("{:?}", e))??;

    println!();
    println!("Succeeded.");

    Ok(())
}

struct ServerCertificate {
    private_key_pem: String,

    // Server certificate only; does not include complete certificate chain.
    signed_certificate_pem: String,
}

fn gen_cert_for_ca() -> Result<Certificate, RcgenError> {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CountryName, "USA");
    dn.push(DnType::CommonName, "Auto-Generated CA");

    let mut params = CertificateParams::default();

    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    params.distinguished_name = dn;
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    Certificate::from_params(params)
}

fn gen_cert_for_server(ca: &Certificate) -> Result<ServerCertificate, RcgenError> {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CountryName, "USA");
    dn.push(DnType::CommonName, "Auto-Generated Server");

    let mut params = CertificateParams::default();

    params.is_ca = IsCa::NoCa;
    params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    params.distinguished_name = dn;
    params.subject_alt_names = vec![SanType::DnsName(SAN.into())];

    let unsigned = Certificate::from_params(params)?;

    let request_pem = unsigned.serialize_request_pem()?;

    let csr = CertificateSigningRequest::from_pem(&request_pem)?;

    let signed_pem = csr.serialize_pem_with_signer(&ca)?;

    Ok(ServerCertificate {
        private_key_pem: unsigned.serialize_private_key_pem(),
        signed_certificate_pem: signed_pem
    })
}

fn map_tls_io_error<S>(tls_result: Result<TlsStream<S>, HandshakeError<S>>) -> Result<TlsStream<S>, String>
where
    S: Read + Write
{
    match tls_result {
        Ok(stream) => Ok(stream),
        Err(he) => {
            match he {
                HandshakeError::Failure(e) => Err(format!("{}", e)),
                // Can't directly unwrap because TlsStream doesn't implement Debug trait
                HandshakeError::WouldBlock(_) => Err("Would block".into())
            }
        }
    }
}
