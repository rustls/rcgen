//! Auto-generate a CA certificate and a server certificate signed
//! by that CA, and start a TLS server and client using them.
//!
//! Run with:
//!
//!     $ cargo run --example auto-gen-ca-and-server-tls --features=x509-parser
//!
//! This doesn't start a network service (not even on localhost).
//! Instead, it creates an in-memory TLS server and an in-memory
//! TLS client in two separate threads in the same process.

use std::error::Error;
use std::io::{BufRead, BufReader, Write};
use std::sync::Arc;
use std::thread;
use rustls;
use rustls::{PrivateKey, RootCertStore, ServerName};
use rustls::server::Acceptor;

use rcgen::{BasicConstraints, CertificateSigningRequest, DnType, IsCa, SanType, KeyUsagePurpose, DistinguishedName, CertificateParams, Certificate, RcgenError};

const SAN: &str = "example-server";

fn read_line<A: BufRead>(reader: &mut A) -> Result<String, std::io::Error> {
	let mut buffer = String::new();

	reader.read_line(&mut buffer)?;

	Ok(buffer.trim_end().into())
}

fn main() -> Result<(), Box<dyn Error>> {
    let ca = gen_cert_for_ca()?;
	let rustls_ca = rustls::Certificate(ca.serialize_der().unwrap());

    println!("CA private key:\n{}", ca.serialize_private_key_pem());
    println!();
    println!("CA certificate:\n{}", ca.serialize_pem()?);

    let host_cert = gen_cert_for_server(&ca)?;
	let host_cert_rustls = rustls::Certificate(host_cert.signed_certificate_der);
	let host_pk = PrivateKey(host_cert.private_key_der);

    println!("Preparing to verify with tls");

    let leaf_then_ca = vec![host_cert_rustls, rustls_ca.clone()];

    println!();

	// Does not work with either buffered or unbuffered bipipe, even when we use the same message
	// pattern as with the nativetls example, where client sends then reads, and server reads and
	// then sends. Client blocks sending a message; server blocks reading a message.
    let (mut p_client, mut p_server) = pipe::bipipe_buffered();

    let t_client = thread::spawn(move || -> Result<(), String> {
        println!("Client creating");

		let mut root_store = RootCertStore::empty();

		root_store.add(&rustls_ca)
			.unwrap();

		let client_config = Arc::new(
			rustls::ClientConfig::builder()
				.with_safe_defaults()
				.with_root_certificates(root_store)
				.with_no_client_auth()
		);

		let server_name = ServerName::try_from(SAN)
			.unwrap();

        println!("Client connecting");

		let mut conn = rustls::ClientConnection::new(client_config, server_name)
			.unwrap();

        println!("Client connected");

		let mut stream = rustls::Stream::new(&mut conn, &mut p_client);

		println!("Client handshaking? {}", stream.conn.is_handshaking());

		stream.conn.process_new_packets().unwrap();

		println!("Client handshaking? {}", stream.conn.is_handshaking());

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

		let server_config = Arc::new(
			rustls::ServerConfig::builder()
				.with_safe_defaults()
				.with_no_client_auth()
				.with_single_cert(leaf_then_ca, host_pk)
				.unwrap()
		);

		let mut acceptor = Acceptor::default();

		println!("Server accepting");
		let accepted = loop {
			acceptor.read_tls(&mut p_server)
				.unwrap();

			if let Some(accepted) = acceptor.accept().unwrap() {
				break accepted;
			}
		};


		let mut conn = accepted.into_connection(server_config)
			.unwrap();

        println!("Server accepted");

		let mut stream = rustls::Stream::new(&mut conn, &mut p_server);

		println!("Server handshaking? {}", stream.conn.is_handshaking());

		stream.conn.process_new_packets().unwrap();

		println!("Server handshaking? {}", stream.conn.is_handshaking());

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
    private_key_der: Vec<u8>,

    // Server certificate only; does not include complete certificate chain.
    signed_certificate_der: Vec<u8>,
}

// Create a certificate authority using rcgen and return and rcgen::Certificate.
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

// Create a server (host) certificate using rcgen and return it encoded into the DER format.
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

    let signed_der = csr.serialize_der_with_signer(&ca)?;

    Ok(ServerCertificate {
        private_key_der: unsigned.serialize_private_key_der(),
        signed_certificate_der: signed_der
    })
}
