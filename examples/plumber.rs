/// Exchange messages across a bidirectional pipe.
///
/// Provided for comparison with auto-gen-ca-and-server-tls, which uses a bidirectional pipe in
/// its implementation, but fails to exchange messages bidirectionally over TLS.

use std::error::Error;
use std::io::{BufRead, Write};
use std::thread;

fn read_line<A: BufRead>(reader: &mut A) -> Result<String, std::io::Error> {
	let mut buffer = String::new();

	reader.read_line(&mut buffer)?;

	Ok(buffer.trim_end().into())
}

fn main() -> Result<(), Box<dyn Error>> {
	// When using pipe::bipipe(), at least one side must read before it writes.
	// When using bipipe_buffered(), both sides can write before they read.
    let (p_client, p_server) = pipe::bipipe();

    let t_client = thread::spawn(move || -> Result<(), String> {
        println!("Client creating");

		let mut text_reader = p_client.0;
		let mut text_writer = p_client.1;

		println!("Client pinging");

		text_writer.write_all("Ping\n".as_bytes())
			.unwrap();

		println!("Client pinged");

		let response = read_line(&mut text_reader)
			.unwrap();

		println!("Client received response: {}", response);

        Ok(())
    });

    let t_server = thread::spawn(move || -> Result<(), String> {
        println!("Server creating");

		let mut text_reader = p_server.0;
		let mut text_writer = p_server.1;

		let request = read_line(&mut text_reader)
			.unwrap();

		println!("Server received request: {}", request);

		println!("Server sending response");

		text_writer.write_all("Pong\n".as_bytes())
			.unwrap();

		println!("Server sent response");

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
