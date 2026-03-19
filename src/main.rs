use letsconnectdreams::*;
use letsconnectdreams::rsa::*;

use std::net::TcpListener;


fn main() {
    let listener = TcpListener::bind("127.0.0.1:4222")
        .expect("Failed to bind address!");
    
    for stream in listener.incoming() {
        handle_client(stream.unwrap(), get_rsa_keypair(), establish_connection());
    }
}