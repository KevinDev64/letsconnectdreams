use diesel::PgConnection;
use letsconnectdreams::*;
use rsa::pkcs1::EncodeRsaPublicKey;
use std::io::prelude::*;
use std::net::{TcpListener, TcpStream, Shutdown};
use rsa::{RsaPrivateKey, RsaPublicKey};
use std::str;

fn abort_message(client: NetworkClient, stream: TcpStream) -> Result<(), std::io::Error> {
    println!("ABORTT message from {}", client.peer);
    stream.shutdown(Shutdown::Both)
}

fn receive_utf8_data(mut stream: &TcpStream, data_length: u32) -> Result<String, Box<dyn std::error::Error>> {
    let mut data_buffer = vec![0_u8; data_length.try_into().unwrap()];
    stream.read(&mut data_buffer)?;
    let data = str::from_utf8(&mut data_buffer)?.to_owned();
    Ok(data)
}

fn receive_raw_data(mut stream: &TcpStream, data_length: u32) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut data_buffer = vec![0_u8; data_length.try_into().unwrap()];
    stream.read(&mut data_buffer)?;
    Ok(data_buffer)
}

fn echo_message(client: NetworkClient, raw_length: &[u8; 4], stream: &mut TcpStream) {
    println!("ECHOOO message from {}", client.peer);
    let length = u32::from_be_bytes(raw_length.to_owned());
    println!("Length -> {}", length);

    let data = receive_utf8_data(&stream, length).expect("Not valid data section! (not UTF-8)");
    println!("Data -> {}", data);

    println!("Sending ECHOOO as answer.");
    let mut answer_buffer = [0_u8; 12];
    answer_buffer[2..8].copy_from_slice(b"ECHOOO");
    answer_buffer[8..12].copy_from_slice(&length.to_be_bytes());
    stream.write_all(&answer_buffer).expect("Failed to send ECHOOO answer!");
	stream.write_all(data.as_bytes()).expect("Failed to send data!");
}

fn pubkey_message(client: NetworkClient, pub_key: RsaPublicKey, stream: &mut TcpStream) {
    println!("PUBKEY message from {}", client.peer);
    let pub_key_raw = pub_key.to_pkcs1_pem(rsa::pkcs8::LineEnding::LF).unwrap();
    let pub_key_raw = pub_key_raw.as_bytes();
    let data_length: u32 = pub_key_raw.len() as u32;

    let mut header_buffer = [0_u8; 12];
    header_buffer[2..8].copy_from_slice(b"PUBKEY");
    header_buffer[8..12].copy_from_slice(&data_length.to_be_bytes());
    stream.write_all(&header_buffer).expect("Failed to send PUBKEY header!");
    stream.write_all(pub_key_raw).expect("Failed to send PUBKEY data!");
}

fn authin_message(
        mut client: NetworkClient, 
        priv_key: RsaPrivateKey, 
        raw_length: &[u8; 4],
        conn: &mut PgConnection,
        stream: &mut TcpStream) {
    println!("AUTH request from {}", client.peer);
    let length = u32::from_be_bytes(*raw_length); 
    let data = receive_raw_data(stream, length).unwrap();
    let auth_data = rsa_decrypt_message(&priv_key, &data);
    let auth_data = UserAuthData::from_bytes(&auth_data);
    if validate_password(conn, auth_data.username, auth_data.password).unwrap() {
        // AUTHOK answer
        let mut answer_buffer = [0_u8; 12];
        answer_buffer[2..8].copy_from_slice(b"AUTHOK");
        client.is_authorized = true; // TODO: when session closes -> change is_authorized to `false`
    } else {
        // AUTHER answer
        let mut answer_buffer = [0_u8; 12];
        answer_buffer[2..8].copy_from_slice(b"AUTHER");
    }

}

fn handle_client(mut stream: TcpStream, keypair: (RsaPrivateKey, RsaPublicKey), mut conn: PgConnection) {
    let priv_key = keypair.0;
    let pub_key = keypair.1;

    loop {
        let this_connection = NetworkClient {
            peer: stream.peer_addr().expect("Unknown peer address!"),
            is_authorized: false,
            user: None
        };

        let mut header_buffer = [0; 12];
        stream.read(&mut header_buffer).expect("Failed to read header!");
        
        if &header_buffer[..2] == [0; 2] {
            println!("Client sent {:?}", &header_buffer[2..12]);
            let mut raw_length: Vec<u8> = vec![0; 4];
            raw_length[..].clone_from_slice(&header_buffer[8..12]);
            let raw_length = raw_length.as_array().unwrap();
            match str::from_utf8(&header_buffer[2..8]).unwrap() {
                "ABORTT" => {
                    abort_message(this_connection, stream).unwrap();
                    break;
                },
                "ECHOOO" => {
                    echo_message(this_connection, raw_length, &mut stream);
                },
                "PUBKEY" => {
                    pubkey_message(this_connection, pub_key.clone(), &mut stream);
                },
                "AUTHIN" => {
                    authin_message(this_connection, priv_key.clone(), raw_length, &mut conn, &mut stream);
                },
                "\0\0\0\0\0\0" => {
                    println!("Client closed the connection.");
                    break;
                }
                _ => panic!("Wrong message type in header!"),
            }
        }
    }
}

fn main() {
    let listener = TcpListener::bind("127.0.0.1:4222")
        .expect("Failed to bind address!");
    
    for stream in listener.incoming() {
        handle_client(stream.unwrap(), get_rsa_keypair(), establish_connection());
    }
}