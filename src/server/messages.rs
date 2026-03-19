use std::net::TcpStream;
use std::net::Shutdown;
use std::io::prelude::*;

use diesel::prelude::*;

use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::{RsaPrivateKey, RsaPublicKey};

use crate::Presence;
use crate::server::{NetworkClient, UserAuthData};
use crate::server::{receive_raw_data, receive_utf8_data};
use crate::crypto::rsa::*;
use crate::crypto::auth::validate_password;
use crate::users::get_user_by_username;
use crate::users::update_address_and_port;
use crate::users::update_presence;

pub fn abortt_handler(client: &mut NetworkClient, stream: TcpStream) -> Result<(), std::io::Error> {
    println!("ABORTT message from {}", client.peer);
    client.is_authorized = false;
    stream.shutdown(Shutdown::Both)
}

pub fn echooo_handler(client: &mut NetworkClient, raw_length: &[u8; 4], stream: &mut TcpStream) {
    println!("ECHOOO message from {}", client.peer);
    let length = u32::from_be_bytes(raw_length.to_owned());
    let data = receive_utf8_data(&stream, length).expect("Not valid data section! (not UTF-8)");

    let mut answer_buffer = [0_u8; 12];
    answer_buffer[2..8].copy_from_slice(b"ECHOOO");
    answer_buffer[8..12].copy_from_slice(&length.to_be_bytes());
    stream.write_all(&answer_buffer).expect("Failed to send ECHOOO answer!");
	stream.write_all(data.as_bytes()).expect("Failed to send data!");
}

pub fn pubsrv_handler(client: &mut NetworkClient, pub_key: RsaPublicKey, stream: &mut TcpStream) {
    println!("PUBSRV message from {}", client.peer);
    let pub_key_raw = pub_key.to_pkcs1_pem(rsa::pkcs8::LineEnding::LF).unwrap();
    let pub_key_raw = pub_key_raw.as_bytes();
    let data_length: u32 = pub_key_raw.len() as u32;

    let mut header_buffer = [0_u8; 12];
    header_buffer[2..8].copy_from_slice(b"PUBKEY");
    header_buffer[8..12].copy_from_slice(&data_length.to_be_bytes());
    stream.write_all(&header_buffer).expect("Failed to send PUBKEY header!");
    stream.write_all(pub_key_raw).expect("Failed to send PUBKEY data!");
}

pub fn pubkey_handler(client: &mut NetworkClient, raw_length: &[u8; 4], stream: &mut TcpStream) {
    println!("PUBKEY message from {}", client.peer);
    let length = u32::from_be_bytes(*raw_length);
    let data = receive_utf8_data(stream, length).unwrap();
    client.auth_data = Some(UserAuthData::init_pubkey(data));
    // println!("{:?}", client);
}

pub fn helloo_handler(client: &mut NetworkClient, raw_length: &[u8; 4], priv_key: RsaPrivateKey, stream: &mut TcpStream) {
    println!("HELLOO message from {}", client.peer);
    let pub_key = client.auth_data.as_ref().unwrap().pub_key.as_ref().unwrap();
    let length = u32::from_be_bytes(*raw_length);
    let data = receive_raw_data(stream, length).unwrap();
    let decrypted_raw = rsa_decrypt_message(&priv_key, &data);
    let decrypted = str::from_utf8(&decrypted_raw).unwrap();
    println!("Decrypted message from HELLOO: {}", decrypted);

    let mut header_buffer = [0_u8; 12];
    header_buffer[2..8].copy_from_slice(b"HELLOO");
    let data = String::from("I'm server!");
    let data = data.as_bytes();
    let data = rsa_encrypt_message(pub_key, data);
    let length = data.len() as u32;
    let length_raw = length.to_be_bytes();
    header_buffer[8..12].copy_from_slice(&length_raw);
    stream.write_all(&header_buffer).expect("Failed to send HELLOO answer header!");
    stream.write_all(&data).expect("Failed to send HELLOO answer data!");
}

pub fn authin_handler(
        client: &mut NetworkClient, 
        priv_key: RsaPrivateKey, 
        raw_length: &[u8; 4],
        conn: &mut PgConnection,
        stream: &mut TcpStream) {
    println!("AUTHIN request from {}", client.peer);
    let length = u32::from_be_bytes(*raw_length); 
    let data = receive_raw_data(stream, length).unwrap();
    let auth_data = rsa_decrypt_message(&priv_key, &data);
    let auth_data = UserAuthData::from_bytes(&auth_data);
    if validate_password(conn, auth_data.username.as_ref().unwrap(), auth_data.password.unwrap()).unwrap() {
        println!("AUTHOK response to {}", client.peer);
        let mut answer_buffer = [0_u8; 12];
        answer_buffer[2..8].copy_from_slice(b"AUTHOK");
        client.is_authorized = true; 
        client.user = match get_user_by_username(auth_data.username.as_ref().unwrap(), conn) {
            Ok(user) => { Some(user) },
            Err(()) => {
                panic!("Authorized unknown user!");
            }
        };
        update_presence(conn, client, Presence::Online).unwrap();
        stream.write_all(&answer_buffer).expect("Failed to send AUTHIN answer!");
    } else {
        println!("AUTHER response to {}", client.peer);
        let mut answer_buffer = [0_u8; 12];
        answer_buffer[2..8].copy_from_slice(b"AUTHER");
        stream.write_all(&answer_buffer).expect("Failed to send AUTHIN answer!");
    }
}

pub fn updadr_handler(
        client: &mut NetworkClient,
        priv_key: RsaPrivateKey,
        raw_length: &[u8; 4],
        conn: &mut PgConnection,
        stream: &mut TcpStream ) {
    println!("UPDADR request from {}", client.peer);
    if !(client.is_authorized) {
        let mut answer_buffer = [0_u8; 12];
        answer_buffer[2..8].copy_from_slice(b"FORBID");
        stream.write_all(&mut answer_buffer).expect("Failed to send FORBID answer!");
        return;
    }
    let length = u32::from_be_bytes(*raw_length);
    let data = receive_raw_data(stream, length).unwrap();
    let data = rsa_decrypt_message(&priv_key, &data);
    let data = str::from_utf8(&data).unwrap();
    let data: Vec<&str> = data.split_ascii_whitespace().collect();
    update_address_and_port(
        conn, 
        client, 
        data.get(0).map(|v| &**v), 
        data.get(1).map(|v| &**v)).unwrap();
    println!("{:?}", data);
}