pub mod messages;

use std::net::TcpStream;
use std::net::SocketAddr;
use std::io::prelude::*;

use rsa::pkcs1::{DecodeRsaPublicKey};
use rsa::{RsaPrivateKey, RsaPublicKey};

use diesel::prelude::*;

use messages::*;
use crate::models::*;

#[derive(Debug)]
pub struct NetworkClient {
    pub peer: SocketAddr,
    pub is_authorized: bool,
    pub user: Option<User>,
    pub auth_data: Option<UserAuthData>
}

#[derive(Debug)]
pub struct UserAuthData {
    pub username: Option<String>,
    pub password: Option<String>,
    pub pub_key: Option<RsaPublicKey>
}

pub enum NATType {
    Unknown = 0,
    FullCone,
    Restricted, 
    PortRestricted, 
    Symmetric 
}

impl TryFrom<i16> for NATType {
    type Error = ();
    fn try_from(value: i16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(NATType::Unknown),
            1 => Ok(NATType::FullCone),
            2 => Ok(NATType::Restricted),
            3 => Ok(NATType::PortRestricted),
            4 => Ok(NATType::Symmetric),
            _ => Err(())
        }
    }
}

#[derive(Debug)]
pub enum Presence {
    Offline = 0,
    Online,
    Connecting,
    Punching
}

impl TryFrom<i16> for Presence {
    type Error = ();
    fn try_from(value: i16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Presence::Offline),
            1 => Ok(Presence::Online),
            2 => Ok(Presence::Connecting),
            3 => Ok(Presence::Punching),
            _ => Err(())
        }
    }
}

impl UserAuthData {
    pub fn from_bytes(auth_data: &[u8]) -> UserAuthData {
        let mut auth_data = str::from_utf8(&auth_data)
            .unwrap()
            .split_ascii_whitespace();
        let username = Some(auth_data.next().unwrap().to_string());
        let password = Some(auth_data.next().unwrap().to_string()) ;

        UserAuthData { username, password, pub_key: None }
    }

    pub fn init_pubkey(pub_key_string: String) -> UserAuthData {
        let pub_key = Some(RsaPublicKey::from_pkcs1_pem(&pub_key_string).unwrap());
        UserAuthData { username: None, password: None, pub_key }
    }
}

pub fn receive_utf8_data(mut stream: &TcpStream, data_length: u32) -> Result<String, Box<dyn std::error::Error>> {
    let mut data_buffer = vec![0_u8; data_length.try_into().unwrap()];
    stream.read(&mut data_buffer)?;
    let data = str::from_utf8(&mut data_buffer)?.to_owned();
    Ok(data)
}

pub fn receive_raw_data(mut stream: &TcpStream, data_length: u32) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut data_buffer = vec![0_u8; data_length.try_into().unwrap()];
    stream.read(&mut data_buffer)?;
    Ok(data_buffer)
}

pub fn handle_client(mut stream: TcpStream, keypair: (RsaPrivateKey, RsaPublicKey), mut conn: PgConnection) {
    let priv_key = keypair.0;
    let pub_key = keypair.1;
    let mut this_connection = NetworkClient {
                peer: stream.peer_addr().expect("Unknown peer address!"),
                is_authorized: false,
                user: None,
                auth_data: None
            };
    loop {
        

        let mut header_buffer = [0; 12];
        stream.read(&mut header_buffer).expect("Failed to read header!");
        
        if &header_buffer[..2] == [0; 2] {
            // println!("Client sent {:?}", &header_buffer[2..12]);
            let mut raw_length: Vec<u8> = vec![0; 4];
            raw_length[..].clone_from_slice(&header_buffer[8..12]);
            let raw_length = raw_length.as_array().unwrap();
            match str::from_utf8(&header_buffer[2..8]).unwrap() {
                "ABORTT" => {
                    abortt_handler(&mut this_connection, stream).unwrap();
                    break;
                },
                "ECHOOO" => {
                    echooo_handler(&mut this_connection, raw_length, &mut stream);
                },
                "PUBSRV" => {
                    pubsrv_handler(&mut this_connection, pub_key.clone(), &mut stream);
                },
                "PUBKEY" => {
                    pubkey_handler(&mut this_connection, raw_length, &mut stream);
                },
                "AUTHIN" => {
                    authin_handler(&mut this_connection, priv_key.clone(), raw_length, &mut conn, &mut stream);
                },
                "HELLOO" => {
                    helloo_handler(&mut this_connection, raw_length, priv_key.clone(), &mut stream);
                },
                "\0\0\0\0\0\0" => {
                    println!("Client closed the connection.");
                    this_connection.is_authorized = false;
                    break;
                }
                _ => panic!("Wrong message type in header!"),
            }
        }
    }
}