use rand::Rng;

use std::net::{Ipv4Addr, UdpSocket};
use ipnetwork::{IpNetwork, Ipv4Network};

const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_MAGIC_COOKIE: u32 = 0x2112A442;
const STUN_SERVER: &str = "stun.nextcloud.com:443";

pub mod models;
pub mod schema;
pub mod server;
pub mod crypto;
pub mod db;

pub use crypto::*;
pub use server::*;
pub use db::*;

fn parse_stun_response(buf: &[u8]) -> Result<(IpNetwork, u16), Box<dyn std::error::Error>> {
    let mut i = 20; 
    let mut ip = [0_u8; 4];
    let mut port: u16 = 0;

    while i < buf.len() {
        let attr_type = u16::from_be_bytes([buf[i], buf[i + 1]]);
        let attr_len = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) as usize;
        i += 4;

        // XOR-MAPPED-ADDRESS
        if attr_type == 0x0020 {
            let family = buf[i + 1];
            port = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
            if family == 0x01 {
                for j in 0..4 {
                    ip[j] = buf[i + 4 + j] ^ (STUN_MAGIC_COOKIE.to_be_bytes()[j]);
                }
            }
        }

        i += attr_len;
        if attr_len % 4 != 0 {
            i += 4 - (attr_len % 4);
        }
    }

    return Ok((IpNetwork::V4(
                Ipv4Network::new(
                    Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]), 
                    0_u8)
                .unwrap()), 
                port))

}

fn get_address_from_stun() -> Result<(IpNetwork, u16), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(std::time::Duration::from_secs(3)))?;
    let mut buf = [0u8; 20];

    buf[0..2].copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    buf[2..4].copy_from_slice(&0u16.to_be_bytes());
    buf[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());

    let mut rng = rand::thread_rng();
    for i in 8..20 {
        buf[i] = rng.r#gen();
    }

    socket.send_to(&buf, STUN_SERVER)?;
    let mut response = [0u8; 1024];
    let (size, _) = socket.recv_from(&mut response)?;

    parse_stun_response(&response[..size])
}


#[cfg(test)]
mod tests {
    #[test]
    fn auth_test_on_user() {
        use crate::crypto::auth::validate_password;
        use crate::db::{establish_connection, users::*};

        let mut conn = establish_connection();
        let test_user = new_user(
            &mut conn, 
            String::from("test"), 
            String::from("secret")
        );
        let result = validate_password(
            &mut conn, 
            &test_user.username.clone(), 
            String::from("secret")
            );
        delete_user(&mut conn, test_user.username);
        assert_eq!(result, Ok(true))
    }

    #[test]
    fn wrong_auth_on_test_user() {
        use crate::crypto::auth::validate_password;
        use crate::db::{establish_connection, users::*};

        let mut conn = establish_connection();
        let test_user = new_user(
            &mut conn, 
            String::from("test"), 
            String::from("secret")
        );
        let result = validate_password(
            &mut conn, 
            &test_user.username.clone(), 
            String::from("SECRET")
            );
        delete_user(&mut conn, test_user.username);
        assert_eq!(result, Ok(false))
    }

    #[test]
    fn test_rsa_crypto() {
        use crate::crypto::rsa::*;
        let (private_key, public_key) = generate_rsa_keypair();
        let some_data = b"some test data";
        let encrypted = rsa_encrypt_message(&public_key, some_data);
        let decrypted = rsa_decrypt_message(&private_key, &encrypted);
        assert_eq!(some_data.to_vec(), decrypted);
    }
}