use diesel::prelude::*;
use dotenvy::dotenv;
use rand::rngs::OsRng;
use rsa::traits::PaddingScheme;
use std::{env, fmt::Display};

use std::net::SocketAddr;

use self::models::{NewUser, User};
use bcrypt::{self, DEFAULT_COST};

use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};

pub mod models;
pub mod schema;

pub enum NATType {
    Unknown = 0,
    FullCone,
    Restricted, 
    PortRestricted, 
    Symmetric 
}

pub enum Message {
    AUTHIN(UserAuthData),
    AUTHOK(String),
    AUTHER(String),
    ECHO(String),
    ABORTT,
}

impl Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", self)
    }
}

pub struct NetworkClient {
    pub peer: SocketAddr,
    pub is_authorized: bool,
    pub user: Option<User>
}

pub struct UserAuthData {
    pub username: String,
    pub password: String
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

pub fn establish_connection() -> PgConnection {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("Failed to parse ENV");
    PgConnection::establish(&database_url)
        .unwrap_or_else(|_| panic!("Failed to connect to DB!"))
}

pub fn new_user(conn: &mut PgConnection, username: String, password: String) -> User {
    use crate::schema::users;

    let new_user = NewUser { 
        username: username, 
        password_hash: hash_password(password)
    };

    diesel::insert_into(users::table)
        .values(&new_user)
        .returning(User::as_returning())
        .get_result(conn)
        .expect("Failed to create new user!")
}

pub fn delete_user(conn: &mut PgConnection, input_username: String) -> bool {
    use crate::schema::users::dsl::*;

    let is_deleted = match diesel::delete(users.filter(username.eq(input_username)))
        .execute(conn)
        .expect("Failed to delete user!") {
            1 => true,
            _ => false
        };
    is_deleted
}

pub fn list_users(conn: &mut PgConnection) -> Vec<User> {
    use crate::schema::users::dsl::*;

    let results = users
        .select(User::as_select())
        .load(conn)
        .expect("Failed to load users!");
    results
}

pub fn hash_password(password: String) -> String {
    bcrypt::hash(password, DEFAULT_COST).unwrap()
} 

pub fn validate_password(conn: &mut PgConnection, input_username: String, input_password: String) -> Result<bool, String> {
    use crate::schema::users::dsl::*;

    let db_password = match users
        .select(password_hash)
        .filter(username.eq(input_username))
        .load::<String>(conn) {
            Ok(hashed_password_vec) => {
                if hashed_password_vec.len() == 0 {
                    Err(String::from("user not found!"))
                }
                else {
                    Ok(hashed_password_vec[0].clone())
                }
            },
            Err(err) => Err(format!("DB error! {err}", ))
        };
    match db_password {
        Ok(db_password) => {
            if bcrypt::verify(input_password, db_password.as_str()).unwrap() {
                return Ok(true);
            } else { 
                return Ok(false);
            }
        },
        Err(err) => Err(err)
    }  
}

pub fn generate_rsa_keypair() -> (RsaPrivateKey, RsaPublicKey) {
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 3072)
        .expect("Failed to generate RSA keypair!");
    let public_key = RsaPublicKey::from(&private_key);
    (private_key, public_key)
}

pub fn rsa_encrypt_message(public_key: &RsaPublicKey, message: &[u8]) -> Vec<u8> {
    let mut rng = OsRng;
    public_key.encrypt(&mut rng, Pkcs1v15Encrypt, message)
        .expect("Failed to encrypt message!")
}

pub fn rsa_decrypt_message(private_key: &RsaPrivateKey, message: &[u8]) -> Vec<u8> {
    let mut rng = OsRng;
    private_key.decrypt(Pkcs1v15Encrypt, message)
        .expect("Failed to decrypt message!")
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_test_on_user() {
        let mut conn = establish_connection();
        let test_user = new_user(
            &mut conn, 
            String::from("test"), 
            String::from("secret")
        );
        let result = validate_password(
            &mut conn, 
            test_user.username.clone(), 
            String::from("secret")
            );
        delete_user(&mut conn, test_user.username);
        assert_eq!(result, Ok(true))
    }

    #[test]
    fn wrong_auth_on_test_user() {
        let mut conn = establish_connection();
        let test_user = new_user(
            &mut conn, 
            String::from("test"), 
            String::from("secret")
        );
        let result = validate_password(
            &mut conn, 
            test_user.username.clone(), 
            String::from("SECRET")
            );
        delete_user(&mut conn, test_user.username);
        assert_eq!(result, Ok(false))
    }

    #[test]
    fn test_rsa_crypto() {
        let (private_key, public_key) = generate_rsa_keypair();
        let some_data = b"some test data";
        let encrypted = rsa_encrypt_message(&public_key, some_data);
        let decrypted = rsa_decrypt_message(&private_key, &encrypted);
        assert_eq!(some_data.to_vec(), decrypted);
    }
}