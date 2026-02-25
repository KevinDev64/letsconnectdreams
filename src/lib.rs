use diesel::prelude::*;
use dotenvy::dotenv;
use std::env;

use self::models::{NewUser, User};
use bcrypt::{self, DEFAULT_COST};

pub mod models;
pub mod schema;

pub enum BcryptVersion {
    TwoA,
    TwoX,
    TwoY,
    TwoB,
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


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_test_user() {
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
}