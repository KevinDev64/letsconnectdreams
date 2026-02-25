use diesel::prelude::*;
use dotenvy::dotenv;
use std::env;
use self::models::{NewUser, User};

pub mod models;
pub mod schema;


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
        password_hash: password
    };

    diesel::insert_into(users::table)
        .values(&new_user)
        .returning(User::as_returning())
        .get_result(conn)
        .expect("Failed to create new user!")
}

pub fn list_users(conn: &mut PgConnection) -> Vec<User> {
    use crate::schema::users::dsl::*;

    let results = users
        .select(User::as_select())
        .load(conn)
        .expect("Failed to load users!");
    results
}