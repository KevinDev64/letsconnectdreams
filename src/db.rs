use diesel::prelude::*;
use dotenvy::dotenv;
use std::env;

pub mod users;

pub fn establish_connection() -> PgConnection {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("Failed to parse ENV");
    PgConnection::establish(&database_url)
        .unwrap_or_else(|_| panic!("Failed to connect to DB!"))
}