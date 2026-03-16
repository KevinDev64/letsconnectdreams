use std::env::args;
use letsconnectdreams::db;
use letsconnectdreams::crypto::auth;

fn main() {
    let mut conn = db::establish_connection();
    let username = args()
        .nth(1)
        .expect("Enter a valid username!");
    let password = args()
        .nth(2)
        .expect("Enter a valid password!");

    let result = auth::validate_password(&mut conn, &username, password).unwrap();
    println!("Is valid? -> {result}");
}