use std::env::args;
use letsconnectdreams::*;

fn main() {
    let mut conn = establish_connection();
    let username = args()
        .nth(1)
        .expect("Enter a valid username!");
    let password = args()
        .nth(2)
        .expect("Enter a valid password!");

    let result = validate_password(&mut conn, username, password).unwrap();
    println!("Is valid? -> {result}");
}