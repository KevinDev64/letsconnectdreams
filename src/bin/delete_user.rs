use std::env::args;
use letsconnectdreams::*;

fn main() {
    let username = args()
        .nth(1)
        .expect("Enter a correct username!");
    let mut conn = establish_connection();
    let result = delete_user(&mut conn, username);
    println!("Is deleted? -> {result}");
}