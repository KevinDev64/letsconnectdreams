use std::env::args;
use letsconnectdreams::*;

fn main() {
    let username = args()
        .nth(1)
        .expect("Enter a correct username!");
    let password = args()
        .nth(2)
        .expect("Enter a correct password!");

    let connection = &mut establish_connection();
    let new_user = new_user(connection, username, password);

    println!("{:#?}", new_user);
}