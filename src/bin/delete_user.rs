use std::env::args;
use letsconnectdreams::db;

fn main() {
    let username = args()
        .nth(1)
        .expect("Enter a correct username!");
    let mut conn = db::establish_connection();
    let result = db::users::delete_user(&mut conn, username);
    println!("Is deleted? -> {result}");
}