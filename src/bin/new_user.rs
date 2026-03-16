use std::env::args;
use letsconnectdreams::db;

fn main() {
    let username = args()
        .nth(1)
        .expect("Enter a correct username!");
    let password = args()
        .nth(2)
        .expect("Enter a correct password!");

    let connection = &mut db::establish_connection();
    let new_user = db::users::new_user(connection, username, password);

    println!("{:#?}", new_user);
}