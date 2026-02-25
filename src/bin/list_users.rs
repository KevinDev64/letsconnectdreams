use letsconnectdreams::{establish_connection, list_users};

fn main() {
    let connection = &mut establish_connection();
    let users = list_users(connection);

    for user in users {
        println!("{:#?}", user); 
    }
}