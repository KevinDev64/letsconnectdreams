use letsconnectdreams::db;

fn main() {
    let connection = &mut db::establish_connection();
    let users = db::users::list_users(connection);

    for user in users {
        println!("{:#?}", user); 
    }
}