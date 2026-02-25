use diesel::prelude::*;
use self::models::*;
use letsconnectdreams::*;

fn main() {
    use self::schema::users::dsl::*;

    let connection = &mut establish_connection();
    let results = users
        .select(User::as_select())
        .load(connection)
        .expect("Failed to load users!");

    println!("Showing {} users", results.len());
    for result in results {
        println!("Username: {}", result.username);
        println!("Presence: {}", result.presence);
        println!("---------------");
    }
}