use diesel::prelude::*;
use crate::crypto::auth::hash_password;
use crate::models::*;

pub fn new_user(conn: &mut PgConnection, username: String, password: String) -> User {
    use crate::schema::users;

    let new_user = NewUser { 
        username: username, 
        password_hash: hash_password(password)
    };

    diesel::insert_into(users::table)
        .values(&new_user)
        .returning(User::as_returning())
        .get_result(conn)
        .expect("Failed to create new user!")
}

pub fn delete_user(conn: &mut PgConnection, input_username: String) -> bool {
    use crate::schema::users::dsl::*;

    let is_deleted = match diesel::delete(users.filter(username.eq(input_username)))
        .execute(conn)
        .expect("Failed to delete user!") {
            1 => true,
            _ => false
        };
    is_deleted
}

pub fn list_users(conn: &mut PgConnection) -> Vec<User> {
    use crate::schema::users::dsl::*;

    let results = users
        .select(User::as_select())
        .load(conn)
        .expect("Failed to load users!");
    results
}