use bcrypt::{self, DEFAULT_COST};
use diesel::prelude::*;

pub fn hash_password(password: String) -> String {
    bcrypt::hash(password, DEFAULT_COST).unwrap()
} 

pub fn validate_password(conn: &mut PgConnection, input_username: &String, input_password: String) -> Result<bool, String> {
    use crate::schema::users::dsl::*;

    let db_password = match users
        .select(password_hash)
        .filter(username.eq(input_username))
        .load::<String>(conn) {
            Ok(hashed_password_vec) => {
                if hashed_password_vec.len() == 0 {
                    Err(String::from("user not found!"))
                }
                else {
                    Ok(hashed_password_vec[0].clone())
                }
            },
            Err(err) => Err(format!("DB error! {err}", ))
        };
    match db_password {
        Ok(db_password) => {
            if bcrypt::verify(input_password, db_password.as_str()).unwrap() {
                return Ok(true);
            } else { 
                return Ok(false);
            }
        },
        Err(err) => Err(err)
    }  
}