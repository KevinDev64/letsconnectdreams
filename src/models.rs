use diesel::prelude::*;
use ipnetwork::IpNetwork;
use std::time::SystemTime;

#[derive(Queryable, Selectable, Debug)]
#[diesel(table_name = crate::schema::users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct User {
    pub user_id: i64,
    pub username: String,
    pub password_hash: String,
    pub presence: i16,
    pub public_ip: Option<IpNetwork>,
    pub public_port: Option<i32>,
    pub nat_type: Option<i16>,
    pub created_at: SystemTime,
    pub last_seen: Option<SystemTime>
}

use crate::schema::users;

#[derive(Insertable)]
#[diesel(table_name = users)]
pub struct NewUser {
    pub username: String,
    pub password_hash: String
}