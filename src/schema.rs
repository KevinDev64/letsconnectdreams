// @generated automatically by Diesel CLI.

diesel::table! {
    users (user_id) {
        user_id -> Int8,
        #[max_length = 64]
        username -> Varchar,
        #[max_length = 255]
        password_hash -> Varchar,
        presence -> Int2,
        public_ip -> Nullable<Inet>,
        public_port -> Nullable<Int4>,
        nat_type -> Nullable<Int2>,
        created_at -> Timestamp,
        last_seen -> Nullable<Timestamp>,
    }
}
