CREATE TABLE users (
    user_id        BIGSERIAL PRIMARY KEY,
    username       VARCHAR(64) UNIQUE NOT NULL,
    password_hash  VARCHAR(255) NOT NULL,

    presence       SMALLINT NOT NULL DEFAULT 0,

    public_ip      INET,
    public_port    INTEGER,
    nat_type       SMALLINT,

    created_at     TIMESTAMP NOT NULL DEFAULT NOW(),
    last_seen      TIMESTAMP
);

CREATE INDEX idx_users_presence ON users(presence);
CREATE INDEX idx_users_username ON users(username);
