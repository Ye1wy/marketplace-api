CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT NOT NULL,
    password VARCHAR NOT NULL,
    email TEXT NOT NULL,
    UNIQUE(username)
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY NOT NULL,
    user_id UUID NOT NULL,
    token_hash TEXT NOT NULL,
    expire_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS ads (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    price FLOAT NOT NULL,
    image_url TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT now(),
    author_id UUID NOT NULL REFERENCES users(id)
);

ALTER TABLE refresh_tokens
ADD CONSTRAINT fk_user
FOREIGN KEY (user_id) REFERENCES users(id)
ON DELETE CASCADE;