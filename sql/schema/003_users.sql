-- +goose UP
ALTER TABLE users
ADD COLUMN hashed_password TEXT NOT NULL DEFAULT 'unset';

-- +goose DOWN
ALTER TABLE users
DROP COLUMN hashed_password;