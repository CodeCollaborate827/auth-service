-- V1__Create_initial_schema.sql

-- Create users table
CREATE TABLE users
(
    id             VARCHAR(255) PRIMARY KEY,
    username       VARCHAR(255),
    email          VARCHAR(255),
    passwordHash   INTEGER,
    account_type  VARCHAR(255),
    account_status VARCHAR(255),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create verification_code table
CREATE TABLE verification_code
(
    id         SERIAL PRIMARY KEY,
    user_id    VARCHAR(255) REFERENCES users (id),
    expiration TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    type      VARCHAR(255),
    code       VARCHAR(255),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create authentication_settings table
CREATE TABLE authentication_settings
(
    id                     SERIAL PRIMARY KEY,
    user_id                VARCHAR(255) REFERENCES users (id),
    mfa_enabled            BOOLEAN,
    new_login_notification BOOLEAN,
    mfa_type              VARCHAR(255),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create login_history table
CREATE TABLE login_history
(
    id            SERIAL PRIMARY KEY,
    user_id       VARCHAR(255) REFERENCES users (id),
    ip_address    VARCHAR(255),
    user_agent     VARCHAR(255),
    is_successful BOOLEAN,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create refresh_tokens table
CREATE TABLE refresh_tokens
(
    id                SERIAL PRIMARY KEY,
    login_history_id  INTEGER REFERENCES login_history (id),
    refresh_token     VARCHAR(255),
    usage_count       INTEGER,
    limit_usage_count INTEGER,
    last_used         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);