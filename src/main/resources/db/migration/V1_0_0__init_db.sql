-- V1__Create_initial_schema.sql
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create users table
CREATE TABLE users
(
    id             UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    username       VARCHAR(255) unique ,
    email          VARCHAR(255) unique ,
    password_hash   VARCHAR(255),
    account_type  VARCHAR(255),
    account_status VARCHAR(255),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create verification_code table
CREATE TABLE verification_code
(
    id         UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_email     VARCHAR(255) REFERENCES users (email),
    expiration TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    type      VARCHAR(255),
    code       VARCHAR(255),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create authentication_settings table
CREATE TABLE authentication_settings
(
    id                     UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id                UUID REFERENCES users (id),
    mfa_enabled            BOOLEAN,
    new_login_notification BOOLEAN,
    mfa_type              VARCHAR(255),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create login_history table
CREATE TABLE login_history
(
    id            UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id       UUID REFERENCES users (id),
    ip_address    VARCHAR(255),
    user_agent     VARCHAR(255),
    is_successful BOOLEAN,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE application_tokens
(
    id                UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    token     TEXT,
    token_type VARCHAR(255),
    usage_count       INTEGER,
    limit_usage_count INTEGER,
    last_used         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);