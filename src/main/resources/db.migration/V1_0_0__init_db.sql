-- V1__Create_initial_schema.sql

-- Create users table
CREATE TABLE users (
                       id VARCHAR PRIMARY KEY,
                       username INTEGER,
                       email VARCHAR,
                       passwordHash INTEGER,
                       account_type ENUM,
                       account_status ENUM,
                       createdAt TIMESTAMP,
                       updatedAt TIMESTAMP
);

-- Create verification_code table
CREATE TABLE verification_code (
                                   id SERIAL PRIMARY KEY,
                                   user_id VARCHAR REFERENCES users(id),
                                   expiration TIMESTAMP,
                                   type ENUM,
                                   code VARCHAR,
                                   createdAt TIMESTAMP,
                                   updatedAt TIMESTAMP
);

-- Create authentication_settings table
CREATE TABLE authentication_settings (
                                         id SERIAL PRIMARY KEY,
                                         user_id VARCHAR REFERENCES users(id),
                                         mfa_enabled BOOLEAN,
                                         new_login_notification BOOLEAN,
                                         mfa_type ENUM,
                                         createdAt TIMESTAMP,
                                         updatedAt TIMESTAMP
);

-- Create login_history table
CREATE TABLE login_history (
                               id SERIAL PRIMARY KEY,
                               user_id VARCHAR REFERENCES users(id),
                               ip_address VARCHAR,
                               user_agent STRING,
                               is_successful BOOLEAN,
                               createdAt TIMESTAMP,
                               updatedAt TIMESTAMP
);

-- Create refresh_tokens table
CREATE TABLE refresh_tokens (
                                id SERIAL PRIMARY KEY,
                                login_history_id INTEGER REFERENCES login_history(id),
                                refresh_token VARCHAR,
                                usage_count INTEGER,
                                limit_usage_count INTEGER,
                                last_used TIMESTAMP,
                                createdAt TIMESTAMP,
                                updatedAt TIMESTAMP
);