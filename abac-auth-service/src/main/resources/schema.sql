CREATE TABLE users (
    id NUMBER(10) PRIMARY KEY,
    username VARCHAR2(50) UNIQUE NOT NULL,
    password VARCHAR2(100) NOT NULL
);

CREATE TABLE user_roles (
    user_id NUMBER(10),
    role VARCHAR2(50),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE user_attributes (
    user_id NUMBER(10),
    attribute_name VARCHAR2(50),
    attribute_value VARCHAR2(100),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE rsa_keys (
    id NUMBER(10) PRIMARY KEY,
    public_key VARCHAR2(2048) NOT NULL,
    private_key VARCHAR2(2048) NOT NULL,
    active NUMBER(1) DEFAULT 1,
    created_at NUMBER(15) NOT NULL,
    last_rotated_at NUMBER(15) NOT NULL
);

CREATE TABLE audit_logs (
    id NUMBER(10) PRIMARY KEY,
    action VARCHAR2(100) NOT NULL,
    username VARCHAR2(50) NOT NULL,
    timestamp NUMBER(15) NOT NULL,
    details VARCHAR2(255)
);
