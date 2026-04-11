CREATE TABLE keys (
    id VARCHAR(36) NOT NULL,
    version INT NOT NULL,
    algorithm TEXT,
    encrypted_key BYTEA,
    status INT,
    created_at TIMESTAMP,
    updated_at TIMESTAMP,
    expiry_at TIMESTAMP,
    disabled_at TIMESTAMP,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE, -- внешний ключ
    PRIMARY KEY (id, version)
);
