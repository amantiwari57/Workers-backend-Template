CREATE TABLE invalidated_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create indexes for better performance
CREATE INDEX idx_invalidated_tokens_user_id ON invalidated_tokens(user_id);
CREATE INDEX idx_invalidated_tokens_expires_at ON invalidated_tokens(expires_at);

-- Create a trigger to automatically clean up expired tokens
CREATE TRIGGER cleanup_expired_tokens
    AFTER INSERT ON invalidated_tokens
    BEGIN
        DELETE FROM invalidated_tokens WHERE expires_at < CURRENT_TIMESTAMP;
    END; 