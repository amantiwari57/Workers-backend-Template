CREATE TABLE user_otps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    otp TEXT NOT NULL,
    type TEXT DEFAULT 'email_verification' CHECK (type IN ('email_verification', 'password_reset', 'login_verification')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME GENERATED ALWAYS AS (DATETIME(created_at, '+30 minutes')) STORED,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create indexes for better performance
CREATE INDEX idx_user_otps_user_id ON user_otps(user_id);
CREATE INDEX idx_user_otps_type ON user_otps(type);
CREATE INDEX idx_user_otps_expires_at ON user_otps(expires_at);

-- Create a trigger to automatically clean up expired OTPs
CREATE TRIGGER cleanup_expired_otps
    AFTER INSERT ON user_otps
    BEGIN
        DELETE FROM user_otps WHERE expires_at < CURRENT_TIMESTAMP;
    END;
