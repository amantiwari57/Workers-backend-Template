DROP TABLE IF EXISTS subscriptions;
CREATE TABLE subscriptions (
    subscriptionID INTEGER PRIMARY KEY AUTOINCREMENT,
    userID INTEGER NOT NULL,
    paymentID INTEGER,
    subscriptionType VARCHAR(10) CHECK(subscriptionType IN ('monthly', 'yearly')),
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    expiresAt DATETIME,
    FOREIGN KEY (userID) REFERENCES users(id),
    FOREIGN KEY (paymentID) REFERENCES payments(paymentID)
);