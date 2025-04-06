CREATE TABLE subscriptions (
    subscriptionID INTEGER PRIMARY KEY AUTOINCREMENT,
    userID INTEGER,
    paymentID INTEGER, -- Or transactionID, depending on your setup
    subscriptionType VARCHAR(10) CHECK(subscriptionType IN ('monthly', 'yearly')),
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    expiresAt DATETIME,
    FOREIGN KEY (userID) REFERENCES users(userID),
    FOREIGN KEY (paymentID) REFERENCES payments(paymentID) -- Or whatever the paymentID/transactionID column name is in your payments table
);