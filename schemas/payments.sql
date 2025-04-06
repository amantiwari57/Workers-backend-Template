CREATE TABLE payments (
    paymentID INTEGER PRIMARY KEY AUTOINCREMENT, -- Note the change here
    userID INTEGER,
    paymentDate DATETIME,
    amount DECIMAL(10, 2),
    paymentMethod VARCHAR(255),
    transactionID VARCHAR(255),
    paymentStatus VARCHAR(50),
    FOREIGN KEY (userID) REFERENCES users(userID)
);