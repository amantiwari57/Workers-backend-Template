# Live Code Backend API

A robust authentication and user management system built with Hono and Cloudflare Workers.

## Features

- 🔐 **Dual Token Authentication**: Access tokens (15min) + Refresh tokens (7 days)
- 👤 **User Management**: Registration, login, profile management
- 🔑 **Google OAuth**: Secure Google authentication
- 📧 **Email Verification**: OTP-based email verification
- 🔒 **Password Reset**: Secure password reset with OTP
- 👨‍💼 **Admin Panel**: Complete admin management system
- 🚪 **Session Management**: Logout and session invalidation
- 🛡️ **Role-Based Access Control**: User, moderator, and admin roles

## API Endpoints

### Authentication

#### User Registration
```http
POST /api/auth/signup
Content-Type: application/json

{
  "username": "john_doe",
  "email": "john@example.com",
  "password": "securepassword123"
}
```

#### Email Verification
```http
POST /api/auth/signup/verify-otp
Content-Type: application/json

{
  "email": "john@example.com",
  "otp": "123456"
}
```

#### User Login
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "john@example.com",
  "password": "securepassword123"
}
```

Response:
```json
{
  "message": "Login successful",
  "accessToken": "eyJ...",
  "refreshToken": "eyJ...",
  "expiresIn": 900,
  "user": {
    "id": 1,
    "email": "john@example.com",
    "role": "user"
  }
}
```

#### Token Refresh
```http
POST /api/auth/login/refresh
Content-Type: application/json

{
  "refreshToken": "eyJ..."
}
```

#### Get Current User
```http
GET /api/auth/me
Authorization: Bearer <access_token>
```

#### Google OAuth
```http
GET /api/auth/google
# Redirects to Google OAuth
```

```http
GET /api/auth/google/callback?code=<auth_code>
# OAuth callback - returns tokens
```

#### Forgot Password
```http
POST /api/auth/forgot-password/request
Content-Type: application/json

{
  "email": "john@example.com"
}
```

#### Reset Password
```http
POST /api/auth/forgot-password/reset
Content-Type: application/json

{
  "email": "john@example.com",
  "otp": "123456",
  "newPassword": "newsecurepassword123"
}
```

#### Logout
```http
POST /api/auth/logout
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "refreshToken": "eyJ..."
}
```

#### Logout All Sessions
```http
POST /api/auth/logout/all
Authorization: Bearer <access_token>
```

### Admin APIs

#### Get All Users
```http
GET /api/auth/admin/users
Authorization: Bearer <admin_access_token>
```

#### Get User by ID
```http
GET /api/auth/admin/users/:id
Authorization: Bearer <admin_access_token>
```

#### Update User Role
```http
PATCH /api/auth/admin/users/:id/role
Authorization: Bearer <admin_access_token>
Content-Type: application/json

{
  "role": "admin"
}
```

#### Delete User
```http
DELETE /api/auth/admin/users/:id
Authorization: Bearer <admin_access_token>
```

#### Get System Statistics
```http
GET /api/auth/admin/stats
Authorization: Bearer <admin_access_token>
```

#### Get OTP Records
```http
GET /api/auth/admin/otps
Authorization: Bearer <admin_access_token>
```

## Database Schema

### Users Table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user' CHECK (role IN ('user', 'admin', 'moderator')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### OTP Table
```sql
CREATE TABLE user_otps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    otp TEXT NOT NULL,
    type TEXT DEFAULT 'email_verification' CHECK (type IN ('email_verification', 'password_reset', 'login_verification')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME GENERATED ALWAYS AS (DATETIME(created_at, '+30 minutes')) STORED,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

### Invalidated Tokens Table
```sql
CREATE TABLE invalidated_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

## Environment Variables

```env
DB=your_d1_database
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
SMTP_USER=your_smtp_user
API_KEY=your_brevo_api_key
```

## Security Features

- **Dual Token System**: Short-lived access tokens with refresh tokens
- **Token Invalidation**: Secure logout with token blacklisting
- **Role-Based Access**: Granular permissions system
- **Password Hashing**: Secure password storage with bcrypt
- **OTP Expiration**: Time-limited OTP codes
- **Input Validation**: Comprehensive request validation with Zod
- **CORS Protection**: Configurable CORS settings
- **Error Handling**: Secure error responses without information leakage

## Development

```bash
# Install dependencies
npm install

# Run development server
npm run dev

# Deploy to Cloudflare
npm run deploy
```

## Token Usage

### Access Token
- Used for API authentication
- Short lifespan (15 minutes)
- Include in Authorization header: `Bearer <access_token>`

### Refresh Token
- Used to get new access tokens
- Longer lifespan (7 days)
- Should be stored securely on client
- Can be invalidated for logout

## Error Handling

All endpoints return consistent error responses:

```json
{
  "error": "Error message",
  "details": "Additional details (optional)"
}
```

Common HTTP status codes:
- `200`: Success
- `201`: Created
- `400`: Bad Request
- `401`: Unauthorized
- `403`: Forbidden
- `404`: Not Found
- `409`: Conflict
- `500`: Internal Server Error
