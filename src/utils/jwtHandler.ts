import { Context } from "hono";
import { Jwt } from "hono/utils/jwt";

const ACCESS_TOKEN_SECRET = "your-access-secret-key"; // Replace with your actual secret
const REFRESH_TOKEN_SECRET = "your-refresh-secret-key"; // Replace with your actual secret

// Token expiration times
const ACCESS_TOKEN_EXPIRY = "15m"; // 15 minutes
const REFRESH_TOKEN_EXPIRY = "7d"; // 7 days

export interface TokenPayload {
  userId: string;
  email: string;
  role?: string;
}

export interface TokenResponse {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export const generateAccessToken = async (payload: TokenPayload): Promise<string> => {
  const token = await Jwt.sign(
    {
      ...payload,
      type: "access",
    },
    ACCESS_TOKEN_SECRET
  );
  return token;
};

export const generateRefreshToken = async (payload: TokenPayload): Promise<string> => {
  const token = await Jwt.sign(
    {
      ...payload,
      type: "refresh",
    },
    REFRESH_TOKEN_SECRET
  );
  return token;
};

export const generateTokenPair = async (userId: string, email: string, role?: string): Promise<TokenResponse> => {
  const payload: TokenPayload = { userId, email, role };
  
  const [accessToken, refreshToken] = await Promise.all([
    generateAccessToken(payload),
    generateRefreshToken(payload)
  ]);

  return {
    accessToken,
    refreshToken,
    expiresIn: 15 * 60, // 15 minutes in seconds
  };
};

export const verifyAccessToken = async (token: string): Promise<TokenPayload> => {
  try {
    const payload = await Jwt.verify(token, ACCESS_TOKEN_SECRET);

    if (!payload || typeof payload !== "object") {
      throw new Error("Invalid token payload");
    }

    if (payload.type !== "access") {
      throw new Error("Invalid token type");
    }

    const userId = payload.userId as string;
    const email = payload.email as string;
    const role = payload.role as string;

    if (!userId || !email) {
      throw new Error("Missing userId or email in token");
    }

    return { userId, email, role };
  } catch (error) {
    console.error("Access token verification failed:", error);
    throw new Error("Invalid access token");
  }
};

export const verifyRefreshToken = async (token: string, db?: D1Database): Promise<TokenPayload> => {
  try {
    const payload = await Jwt.verify(token, REFRESH_TOKEN_SECRET);

    if (!payload || typeof payload !== "object") {
      throw new Error("Invalid token payload");
    }

    if (payload.type !== "refresh") {
      throw new Error("Invalid token type");
    }

    const userId = payload.userId as string;
    const email = payload.email as string;
    const role = payload.role as string;

    if (!userId || !email) {
      throw new Error("Missing userId or email in token");
    }

    // Check if token is invalidated (if database is provided)
    if (db) {
      const invalidatedStmt = db
        .prepare("SELECT id FROM invalidated_tokens WHERE user_id = ? AND token_hash = ? AND expires_at > CURRENT_TIMESTAMP")
        .bind(userId, token);
      const invalidated = await invalidatedStmt.first();

      if (invalidated) {
        throw new Error("Token has been invalidated");
      }
    }

    return { userId, email, role };
  } catch (error) {
    console.error("Refresh token verification failed:", error);
    throw new Error("Invalid refresh token");
  }
};

export const authenticate = async (c: Context): Promise<TokenPayload | null> => {
  const authHeader = c.req.header("Authorization");

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return null;
  }

  const token = authHeader.slice(7).trim();

  try {
    const decoded = await verifyAccessToken(token);
    return decoded;
  } catch (error) {
    console.error("JWT verification failed:", error);
    return null;
  }
};

export const requireAuth = async (c: Context): Promise<TokenPayload> => {
  const user = await authenticate(c);
  if (!user) {
    throw new Error("Unauthorized");
  }
  return user;
};

export const requireRole = (requiredRole: string) => {
  return async (c: Context): Promise<TokenPayload> => {
    const user = await requireAuth(c);
    if (user.role !== requiredRole && user.role !== "admin") {
      throw new Error("Insufficient permissions");
    }
    return user;
  };
};

// Legacy function for backward compatibility
export const generateToken = async (userId: string, email: string) => {
  return generateAccessToken({ userId, email });
};

export const verifyToken = async (token: string) => {
  return verifyAccessToken(token);
};
