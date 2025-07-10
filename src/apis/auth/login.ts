import { Hono } from "hono";
import { z } from "zod";
import { verifyPassword } from "../../utils/passwordHash";
import { generateTokenPair } from "../../utils/jwtHandler";

export type Env = {
  DB: D1Database;
};

const LoginSchema = z.object({
  email: z
    .string()
    .regex(/^[^\s@]+@[^\s@]+\.[^\s@]+$/, { message: "Invalid email address" }),
  password: z
    .string()
    .min(8, { message: "Password must be at least 8 characters long" }),
});

const login = new Hono<{ Bindings: Env }>();

login.post("/", async (c) => {
  try {
    const body = await c.req.json();
    const result = LoginSchema.safeParse(body);

    if (!result.success) {
      return c.json({ error: result.error.errors }, 400);
    }

    const { email, password } = result.data;

    // Select user with role
    const userStmt = c.env.DB
      .prepare("SELECT id, password, role FROM users WHERE email = ?")
      .bind(email);
    const user = await userStmt.first<{ id: number; password: string; role?: string }>();

    if (!user) {
      return c.json({ error: "Invalid email or password" }, 401);
    }

    const isValid = verifyPassword(password, user.password);
    if (!isValid) {
      return c.json({ error: "Invalid email or password" }, 401);
    }

    // Generate token pair
    const tokens = await generateTokenPair(user.id.toString(), email, user.role);

    return c.json(
      {
        message: "Login successful",
        ...tokens,
        user: {
          id: user.id,
          email,
          role: user.role || "user",
        },
      },
      200
    );
  } catch (error) {
    console.error("Login error:", error);
    return c.json({ error: "Internal server error" }, 500);
  }
});

// Refresh token endpoint
login.post("/refresh", async (c) => {
  try {
    const body = await c.req.json();
    const { refreshToken } = body;

    if (!refreshToken) {
      return c.json({ error: "Refresh token is required" }, 400);
    }

    const { verifyRefreshToken, generateTokenPair } = await import("../../utils/jwtHandler");
    
    // Verify refresh token
    const payload = await verifyRefreshToken(refreshToken, c.env.DB);
    
    // Generate new token pair
    const tokens = await generateTokenPair(payload.userId, payload.email, payload.role);

    return c.json({
      message: "Token refreshed successfully",
      ...tokens,
    });
  } catch (error) {
    console.error("Token refresh error:", error);
    return c.json({ error: "Invalid refresh token" }, 401);
  }
});

export default login;
