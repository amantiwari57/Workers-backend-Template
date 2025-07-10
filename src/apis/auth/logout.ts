import { Hono } from "hono";
import { requireAuth } from "../../utils/jwtHandler";

export type Env = {
  DB: D1Database;
};

const logout = new Hono<{ Bindings: Env }>();

// Logout endpoint - invalidate refresh token
logout.post("/", async (c) => {
  try {
    const user = await requireAuth(c);
    const body = await c.req.json();
    const { refreshToken } = body;

    if (!refreshToken) {
      return c.json({ error: "Refresh token is required" }, 400);
    }

    // Store invalidated refresh token in database
    // This prevents the refresh token from being used again
    const invalidateStmt = c.env.DB
      .prepare("INSERT INTO invalidated_tokens (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now', '+7 days'))")
      .bind(user.userId, refreshToken); // In production, hash the token
    await invalidateStmt.run();

    return c.json({
      message: "Logged out successfully",
    });
  } catch (error) {
    console.error("Logout error:", error);
    if (error instanceof Error && error.message === "Unauthorized") {
      return c.json({ error: "Unauthorized" }, 401);
    }
    return c.json({ error: "Internal server error" }, 500);
  }
});

// Logout all sessions for a user
logout.post("/all", async (c) => {
  try {
    const user = await requireAuth(c);

    // Invalidate all refresh tokens for this user
    const invalidateAllStmt = c.env.DB
      .prepare("INSERT INTO invalidated_tokens (user_id, token_hash, expires_at) VALUES (?, 'ALL_SESSIONS', datetime('now', '+7 days'))")
      .bind(user.userId);
    await invalidateAllStmt.run();

    return c.json({
      message: "All sessions logged out successfully",
    });
  } catch (error) {
    console.error("Logout all error:", error);
    if (error instanceof Error && error.message === "Unauthorized") {
      return c.json({ error: "Unauthorized" }, 401);
    }
    return c.json({ error: "Internal server error" }, 500);
  }
});

export default logout; 