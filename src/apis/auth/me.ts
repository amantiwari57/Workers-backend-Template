import { Hono } from "hono";
import { requireAuth } from "../../utils/jwtHandler";

export type Env = {
  DB: D1Database;
};

const me = new Hono<{ Bindings: Env }>();

me.get("/", async (c) => {
  try {
    const user = await requireAuth(c);

    // Get user details from database
    const userStmt = c.env.DB
      .prepare("SELECT id, username, email, role, created_at FROM users WHERE id = ?")
      .bind(user.userId);
    const userData = await userStmt.first();

    if (!userData) {
      return c.json({ error: "User not found" }, 404);
    }

    return c.json({
      user: {
        id: userData.id,
        username: userData.username,
        email: userData.email,
        role: userData.role || "user",
        created_at: userData.created_at,
      },
    });
  } catch (error) {
    console.error("Get user error:", error);
    if (error instanceof Error && error.message === "Unauthorized") {
      return c.json({ error: "Unauthorized" }, 401);
    }
    return c.json({ error: "Internal server error" }, 500);
  }
});

export default me; 