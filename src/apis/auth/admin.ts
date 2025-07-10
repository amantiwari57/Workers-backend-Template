import { Hono } from "hono";
import { z } from "zod";
import { requireRole } from "../../utils/jwtHandler";

export type Env = {
  DB: D1Database;
};

const admin = new Hono<{ Bindings: Env }>();

// Admin middleware - requires admin role
const requireAdmin = requireRole("admin");

// Get all users (admin only)
admin.get("/users", requireAdmin, async (c) => {
  try {
    const usersStmt = c.env.DB
      .prepare("SELECT id, username, email, role, created_at FROM users ORDER BY created_at DESC");
    const users = await usersStmt.all();

    return c.json({
      users: users.results || [],
      total: users.results?.length || 0,
    });
  } catch (error) {
    console.error("Get users error:", error);
    return c.json({ error: "Internal server error" }, 500);
  }
});

// Get user by ID (admin only)
admin.get("/users/:id", requireAdmin, async (c) => {
  try {
    const userId = c.req.param("id");
    
    const userStmt = c.env.DB
      .prepare("SELECT id, username, email, role, created_at FROM users WHERE id = ?")
      .bind(userId);
    const user = await userStmt.first();

    if (!user) {
      return c.json({ error: "User not found" }, 404);
    }

    return c.json({ user });
  } catch (error) {
    console.error("Get user error:", error);
    return c.json({ error: "Internal server error" }, 500);
  }
});

// Update user role (admin only)
const UpdateUserRoleSchema = z.object({
  role: z.enum(["user", "admin", "moderator"]),
});

admin.patch("/users/:id/role", requireAdmin, async (c) => {
  try {
    const userId = c.req.param("id");
    const body = await c.req.json();
    const result = UpdateUserRoleSchema.safeParse(body);

    if (!result.success) {
      return c.json({ error: result.error.errors }, 400);
    }

    const { role } = result.data;

    // Check if user exists
    const userStmt = c.env.DB
      .prepare("SELECT id FROM users WHERE id = ?")
      .bind(userId);
    const user = await userStmt.first();

    if (!user) {
      return c.json({ error: "User not found" }, 404);
    }

    // Update user role
    const updateStmt = c.env.DB
      .prepare("UPDATE users SET role = ? WHERE id = ?")
      .bind(role, userId);
    await updateStmt.run();

    return c.json({
      message: "User role updated successfully",
      userId,
      role,
    });
  } catch (error) {
    console.error("Update user role error:", error);
    return c.json({ error: "Internal server error" }, 500);
  }
});

// Delete user (admin only)
admin.delete("/users/:id", requireAdmin, async (c) => {
  try {
    const userId = c.req.param("id");

    // Check if user exists
    const userStmt = c.env.DB
      .prepare("SELECT id FROM users WHERE id = ?")
      .bind(userId);
    const user = await userStmt.first();

    if (!user) {
      return c.json({ error: "User not found" }, 404);
    }

    // Delete user (cascade will handle related records)
    const deleteStmt = c.env.DB
      .prepare("DELETE FROM users WHERE id = ?")
      .bind(userId);
    await deleteStmt.run();

    return c.json({
      message: "User deleted successfully",
      userId,
    });
  } catch (error) {
    console.error("Delete user error:", error);
    return c.json({ error: "Internal server error" }, 500);
  }
});

// Get system statistics (admin only)
admin.get("/stats", requireAdmin, async (c) => {
  try {
    // Get total users
    const totalUsersStmt = c.env.DB
      .prepare("SELECT COUNT(*) as total FROM users");
    const totalUsers = await totalUsersStmt.first();

    // Get users by role
    const usersByRoleStmt = c.env.DB
      .prepare("SELECT role, COUNT(*) as count FROM users GROUP BY role");
    const usersByRole = await usersByRoleStmt.all();

    // Get recent registrations (last 7 days)
    const recentUsersStmt = c.env.DB
      .prepare("SELECT COUNT(*) as count FROM users WHERE created_at >= datetime('now', '-7 days')");
    const recentUsers = await recentUsersStmt.first();

    return c.json({
      stats: {
        totalUsers: totalUsers?.total || 0,
        usersByRole: usersByRole.results || [],
        recentRegistrations: recentUsers?.count || 0,
      },
    });
  } catch (error) {
    console.error("Get stats error:", error);
    return c.json({ error: "Internal server error" }, 500);
  }
});

// Get OTP records (admin only)
admin.get("/otps", requireAdmin, async (c) => {
  try {
    const otpsStmt = c.env.DB
      .prepare(`
        SELECT uo.id, uo.user_id, uo.otp, uo.type, uo.expires_at, uo.created_at,
               u.username, u.email
        FROM user_otps uo
        JOIN users u ON uo.user_id = u.id
        ORDER BY uo.created_at DESC
        LIMIT 100
      `);
    const otps = await otpsStmt.all();

    return c.json({
      otps: otps.results || [],
      total: otps.results?.length || 0,
    });
  } catch (error) {
    console.error("Get OTPs error:", error);
    return c.json({ error: "Internal server error" }, 500);
  }
});

export default admin; 