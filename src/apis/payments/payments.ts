import { Context, Hono } from "hono";
import { authenticate, verifyToken } from "../../utils/jwtHandler";

export type Env = {
  DB: D1Database;
  JWT_SECRET: string;
};

const payments = new Hono<{ Bindings: Env }>();

// Middleware to verify JWT and set user ID


// Get all payments (admin only)
payments.get("/all", async (c) => {
  const authResult = await authenticate(c);
  if (!authResult) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  const { userId } = authResult;

  try {
    // Check if user is admin
    const adminCheck = await c.env.DB.prepare(
      "SELECT isAdmin FROM users WHERE id = ?"
    ).bind(userId).first();

    if (!adminCheck || adminCheck.isAdmin !== 1) {
      return c.json({ error: "Forbidden: Admins only" }, 403);
    }

    const paymentsStmt = c.env.DB.prepare("SELECT * FROM payments");
    const paymentsResult = await paymentsStmt.all();

    return c.json(paymentsResult.results, 200);
  } catch (error) {
    console.error("Get all payments error:", error);
    return c.json({ error: "Internal server error" }, 500);
  }
});

// Get a single payment (user or admin)
payments.get("/:id", async (c) => {
    const authResult = await authenticate(c);
    if (!authResult) {
      return c.json({ error: "Unauthorized" }, 401);
    }
  
    const { userId } = authResult;
    const paymentId = c.req.param("id");
  
    try {
      const paymentStmt = c.env.DB.prepare(`
        SELECT * FROM payments 
        WHERE paymentID = ? AND userID = ?
      `).bind(paymentId, userId);
  
      const payment = await paymentStmt.first();
  
      if (!payment) {
        return c.json({ error: "Payment not found or unauthorized" }, 404);
      }
  
      return c.json(payment, 200);
    } catch (error) {
      console.error("Get single payment error:", error);
      return c.json({ error: "Internal server error" }, 500);
    }
  });
  

export default payments;
