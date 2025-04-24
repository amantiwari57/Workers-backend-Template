import { Context, Hono } from "hono";
import { authenticate, verifyToken } from "../../utils/jwtHandler";
import { z } from "zod";

export type Env = {
  DB: D1Database;
  JWT_SECRET: string;
};

const subscriptions = new Hono<{ Bindings: Env }>();

// ✅ Admin-only: Get all subscriptions
subscriptions.get("/all", async (c) => {
  const auth = await authenticate(c);
  if (!auth) return c.json({ error: "Unauthorized" }, 401);

  const { userId } = auth;

  try {
    // Check if user is admin
    const adminCheck = await c.env.DB.prepare(
      "SELECT isAdmin FROM users WHERE id = ?"
    )
      .bind(userId)
      .first();

    if (!adminCheck || adminCheck.isAdmin !== 1) {
      return c.json({ error: "Forbidden: Admins only" }, 403);
    }

    const subsStmt = c.env.DB.prepare("SELECT * FROM subscriptions");
    const subsResult = await subsStmt.all();

    return c.json(subsResult.results, 200);
  } catch (err) {
    console.error("Get all subscriptions error:", err);
    return c.json({ error: "Internal server error" }, 500);
  }
});

// ✅ User-only: Get a single subscription (by ID)
subscriptions.get("/:id", async (c) => {
  const auth = await authenticate(c);
  if (!auth) return c.json({ error: "Unauthorized" }, 401);

  const { userId } = auth;
  const subscriptionId = c.req.param("id");

  try {
    const subStmt = c.env.DB.prepare(
      "SELECT * FROM subscriptions WHERE subscriptionID = ? AND userID = ?"
    ).bind(subscriptionId, userId);

    const subscription = await subStmt.first();

    if (!subscription) {
      return c.json({ error: "Subscription not found or unauthorized" }, 404);
    }

    return c.json(subscription, 200);
  } catch (err) {
    console.error("Get single subscription error:", err);
    return c.json({ error: "Internal server error" }, 500);
  }
});

// POST schema
const subscriptionSchema = z.object({
  subscriptionType: z.enum(["monthly", "yearly"]),
  paymentID: z.number(),
});

subscriptions.post("/", async (c) => {
  const auth = await authenticate(c);
  if (!auth) return c.json({ error: "Unauthorized" }, 401);

  const body = await c.req.json();
  const parsed = subscriptionSchema.safeParse(body);

  if (!parsed.success) {
    return c.json(
      { error: "Invalid input", details: parsed.error.format() },
      400
    );
  }

  const { subscriptionType, paymentID } = parsed.data;
  const userId = parseInt(auth.userId);

  try {
    // Check for active subscription
    const activeSub = await c.env.DB.prepare(
      `SELECT * FROM subscriptions WHERE userID = ? AND expiresAt > CURRENT_TIMESTAMP`
    )
      .bind(userId)
      .first();

    if (activeSub) {
      return c.json({ error: "User already has an active subscription" }, 409);
    }

    // Verify payment status
    const payment = await c.env.DB.prepare(
      `SELECT * FROM payments WHERE paymentID = ? AND userID = ?`
    )
      .bind(paymentID, userId)
      .first();

    if (!payment) {
      return c.json({ error: "Payment not found or does not belong to the user" }, 404);
    }

    if (payment.paymentStatus !== "success") {
      return c.json({ error: "Payment is not successful" }, 400);
    }

    // Calculate expiry
    const now = new Date();
    const expiresAt = new Date(
      subscriptionType === "monthly"
        ? now.setMonth(now.getMonth() + 1)
        : now.setFullYear(now.getFullYear() + 1)
    ).toISOString();

    const createdAt = new Date().toISOString();

    // Insert subscription
    const insert = await c.env.DB.prepare(
      `INSERT INTO subscriptions (userID, paymentID, subscriptionType, createdAt, expiresAt)
         VALUES (?, ?, ?, ?, ?)`
    )
      .bind(userId, paymentID, subscriptionType, createdAt, expiresAt)
      .run();

    if (!insert.success) {
      return c.json({ error: "Failed to create subscription" }, 500);
    }

    // Update payment status to 'subscribed'
    const update = await c.env.DB.prepare(
      `UPDATE payments SET paymentStatus = ? WHERE paymentID = ?`
    )
      .bind("subscribed", paymentID)
      .run();

    if (!update.success) {
      console.error("Failed to update payment status to 'subscribed'");
      // Depending on your requirements, you might want to handle this scenario
    }

    return c.json({ message: "Subscription created successfully" }, 201);
  } catch (err) {
    console.error("Create subscription error:", err);
    return c.json({ error: "Internal server error" }, 500);
  }
});


subscriptions.get("/check", async (c) => {
  const auth = await authenticate(c);
  console.log("Auth:", auth);
  if (!auth) return c.json({ error: "Unauthorized" }, 401);

  const userId = parseInt(auth.userId);
  if (isNaN(userId)) {
    console.error("Invalid user ID:", auth.userId);
    return c.json({ error: "Invalid user ID" }, 400);
  }

  console.log("User ID:", userId);

  try {
    const activeSub = await c.env.DB.prepare(
      `
        SELECT * FROM subscriptions 
        WHERE userID = ? AND expiresAt > CURRENT_TIMESTAMP
      `
    )
      .bind(userId)
      .first();

    if (activeSub) {
      return c.json(
        {
          active: true,
          subscription: activeSub,
        },
        200
      );
    }

    return c.json(
      {
        active: false,
        message: "No active subscription",
      },
      200
    );
  } catch (err) {
    console.error("Subscription check error:", err);
    return c.json({ error: "Internal server error" }, 500);
  }
});

export default subscriptions;
