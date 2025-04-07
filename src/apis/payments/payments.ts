import { Context, Hono } from "hono";
import { authenticate, verifyToken } from "../../utils/jwtHandler";

export type Env = {
  DB: D1Database;
  JWT_SECRET: string;
  AppID: string;
  CashFreeSecretKey: string;
};

const payments = new Hono<{ Bindings: Env }>();

// Middleware to verify JWT and set user ID
type CashfreeResponse = {
  payment_link_id: string;
  payment_link_url: string;
  status: string;
  message?: string;
};



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

  payments.post("/create", async (c) => {
    const auth = await authenticate(c);
    if (!auth) return c.json({ error: "Unauthorized" }, 401);
  
    const { userId, email } = auth;
    const baseUrl = "https://sandbox.cashfree.com/pg/links"; // use production URL in production
  
    try {
      const orderId = `order_${Date.now()}_${userId}`;
      const amount = 99.0;
  
      const payload = {
        customer_details: {
          customer_id: String(userId),
          customer_email: email,
        },
        order_amount: amount,
        order_currency: "INR",
        order_id: orderId,
        order_note: "Subscription Payment",
        order_expiry_time: 900, // 15 mins
      };
  
      const res = await fetch(baseUrl, {
        method: "POST",
        headers: {
          accept: "application/json",
          "content-type": "application/json",
          "x-api-version": "2022-09-01",
          "x-client-id": c.env.AppID,
          "x-client-secret": c.env.CashFreeSecretKey,
        },
        body: JSON.stringify(payload),
      });
  
      const data = (await res.json()) as CashfreeResponse;
  
      if (!res.ok || !data.payment_link_url) {
        console.error("Cashfree error:", data);
        return c.json(
          { error: data.message || "Failed to create payment link" },
          500
        );
      }
  
      const now = new Date().toISOString();
  
      // Insert into payments table
      const insert = await c.env.DB.prepare(
        `INSERT INTO payments 
         (userID, paymentDate, amount, paymentMethod, transactionID, paymentStatus) 
         VALUES (?, ?, ?, ?, ?, ?)`
      )
        .bind(userId, now, amount, "cashfree", orderId, "pending")
        .run();
  
      if (!insert.success) {
        return c.json({ error: "Failed to store payment record" }, 500);
      }
  
      return c.json({ paymentLink: data.payment_link_url, orderId }, 201);
    } catch (err) {
      console.error("Create payment error:", err);
      return c.json({ error: "Internal server error" }, 500);
    }
  })


  payments.post("/webhook", async (c) => {
    try {
      const body = await c.req.json();
  
      const {
        order_id,
        event_time,
        event_type,
        payment,
        data,
      } = body;
  
      // Only act on successful payments
      if (event_type === "PAYMENT_SUCCESS_WEBHOOK" || data?.payment_status === "SUCCESS") {
        const txnId = order_id;
        const paidAt = event_time;
        const amount = data.order_amount || payment?.amount;
  
        // Update the record in the database
        const update = await c.env.DB.prepare(
          `UPDATE payments 
           SET paymentStatus = ?, paymentDate = ?, amount = ? 
           WHERE transactionID = ?`
        )
          .bind("success", paidAt, amount, txnId)
          .run();
  
        if (!update.success) {
          console.error("Payment update failed:", update);
          return c.json({ error: "Failed to update payment status" }, 500);
        }
  
        return c.json({ success: true }, 200);
      }
  
      // If payment failed
      if (event_type === "PAYMENT_FAILED_WEBHOOK" || data?.payment_status === "FAILED") {
        const txnId = order_id;
  
        await c.env.DB.prepare(
          `UPDATE payments 
           SET paymentStatus = ? 
           WHERE transactionID = ?`
        )
          .bind("failed", txnId)
          .run();
  
        return c.json({ success: true }, 200);
      }
  
      return c.json({ message: "Unhandled event type" }, 206);
    } catch (err) {
      console.error("Webhook error:", err);
      return c.json({ error: "Webhook processing failed" }, 500);
    }
  });
  
  

export default payments;
