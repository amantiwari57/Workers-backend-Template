import { Context, Hono } from "hono";
import { authenticate, verifyToken } from "../../utils/jwtHandler";
import { z } from "zod";


// Define the payment schema using Zod
 const paymentSchema = z.object({
  amount: z.number().positive("Amount must be a positive number"),
  customer_phone: z
    .string()
    .regex(/^\d{10}$/, "Phone number must be 10 digits"),
});

// Define environment bindings
export type Env = {
  DB: D1Database; // Cloudflare D1 database type
  JWT_SECRET: string;
  AppID: string;
  CashFreeSecretKey: string;
};

// Define Cashfree response type based on their API docs
type CashfreeOrderResponse = {
  order_id?: string;
  payment_session_id?: string; // Updated to expect this field
  status?: string;
  message?: string;
};

type CashfreePayResponse = {
  payment_session_id?: string;
  status?: string;
  message?: string;
};

type PaymentRow = {
  paymentID: number;
  userID: number | string;
  paymentDate: string;
  amount: number;
  paymentMethod: string;
  transactionID: string;
  paymentStatus: "pending" | "success" | "failed";
};

// Initialize Hono app with bindings
const payments = new Hono<{ Bindings: Env }>();

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
    )
      .bind(userId)
      .first<{ isAdmin: number }>();

    if (!adminCheck || adminCheck.isAdmin !== 1) {
      return c.json({ error: "Forbidden: Admins only" }, 403);
    }

    const paymentsStmt = c.env.DB.prepare("SELECT * FROM payments");
    const paymentsResult = await paymentsStmt.all<PaymentRow>();

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
    const paymentStmt = c.env.DB.prepare(
      `
      SELECT * FROM payments 
      WHERE paymentID = ? AND userID = ?
    `
    ).bind(paymentId, userId);

    const payment = await paymentStmt.first<PaymentRow>();

    if (!payment) {
      return c.json({ error: "Payment not found or unauthorized" }, 404);
    }

    return c.json(payment, 200);
  } catch (error) {
    console.error("Get single payment error:", error);
    return c.json({ error: "Internal server error" }, 500);
  }
});

// Create a payment link


payments.post("/create", async (c) => {
  // Authenticate the user
  const auth = await authenticate(c);
  if (!auth) return c.json({ error: "Unauthorized" }, 401);

  const { userId, email } = auth;
  const baseUrl = "https://sandbox.cashfree.com/pg/orders"; // Sandbox for testing

  try {
    const orderId = `order_${Date.now()}_${userId}`;
    
    // Parse the incoming request body
    const body = await c.req.json();
    const parsed = paymentSchema.safeParse(body);

    // Check if parsing was successful
    if (!parsed.success) {
      console.error("Invalid data:", parsed.error); // Log the error details
      return c.json({ error: "Invalid input data" }, 400);
    }

    // Extract parsed data
    const { amount, customer_phone } = parsed.data;

    console.log("Parsed Amount:", amount); // This should now print the correct amount

    // Ensure amount is a valid number and greater than 0 (although Zod already validates it)
    if (!amount || isNaN(amount) || amount <= 0) {
      return c.json({ error: "Invalid amount" }, 400);
    }

    // Create the order payload for Cashfree
    const orderPayload = {
      customer_details: {
        customer_id: String(userId),
        customer_email: email,
        customer_phone: customer_phone, // Required
      },
      order_amount: amount, // No need to parse again, it's already a valid number
      order_currency: "INR",
      order_id: orderId,
      order_note: "Subscription Payment",
    };

    console.log("Creating order with payload:", orderPayload);

    // Make a request to Cashfree to create an order
    const orderRes = await fetch(baseUrl, {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
        "x-api-version": "2023-08-01",
        "x-client-id": c.env.AppID,
        "x-client-secret": c.env.CashFreeSecretKey,
      },
      body: JSON.stringify(orderPayload),
    });

    const orderData = await orderRes.json() as CashfreeOrderResponse;
    console.log("Order creation response:", orderData);

    // Check for errors in the Cashfree response
    if (!orderRes.ok) {
      console.error("Cashfree order error:", orderData);
      return c.json(
        { error: orderData.message || "Failed to create order" },
      500
      );
    }

    // Extract payment session ID from response
    const paymentSessionId = orderData.payment_session_id;
    if (!paymentSessionId) {
      console.error("No payment_session_id in response:", orderData);
      return c.json({ error: "Failed to generate payment session" }, 500);
    }

    // Insert the payment details into the database
    const now = new Date().toISOString();
    const insert = await c.env.DB.prepare(
      `INSERT INTO payments (userID, paymentDate, amount, paymentMethod, transactionID, paymentStatus) VALUES (?, ?, ?, ?, ?, ?)`
    )
      .bind(userId, now, amount, "cashfree", orderId, "pending")
      .run();

    if (!insert.success) {
      console.error("Database Error:", insert.error);
      return c.json({ error: "Failed to store payment record" }, 500);
    }

    // Respond with payment session ID and order ID
    return c.json({ paymentSessionId, orderId }, 201);
  } catch (err) {
    console.error("Create payment error:", err);
    return c.json({ error: "Internal server error" }, 500);
  }
});


// Webhook handler for Cashfree events
payments.post("/webhook", async (c) => {
  try {
    const body = await c.req.json<{
      order_id: string;
      event_time: string;
      event_type: string;
      payment?: { amount: number };
      data?: { payment_status: string; order_amount: number };
    }>();

    const { order_id, event_time, event_type, payment, data } = body;

    // Handle successful payments
    if (
      event_type === "payment.success" ||
      data?.payment_status === "SUCCESS"
    ) {
      const txnId = order_id;
      const paidAt = event_time;
      const amount = data?.order_amount || payment?.amount;

      if (!amount) {
        console.error("Missing amount in webhook:", body);
        return c.json({ error: "Invalid webhook data" }, 400);
      }

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

    // Handle failed payments
    if (
      event_type === "payment.failed" ||
      data?.payment_status === "FAILED"
    ) {
      const txnId = order_id;

      const update = await c.env.DB.prepare(
        `UPDATE payments 
         SET paymentStatus = ? 
         WHERE transactionID = ?`
      )
        .bind("failed", txnId)
        .run();

      if (!update.success) {
        console.error("Payment update failed:", update);
        return c.json({ error: "Failed to update payment status" }, 500);
      }

      return c.json({ success: true }, 200);
    }

    return c.json({ message: "Unhandled event type" }, 206);
  } catch (err) {
    console.error("Webhook error:", err);
    return c.json({ error: "Webhook processing failed" }, 500);
  }
});


export default payments;
