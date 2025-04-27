import { Context, Hono } from "hono";
import { authenticate, verifyToken } from "../../utils/jwtHandler";
import { z } from "zod";
import Razorpay from "razorpay";
import { computeHmacSHA256 } from "../../utils/hmac";

// Define the payment schema using Zod
const paymentSchema = z.object({
  amount: z.number().positive("Amount must be a positive number"),
  customer_phone: z
    .string()
    .regex(/^(\+\d{1,4})?\d{10}$/, "Phone number must be 10 digits, optionally with country code"),
});

// Define environment bindings
export type Env = {
  DB: D1Database; // Cloudflare D1 database type
  JWT_SECRET: string;
  keyID: string;
  keySecret: string;
  WEBHOOK_SECRET: string;
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
payments.post("/create-order", async (c) => {
  const authResult = await authenticate(c);
  console.log("auth result", authResult);
  if (!authResult) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  const body = await c.req.json();
  console.log("Body received:", body);

  const validation = paymentSchema.safeParse(body);

  console.log("validation", validation);
  if (!validation.success) {
    return c.json({ error: validation.error.format() }, 400);
  }

  const { amount, customer_phone } = validation.data;
  const { userId } = authResult;

  // Initialize Razorpay within the request context
  const razorpay = new Razorpay({
    key_id: c.env.keyID,
    key_secret: c.env.keySecret,
  });

  try {
    const options = {
      amount: amount * 100, // Razorpay expects amount in paise
      currency: "INR",
      receipt: `receipt_${Date.now()}`,
    };

    const order = await razorpay.orders.create(options);

    // Optionally insert into your DB
    await c.env.DB.prepare(
      `INSERT INTO payments (userID, amount, paymentDate, paymentMethod, transactionID, paymentStatus)
       VALUES (?, ?, datetime('now'), 'razorpay', ?, 'pending')`
    )
      .bind(userId, amount, order.id)
      .run();

    return c.json({
      orderId: order.id,
      amount: order.amount,
      currency: order.currency,
      key: c.env.keyID,
      successPage: "https://localhost:8000/payment-success",
    });
  } catch (err) {
    console.error("Razorpay order creation failed:", err);
    return c.json({ error: "Order creation failed" }, 500);
  }
});

// Verify a payment after success
payments.post("/verify-payment", async (c) => {
  const body = await c.req.json();
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = body;

  if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
    return c.json({ error: "Missing payment details" }, 400);
  }

  const expectedSignature = await computeHmacSHA256(c.env.keySecret, razorpay_order_id, razorpay_payment_id);

  if (expectedSignature === razorpay_signature) {
    // Update payment status in database
    await c.env.DB.prepare(
      `UPDATE payments SET paymentStatus = 'success' WHERE transactionID = ?`
    )
    .bind(razorpay_order_id)
    .run();

    return c.json({ success: true, message: "Payment verified" });
  } else {
    return c.json({ error: "Invalid signature" }, 400);
  }
});


// payments.post("/webhook", async (c) => {
//   try {
//     // Retrieve the raw body and signature
//     const rawBody = await c.req.text();
//     const signature = c.req.header("x-razorpay-signature");
//     const secret = c.env.WEBHOOK_SECRET;

//     // Verify the signature
//     const expectedSignature = await computeHmacSHA256(secret, rawBody);
//     if (signature !== expectedSignature) {
//       console.warn("Invalid webhook signature");
//       return c.json({ error: "Invalid signature" }, 400);
//     }

//     // Parse the JSON body
//     const body = JSON.parse(rawBody);
//     const event = body.event;

//     // Handle specific events
//     if (event === "payment.captured") {
//       const payment = body.payload.payment.entity;
//       const transactionID = payment.order_id;
//       const amount = payment.amount / 100; // Convert from paise to INR
//       const paymentDate = new Date(payment.created_at * 1000).toISOString();

//       // Update the payment record in the database
//       await c.env.DB.prepare(
//         `UPDATE payments SET paymentStatus = 'success', paymentDate = ? WHERE transactionID = ?`
//       )
//         .bind(paymentDate, transactionID)
//         .run();

//       console.log(`Payment ${payment.id} captured and updated.`);
//     }

//     // Respond with a success status
//     return c.json({ status: "ok" });
//   } catch (error) {
//     console.error("Webhook handling error:", error);
//     return c.json({ error: "Internal server error" }, 500);
//   }
// });
export default payments;
