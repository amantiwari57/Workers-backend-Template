import { z } from "zod";

export const paymentSchema = z.object({
  amount: z.number().positive("Amount must be a positive number"),
  customer_phone: z
    .string()
    .regex(/^\d{10}$/, "Phone number must be 10 digits"),
});
