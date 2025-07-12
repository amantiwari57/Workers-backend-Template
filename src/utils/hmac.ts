export async function computeHmacSHA256(secret: string, orderId: string, paymentId: string): Promise<string> {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);
  const message = `${orderId}|${paymentId}`;
  const msgBuffer = encoder.encode(message);

  // Import the secret key
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  // Compute the HMAC signature
  const signatureBuffer = await crypto.subtle.sign("HMAC", cryptoKey, msgBuffer);

  // Convert the signature to hexadecimal
  const signatureArray = Array.from(new Uint8Array(signatureBuffer));
  const signatureHex = signatureArray.map(b => b.toString(16).padStart(2, '0')).join('');

  return signatureHex;
}

export async function verifyWebhookSignature(secret: string, body: string, signature: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);
  const msgBuffer = encoder.encode(body);

  // Import the secret key
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  // Compute the HMAC signature
  const signatureBuffer = await crypto.subtle.sign("HMAC", cryptoKey, msgBuffer);

  // Convert the signature to hexadecimal
  const signatureArray = Array.from(new Uint8Array(signatureBuffer));
  const expectedSignature = signatureArray.map(b => b.toString(16).padStart(2, '0')).join('');

  return expectedSignature === signature;
}
