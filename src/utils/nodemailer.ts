import axios from 'axios';

export type Env = {
  API_KEY: string; // Brevo API Key
};

export async function sendOtpEmail(env: Env, to: string, otp: string) {
  const emailData = {
    // Define the campaign settings
    name: 'Campaign sent via the API',
    subject: 'Your One Time Password (OTP)',
    sender: {
      name: 'Auto Coder',
      email: 'dualdevssolutions@gmail.com', // Replace with your "from" email
    },
    type: 'classic',
    // Content that will be sent
    htmlContent: `
      <div style="font-family: Arial, sans-serif; font-size: 16px;">
        <p>Hello,</p>
        <p>Your OTP Code is:</p>
        <h2>${otp}</h2>
        <p>This code will expire in 30 minutes.</p>
      </div>
    `,
    // Set the recipient's email directly
    to: [
      {
        email: to, // The recipient's email address
      },
    ],
    // Optional: Schedule the sending in one hour
  };

  try {
    // Making a POST request to Brevo's API to send the email
    await axios.post(
      'https://api.brevo.com/v3/smtp/email',
      emailData,
      {
        headers: {
          'api-key': env.API_KEY, // API Key
          'Content-Type': 'application/json',
        },
      }
    );
    console.log('OTP sent successfully via Brevo');
  } catch (error) {
    console.error('Error sending OTP via Brevo:', error);
  }
}
