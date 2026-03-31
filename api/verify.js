// api/verify.js — verifies Stripe checkout and issues signed token

import crypto from 'crypto';

function signToken(email) {
  const secret = process.env.TOKEN_SECRET;
  const expiry = Date.now() + 37 * 24 * 60 * 60 * 1000;
  const payload = `${email}:${expiry}`;
  const sig = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  return Buffer.from(payload).toString('base64url') + '.' + sig;
}

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { sessionId } = req.body || {};
  if (!sessionId || typeof sessionId !== 'string' || sessionId.length > 200) {
    return res.status(400).json({ error: 'Invalid session ID.' });
  }

  const stripeKey = process.env.STRIPE_SECRET_KEY;
  const tokenSecret = process.env.TOKEN_SECRET;
  if (!stripeKey || !tokenSecret) {
    console.error('Missing env vars');
    return res.status(500).json({ error: 'Server configuration error.' });
  }

  try {
    const stripeRes = await fetch(
      `https://api.stripe.com/v1/checkout/sessions/${encodeURIComponent(sessionId)}`,
      { headers: { Authorization: `Bearer ${stripeKey}`, 'Stripe-Version': '2024-04-10' } }
    );

    if (!stripeRes.ok) {
      const err = await stripeRes.json();
      console.error('Stripe error:', err);
      throw new Error('Could not verify payment.');
    }

    const session = await stripeRes.json();
    if (session.payment_status !== 'paid') return res.status(402).json({ error: 'Payment not completed.' });

    const email = session.customer_details?.email || session.customer_email || 'unknown';
    const token = signToken(email);

    res.setHeader('X-Content-Type-Options', 'nosniff');
    return res.status(200).json({ token, email });
  } catch (err) {
    console.error('Verify error:', err.message);
    return res.status(500).json({ error: err.message || 'Verification failed.' });
  }
}
