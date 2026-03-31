// api/restore.js — re-issues pro token by verifying active Stripe subscription

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

  const allowedOrigins = [process.env.ALLOWED_ORIGIN, 'http://localhost:3000'].filter(Boolean);
  const origin = req.headers['origin'] || '';
  if (allowedOrigins.length > 0 && !allowedOrigins.includes(origin)) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const { email } = req.body || {};
  if (!email || typeof email !== 'string') return res.status(400).json({ error: 'Email is required.' });

  const emailClean = email.trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailClean)) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }

  const stripeKey = process.env.STRIPE_SECRET_KEY;
  if (!stripeKey || !process.env.TOKEN_SECRET) {
    return res.status(500).json({ error: 'Server configuration error.' });
  }

  try {
    const searchRes = await fetch(
      `https://api.stripe.com/v1/customers/search?query=email:'${encodeURIComponent(emailClean)}'&limit=5`,
      { headers: { Authorization: `Bearer ${stripeKey}`, 'Stripe-Version': '2024-04-10' } }
    );

    if (!searchRes.ok) throw new Error('Could not verify subscription.');

    const { data: customers } = await searchRes.json();
    if (!customers?.length) {
      return res.status(404).json({ error: 'No subscription found for this email.' });
    }

    let hasActive = false;
    for (const customer of customers) {
      const subRes = await fetch(
        `https://api.stripe.com/v1/subscriptions?customer=${customer.id}&status=active&limit=1`,
        { headers: { Authorization: `Bearer ${stripeKey}`, 'Stripe-Version': '2024-04-10' } }
      );
      if (!subRes.ok) continue;
      const subData = await subRes.json();
      if (subData.data?.length > 0) { hasActive = true; break; }
    }

    if (!hasActive) {
      return res.status(403).json({ error: 'No active subscription found for this email.' });
    }

    const token = signToken(emailClean);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    return res.status(200).json({ token, email: emailClean });

  } catch (err) {
    console.error('Restore error:', err.message);
    return res.status(500).json({ error: err.message || 'Failed to restore access.' });
  }
}
