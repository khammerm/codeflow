// api/generate-from-activities.js — CodeFlow
// Generates CPT codes + insurance-compliant narratives from checkbox selections.
// Supports granular ADL sub-items with assist levels (MIN, MOD, MAX, etc.)

import crypto from 'crypto';

// ─── RATE LIMITING (Upstash Redis) ───────────────────────────────────────────
// Falls back to in-memory if Redis is not configured (dev only).

const rateMap = new Map();

function inMemoryRateLimit(ip) {
  const now = Date.now();
  const entry = rateMap.get(ip) || { count: 0, start: now };
  if (now - entry.start > 60_000) { rateMap.set(ip, { count: 1, start: now }); return false; }
  if (entry.count >= 10) return true;
  entry.count++;
  rateMap.set(ip, entry);
  return false;
}

async function isRateLimited(ip) {
  const redisUrl   = process.env.UPSTASH_REDIS_REST_URL;
  const redisToken = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!redisUrl || !redisToken) {
    console.warn('Redis not configured — using in-memory rate limit (dev only)');
    return inMemoryRateLimit(ip);
  }
  try {
    const key    = `ratelimit:${ip}`;
    const limit  = 10;
    const window = 60_000;
    const incrRes = await fetch(`${redisUrl}/incr/${key}`, {
      headers: { Authorization: `Bearer ${redisToken}` }
    });
    const { result: count } = await incrRes.json();
    if (count === 1) {
      await fetch(`${redisUrl}/pexpire/${key}/${window}`, {
        headers: { Authorization: `Bearer ${redisToken}` }
      });
    }
    return count > limit;
  } catch (err) {
    console.error('Redis rate limit error:', err);
    return inMemoryRateLimit(ip);
  }
}

// ─── SERVER-SIDE FREE USAGE TRACKING ─────────────────────────────────────────
// Prevents client-side localStorage bypass. Tracked by IP in Redis.
// Pro users bypass this entirely.

const MAX_FREE_USES = 5;

async function getFreeUsage(ip) {
  const redisUrl   = process.env.UPSTASH_REDIS_REST_URL;
  const redisToken = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!redisUrl || !redisToken) return 0; // Dev: no enforcement
  try {
    const res  = await fetch(`${redisUrl}/get/usage:${ip}`, {
      headers: { Authorization: `Bearer ${redisToken}` }
    });
    const data = await res.json();
    return parseInt(data.result || '0', 10);
  } catch { return 0; }
}

async function incrementFreeUsage(ip) {
  const redisUrl   = process.env.UPSTASH_REDIS_REST_URL;
  const redisToken = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!redisUrl || !redisToken) return;
  try {
    const key    = `usage:${ip}`;
    const ttl    = 30 * 24 * 60 * 60 * 1000; // 30 days
    await fetch(`${redisUrl}/incr/${key}`, {
      headers: { Authorization: `Bearer ${redisToken}` }
    });
    // Set TTL on first increment (only if key is new)
    await fetch(`${redisUrl}/pexpire/${key}/${ttl}`, {
      headers: { Authorization: `Bearer ${redisToken}` }
    });
  } catch (err) {
    console.error('Redis usage increment error:', err);
  }
}

// ─── TOKEN VERIFICATION ───────────────────────────────────────────────────────

function verifyToken(token) {
  const secret = process.env.TOKEN_SECRET;
  if (!secret || !token) return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const [b64payload, sig] = parts;
  const payload = Buffer.from(b64payload, 'base64url').toString();
  const [, expiry] = payload.split(':');
  if (!expiry || Date.now() > parseInt(expiry, 10)) return false;
  const expected = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'));
  } catch { return false; }
}

// ─── LOGGING ──────────────────────────────────────────────────────────────────

function log(ip, activityCount, isPro, success, error = null) {
  console.log('REQUEST:', JSON.stringify({
    timestamp: new Date().toISOString(),
    ip: ip.substring(0, 10) + '...',
    activityCount,
    isPro,
    success,
    error: error ? error.substring(0, 120) : null
  }));
}

// ─── HANDLER ─────────────────────────────────────────────────────────────────

export default async function handler(req, res) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 'unknown';

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // Rate limit check
  if (await isRateLimited(ip)) {
    log(ip, 0, false, false, 'Rate limited');
    return res.status(429).json({ error: 'Too many requests. Please wait a minute.' });
  }

  // Auth
  const authHeader = req.headers['authorization'] || '';
  const token      = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  const isPro      = token ? verifyToken(token) : false;

  // Server-side free usage enforcement
  if (!isPro) {
    const usageCount = await getFreeUsage(ip);
    if (usageCount >= MAX_FREE_USES) {
      return res.status(402).json({
        error: `You've used all ${MAX_FREE_USES} free generations. Upgrade to Pro for unlimited access.`,
        paywall: true,
        usageCount
      });
    }
  }

  // Validate input
  const { activities } = req.body || {};
  if (!activities || typeof activities !== 'object' || Array.isArray(activities)) {
    return res.status(400).json({ error: 'Missing or invalid activities.' });
  }

  const activityCount = Object.values(activities).flat().length;
  if (activityCount === 0) {
    return res.status(400).json({ error: 'Please select at least one activity.' });
  }

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    console.error('GEMINI_API_KEY not set');
    return res.status(500).json({ error: 'Server configuration error.' });
  }

  // ─── SYSTEM PROMPT ─────────────────────────────────────────────────────────

  const systemPrompt = `You are a CPT code documentation expert for occupational therapy in SNF (skilled nursing facility) settings, with deep knowledge of Medicare Part A/B billing compliance.

The therapist has selected specific activities performed during a session. Generate insurance-compliant CPT codes with narratives ready to paste directly into an EMR.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ACTIVITY → CPT CODE MAPPING
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

97535 — Self-Care / Home Management Training (PRIMARY)
  Triggers: ANY item under "ADL Training" categories (UB Dressing, LB Dressing,
  Grooming, Bathing, Toileting, Feeding, Functional Transfers)
  ALWAYS listed FIRST when ADL activities are present.
  80-90% of SNF sessions include this code.

97530 — Therapeutic Activities
  Triggers: Functional Mobility activities, Functional Transfers
  Often paired with 97535. Second priority.

97112 — Neuromuscular Re-education
  Triggers: Balance & Coordination activities
  NEVER use 97530 for balance work — this is a common billing error.

97110 — Therapeutic Exercise
  Triggers: Upper Body Strengthening, Core Strengthening, Hand Strengthening
  MUST tie to functional outcomes or flag as HIGH risk.
  Without ADL or mobility context, this requires extra justification.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ASSIST LEVEL INTEGRATION — CRITICAL
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Activities may include an assist level in parentheses, e.g.:
  "Shirt (donning) (MIN)"
  "Pants (donning) (MOD)"
  "Socks (donning) (MAX)"
  "Transfer to toilet (CGA)"
  "UB bathing (I)"

You MUST incorporate these specific levels into the narrative. Use precise language:

  I / MI → "Patient demonstrated independence / modified independence; therapist assessed 
            performance and provided education for carryover."
  S/U / SUP / SBA → "Patient required setup / supervision / standby assist; therapist 
                     monitored safety and provided verbal cueing as needed."
  CGA → "Patient required contact guard assist with therapist maintaining close physical 
         proximity to ensure safety during task performance."
  MIN → "Patient required minimal physical assistance (less than 25%), with therapist 
         providing tactile/verbal cues to complete the task."
  MOD → "Patient required moderate physical assistance (25–50%), with therapist providing 
         direct physical guidance and grading of the task."
  MAX → "Patient required maximal physical assistance (50–75%), with therapist guiding the 
         majority of the movement to ensure safety and skill development."
  TD+ / TD → "Patient required total dependence with full physical assist from therapist; 
              skilled intervention documented to establish baseline and develop treatment plan."

When a task has no level specified, describe the activity without a specific level.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NARRATIVE REQUIREMENTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Each narrative MUST be a single flowing paragraph (3–5 sentences) that includes:
1. WHAT was done — specific tasks/activities with their assist levels
2. HOW it was skilled — therapist's professional role (grading, cueing, assessing, instructing)
3. WHY it's medically necessary — functional relevance, safety, goal of independence

Required language patterns:
  ✓ "Therapist facilitated..."
  ✓ "Skilled occupational therapy services were provided..."
  ✓ "Therapist graded task demands to..."
  ✓ "Therapist provided skilled instruction in compensatory strategies..."
  ✓ "Therapist assessed and documented functional performance..."
  ✗ "Patient worked on..." (alone, without therapist context)
  ✗ "Patient completed..." (alone, without therapist context)

When strengthening is selected without ADL context, connect it to function:
  "...to improve overhead reach required for UB dressing independence"
  "...to enhance grip strength necessary for utensil use and meal independence"
  "...to support safe transfer performance and fall prevention"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
COMPLIANCE FLAGS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Flag as risk: "high" + include warning string when:
  - 97110 selected with no ADL or functional mobility activities
  - Only strengthening activities selected (no functional context)
  
Flag as risk: "medium" + include warning when:
  - 97110 narrative could be stronger in linking to function
  - Balance work is listed but coded under 97530 (should be 97112)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
RESPONSE FORMAT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Return ONLY a raw JSON array. No markdown, no backticks, no explanation.
First character must be [ and last must be ].

[
  {
    "code": "97535",
    "name": "Self-care / home management training",
    "narrative": "Single flowing paragraph here...",
    "confidence": "high",
    "risk": "low",
    "warning": null
  }
]

confidence: "high" | "medium" | "low"
risk: "low" | "medium" | "high"
warning: string with specific compliance guidance, or null`;

  // ─── FORMAT ACTIVITIES FOR PROMPT ─────────────────────────────────────────

  let activitiesText = 'SELECTED SESSION ACTIVITIES:\n\n';
  Object.entries(activities).forEach(([category, acts]) => {
    if (Array.isArray(acts) && acts.length > 0) {
      activitiesText += `${category}:\n`;
      acts.forEach(act => activitiesText += `  • ${act}\n`);
      activitiesText += '\n';
    }
  });

  const userPrompt = `${activitiesText}
Generate CPT codes with insurance-compliant narratives. Incorporate all assist levels into the narratives where specified. Return JSON array only.`;

  // ─── CALL GEMINI ───────────────────────────────────────────────────────────

  try {
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          systemInstruction: { parts: [{ text: systemPrompt }] },
          contents: [{ role: 'user', parts: [{ text: userPrompt }] }],
          generationConfig: { temperature: 0.2, maxOutputTokens: 4096 }
        })
      }
    );

    if (!response.ok) {
      const err = await response.json();
      console.error('Gemini error:', err);
      log(ip, activityCount, isPro, false, `Gemini ${err?.error?.code}`);
      if (err?.error?.code === 503 || err?.error?.status === 'UNAVAILABLE') {
        throw new Error('The AI service is temporarily overloaded. Please wait 30 seconds and try again.');
      }
      if (err?.error?.code === 429) {
        throw new Error('Too many requests to the AI service. Please wait a moment and try again.');
      }
      throw new Error('AI service error. Please try again.');
    }

    const data = await response.json();
    const raw  = data.candidates?.[0]?.content?.parts?.[0]?.text || '';

    const stripped  = raw.replace(/```json|```|`/g, '').trim();
    const jsonMatch = stripped.match(/\[[\s\S]*\]/);
    const jsonStr   = jsonMatch ? jsonMatch[0] : stripped;

    let codes;
    try {
      codes = JSON.parse(jsonStr);
    } catch {
      console.error('Parse error. Raw response:', raw);
      log(ip, activityCount, isPro, false, 'Parse error');
      throw new Error('Could not parse generated codes. Please try again.');
    }

    if (!Array.isArray(codes) || codes.length === 0) {
      throw new Error('No CPT codes identified. Please try again.');
    }

    // Increment free usage after successful generation
    if (!isPro) await incrementFreeUsage(ip);

    log(ip, activityCount, isPro, true);

    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    return res.status(200).json({ codes, isPro });

  } catch (err) {
    console.error('Handler error:', err.message);
    log(ip, activityCount, isPro, false, err.message);
    return res.status(500).json({ error: err.message || 'Failed to generate documentation.' });
  }
}
