// api/generate-from-activities.js — Generate CPT codes from checkbox selections

import crypto from 'crypto';

// Upstash Redis rate limiting
async function isRateLimited(ip) {
  const redisUrl = process.env.UPSTASH_REDIS_REST_URL;
  const redisToken = process.env.UPSTASH_REDIS_REST_TOKEN;
  
  if (!redisUrl || !redisToken) {
    console.warn('Redis not configured - using in-memory rate limit');
    return inMemoryRateLimit(ip);
  }

  try {
    const key = `ratelimit:${ip}`;
    const window = 60000;
    const limit = 10;

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

const rateMap = new Map();
function inMemoryRateLimit(ip) {
  const now = Date.now();
  const entry = rateMap.get(ip) || { count: 0, start: now };
  if (now - entry.start > 60000) { 
    rateMap.set(ip, { count: 1, start: now }); 
    return false; 
  }
  if (entry.count >= 10) return true;
  entry.count++;
  rateMap.set(ip, entry);
  return false;
}

function logRequest(ip, activityCount, isPro, success, error = null) {
  const log = {
    timestamp: new Date().toISOString(),
    ip: ip.substring(0, 12) + '...',
    activityCount,
    isPro,
    success,
    error: error ? error.substring(0, 100) : null
  };
  console.log('REQUEST:', JSON.stringify(log));
}

function verifyToken(token) {
  const secret = process.env.TOKEN_SECRET;
  if (!secret || !token) return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const [b64payload, sig] = parts;
  const payload = Buffer.from(b64payload, 'base64url').toString();
  const [, expiry] = payload.split(':');
  if (!expiry || Date.now() > parseInt(expiry)) return false;
  const expected = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'));
  } catch { return false; }
}

export default async function handler(req, res) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 'unknown';
  
  if (req.method !== 'POST') {
    logRequest(ip, 0, false, false, 'Method not allowed');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const rateLimited = await isRateLimited(ip);
  if (rateLimited) {
    logRequest(ip, 0, false, false, 'Rate limited');
    return res.status(429).json({ error: 'Too many requests. Please wait a minute.' });
  }

  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  const isPro = token ? verifyToken(token) : false;

  const { activities } = req.body || {};
  if (!activities || typeof activities !== 'object') {
    logRequest(ip, 0, isPro, false, 'Missing activities');
    return res.status(400).json({ error: 'Missing activities.' });
  }

  const activityCount = Object.values(activities).flat().length;
  if (activityCount === 0) {
    logRequest(ip, 0, isPro, false, 'No activities selected');
    return res.status(400).json({ error: 'Please select at least one activity.' });
  }

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) { 
    logRequest(ip, activityCount, isPro, false, 'API key not configured');
    console.error('GEMINI_API_KEY not set'); 
    return res.status(500).json({ error: 'Server configuration error.' }); 
  }

  const systemPrompt = `You are a CPT code extraction expert for occupational therapy and physical therapy, with specialized knowledge of SNF billing compliance.

The user has selected specific activities they performed during a therapy session. Your task is to:
1. Determine which CPT codes apply based on the activities
2. Generate insurance-compliant narratives for each code
3. Provide confidence and risk assessments

ACTIVITY-TO-CODE MAPPING:

Upper Body Strengthening activities → 97110 Therapeutic Exercise
- Examples: shoulder flexion, chest press, triceps, overhead press, trunk rotation
- CRITICAL: Must tie to functional outcomes (ADL performance, transfer safety, etc.)
- If no functional tie-in mentioned, flag as HIGH risk

Core Strengthening activities → 97110 Therapeutic Exercise  
- Examples: medicine ball work, planks, trunk exercises
- Must relate to functional mobility, postural control, or ADL performance

Hand Strengthening activities → 97110 Therapeutic Exercise
- Examples: putty, pinches, grip work, pegboard
- Should connect to fine motor ADLs (dressing, grooming, feeding)

ADL Training (if mentioned) → 97535 Self-care Training (PRIMARY)
- Dressing, bathing, toileting, grooming, feeding
- This code takes priority over all others when ADLs are involved

Functional Mobility (if mentioned) → 97530 Therapeutic Activities
- Transfers, bed mobility, functional reaching

Balance/Coordination → 97112 Neuromuscular Re-education
- NOT 97530 (common error)

CRITICAL RULES:
- 97110 without functional justification = HIGH risk flag
- All narratives must explain WHY the activity is skilled OT/PT
- Connect strengthening to functional outcomes
- 80-90% of SNF sessions use 97535 + 97530 combination
- If only strengthening exercises selected, you MUST justify why it's medically necessary

NARRATIVE REQUIREMENTS:
- Single flowing paragraph (3-4 sentences)
- Include: what was done + why it's skilled + functional relevance
- Use insurance-compliant language
- Avoid saying "patient performed exercises" - say "patient participated in skilled therapeutic intervention"
- Must demonstrate medical necessity

RESPONSE FORMAT:
Return ONLY a JSON array:
[
  {
    "code": "97110",
    "name": "Therapeutic exercise",
    "narrative": "Patient participated in skilled therapeutic exercise intervention targeting upper body strengthening necessary for functional ADL performance. Interventions included shoulder flexion exercises with 4-pound weight to improve overhead reach required for dressing tasks, chest press to enhance trunk stability during transfers, and trunk rotation exercises to support dynamic balance during toileting. Skilled occupational therapy intervention was required to grade resistance appropriately, monitor compensatory patterns, and ensure carryover to functional activities.",
    "confidence": "high",
    "risk": "low",
    "warning": null
  }
]

If activities don't clearly map to functional goals, include this warning:
"Ensure documentation includes specific functional goals these exercises are addressing to demonstrate medical necessity."

Return ONLY the JSON array. No markdown, no backticks, no preamble. First character must be [ and last must be ].`;

  // Format activities into readable text
  let activitiesText = 'SELECTED ACTIVITIES:\n\n';
  Object.entries(activities).forEach(([category, acts]) => {
    activitiesText += `${category}:\n`;
    acts.forEach(act => activitiesText += `- ${act}\n`);
    activitiesText += '\n';
  });

  const userPrompt = `${activitiesText}

Generate CPT codes and insurance-compliant narratives for these activities. Ensure each narrative connects the activities to functional outcomes and demonstrates medical necessity. Return JSON array only.`;

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
      logRequest(ip, activityCount, isPro, false, `Gemini error: ${err?.error?.code}`);
      
      if (err?.error?.code === 503 || err?.error?.status === 'UNAVAILABLE') {
        throw new Error('The AI service is temporarily overloaded. Please wait 30 seconds and try again.');
      }
      if (err?.error?.code === 429) {
        throw new Error('Too many requests to the AI service. Please wait a moment and try again.');
      }
      throw new Error('AI service error. Please try again.');
    }

    const data = await response.json();
    const raw = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
    
    const stripped = raw.replace(/```json|```|`/g, '').trim();
    const jsonMatch = stripped.match(/\[[\s\S]*\]/);
    const jsonStr = jsonMatch ? jsonMatch[0] : stripped;
    
    let codes;
    try { codes = JSON.parse(jsonStr); }
    catch (parseErr) {
      console.error('Parse error. Raw response:', raw);
      logRequest(ip, activityCount, isPro, false, 'Parse error');
      throw new Error('Could not parse CPT codes. Please try again.');
    }

    if (!Array.isArray(codes) || codes.length === 0) {
      logRequest(ip, activityCount, isPro, false, 'No codes identified');
      throw new Error('No CPT codes identified. Please try again.');
    }

    logRequest(ip, activityCount, isPro, true);

    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    return res.status(200).json({ codes, isPro });

  } catch (err) {
    console.error('Handler error:', err.message);
    logRequest(ip, activityCount, isPro, false, err.message);
    return res.status(500).json({ error: err.message || 'Failed to generate documentation.' });
  }
}
