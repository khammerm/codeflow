// api/extract-codes.js — CodeFlow CPT extraction

import crypto from 'crypto';

const rateMap = new Map();
const RATE_LIMIT = 10;
const RATE_WINDOW = 60_000;

function isRateLimited(ip) {
  const now = Date.now();
  const entry = rateMap.get(ip) || { count: 0, start: now };
  if (now - entry.start > RATE_WINDOW) { rateMap.set(ip, { count: 1, start: now }); return false; }
  if (entry.count >= RATE_LIMIT) return true;
  entry.count++;
  rateMap.set(ip, entry);
  return false;
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
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  // const allowedOrigins = [process.env.ALLOWED_ORIGIN, 'http://localhost:3000'].filter(Boolean);
  // const origin = req.headers['origin'] || '';
  // if (allowedOrigins.length > 0 && !allowedOrigins.includes(origin)) {
  //   return res.status(403).json({ error: 'Forbidden' });
  // }

  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 'unknown';
  if (isRateLimited(ip)) return res.status(429).json({ error: 'Too many requests. Please wait a minute.' });

  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  const isPro = token ? verifyToken(token) : false;

  const { note } = req.body || {};
  if (!note || typeof note !== 'string') return res.status(400).json({ error: 'Missing clinical note.' });
  const trimmed = note.trim();
  if (trimmed.length < 50) return res.status(400).json({ error: 'Clinical note is too short.' });
  if (trimmed.length > 10000) return res.status(400).json({ error: 'Clinical note is too long (max 10000 chars).' });

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) { console.error('GEMINI_API_KEY not set'); return res.status(500).json({ error: 'Server configuration error.' }); }

  const systemPrompt = `You are a CPT code extraction expert for occupational therapy and physical therapy clinical notes.

Analyze the clinical note and identify which CPT codes apply. For each code, provide:
1. The CPT code number
2. Code name
3. Activities from the note that justify this code
4. A compliance-focused justification explaining why this qualifies as skilled OT/PT
5. Confidence level (high/medium/low)
6. Risk level (low/medium/high)
7. Warning if there's a compliance risk

MOST COMMON OT/PT CPT CODES:
- 97535: Self-care/home management training (ADLs: dressing, bathing, toileting, grooming, feeding)
- 97530: Therapeutic activities (functional tasks: transfers, bed mobility, functional mobility, dynamic reaching)
- 97110: Therapeutic exercise (strengthening, ROM, endurance - MUST tie back to function)
- 97112: Neuromuscular re-education (balance, coordination, proprioception, postural control)
- 97532: Cognitive skills development (memory, problem-solving, safety awareness)
- 97140: Manual therapy techniques
- 97010: Hot/cold packs (modality)
- 97032: Electrical stimulation
- 97035: Ultrasound

CRITICAL RULES:
- 97535 is PRIMARY for any ADL training (dressing, bathing, toileting, grooming, feeding)
- 97530 is the "functional catch-all" for transfers, bed mobility, and functional mobility
- 97110 MUST have functional justification or it becomes non-skilled and risks denial
- Balance/coordination activities = 97112 neuromuscular re-ed, NOT 97530
- If strengthening is mentioned without functional context, flag as MEDIUM-HIGH risk
- Manual therapy without skilled justification = flag as HIGH risk
- Modalities (97010, 97032, 97035) have low reimbursement and high scrutiny

ABBREVIATION GUIDE:
- MIN A = minimal assistance
- MOD A = moderate assistance  
- MAX A = maximal assistance
- SUP = supervision
- CGA = contact guard assist
- SBA = standby assistance
- EOB = edge of bed
- BOS = base of support
- LOB = loss of balance
- FWW = front-wheeled walker
- UE/LUE/RUE = upper extremity / left UE / right UE
- LE/LLE/RLE = lower extremity / left LE / right LE
- UB = upper body
- LB = lower body
- ROM = range of motion
- STS = sit-to-stand
- sup>sit = supine to sitting

RESPONSE FORMAT:
Return ONLY a JSON array with this exact structure:
[
  {
    "code": "97535",
    "name": "Self-care training",
    "activities": "LB dressing (MIN A), UB dressing (SUP), sock assist",
    "justification": "Skilled instruction in compensatory techniques for ADL independence with min-mod assist required for sequencing and safety awareness during dressing tasks. Therapist provided skilled facilitation for functional performance.",
    "confidence": "high",
    "risk": "low",
    "warning": null
  }
]

CRITICAL: Return ONLY the JSON array. No markdown, no backticks, no preamble, no explanation. First character must be [ and last must be ].`;

  const userPrompt = `Clinical note:
${trimmed}

Extract all applicable CPT codes with compliance-focused justifications. Return JSON array only.`;

  try {
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          systemInstruction: { parts: [{ text: systemPrompt }] },
          contents: [{ role: 'user', parts: [{ text: userPrompt }] }],
          generationConfig: { temperature: 0.2, maxOutputTokens: 2048 }
        })
      }
    );

    if (!response.ok) {
      const err = await response.json();
      console.error('Gemini error:', err);
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
      throw new Error('Could not parse CPT codes. Please try again.');
    }

    if (!Array.isArray(codes) || codes.length === 0) {
      throw new Error('No CPT codes identified. Please check the clinical note.');
    }

    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    return res.status(200).json({ codes, isPro });

  } catch (err) {
    console.error('Handler error:', err.message);
    return res.status(500).json({ error: err.message || 'Failed to extract codes.' });
  }
}
