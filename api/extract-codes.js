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

  // CORS security - allow same-origin OR specific allowed origins
  const origin = req.headers['origin'];
  const allowedOrigin = process.env.ALLOWED_ORIGIN; // e.g., https://codeflow-silk.vercel.app
  
  // If there's an origin header AND it doesn't match allowed origin, block it
  if (origin && allowedOrigin && origin !== allowedOrigin) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  
  // Allow same-origin requests (no origin header) and matching origins
  // This is correct because same-origin requests don't send Origin header

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

  const systemPrompt = `You are a CPT code extraction expert for occupational therapy and physical therapy clinical notes, with specialized knowledge of SNF billing compliance.

Analyze the clinical note and identify which CPT codes apply. For each code, provide:
1. The CPT code number
2. Code name
3. A single narrative paragraph combining activities and justification (don't separate them)
4. Confidence level (high/medium/low)
5. Risk level (low/medium/high)
6. Warning if there's a compliance risk

MOST COMMON OT/PT CPT CODES (80-90% of SNF sessions use 97535 + 97530):
- 97535: Self-care/home management training (ADLs: dressing, bathing, toileting, grooming, feeding, meal prep)
- 97530: Therapeutic activities (functional tasks: transfers, bed mobility, functional mobility, dynamic reaching)
- 97110: Therapeutic exercise (strengthening, ROM, endurance - MUST tie back to function)
- 97112: Neuromuscular re-education (balance, coordination, proprioception, postural control)
- 97532: Cognitive skills development (memory, problem-solving, safety awareness - often overlaps with 97530)
- 97140: Manual therapy techniques (often incorrectly billed under 97110)
- 97010: Hot/cold packs (modality - low reimbursement, high scrutiny)
- 97032: Electrical stimulation
- 97035: Ultrasound

CRITICAL RULES (from SNF therapist expert feedback):
- 97535 is PRIMARY for any ADL training - if dressing, bathing, toileting, grooming, or feeding appears, this MUST be first
- Self-feeding (eating, meal prep) = 97535, same priority as other ADLs
- "Functional mobility" is OT-specific terminology for ambulation - always code as 97530, not PT codes
- Balance/coordination activities = 97112 neuromuscular re-ed, NEVER 97530 (common error to avoid)
- 97530 overuse: if this code appears for everything in a session, flag as potential misuse
- 97110 MUST explicitly link to functional outcomes (ADL performance, transfer safety, etc.) or flag as HIGH risk
- If note mentions "endurance training," flag and suggest rewording to "functional activity tolerance" for compliance
- Manual therapy is often unintentionally miscoded as 97110 - note this if manual therapy techniques are mentioned
- If a session has neither 97535 nor 97530, verify - 80-90% of SNF sessions use this combination

GOAL/PLAN DETECTION (SPECIAL HANDLING):
If the note uses language indicating future plans or goals rather than completed interventions:
- "Pt has goal of..." / "Pt will work on..." / "Plan to address..." / "Continue with..." / "To improve..."
- "Patient to participate in..." / "Goals include..." / "Treatment plan..."

Extract codes based on what interventions would REASONABLY be provided for that goal. Write narratives as if the intervention occurred. Keep narratives CONCISE (3-4 sentences maximum). Add this warning to codes extracted from goals:

"Based on goal statement. Verify these interventions were actually provided before billing."

Example: If input is "Pt has goal of improved LB dressing, participation in UB strengthening"
- Extract 97535 for dressing training
- Extract 97110 for UB strengthening (clinically justified: arm strength supports LB dressing independence)
- Keep each narrative to 3-4 sentences focusing on skilled intervention and functional relevance

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
Return ONLY a JSON array with this exact structure (note: "narrative" field combines activities and justification):
[
  {
    "code": "97535",
    "name": "Self-care training",
    "narrative": "Patient received skilled occupational therapy intervention for lower body dressing requiring minimal assistance for threading right lower extremity through pants with touching assist to complete task, sock donning requiring assistance positioning socks over toes then able to complete independently, and upper body dressing completed with supervision. Skilled instruction was provided in compensatory techniques, sequencing strategies, and safety awareness to improve independence with ADL performance. Intervention qualifies as skilled OT due to the need for therapeutic assessment, grading of assistance levels, and education in adaptive strategies for functional independence.",
    "confidence": "high",
    "risk": "low",
    "warning": null
  }
]

CRITICAL: 
- Write the narrative as ONE flowing paragraph that reads naturally when copied into an EMR
- Include specific details from the note (assist levels, specific activities) in the narrative
- Explain WHY it's skilled OT/PT within the same paragraph
- Return ONLY the JSON array. No markdown, no backticks, no preamble, no explanation. First character must be [ and last must be ].`;

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
          generationConfig: { temperature: 0.2, maxOutputTokens: 4096 }
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
