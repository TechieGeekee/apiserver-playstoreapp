import { Router } from "express";
import { openrouter } from "../lib/openrouter.js";

const router = Router();

// ─── Types ────────────────────────────────────────────────────────────────────

interface LlmAnalysis {
  verdict: string;
  privacyConcerns: string[];
  recommendation: string;
  riskLevel: "Low" | "Medium" | "High" | "Critical";
}

interface HibpBreach {
  Name: string;
  Title: string;
  Domain: string;
  BreachDate: string;
  AddedDate: string;
  PwnCount: number;
  DataClasses: string[];
  Description: string;
  IsVerified: boolean;
  IsSensitive: boolean;
}

// ─── In-memory caches ─────────────────────────────────────────────────────────

const analysisCache = new Map<string, { data: LlmAnalysis & { generatedAt: string }; ts: number }>();
const ANALYSIS_TTL = 60 * 60 * 1000; // 1 hour

let hibpBreachCache: HibpBreach[] | null = null;
let hibpCacheTs = 0;
const HIBP_CACHE_TTL = 60 * 60 * 1000;

// ─── HIBP helpers ─────────────────────────────────────────────────────────────

async function fetchAllHibpBreaches(): Promise<HibpBreach[]> {
  const now = Date.now();
  if (hibpBreachCache && now - hibpCacheTs < HIBP_CACHE_TTL) {
    return hibpBreachCache;
  }
  const resp = await fetch("https://haveibeenpwned.com/api/v3/breaches", {
    headers: {
      "User-Agent": "JustAskUs-Privacy-App/1.0",
      "hibp-api-key": "",
    },
    signal: AbortSignal.timeout(15000),
  });
  if (!resp.ok) {
    throw new Error(`HIBP returned ${resp.status}`);
  }
  const data = (await resp.json()) as HibpBreach[];
  hibpBreachCache = data;
  hibpCacheTs = now;
  return data;
}

function normalise(s: string) {
  return s.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function matchesApp(breach: HibpBreach, appName: string): boolean {
  const q = normalise(appName);
  const bName = normalise(breach.Name);
  const bTitle = normalise(breach.Title);
  const bDomain = normalise((breach.Domain || "").split(".")[0]);
  return (
    bName.includes(q) ||
    q.includes(bName) ||
    bTitle.includes(q) ||
    q.includes(bTitle) ||
    (bDomain.length >= 3 && (bDomain.includes(q) || q.includes(bDomain)))
  );
}

// ─── LLM helpers ──────────────────────────────────────────────────────────────

const MODEL = "meta-llama/llama-3.2-3b-instruct:free";
const MAX_RETRIES = 4;

async function analyzeWithLlm(appName: string, category: string): Promise<LlmAnalysis> {
  const systemPrompt =
    "You are a mobile app privacy and security analyst. Respond ONLY with valid JSON matching the requested schema. No markdown, no explanation — raw JSON only.";

  const userPrompt = `Analyze the mobile app "${appName}" (category: "${category}") for privacy and security risks.
Return exactly this JSON structure:
{
  "verdict": "<2-3 sentence summary of this app's privacy posture and key risks>",
  "privacyConcerns": ["<specific concern 1>", "<specific concern 2>", "<specific concern 3>"],
  "recommendation": "<one sentence recommendation for users>",
  "riskLevel": "<one of: Low | Medium | High | Critical>"
}
Base your analysis on publicly known information about ${appName}. Be specific and factual.`;

  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    try {
      const response = await openrouter.chat.completions.create({
        model: MODEL,
        max_tokens: 500,
        temperature: 0.3,
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: userPrompt },
        ],
      });

      const raw = response.choices[0]?.message?.content ?? "";
      const jsonMatch = raw.match(/\{[\s\S]*\}/);
      if (!jsonMatch) throw new Error("No JSON block found in LLM response");
      const parsed = JSON.parse(jsonMatch[0]) as LlmAnalysis;

      if (!parsed.verdict || !Array.isArray(parsed.privacyConcerns)) {
        throw new Error("Malformed LLM response structure");
      }
      return parsed;
    } catch (err: any) {
      const isRateLimit = err?.status === 429 || err?.message?.includes("429");
      if (isRateLimit && attempt < MAX_RETRIES - 1) {
        const delay = (attempt + 1) * 4000;
        await new Promise((r) => setTimeout(r, delay));
        continue;
      }
      throw err;
    }
  }
  throw new Error("LLM analysis failed after all retries");
}

// ─── Routes ───────────────────────────────────────────────────────────────────

// POST /api/intel/analyze
// Body: { appName: string; category?: string }
router.post("/analyze", async (req, res) => {
  const { appName, category = "General" } = req.body ?? {};

  if (!appName || typeof appName !== "string") {
    res.status(400).json({ error: "appName is required" });
    return;
  }

  const cacheKey = `${normalise(appName)}_${normalise(category)}`;
  const cached = analysisCache.get(cacheKey);
  if (cached && Date.now() - cached.ts < ANALYSIS_TTL) {
    res.json({ ...cached.data, cached: true });
    return;
  }

  try {
    const analysis = await analyzeWithLlm(appName.trim(), category.trim());
    const result = { ...analysis, generatedAt: new Date().toISOString() };
    analysisCache.set(cacheKey, { data: result, ts: Date.now() });
    res.json({ ...result, cached: false });
  } catch (err: any) {
    const isRateLimit = err?.status === 429 || err?.message?.includes("429");
    if (isRateLimit) {
      res.status(429).json({ error: "AI analysis is temporarily rate-limited. Please try again shortly." });
      return;
    }
    res.status(500).json({ error: "Analysis failed", detail: err?.message });
  }
});

// GET /api/intel/breaches?appName=<name>
router.get("/breaches", async (req, res) => {
  const appName = req.query["appName"] as string | undefined;

  if (!appName) {
    res.status(400).json({ error: "appName query parameter is required" });
    return;
  }

  try {
    const allBreaches = await fetchAllHibpBreaches();
    const matches = allBreaches.filter((b) => matchesApp(b, appName));

    res.json({
      breaches: matches.map((b) => ({
        name: b.Name,
        title: b.Title,
        domain: b.Domain,
        breachDate: b.BreachDate,
        pwnCount: b.PwnCount,
        dataClasses: b.DataClasses,
        description: b.Description,
        isVerified: b.IsVerified,
        isSensitive: b.IsSensitive,
      })),
      total: matches.length,
      source: "haveibeenpwned.com",
    });
  } catch (err: any) {
    res.status(502).json({ error: "Unable to fetch breach data", detail: err?.message });
  }
});

export default router;
