import { Router } from "express";
import { openrouter } from "@workspace/integrations-openrouter-ai";
import { APP_DB } from "./search.js";
import { getAppCache, setAppCache } from "../lib/dbCache";

const router = Router();

// ─── Types ─────────────────────────────────────────────────────────────────────

export interface PlaySearchResult {
  name: string;
  packageId: string;
  developer: string | null;
  playRating: number | null;
  downloads: string | null;
  icon: string | null;
  free: boolean;
  price: string;
}

export interface AnalyzedApp extends PlaySearchResult {
  category: string;
  trustScore: number;
  riskLevel: "Low" | "Medium" | "High" | "Critical";
  tagline: string;
  verdict: string;
  concerns: string[];
  greenFlags: string[];
  breachCount: number;
  breaches: Array<{ title: string; date: string; pwnCount: number; dataClasses: string[] }>;
  playRatingsCount: string | null;
}

// ─── Caches ────────────────────────────────────────────────────────────────────

const searchCache = new Map<string, { apps: PlaySearchResult[]; ts: number }>();
const analyzeCache = new Map<string, { data: AnalyzedApp; ts: number }>();
const SEARCH_TTL = 5 * 60 * 1000;   // 5 min
const ANALYZE_TTL = 60 * 60 * 1000; // 1 hour

// ─── Helpers ───────────────────────────────────────────────────────────────────

function formatCount(n: number): string {
  if (n >= 1_000_000_000) return `${(n / 1_000_000_000).toFixed(1)}B`;
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(0)}K`;
  return `${n}`;
}

function normalise(s: string) {
  return s.toLowerCase().replace(/[^a-z0-9]/g, "");
}

// ─── HIBP (shared simple version) ─────────────────────────────────────────────

interface HibpBreach {
  Name: string;
  Title: string;
  Domain: string;
  BreachDate: string;
  PwnCount: number;
  DataClasses: string[];
}

let hibpCache: HibpBreach[] | null = null;
let hibpCacheTs = 0;
const HIBP_TTL = 60 * 60 * 1000;

async function getHibpBreaches(): Promise<HibpBreach[]> {
  if (hibpCache && Date.now() - hibpCacheTs < HIBP_TTL) return hibpCache;
  try {
    const resp = await fetch("https://haveibeenpwned.com/api/v3/breaches", {
      headers: { "User-Agent": "JustAskUs-Privacy-App/1.0" },
      signal: AbortSignal.timeout(12000),
    });
    if (!resp.ok) throw new Error(`HIBP ${resp.status}`);
    const data = (await resp.json()) as HibpBreach[];
    hibpCache = data;
    hibpCacheTs = Date.now();
    return data;
  } catch {
    return hibpCache ?? [];
  }
}

function findBreaches(breaches: HibpBreach[], appName: string) {
  // Normalise app name and extract significant words (3+ chars)
  const q = normalise(appName);
  const qWords = appName.toLowerCase()
    .split(/\s+/)
    .map((w) => w.replace(/[^a-z]/g, ""))
    .filter((w) => w.length >= 3);

  return breaches.filter((b) => {
    const bName = normalise(b.Name);
    const bTitle = normalise(b.Title);
    const bDomain = normalise((b.Domain || "").split(".")[0]);

    // Require a meaningful match: the app name must appear in the breach name/domain,
    // not just any substring match (prevents false positives like "phone" matching unrelated sites)
    const exactOrStrong =
      bName === q ||
      bTitle === q ||
      bDomain === q ||
      // The breach name is fully contained in the app name or vice versa (min 5 chars to avoid noise)
      (q.length >= 5 && bName.includes(q)) ||
      (bName.length >= 5 && q.includes(bName)) ||
      (q.length >= 5 && bDomain.includes(q)) ||
      (bDomain.length >= 5 && q.includes(bDomain));

    if (exactOrStrong) return true;

    // Word-level match: any significant word from the app name matches the breach domain
    return qWords.some(
      (w) => w.length >= 5 && (bDomain === w || bName === w)
    );
  });
}

// ─── LLM security analysis ────────────────────────────────────────────────────

const MODEL = "meta-llama/llama-3.2-3b-instruct:free";

interface LlmAnalysis {
  category: string;
  trustScore: number;
  riskLevel: "Low" | "Medium" | "High" | "Critical";
  tagline: string;
  verdict: string;
  concerns: string[];
  greenFlags: string[];
}

async function analyzeWithLlm(appName: string, developer: string | null): Promise<LlmAnalysis> {
  const systemPrompt =
    "You are a mobile app privacy and security analyst. Respond ONLY with valid JSON. No markdown, no explanation — raw JSON only.";

  const devHint = developer ? ` (by ${developer})` : "";
  const userPrompt = `Analyze the mobile app "${appName}"${devHint} for privacy and security. Return exactly:
{
  "category": "<single word category: Payments | Messaging | Shopping | Streaming | Music | Food | Navigation | Browser | Social | Productivity | Health | Gaming | Other>",
  "trustScore": <integer 0-100>,
  "riskLevel": "<Low | Medium | High | Critical>",
  "tagline": "<1 sentence describing what the app does>",
  "verdict": "<2-3 sentence privacy verdict>",
  "concerns": ["<specific concern>", "<specific concern>", "<specific concern>"],
  "greenFlags": ["<strength>", "<strength>"]
}
Base your analysis on publicly known information. Be specific and factual. trustScore: 80-100=Low risk, 60-79=Medium, 40-59=High, 0-39=Critical.`;

  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const response = await openrouter.chat.completions.create({
        model: MODEL,
        max_tokens: 300,
        temperature: 0.1,
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: userPrompt },
        ],
      });

      const raw = response.choices[0]?.message?.content ?? "";
      const jsonMatch = raw.match(/\{[\s\S]*\}/);
      if (!jsonMatch) throw new Error("No JSON in: " + raw.substring(0, 100));
      const parsed = JSON.parse(jsonMatch[0]) as Partial<LlmAnalysis>;

      return {
        category: parsed.category ?? "Other",
        trustScore: Math.max(0, Math.min(100, parsed.trustScore ?? 50)),
        riskLevel: parsed.riskLevel ?? "Medium",
        tagline: parsed.tagline ?? `${appName} mobile app`,
        verdict: parsed.verdict ?? "No verdict available.",
        concerns: Array.isArray(parsed.concerns) ? parsed.concerns.slice(0, 4) : [],
        greenFlags: Array.isArray(parsed.greenFlags) ? parsed.greenFlags.slice(0, 4) : [],
      };
    } catch (err: any) {
      const isRateLimit = err?.status === 429 || err?.message?.includes("429");
      if (isRateLimit && attempt < 2) {
        await new Promise((r) => setTimeout(r, (attempt + 1) * 4000));
        continue;
      }
      throw err;
    }
  }
  throw new Error("LLM analysis failed");
}

// ─── Route: GET /api/apps/search?q=...&country=in ─────────────────────────────
// Fast real-time Play Store search — no LLM, returns within ~1-2s

router.get("/search", async (req, res) => {
  const { q, country = "in" } = req.query as Record<string, string>;

  if (!q || q.trim().length < 2) {
    res.status(400).json({ error: "q must be at least 2 characters" });
    return;
  }

  const cacheKey = `search:${q.trim().toLowerCase()}:${country}`;
  const cached = searchCache.get(cacheKey);
  if (cached && Date.now() - cached.ts < SEARCH_TTL) {
    res.json({ apps: cached.apps, cached: true });
    return;
  }

  try {
    const gplay = (await import("google-play-scraper")).default;
    const raw = await gplay.search({
      term: q.trim(),
      num: 15,
      country: country as string,
      lang: "en",
      fullDetail: false,
    });

    const apps: PlaySearchResult[] = raw.map((app: any) => {
      const isFree = app.free !== false || !app.price || app.price === "0";
      return {
        name: app.title,
        packageId: app.appId,
        developer: app.developer ?? null,
        playRating: typeof app.score === "number" ? Math.round(app.score * 10) / 10 : null,
        downloads: app.installs ?? null,
        icon: app.icon ?? null,
        free: isFree,
        price: isFree ? "Free" : `$${app.price}`,
      };
    });

    searchCache.set(cacheKey, { apps, ts: Date.now() });
    res.json({ apps, cached: false });
  } catch (err: any) {
    res.status(500).json({ error: "Play Store search failed", detail: err?.message });
  }
});

// ─── Static DB lookup by packageId ────────────────────────────────────────────
// Checks the curated app database first — no LLM needed for known apps

function lookupStaticApp(packageId: string, appName: string) {
  // Check by exact packageId first
  const byId = Object.values(APP_DB).find(
    (r) => r.packageId.toLowerCase() === packageId.toLowerCase()
  );
  if (byId) return byId;

  // Check by normalised name
  const nameNorm = normalise(appName);
  return Object.values(APP_DB).find(
    (r) => normalise(r.name) === nameNorm ||
           nameNorm.startsWith(normalise(r.name)) ||
           normalise(r.name).startsWith(nameNorm)
  ) ?? null;
}

// ─── Route: POST /api/apps/analyze ────────────────────────────────────────────
// Full security analysis for a specific app — static DB first, then LLM + HIBP + Play Store
// Body: { name: string, packageId: string, developer?: string }

router.post("/analyze", async (req, res) => {
  const { name, packageId, developer } = req.body ?? {};

  if (!name || typeof name !== "string" || name.trim().length < 2) {
    res.status(400).json({ error: "name is required" });
    return;
  }
  if (!packageId || typeof packageId !== "string") {
    res.status(400).json({ error: "packageId is required" });
    return;
  }

  const cacheKey = `analyze:${packageId.toLowerCase()}`;

  // L1: in-memory
  const cached = analyzeCache.get(cacheKey);
  if (cached && Date.now() - cached.ts < ANALYZE_TTL) {
    res.json({ app: cached.data, cached: true });
    return;
  }

  // L2: database cache (persistent across restarts)
  const dbCached = await getAppCache(cacheKey);
  if (dbCached) {
    analyzeCache.set(cacheKey, { data: dbCached as any, ts: Date.now() });
    res.json({ app: dbCached, cached: true });
    return;
  }

  try {
    const gplay = (await import("google-play-scraper")).default;

    // ── Step 1: Check static curated DB first — no LLM needed ──
    const staticRecord = lookupStaticApp(packageId, name.trim());

    // ── Step 2: Run Play Store + HIBP in parallel; LLM only for unknown apps ──
    const parallelTasks: [Promise<any>, Promise<HibpBreach[]>, Promise<any> | null] = [
      gplay.app({ appId: packageId, country: "in", lang: "en" }).catch(() => null),
      getHibpBreaches(),
      staticRecord ? Promise.resolve(null) : analyzeWithLlm(name.trim(), developer ?? null).catch(() => null),
    ];

    const [ps, allBreaches, llmRaw] = await Promise.all(parallelTasks);

    // ── Play Store data ──
    const isFree = ps?.free !== false || !ps?.price || ps?.price === "0";
    const psData: Partial<PlaySearchResult> = ps
      ? {
          name: ps.title ?? name,
          developer: ps.developer ?? developer ?? null,
          playRating: typeof ps.score === "number" ? Math.round(ps.score * 10) / 10 : null,
          downloads: ps.installs ?? null,
          icon: ps.icon ?? null,
          free: isFree,
          price: isFree ? "Free" : `$${ps.price}`,
        }
      : {
          name,
          developer: developer ?? null,
          playRating: null,
          downloads: null,
          icon: null,
          free: true,
          price: "Free",
        };

    const playRatingsCount = ps?.ratings ? formatCount(ps.ratings) : null;

    // ── HIBP breaches ──
    const matched = findBreaches(allBreaches ?? [], name.trim());

    // ── Intelligence: static DB wins, LLM is fallback ──
    const intel = staticRecord
      ? {
          category: "Known App",
          trustScore: staticRecord.trustScore,
          riskLevel: staticRecord.riskLevel,
          tagline: staticRecord.tagline,
          verdict: staticRecord.description,
          concerns: staticRecord.concerns,
          greenFlags: staticRecord.greenFlags,
        }
      : (llmRaw ?? {
          category: "Other",
          trustScore: 55,
          riskLevel: "Medium" as const,
          tagline: `${name} mobile app`,
          verdict: "AI analysis temporarily unavailable. Play Store data and breach check still applied.",
          concerns: ["Unable to complete AI analysis — check back shortly"],
          greenFlags: [],
        });

    // ── Adjust trust score for confirmed breaches ──
    let trustScore = intel.trustScore;
    if (matched.length > 0 && !staticRecord) {
      trustScore = Math.max(5, trustScore - matched.length * 8);
    }

    const analyzed: AnalyzedApp = {
      name: psData.name ?? name,
      packageId,
      developer: psData.developer ?? staticRecord?.developer ?? null,
      playRating: psData.playRating ?? null,
      playRatingsCount,
      downloads: psData.downloads ?? null,
      icon: psData.icon ?? null,
      free: psData.free ?? true,
      price: psData.price ?? "Free",
      category: intel.category,
      trustScore,
      riskLevel: intel.riskLevel,
      tagline: intel.tagline,
      verdict: intel.verdict,
      concerns: intel.concerns,
      greenFlags: intel.greenFlags,
      breachCount: matched.length,
      breaches: matched.slice(0, 3).map((b) => ({
        title: b.Title,
        date: b.BreachDate,
        pwnCount: b.PwnCount,
        dataClasses: b.DataClasses.slice(0, 4),
      })),
    };

    analyzeCache.set(cacheKey, { data: analyzed, ts: Date.now() });
    setAppCache(cacheKey, analyzed, 12).catch(() => {});
    res.json({ app: analyzed, cached: false });
  } catch (err: any) {
    const isRateLimit = err?.status === 429 || err?.message?.includes("429");
    if (isRateLimit) {
      res.status(429).json({ error: "AI is busy — please wait 30 seconds and try again." });
      return;
    }
    res.status(500).json({ error: "Analysis failed", detail: err?.message });
  }
});

// ─── Route: GET /api/apps/detail?packageId=... ────────────────────────────────
// Full app detail — Play Store data + top positive/negative reviews + security score
// Returns instantly from cache after first call (cached 2h)

export interface AppReview {
  userName: string;
  text: string;
  score: number;
  thumbsUp: number;
  date: string;
}

export interface AppDetailResult {
  packageId: string;
  name: string;
  developer: string | null;
  developerEmail: string | null;
  icon: string | null;
  headerImage: string | null;
  screenshots: string[];
  description: string;
  shortDescription: string;
  playRating: number | null;
  ratingsCount: string | null;
  installs: string | null;
  category: string | null;
  contentRating: string | null;
  updated: string | null;
  version: string | null;
  size: string | null;
  recentChanges: string | null;
  free: boolean;
  price: string;
  positiveReviews: AppReview[];
  negativeReviews: AppReview[];
  trustScore: number;
  riskLevel: "Low" | "Medium" | "High" | "Critical";
  breachCount: number;
  developerWebsite: string | null;
}

const detailCache = new Map<string, { data: AppDetailResult; ts: number }>();
const DETAIL_TTL = 2 * 60 * 60 * 1000; // 2 hours

router.get("/detail", async (req, res) => {
  const { packageId } = req.query as Record<string, string>;

  if (!packageId || typeof packageId !== "string" || packageId.trim().length < 3) {
    res.status(400).json({ error: "packageId is required" });
    return;
  }

  const cacheKey = packageId.trim().toLowerCase();
  const cached = detailCache.get(cacheKey);
  if (cached && Date.now() - cached.ts < DETAIL_TTL) {
    res.json({ app: cached.data, cached: true });
    return;
  }

  try {
    const gplay = (await import("google-play-scraper")).default;

    // Fetch app details and reviews in parallel
    const [psResult, reviewsResult] = await Promise.allSettled([
      gplay.app({ appId: packageId.trim(), lang: "en", country: "in" }),
      gplay.reviews({
        appId: packageId.trim(),
        lang: "en",
        country: "in",
        sort: 3, // HELPFULNESS — most useful reviews first
        num: 60,
      }),
    ]);

    if (psResult.status === "rejected") {
      res.status(404).json({ error: "App not found on Play Store" });
      return;
    }

    const ps = psResult.value as any;
    const rawReviews: any[] = reviewsResult.status === "fulfilled"
      ? (reviewsResult.value as any)?.data ?? []
      : [];

    // Split into positive and negative
    const positiveReviews: AppReview[] = rawReviews
      .filter((r: any) => r.score >= 4 && r.text && r.text.trim().length > 20)
      .sort((a: any, b: any) => (b.thumbsUp ?? 0) - (a.thumbsUp ?? 0))
      .slice(0, 5)
      .map((r: any) => ({
        userName: r.userName ?? "User",
        text: r.text ?? "",
        score: r.score,
        thumbsUp: r.thumbsUp ?? 0,
        date: r.date ? new Date(r.date).toLocaleDateString("en-IN", { day: "numeric", month: "short", year: "numeric" }) : "",
      }));

    const negativeReviews: AppReview[] = rawReviews
      .filter((r: any) => r.score <= 2 && r.text && r.text.trim().length > 20)
      .sort((a: any, b: any) => (b.thumbsUp ?? 0) - (a.thumbsUp ?? 0))
      .slice(0, 5)
      .map((r: any) => ({
        userName: r.userName ?? "User",
        text: r.text ?? "",
        score: r.score,
        thumbsUp: r.thumbsUp ?? 0,
        date: r.date ? new Date(r.date).toLocaleDateString("en-IN", { day: "numeric", month: "short", year: "numeric" }) : "",
      }));

    // HIBP breach check
    const allBreaches = await getHibpBreaches();
    const breaches = findBreaches(allBreaches, ps.title ?? packageId);

    // Trust score
    const playRating = typeof ps.score === "number" ? Math.round(ps.score * 10) / 10 : null;
    const { score, riskLevel } = fastTrustScore(playRating, ps.installs ?? null, ps.developer ?? null, breaches.length);

    const ratingCount = typeof ps.ratings === "number" ? formatCount(ps.ratings) : null;

    const detail: AppDetailResult = {
      packageId: packageId.trim(),
      name: ps.title ?? packageId,
      developer: ps.developer ?? null,
      developerEmail: ps.developerEmail ?? null,
      developerWebsite: ps.developerWebsite ?? null,
      icon: ps.icon ?? null,
      headerImage: ps.headerImage ?? null,
      screenshots: Array.isArray(ps.screenshots) ? ps.screenshots.slice(0, 4) : [],
      description: ps.description ?? "",
      shortDescription: ps.summary ?? "",
      playRating,
      ratingsCount: ratingCount,
      installs: ps.installs ?? null,
      category: ps.genre ?? null,
      contentRating: ps.contentRating ?? null,
      updated: ps.updated
        ? new Date(ps.updated).toLocaleDateString("en-IN", { day: "numeric", month: "short", year: "numeric" })
        : null,
      version: ps.version ?? null,
      size: ps.size ?? null,
      recentChanges: ps.recentChanges ?? null,
      free: ps.free !== false,
      price: ps.free !== false ? "Free" : (ps.price ? `$${ps.price}` : "Paid"),
      positiveReviews,
      negativeReviews,
      trustScore: score,
      riskLevel,
      breachCount: breaches.length,
    };

    detailCache.set(cacheKey, { data: detail, ts: Date.now() });
    res.json({ app: detail, cached: false });
  } catch (err: any) {
    res.status(500).json({ error: "Failed to fetch app details", detail: err?.message });
  }
});

// ─── Route: POST /api/apps/batch-check ────────────────────────────────────────
// Fast batch analysis for My Apps scan — no LLM, uses Play Store + HIBP + static DB
// Body: { packages: Array<{ packageId: string; name: string }> }
// Returns a trust score for every app that exists on the Play Store

export interface BatchCheckResult {
  packageId: string;
  name: string;
  developer: string | null;
  icon: string | null;
  playRating: number | null;
  downloads: string | null;
  category: string;
  trustScore: number;
  riskLevel: "Low" | "Medium" | "High" | "Critical";
  breachCount: number;
  isFromStaticDb: boolean;
  source: "static" | "playstore";
}

// System/framework packages to skip — not user apps
const SYSTEM_PREFIXES = [
  "com.android.", "android.", "com.google.android.gms",
  "com.google.android.gsf", "com.google.android.webview",
  "com.qualcomm.", "com.mediatek.", "com.qti.", "com.sec.android.provider",
  "com.miui.securitycenter", "com.samsung.android.incallui",
  "com.google.android.permissioncontroller", "com.google.android.ext.services",
  "dalvik.", "com.android.providers.", "com.android.settings",
];

function isSystemPackage(pkg: string): boolean {
  return SYSTEM_PREFIXES.some((p) => pkg.startsWith(p)) ||
    !pkg.includes(".") || // bare package names
    pkg.startsWith("android");
}

// Fast trust score without LLM — based on Play Store rating + HIBP + known red flags
function fastTrustScore(
  rating: number | null,
  downloads: string | null,
  developerName: string | null,
  breachCount: number,
  staticScore?: number
): { score: number; riskLevel: "Low" | "Medium" | "High" | "Critical" } {
  if (staticScore !== undefined) {
    // Static DB score is curated and accurate — use it directly
    const risk = staticScore >= 80 ? "Low" : staticScore >= 60 ? "Medium" : staticScore >= 40 ? "High" : "Critical";
    return { score: staticScore, riskLevel: risk };
  }

  let score = 60; // neutral baseline

  // Play Store rating factor
  if (rating !== null) {
    score += Math.round((rating - 3.5) * 10); // 5.0 = +15, 4.0 = +5, 3.0 = -5, 2.0 = -15
  }

  // Download volume factor (popular apps tend to be better maintained)
  if (downloads) {
    if (downloads.includes("1,000,000,000") || downloads.toLowerCase().includes("1b")) score += 8;
    else if (downloads.includes("500,000,000")) score += 6;
    else if (downloads.includes("100,000,000")) score += 4;
    else if (downloads.includes("10,000,000")) score += 2;
  }

  // Breach penalty
  score -= breachCount * 10;

  // Developer red flags
  const dev = (developerName ?? "").toLowerCase();
  if (/alibaba|bytedance|baidu|tencent|huawei|xiaomi|shein|ucweb/i.test(dev)) score -= 15;
  if (/cambridge|analytica/i.test(dev)) score -= 20;
  if (/meta platforms|facebook/i.test(dev)) score -= 8;

  score = Math.max(5, Math.min(95, score));
  const risk = score >= 80 ? "Low" : score >= 60 ? "Medium" : score >= 40 ? "High" : "Critical";
  return { score, riskLevel: risk };
}

const batchCache = new Map<string, { result: BatchCheckResult; ts: number }>();
const BATCH_TTL = 2 * 60 * 60 * 1000; // 2 hours

router.post("/batch-check", async (req, res) => {
  const { packages } = req.body ?? {};

  if (!Array.isArray(packages) || packages.length === 0) {
    res.status(400).json({ error: "packages array is required" });
    return;
  }

  // Cap at 80 apps per request; filter out system packages
  const userPackages = packages
    .filter((p: any) => p?.packageId && typeof p.packageId === "string" && !isSystemPackage(p.packageId))
    .slice(0, 80);

  if (userPackages.length === 0) {
    res.json({ results: [] });
    return;
  }

  try {
    const gplay = (await import("google-play-scraper")).default;
    const allBreaches = await getHibpBreaches();

    // Process in parallel batches of 10 to avoid rate-limiting the Play Store scraper
    const BATCH = 10;
    const results: BatchCheckResult[] = [];

    for (let i = 0; i < userPackages.length; i += BATCH) {
      const chunk = userPackages.slice(i, i + BATCH);

      const chunkResults = await Promise.allSettled(
        chunk.map(async (pkg: { packageId: string; name: string }) => {
          // ── Cache check ──
          const cached = batchCache.get(pkg.packageId.toLowerCase());
          if (cached && Date.now() - cached.ts < BATCH_TTL) return cached.result;

          // ── Static DB check ──
          const staticRecord = lookupStaticApp(pkg.packageId, pkg.name ?? "");

          // ── Play Store data ──
          let ps: any = null;
          try {
            ps = await gplay.app({ appId: pkg.packageId, country: "in", lang: "en" });
          } catch {
            // App not on Play Store or fetch failed — skip
            if (!staticRecord) return null;
          }

          const appName = ps?.title ?? staticRecord?.name ?? pkg.name ?? pkg.packageId;
          const developer = ps?.developer ?? staticRecord?.developer ?? null;
          const isFree = ps?.free !== false || !ps?.price || ps?.price === "0";

          // ── HIBP breach check ──
          const breaches = findBreaches(allBreaches, appName);

          // ── Trust score ──
          const playRating = typeof ps?.score === "number" ? Math.round(ps.score * 10) / 10 : null;
          const { score, riskLevel } = fastTrustScore(
            playRating,
            ps?.installs ?? null,
            developer,
            breaches.length,
            staticRecord?.trustScore
          );

          // ── Category ──
          let category = staticRecord ? "Known App" : (ps?.genre ?? ps?.genreId ?? "App");
          if (category.toLowerCase().includes("finance") || category.toLowerCase().includes("business"))
            category = "Finance";
          else if (category.toLowerCase().includes("social") || category.toLowerCase().includes("communication"))
            category = "Social";
          else if (category.toLowerCase().includes("shopping") || category.toLowerCase().includes("ecommerce"))
            category = "Shopping";
          else if (category.toLowerCase().includes("entertainment") || category.toLowerCase().includes("video"))
            category = "Streaming";
          else if (category.toLowerCase().includes("music"))
            category = "Music";
          else if (category.toLowerCase().includes("productivity"))
            category = "Productivity";
          else if (category.toLowerCase().includes("game"))
            category = "Gaming";
          else if (category.toLowerCase().includes("health"))
            category = "Health";
          else if (category.toLowerCase().includes("travel"))
            category = "Navigation";
          else if (category.toLowerCase().includes("food"))
            category = "Food";
          else if (category.toLowerCase().includes("tool") || category.toLowerCase().includes("util"))
            category = "Tools";
          else if (staticRecord)
            category = "Known App";

          const result: BatchCheckResult = {
            packageId: pkg.packageId,
            name: appName,
            developer,
            icon: ps?.icon ?? null,
            playRating,
            downloads: ps?.installs ?? null,
            category,
            trustScore: score,
            riskLevel,
            breachCount: breaches.length,
            isFromStaticDb: !!staticRecord,
            source: staticRecord ? "static" : "playstore",
          };

          batchCache.set(pkg.packageId.toLowerCase(), { result, ts: Date.now() });
          return result;
        })
      );

      const valid = chunkResults
        .filter((r): r is PromiseFulfilledResult<BatchCheckResult | null> => r.status === "fulfilled")
        .map((r) => r.value)
        .filter((r): r is BatchCheckResult => r !== null);

      results.push(...valid);
    }

    // Sort: highest risk first, then by trust score descending
    results.sort((a, b) => a.trustScore - b.trustScore);

    res.json({ results, total: results.length });
  } catch (err: any) {
    res.status(500).json({ error: "Batch check failed", detail: err?.message });
  }
});

export default router;

