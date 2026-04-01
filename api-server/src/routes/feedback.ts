import { Router } from "express";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { randomUUID } from "crypto";
import { join } from "path";

const router = Router();

const DATA_DIR = join(process.cwd(), "data");
const FEEDBACK_FILE = join(DATA_DIR, "feedback.json");

if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });
if (!existsSync(FEEDBACK_FILE)) writeFileSync(FEEDBACK_FILE, "[]");

interface FeedbackEntry {
  id: string;
  appName: string;
  rating: number;
  tags: string[];
  comment?: string;
  deviceId: string;
  timestamp: number;
}

function readAll(): FeedbackEntry[] {
  try { return JSON.parse(readFileSync(FEEDBACK_FILE, "utf-8")); }
  catch { return []; }
}

function writeAll(data: FeedbackEntry[]): void {
  writeFileSync(FEEDBACK_FILE, JSON.stringify(data));
}

// POST /api/feedback — submit or update review for an app
router.post("/", (req, res) => {
  const { appName, rating, tags, comment, deviceId } = req.body as Record<string, unknown>;

  if (!appName || !rating || !deviceId) {
    return res.status(400).json({ error: "appName, rating, and deviceId are required" });
  }
  if (typeof rating !== "number" || rating < 1 || rating > 5) {
    return res.status(400).json({ error: "rating must be 1-5" });
  }

  const data = readAll();
  const name = String(appName).toLowerCase().trim();
  const did = String(deviceId);
  const existingIdx = data.findIndex((e) => e.appName === name && e.deviceId === did);

  const entry: FeedbackEntry = {
    id: existingIdx >= 0 ? data[existingIdx].id : randomUUID(),
    appName: name,
    rating: Number(rating),
    tags: Array.isArray(tags) ? (tags as string[]) : [],
    comment: typeof comment === "string" && comment.trim() ? comment.trim() : undefined,
    deviceId: did,
    timestamp: Date.now(),
  };

  if (existingIdx >= 0) data[existingIdx] = entry; else data.push(entry);
  writeAll(data);
  return res.json({ success: true, id: entry.id });
});

// GET /api/feedback/community/:appName — aggregated view for one app
router.get("/community/:appName", (req, res) => {
  const name = req.params.appName.toLowerCase().trim();
  const entries = readAll().filter((e) => e.appName === name);

  if (entries.length === 0) {
    return res.json({ found: false, appName: name, totalReviews: 0 });
  }

  const avgRating = entries.reduce((s, e) => s + e.rating, 0) / entries.length;

  const tagCounts: Record<string, number> = {};
  for (const e of entries) for (const t of e.tags) tagCounts[t] = (tagCounts[t] ?? 0) + 1;
  const topTags = Object.entries(tagCounts)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 6)
    .map(([tag, count]) => ({ tag, count, pct: Math.round((count / entries.length) * 100) }));

  const distribution = [1, 2, 3, 4, 5].map((r) => ({
    rating: r, count: entries.filter((e) => e.rating === r).length,
  }));

  const communityTrustScore = Math.round(((avgRating - 1) / 4) * 100);

  return res.json({
    found: true,
    appName: name,
    totalReviews: entries.length,
    avgRating: Math.round(avgRating * 10) / 10,
    communityTrustScore,
    topTags,
    distribution,
  });
});

// GET /api/feedback/summary — all apps with community data (for blending into search)
router.get("/summary", (_req, res) => {
  const data = readAll();
  const byApp: Record<string, FeedbackEntry[]> = {};
  for (const e of data) (byApp[e.appName] ??= []).push(e);

  const summary = Object.entries(byApp).map(([appName, entries]) => {
    const avg = entries.reduce((s, e) => s + e.rating, 0) / entries.length;
    return {
      appName,
      totalReviews: entries.length,
      avgRating: Math.round(avg * 10) / 10,
      communityTrustScore: Math.round(((avg - 1) / 4) * 100),
    };
  });

  return res.json({ apps: summary });
});

export default router;
