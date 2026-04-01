import { Router } from "express";

const router = Router();

// ─── Types ────────────────────────────────────────────────────────────────────

export interface FeedItem {
  id: string;
  source: "hibp" | "thehackernews" | "securityweek" | "cisa_alerts" | "cisa_kev";
  type: "breach" | "news" | "threat" | "vulnerability";
  title: string;
  description: string;
  url?: string;
  publishedAt: string;
  severity: "Low" | "Medium" | "High" | "Critical";
  affectedApps: string[];
  pwnCount?: number;
  dataClasses?: string[];
}

// ─── Known app names for matching ────────────────────────────────────────────

const KNOWN_APPS = [
  "GPay","PhonePe","Paytm","WhatsApp","Signal","Telegram","Facebook","Instagram",
  "TikTok","UC Browser","Chrome","Spotify","Google Maps","Zomato","Netflix","Amazon",
  "Flipkart","Meesho","Uber","Ola","Groww","Zerodha","CRED","Swiggy","Firefox",
  "Brave","NordVPN","Hotspot Shield","BGMI","Snapchat","Duolingo","HealthifyMe","Notion",
  "Twitter","X","LinkedIn","YouTube","Google","Apple","Microsoft","Adobe","Zoom",
  "Slack","Dropbox","PayPal","Airbnb","Pinterest","Reddit","Twitch","Discord",
  "Canva","Figma","Shopify","Alibaba","TikTok","ByteDance","Temu","Shein",
];

function findAffectedApps(text: string): string[] {
  const lower = text.toLowerCase();
  return KNOWN_APPS.filter((app) => lower.includes(app.toLowerCase()));
}

// ─── Cache ────────────────────────────────────────────────────────────────────

let feedCache: FeedItem[] | null = null;
let feedCacheTs = 0;
const FEED_CACHE_TTL = 20 * 60 * 1000; // 20 min

// ─── RSS parsing ─────────────────────────────────────────────────────────────

function extractCdata(raw: string): string {
  return raw.replace(/<!\[CDATA\[|\]\]>/g, "").trim();
}

function parseRssItems(
  xml: string,
  source: FeedItem["source"],
  type: FeedItem["type"],
  defaultSeverity: FeedItem["severity"]
): FeedItem[] {
  const items: FeedItem[] = [];
  const blocks = xml.matchAll(/<item>([\s\S]*?)<\/item>/g);

  for (const block of blocks) {
    const body = block[1];
    const rawTitle = body.match(/<title>([\s\S]*?)<\/title>/)?.[1] ?? "";
    const rawDesc = body.match(/<description>([\s\S]*?)<\/description>/s)?.[1] ?? "";
    const rawLink =
      body.match(/<link>([\s\S]*?)<\/link>/)?.[1] ??
      body.match(/<link\s+href="([^"]+)"/)?.[1] ?? "";
    const rawDate = body.match(/<pubDate>([\s\S]*?)<\/pubDate>/)?.[1] ??
      body.match(/<dc:date>([\s\S]*?)<\/dc:date>/)?.[1] ?? "";

    const title = extractCdata(rawTitle);
    const description = extractCdata(rawDesc)
      .replace(/<[^>]+>/g, "")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 280);
    const url = extractCdata(rawLink).trim();

    if (!title) continue;

    const fullText = `${title} ${description}`.toLowerCase();
    let severity: FeedItem["severity"] = defaultSeverity;
    if (/critical|zero.?day|zero.day|ransomware|nation.state/.test(fullText)) severity = "Critical";
    else if (/hack|breach|exploit|attack|malware|phish|leak/.test(fullText)) severity = "High";
    else if (/warning|vulnerabilit|update|patch/.test(fullText)) severity = "Medium";

    const publishedAt = rawDate ? new Date(extractCdata(rawDate.trim())).toISOString() : new Date().toISOString();
    const id = `${source}_${Buffer.from(title).toString("base64").slice(0, 16)}`;

    items.push({
      id,
      source,
      type,
      title,
      description,
      url,
      publishedAt,
      severity,
      affectedApps: findAffectedApps(`${title} ${description}`),
    });
  }

  return items;
}

// ─── Fetchers ─────────────────────────────────────────────────────────────────

async function fetchHibpBreaches(): Promise<FeedItem[]> {
  const resp = await fetch("https://haveibeenpwned.com/api/v3/breaches", {
    headers: { "User-Agent": "JustAskUs-SecurityFeed/1.0" },
    signal: AbortSignal.timeout(12000),
  });
  if (!resp.ok) return [];

  const breaches = (await resp.json()) as any[];
  const cutoff = Date.now() - 180 * 24 * 60 * 60 * 1000; // last 180 days

  return breaches
    .filter((b) => {
      const added = new Date(b.AddedDate).getTime();
      return added > cutoff;
    })
    .sort((a, b) => new Date(b.AddedDate).getTime() - new Date(a.AddedDate).getTime())
    .slice(0, 25)
    .map((b) => {
      const count: number = b.PwnCount;
      let severity: FeedItem["severity"] =
        count > 10_000_000 ? "Critical" :
        count > 1_000_000 ? "High" :
        count > 100_000 ? "Medium" : "Low";
      if (b.IsSensitive) severity = "Critical";

      return {
        id: `hibp_${b.Name}`,
        source: "hibp" as const,
        type: "breach" as const,
        title: `${b.Title} Data Breach`,
        description: `${count.toLocaleString()} accounts exposed. Data included: ${(b.DataClasses as string[]).slice(0, 3).join(", ")}.`,
        url: `https://haveibeenpwned.com/PwnedWebsites#${b.Name}`,
        publishedAt: new Date(b.AddedDate).toISOString(),
        severity,
        affectedApps: findAffectedApps(`${b.Name} ${b.Title} ${b.Domain}`),
        pwnCount: count,
        dataClasses: b.DataClasses,
      } satisfies FeedItem;
    });
}

async function fetchRssFeed(
  url: string,
  source: FeedItem["source"],
  type: FeedItem["type"],
  defaultSeverity: FeedItem["severity"]
): Promise<FeedItem[]> {
  try {
    const resp = await fetch(url, {
      headers: { "User-Agent": "Mozilla/5.0 (compatible; JustAskUs-SecurityBot/1.0)" },
      signal: AbortSignal.timeout(10000),
    });
    if (!resp.ok) return [];
    const xml = await resp.text();
    return parseRssItems(xml, source, type, defaultSeverity).slice(0, 15);
  } catch {
    return [];
  }
}

async function fetchCisaKev(): Promise<FeedItem[]> {
  try {
    const resp = await fetch(
      "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
      { signal: AbortSignal.timeout(12000) }
    );
    if (!resp.ok) return [];
    const data = (await resp.json()) as {
      vulnerabilities: {
        cveID: string;
        vulnerabilityName: string;
        dateAdded: string;
        shortDescription: string;
        product: string;
        vendorProject: string;
        requiredAction: string;
        dueDate: string;
        knownRansomwareCampaignUse: string;
      }[];
    };

    const cutoff = Date.now() - 90 * 24 * 60 * 60 * 1000;
    return data.vulnerabilities
      .filter((v) => new Date(v.dateAdded).getTime() > cutoff)
      .sort((a, b) => new Date(b.dateAdded).getTime() - new Date(a.dateAdded).getTime())
      .slice(0, 15)
      .map((v) => {
        const isRansomware = v.knownRansomwareCampaignUse === "Known";
        return {
          id: `cisa_${v.cveID}`,
          source: "cisa_kev" as const,
          type: "vulnerability" as const,
          title: `${v.cveID}: ${v.vulnerabilityName}`,
          description: `${v.shortDescription} Affects: ${v.vendorProject} ${v.product}. Action required by ${v.dueDate}.`,
          url: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`,
          publishedAt: new Date(v.dateAdded).toISOString(),
          severity: isRansomware ? "Critical" : "High",
          affectedApps: findAffectedApps(`${v.vendorProject} ${v.product} ${v.vulnerabilityName}`),
        } satisfies FeedItem;
      });
  } catch {
    return [];
  }
}

async function fetchCisaAlerts(): Promise<FeedItem[]> {
  return fetchRssFeed(
    "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "cisa_alerts",
    "threat",
    "High"
  );
}

async function fetchTheHackerNews(): Promise<FeedItem[]> {
  return fetchRssFeed(
    "https://feeds.feedburner.com/TheHackersNews",
    "thehackernews",
    "news",
    "Medium"
  );
}

async function fetchSecurityWeek(): Promise<FeedItem[]> {
  return fetchRssFeed(
    "https://feeds.feedburner.com/securityweek",
    "securityweek",
    "news",
    "Medium"
  );
}

// ─── Aggregator ───────────────────────────────────────────────────────────────

async function buildFeed(): Promise<FeedItem[]> {
  const [hibp, thn, sw, cisaAlerts, cisaKev] = await Promise.allSettled([
    fetchHibpBreaches(),
    fetchTheHackerNews(),
    fetchSecurityWeek(),
    fetchCisaAlerts(),
    fetchCisaKev(),
  ]);

  const all: FeedItem[] = [
    ...(hibp.status === "fulfilled" ? hibp.value : []),
    ...(thn.status === "fulfilled" ? thn.value : []),
    ...(sw.status === "fulfilled" ? sw.value : []),
    ...(cisaAlerts.status === "fulfilled" ? cisaAlerts.value : []),
    ...(cisaKev.status === "fulfilled" ? cisaKev.value : []),
  ];

  // Deduplicate by id
  const seen = new Set<string>();
  const deduped = all.filter((item) => {
    if (seen.has(item.id)) return false;
    seen.add(item.id);
    return true;
  });

  // Sort by date descending
  return deduped.sort(
    (a, b) => new Date(b.publishedAt).getTime() - new Date(a.publishedAt).getTime()
  );
}

// ─── Routes ───────────────────────────────────────────────────────────────────

// GET /api/intel/feed
router.get("/feed", async (req, res) => {
  const now = Date.now();

  if (feedCache && now - feedCacheTs < FEED_CACHE_TTL) {
    res.json({ items: feedCache, total: feedCache.length, cached: true, lastUpdated: new Date(feedCacheTs).toISOString() });
    return;
  }

  try {
    const items = await buildFeed();
    feedCache = items;
    feedCacheTs = now;
    res.json({ items, total: items.length, cached: false, lastUpdated: new Date().toISOString() });
  } catch (err: any) {
    res.status(500).json({ error: "Feed fetch failed", detail: err?.message });
  }
});

export default router;
