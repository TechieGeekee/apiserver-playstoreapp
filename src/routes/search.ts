import { Router } from "express";
import { openrouter } from "../lib/openrouter.js";
import { getSearchCache, setSearchCache } from "../lib/dbCache";

const router = Router();

// ─── Types ────────────────────────────────────────────────────────────────────

export interface AppResult {
  name: string;
  packageId: string;
  category: string;
  trustScore: number;
  riskLevel: "Low" | "Medium" | "High" | "Critical";
  tagline: string;
  description: string;
  concerns: string[];
  greenFlags: string[];
  playRating: number | null;
  playRatingsCount: string | null;
  playDownloads: string | null;
  developer: string | null;
  playIcon: string | null;
  price: string;
  breachCount: number;
  breaches: Array<{ title: string; date: string; pwnCount: number; dataClasses: string[] }>;
}

// ─── Curated app intelligence database ───────────────────────────────────────
// Separated strictly by category so cross-category contamination is impossible

export type AppRecord = {
  name: string;
  packageId: string;
  trustScore: number;
  riskLevel: "Low" | "Medium" | "High" | "Critical";
  tagline: string;
  description: string;
  concerns: string[];
  greenFlags: string[];
  developer: string;
};

export const APP_DB: Record<string, AppRecord> = {
  GPay: {
    name: "GPay", packageId: "com.google.android.apps.nbu.paisa.user",
    trustScore: 88, riskLevel: "Low",
    tagline: "Google's UPI payment app with AI fraud detection",
    description: "Google Pay offers instant UPI transfers, bill payments, and cashback rewards. Backed by Google's security infrastructure.",
    concerns: ["Transaction patterns used to improve Google ad targeting", "Requires active Google account"],
    greenFlags: ["Google AI fraud detection", "Zero transaction fees", "RBI-regulated", "NPCI certified"],
    developer: "Google LLC",
  },
  PhonePe: {
    name: "PhonePe", packageId: "com.phonepe.app",
    trustScore: 68, riskLevel: "Medium",
    tagline: "India's most used payment super-app",
    description: "PhonePe offers UPI payments, insurance, investments, and merchant QR. Walmart subsidiary.",
    concerns: ["SMS reading permission broader than needed for UPI", "Data shared with Walmart", "Undisclosed breach in 2021"],
    greenFlags: ["NPCI certified UPI", "Large merchant network", "RBI regulated"],
    developer: "PhonePe Private Limited",
  },
  Paytm: {
    name: "Paytm", packageId: "net.one97.paytm",
    trustScore: 32, riskLevel: "Critical",
    tagline: "India's pioneer digital payments platform",
    description: "Paytm offers UPI, wallet, savings, and loans. RBI banned Paytm Payments Bank in 2024 for data-sharing with a Chinese entity.",
    concerns: ["RBI banned Paytm Payments Bank (Jan 2024) for KYC failures and Chinese data-sharing", "Call log and SMS permissions", "Data linkage to Chinese tech company"],
    greenFlags: ["Largest merchant QR network", "Offline UPI support"],
    developer: "One97 Communications",
  },
  CRED: {
    name: "CRED", packageId: "com.dreamplug.androidapp",
    trustScore: 65, riskLevel: "Medium",
    tagline: "Credit card bill payments with exclusive rewards",
    description: "CRED rewards users for paying credit card bills on time. Premium fintech app with CRED coins and exclusive brand offers.",
    concerns: ["Requires full credit score access", "Limited to credit card users", "Startup — limited regulatory track record vs banks"],
    greenFlags: ["Encrypted financial data", "RBI registered", "Strong verification process"],
    developer: "Dreamplug Technologies",
  },
  "Amazon Pay": {
    name: "Amazon Pay", packageId: "in.amazon.mShop.android.shopping",
    trustScore: 72, riskLevel: "Low",
    tagline: "Amazon's embedded payments solution",
    description: "Amazon Pay enables UPI, wallet, and card payments within Amazon's ecosystem. Tied to Amazon account.",
    concerns: ["Purchase data feeds Amazon's ad targeting", "Combined with shopping behavior data"],
    greenFlags: ["Amazon-level security infrastructure", "Zero transaction fees", "RBI regulated"],
    developer: "Amazon.com",
  },
  Signal: {
    name: "Signal", packageId: "org.thoughtcrime.securesms",
    trustScore: 97, riskLevel: "Low",
    tagline: "The gold standard of private messaging",
    description: "Signal uses end-to-end encryption for all messages and calls. No ads, no data collection, non-profit.",
    concerns: ["Requires phone number to register", "Limited to messaging — no payments or stories"],
    greenFlags: ["Open-source encryption", "No ads ever", "Non-profit Signal Foundation", "Sealed sender to hide metadata"],
    developer: "Signal Foundation",
  },
  WhatsApp: {
    name: "WhatsApp", packageId: "com.whatsapp",
    trustScore: 54, riskLevel: "High",
    tagline: "World's most popular messaging app",
    description: "WhatsApp offers end-to-end encrypted messaging and calls but shares metadata with Meta's advertising ecosystem.",
    concerns: ["Metadata shared with Meta/Facebook", "Phone contacts uploaded to Meta servers", "2021 privacy policy forced consent"],
    greenFlags: ["End-to-end encryption for messages", "Calls are encrypted", "Free global calls"],
    developer: "Meta Platforms",
  },
  Telegram: {
    name: "Telegram", packageId: "org.telegram.messenger",
    trustScore: 62, riskLevel: "Medium",
    tagline: "Fast cloud-based messaging with large groups",
    description: "Telegram offers fast messaging, large groups, and bots. Default chats are NOT end-to-end encrypted.",
    concerns: ["Default chats stored on Telegram servers — not E2E encrypted", "CEO arrested in France (2024) over lack of moderation", "Russia-linked origin"],
    greenFlags: ["Secret chats are E2E encrypted", "Self-destructing messages", "No ads in personal chats"],
    developer: "Telegram FZ-LLC",
  },
  Snapchat: {
    name: "Snapchat", packageId: "com.snapchat.android",
    trustScore: 40, riskLevel: "High",
    tagline: "Disappearing photo and video messaging",
    description: "Snapchat popularized ephemeral media but has a significant breach history and aggressive data collection.",
    concerns: ["4.6M user phone numbers leaked (2014)", "Aggressive advertising tracking", "Snap Map shares real-time location"],
    greenFlags: ["Photos disappear by default", "Friend check feature for safety"],
    developer: "Snap Inc.",
  },
  Brave: {
    name: "Brave", packageId: "com.brave.browser",
    trustScore: 92, riskLevel: "Low",
    tagline: "Privacy-first browser with built-in ad blocking",
    description: "Brave blocks ads and trackers by default, is Chromium-based, and optionally pays users for viewing privacy-respecting ads.",
    concerns: ["Brave Ads program shares browsing context (opt-in only)", "Some controversy around affiliate link handling"],
    greenFlags: ["Blocks all third-party trackers", "Built-in fingerprinting protection", "No data collection", "Open-source"],
    developer: "Brave Software",
  },
  Firefox: {
    name: "Firefox", packageId: "org.mozilla.firefox",
    trustScore: 88, riskLevel: "Low",
    tagline: "Open-source browser by Mozilla Foundation",
    description: "Firefox is fully open-source, privacy-respecting, and highly customizable with strong user tracking protection.",
    concerns: ["Mozilla collects some telemetry by default (can be disabled)", "Market share declining"],
    greenFlags: ["Open-source", "Enhanced Tracking Protection built-in", "Non-profit Mozilla", "No selling user data"],
    developer: "Mozilla",
  },
  Chrome: {
    name: "Chrome", packageId: "com.android.chrome",
    trustScore: 45, riskLevel: "High",
    tagline: "Google's browser with deep integration",
    description: "Chrome dominates market share but aggressively profiles users for Google's advertising ecosystem.",
    concerns: ["Browsing history linked to Google account for ad targeting", "Deprecated third-party cookie alternative still profiles users", "Significant fingerprinting surface"],
    greenFlags: ["Fast performance", "Frequent security patches", "Safe Browsing protection"],
    developer: "Google LLC",
  },
  "UC Browser": {
    name: "UC Browser", packageId: "com.UCMobile.intl",
    trustScore: 12, riskLevel: "Critical",
    tagline: "Chinese browser with severe privacy issues",
    description: "UC Browser is owned by Alibaba and has been found to transmit user data to servers in China without encryption.",
    concerns: ["Transmits IMSI, device IDs to Chinese servers", "Banned in India temporarily for security", "No transparency about data handling"],
    greenFlags: ["Data saving mode"],
    developer: "Alibaba",
  },
  Zomato: {
    name: "Zomato", packageId: "com.application.zomato",
    trustScore: 58, riskLevel: "Medium",
    tagline: "India's largest food delivery platform",
    description: "Zomato connects users to restaurants for delivery and dining. 17M user email/password breach in 2017.",
    concerns: ["17M accounts breached (2017) — email and hashed passwords", "Precise location tracked continuously", "Delivery partner earnings controversy"],
    greenFlags: ["Large restaurant selection", "Live order tracking", "Good refund policy"],
    developer: "Zomato Ltd.",
  },
  Swiggy: {
    name: "Swiggy", packageId: "in.swiggy.android",
    trustScore: 63, riskLevel: "Medium",
    tagline: "Fast food delivery with Swiggy Instamart",
    description: "Swiggy delivers food and groceries. Cleaner privacy record than Zomato but still collects extensive location data.",
    concerns: ["Continuous location access required", "Order data analyzed for advertising", "High commission structure affects restaurant pricing"],
    greenFlags: ["No major breach on record", "Quick commerce integration", "Good delivery tracking"],
    developer: "Bundl Technologies",
  },
  Netflix: {
    name: "Netflix", packageId: "com.netflix.mediaclient",
    trustScore: 72, riskLevel: "Low",
    tagline: "World's leading streaming service",
    description: "Netflix leads in content quality and delivery. No major security breaches. Password-sharing crackdown is controversial.",
    concerns: ["Viewing behavior analyzed for recommendations and ads", "Password sharing restrictions", "Price increases every year"],
    greenFlags: ["No major data breach", "Strong content security (Widevine)", "Clear privacy policy"],
    developer: "Netflix Inc.",
  },
  Amazon: {
    name: "Amazon", packageId: "in.amazon.mShop.android.shopping",
    trustScore: 62, riskLevel: "Medium",
    tagline: "The world's largest online retailer",
    description: "Amazon offers competitive prices and fast delivery but tracks purchase behavior for targeted advertising.",
    concerns: ["Purchase behavior feeds extensive ad targeting", "Third-party seller data practices vary", "Alexa integration privacy"],
    greenFlags: ["Strong account security", "Easy returns", "A-to-Z Guarantee"],
    developer: "Amazon.com",
  },
  Flipkart: {
    name: "Flipkart", packageId: "com.flipkart.android",
    trustScore: 60, riskLevel: "Medium",
    tagline: "India's homegrown e-commerce giant",
    description: "Flipkart is Walmart-owned and India's largest e-commerce platform by orders.",
    concerns: ["Walmart data access", "Targeted advertising based on browsing", "Customer support inconsistency"],
    greenFlags: ["No major data breach", "Strong delivery network in India", "Cash on delivery available"],
    developer: "Flipkart Internet Pvt Ltd",
  },
  Meesho: {
    name: "Meesho", packageId: "com.meesho.supply",
    trustScore: 55, riskLevel: "Medium",
    tagline: "Social commerce for small Indian businesses",
    description: "Meesho enables individuals to resell products via social networks. Strong growth in Tier 2/3 India.",
    concerns: ["Product quality control issues", "Reseller data practices", "Limited dispute resolution"],
    greenFlags: ["Zero commission for sellers", "Free delivery frequently", "Strong return policy"],
    developer: "Meesho Inc.",
  },
  Uber: {
    name: "Uber", packageId: "com.ubercab",
    trustScore: 52, riskLevel: "High",
    tagline: "Global ride-hailing leader",
    description: "Uber connects riders to drivers. Had a significant 2022 security breach where internal systems were compromised.",
    concerns: ["2022 hacker accessed internal Slack, AWS, and security tools", "Location data tracking after rides", "Surge pricing algorithm"],
    greenFlags: ["Strong safety features (SOS, trip sharing)", "Insurance for rides", "Cashless payments"],
    developer: "Uber Technologies",
  },
  Ola: {
    name: "Ola", packageId: "com.olacabs.customer",
    trustScore: 58, riskLevel: "Medium",
    tagline: "India's homegrown cab aggregator",
    description: "Ola is India's largest ride-hailing platform with autos, bikes, and cabs.",
    concerns: ["Location history retained for extended periods", "Ola Money wallet data", "Driver behavior inconsistency"],
    greenFlags: ["India-first safety features", "Wide city coverage", "Auto and bike rickshaw options"],
    developer: "ANI Technologies",
  },
  Groww: {
    name: "Groww", packageId: "com.nextbillion.groww",
    trustScore: 72, riskLevel: "Low",
    tagline: "Beginner-friendly investment platform",
    description: "Groww simplifies stock, mutual fund, and FD investing for retail investors.",
    concerns: ["Limited to investment — not a payment or UPI app", "SEBI regulated but startup risk"],
    greenFlags: ["SEBI registered", "Clean interface", "No major breach", "Zero commission mutual funds"],
    developer: "Nextbillion Technology",
  },
  Zerodha: {
    name: "Zerodha", packageId: "com.zerodha.kite3",
    trustScore: 75, riskLevel: "Low",
    tagline: "India's largest stockbroker by active clients",
    description: "Zerodha is the market leader in retail stock trading with the lowest brokerage fees.",
    concerns: ["Complex for beginners", "No dedicated mobile banking — trading only"],
    greenFlags: ["SEBI registered", "No major breach", "Transparent fee structure", "Varsity free education"],
    developer: "Zerodha Broking Ltd.",
  },
  NordVPN: {
    name: "NordVPN", packageId: "com.nordvpn.android",
    trustScore: 78, riskLevel: "Low",
    tagline: "Industry-leading VPN with no-logs policy",
    description: "NordVPN provides encrypted tunneling, double VPN, and a verified no-logs policy audited by PwC.",
    concerns: ["One server breach in 2018 (no user data taken)", "Premium pricing", "Based in Panama (good for privacy, but less regulated"],
    greenFlags: ["Independently audited no-logs policy", "Double VPN option", "6000+ servers"],
    developer: "Nord Security",
  },
  "Hotspot Shield": {
    name: "Hotspot Shield", packageId: "com.anchorfree.hydravpn",
    trustScore: 32, riskLevel: "Critical",
    tagline: "Free VPN with significant privacy issues",
    description: "Hotspot Shield free tier was found to inject JavaScript into users' browsers for advertising purposes.",
    concerns: ["FTC complaint: tracked browsing for ad targeting", "JavaScript injected into HTTP traffic", "Logs connection metadata"],
    greenFlags: ["Fast speeds on premium tier"],
    developer: "Pango",
  },
  BGMI: {
    name: "BGMI", packageId: "com.pubg.imobile",
    trustScore: 48, riskLevel: "High",
    tagline: "India's official PUBG Mobile replacement",
    description: "Battlegrounds Mobile India is the India-specific version of PUBG Mobile. Twice banned in India (2020, 2022).",
    concerns: ["Twice banned by Indian government over data sovereignty concerns", "Extensive device permissions", "Addictive mechanics targeting minors"],
    greenFlags: ["India-specific data centers", "Age verification system", "Gameplay time limits for minors"],
    developer: "Krafton Inc.",
  },
  Spotify: {
    name: "Spotify", packageId: "com.spotify.music",
    trustScore: 70, riskLevel: "Low",
    tagline: "World's largest music streaming service",
    description: "Spotify offers 100M+ tracks with excellent recommendation algorithms.",
    concerns: ["Listening behavior used for targeted advertising", "Microphone access on some features", "Premium required for full features"],
    greenFlags: ["No major data breach", "Transparent data controls", "GDPR compliant"],
    developer: "Spotify AB",
  },
  "Google Maps": {
    name: "Google Maps", packageId: "com.google.android.apps.maps",
    trustScore: 42, riskLevel: "High",
    tagline: "World's most accurate navigation app",
    description: "Google Maps is unmatched for navigation but tracks location at all times for Google's ad ecosystem.",
    concerns: ["Continuous location tracking even when not in use", "Timeline feature stores all movement history", "Location data sold to data brokers"],
    greenFlags: ["Most accurate maps globally", "Excellent real-time traffic", "Offline maps available"],
    developer: "Google LLC",
  },
  Duolingo: {
    name: "Duolingo", packageId: "com.duolingo",
    trustScore: 78, riskLevel: "Low",
    tagline: "World's most popular language learning app",
    description: "Duolingo gamifies language learning with daily streaks. No major security incidents.",
    concerns: ["Email and learning data shared with analytics partners", "Aggressive push notifications"],
    greenFlags: ["No major breach", "Learning data used only to improve app", "Free core features"],
    developer: "Duolingo Inc.",
  },
  HealthifyMe: {
    name: "HealthifyMe", packageId: "com.healthifyme.basic",
    trustScore: 65, riskLevel: "Medium",
    tagline: "India's #1 calorie counter and fitness app",
    description: "HealthifyMe tracks diet, exercise, and health goals with AI coaching.",
    concerns: ["Health and fitness data is highly sensitive", "Data sharing with insurance partners", "Premium features locked behind subscription"],
    greenFlags: ["No major breach", "India-specific food database", "RBI-approved for health data"],
    developer: "Curefit Healthcare",
  },
  Notion: {
    name: "Notion", packageId: "notion.id",
    trustScore: 80, riskLevel: "Low",
    tagline: "All-in-one productivity and notes workspace",
    description: "Notion is a flexible workspace for notes, databases, and collaboration. Strong security track record.",
    concerns: ["All data stored on Notion servers in US", "Free plan data used for AI training", "Limited offline support"],
    greenFlags: ["No major breach", "SOC 2 certified", "GDPR compliant", "Transparent AI data policy"],
    developer: "Notion Labs",
  },
  "Clean Master": {
    name: "Clean Master", packageId: "com.cleanmaster.mguard",
    trustScore: 8, riskLevel: "Critical",
    tagline: "Phone cleaner with severe security risks",
    description: "Clean Master is owned by Cheetah Mobile (China). Multiple Play Store bans for ad fraud, malware, and deceptive behavior.",
    concerns: ["Removed from Play Store multiple times for ad fraud", "Chinese ownership with data sovereignty concerns", "Fake virus alerts to push premium", "Documented malware behavior"],
    greenFlags: [],
    developer: "Cheetah Mobile (China)",
  },
};

// ─── Category → App mapping (strict — no cross-category contamination) ────────

const CATEGORY_APPS: Record<string, { label: string; apps: string[] }> = {
  "UPI Payment": { label: "UPI Payment", apps: ["GPay", "PhonePe", "Paytm", "CRED", "Amazon Pay"] },
  "Digital Wallet": { label: "Digital Wallet", apps: ["GPay", "PhonePe", "Paytm", "CRED", "Amazon Pay"] },
  "Messaging": { label: "Messaging", apps: ["Signal", "WhatsApp", "Telegram", "Snapchat"] },
  "Browser": { label: "Browser", apps: ["Brave", "Firefox", "Chrome", "UC Browser"] },
  "Social Media": { label: "Social Media", apps: ["Instagram", "Facebook", "Snapchat"] },
  "Food Delivery": { label: "Food Delivery", apps: ["Zomato", "Swiggy"] },
  "Streaming": { label: "Streaming", apps: ["Netflix", "Spotify"] },
  "Music": { label: "Music", apps: ["Spotify"] },
  "E-commerce": { label: "E-commerce", apps: ["Amazon", "Flipkart", "Meesho"] },
  "Cab Booking": { label: "Cab Booking", apps: ["Uber", "Ola"] },
  "Investment": { label: "Investment", apps: ["Groww", "Zerodha"] },
  "VPN": { label: "VPN", apps: ["NordVPN", "Hotspot Shield"] },
  "Navigation": { label: "Navigation", apps: ["Google Maps"] },
  "Language Learning": { label: "Language Learning", apps: ["Duolingo"] },
  "Health & Fitness": { label: "Health & Fitness", apps: ["HealthifyMe"] },
  "Gaming": { label: "Gaming", apps: ["BGMI"] },
  "Productivity": { label: "Productivity", apps: ["Notion"] },
  "Utility": { label: "Utility", apps: ["Clean Master"] },
};

// ─── Caches ───────────────────────────────────────────────────────────────────

const classifyCache = new Map<string, { category: string; intent: string; ts: number }>();
const searchCache = new Map<string, { data: AppResult[]; category: string; intent: string; ts: number }>();
const SEARCH_TTL = 30 * 60 * 1000;
const CLASSIFY_TTL = 60 * 60 * 1000;

let hibpCache: Array<{ Name: string; Title: string; BreachDate: string; PwnCount: number; DataClasses: string[]; Domain: string }> | null = null;
let hibpTs = 0;
const HIBP_TTL = 60 * 60 * 1000;

// ─── HIBP ─────────────────────────────────────────────────────────────────────

async function getHibpBreaches() {
  if (hibpCache && Date.now() - hibpTs < HIBP_TTL) return hibpCache;
  try {
    const r = await fetch("https://haveibeenpwned.com/api/v3/breaches", {
      headers: { "User-Agent": "JustAskUs-Privacy-App/1.0" },
      signal: AbortSignal.timeout(10000),
    });
    if (!r.ok) return hibpCache ?? [];
    hibpCache = await r.json() as typeof hibpCache;
    hibpTs = Date.now();
    return hibpCache!;
  } catch {
    return hibpCache ?? [];
  }
}

function findBreaches(allBreaches: NonNullable<typeof hibpCache>, appName: string) {
  const q = appName.toLowerCase().replace(/[^a-z0-9]/g, "");
  return allBreaches.filter((b) => {
    const n = b.Name.toLowerCase().replace(/[^a-z0-9]/g, "");
    const t = b.Title.toLowerCase().replace(/[^a-z0-9]/g, "");
    const d = (b.Domain || "").toLowerCase().split(".")[0];
    return n.includes(q) || q.includes(n) || t.includes(q) || q.includes(t) ||
      (d.length >= 3 && (d.includes(q) || q.includes(d)));
  }).slice(0, 5);
}

// ─── Play Store ───────────────────────────────────────────────────────────────

function formatCount(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(0)}K`;
  return String(n);
}

async function fetchPlayStore(packageId: string, appName: string) {
  try {
    const gplay = (await import("google-play-scraper")).default;
    const app = await Promise.race([
      gplay.app({ appId: packageId, country: "in", lang: "en" }),
      new Promise<null>((_, r) => setTimeout(() => r(new Error("timeout")), 7000)),
    ]) as any;
    if (!app) return null;
    return {
      playRating: typeof app.score === "number" ? Math.round(app.score * 10) / 10 : null,
      playRatingsCount: app.ratings ? formatCount(app.ratings) : null,
      playDownloads: app.installs ?? null,
      developer: app.developer ?? null,
      playIcon: app.icon ?? null,
      price: app.free === false ? `$${app.price ?? 0}` : "Free",
    };
  } catch {
    try {
      const gplay = (await import("google-play-scraper")).default;
      const results = await Promise.race([
        gplay.search({ term: appName, num: 1, country: "in", lang: "en" }),
        new Promise<any[]>((_, r) => setTimeout(() => r([]), 6000)),
      ]) as any[];
      const app = results?.[0];
      if (!app) return null;
      return {
        playRating: typeof app.score === "number" ? Math.round(app.score * 10) / 10 : null,
        playRatingsCount: app.ratings ? formatCount(app.ratings) : null,
        playDownloads: app.installs ?? null,
        developer: app.developer ?? null,
        playIcon: app.icon ?? null,
        price: app.free === false ? `$${app.price ?? 0}` : "Free",
      };
    } catch {
      return null;
    }
  }
}

// ─── Local fast classifier (no LLM — handles common patterns instantly) ───────

type ClassifyRule = { patterns: RegExp[]; category: string };

const LOCAL_RULES: ClassifyRule[] = [
  // Payments — must come before "invest" patterns
  { patterns: [/\b(payment|pay|upi|gpay|phonepe|paytm|cred|wallet|transfer money|send money|money transfer|fintech|digital payment|cashless)\b/i], category: "UPI Payment" },
  // Messaging
  { patterns: [/\b(message|messaging|chat|whatsapp|signal|telegram|text|sms|instant message)\b/i], category: "Messaging" },
  // Browser
  { patterns: [/\b(browser|browse|web browser|chrome|firefox|brave|surfing)\b/i], category: "Browser" },
  // Food delivery
  { patterns: [/\b(food|delivery|zomato|swiggy|order food|restaurant|eat)\b/i], category: "Food Delivery" },
  // Streaming / video
  { patterns: [/\b(streaming|stream|netflix|ott|watch movie|web series|video streaming)\b/i], category: "Streaming" },
  // Music
  { patterns: [/\b(music|song|spotify|playlist|audio streaming)\b/i], category: "Music" },
  // Investment — comes AFTER payment to avoid misclassification
  { patterns: [/\b(invest|investment|stocks?|mutual fund|trading|zerodha|groww|shares?|equity|sip)\b/i], category: "Investment" },
  // Shopping
  { patterns: [/\b(shopping|ecommerce|amazon|flipkart|meesho|buy online|purchase)\b/i], category: "E-commerce" },
  // Cab / Ride
  { patterns: [/\b(cab|ride|taxi|auto|ola|uber|book a ride|rickshaw)\b/i], category: "Cab Booking" },
  // VPN
  { patterns: [/\b(vpn|nordvpn|hotspot shield|virtual private|proxy)\b/i], category: "VPN" },
  // Navigation
  { patterns: [/\b(navigation|maps?|google maps|directions?|gps|route)\b/i], category: "Navigation" },
  // Health
  { patterns: [/\b(health|fitness|calorie|diet|workout|healthifyme|steps?)\b/i], category: "Health & Fitness" },
  // Language
  { patterns: [/\b(language|learn english|duolingo|french|spanish|translation)\b/i], category: "Language Learning" },
  // Gaming
  { patterns: [/\b(gaming|game|bgmi|pubg|battlegrounds|mobile game)\b/i], category: "Gaming" },
  // Productivity
  { patterns: [/\b(productivity|notes?|notion|workspace|organize|tasks?)\b/i], category: "Productivity" },
  // Social media
  { patterns: [/\b(social media|instagram|facebook|snapchat|tiktok|social network)\b/i], category: "Social Media" },
];

function detectIntent(query: string): string {
  const q = query.toLowerCase();
  if (/\b(safest|most secure|privacy|secure|safe)\b/.test(q)) return "safety";
  if (/\b(best|top|alternative|instead of|vs|versus|compare)\b/.test(q)) return "comparison";
  if (/\b(feature|fastest|cheapest|free)\b/.test(q)) return "features";
  return "features";
}

function localClassify(query: string): { category: string; intent: string } | null {
  for (const rule of LOCAL_RULES) {
    if (rule.patterns.some((p) => p.test(query))) {
      return { category: rule.category, intent: detectIntent(query) };
    }
  }
  return null;
}

// ─── LLM classification (tiny — just category + intent) ──────────────────────

const MODEL = "meta-llama/llama-3.2-3b-instruct:free";
const MAX_RETRIES = 4;

const KNOWN_CATEGORIES = Object.keys(CATEGORY_APPS).join(", ");

async function classifyQuery(query: string, location: string): Promise<{ category: string; intent: string }> {
  const cacheKey = `${query.trim().toLowerCase()}_${location}`;
  const cached = classifyCache.get(cacheKey);
  if (cached && Date.now() - cached.ts < CLASSIFY_TTL) {
    return { category: cached.category, intent: cached.intent };
  }

  // Fast path: local regex classifier handles >90% of queries instantly
  const local = localClassify(query);
  if (local) {
    classifyCache.set(cacheKey, { ...local, ts: Date.now() });
    return local;
  }

  const systemPrompt = `You are an app category classifier. Given a search query, identify the EXACT category from the list.
Known categories: ${KNOWN_CATEGORIES}
Rules:
- Payment/UPI/money transfer queries → "UPI Payment" (never Investment or E-commerce)
- Chat/message/text queries → "Messaging"
- Trading/stocks/mutual funds → "Investment" (never Payment)
- Respond ONLY with JSON: {"category": "<exact category>", "intent": "<safety|features|comparison|alternatives>"}`;

  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    try {
      const response = await openrouter.chat.completions.create({
        model: MODEL,
        max_tokens: 60,
        temperature: 0.1,
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: `Query: "${query}" (Location: ${location})` },
        ],
      });

      const raw = response.choices[0]?.message?.content ?? "";
      const jsonMatch = raw.match(/\{[\s\S]*?\}/);
      if (!jsonMatch) throw new Error("No JSON in LLM response");
      const parsed = JSON.parse(jsonMatch[0]) as { category: string; intent: string };
      if (!parsed.category) throw new Error("No category");

      // Validate category exists in our map
      const validCategory = Object.keys(CATEGORY_APPS).find(
        (k) => k.toLowerCase() === parsed.category.toLowerCase()
      ) ?? parsed.category;

      classifyCache.set(cacheKey, { category: validCategory, intent: parsed.intent ?? "features", ts: Date.now() });
      return { category: validCategory, intent: parsed.intent ?? "features" };
    } catch (err: any) {
      const isRateLimit = err?.status === 429 || err?.message?.includes("429");
      if (isRateLimit) {
        if (attempt < MAX_RETRIES - 1) {
          await new Promise((r) => setTimeout(r, (attempt + 1) * 4000));
          continue;
        }
        // Retries exhausted — surface a proper 429 so the client handles it correctly.
        const rateErr = new Error("AI is busy — please wait 30 seconds and try again.") as any;
        rateErr.status = 429;
        throw rateErr;
      }
      throw err;
    }
  }
  throw new Error("Classification failed");
}

// ─── Route: POST /api/intel/search ────────────────────────────────────────────

router.post("/search", async (req, res) => {
  const { query, location = "India", categoryOverride } = req.body ?? {};
  if (!query || typeof query !== "string" || query.trim().length < 2) {
    res.status(400).json({ error: "query is required (min 2 chars)" });
    return;
  }

  const cacheKey = `${query.trim().toLowerCase()}_${location}_${categoryOverride ?? ""}`;

  // L1: in-memory cache (fast, lost on restart)
  const memCached = searchCache.get(cacheKey);
  if (memCached && Date.now() - memCached.ts < SEARCH_TTL) {
    res.json({ apps: memCached.data, category: memCached.category, intent: memCached.intent, cached: true });
    return;
  }

  // L2: database cache (persistent across restarts, survives scaling)
  const dbCached = await getSearchCache(cacheKey);
  if (dbCached) {
    // Warm L1 from DB hit
    searchCache.set(cacheKey, { data: dbCached.apps as AppResult[], category: dbCached.category, intent: dbCached.intent, ts: Date.now() });
    res.json({ apps: dbCached.apps, category: dbCached.category, intent: dbCached.intent, cached: true });
    return;
  }

  try {
    // Step 1: Classify — use categoryOverride if caller provided a known category (skips LLM)
    let category: string;
    let intent: string;
    if (categoryOverride && typeof categoryOverride === "string" && CATEGORY_APPS[categoryOverride]) {
      category = categoryOverride;
      intent = "comparison";
    } else {
      const classification = await classifyQuery(query.trim(), location);
      category = classification.category;
      intent = classification.intent;
    }

    // Step 2: Get curated app list for this category
    const categoryDef = CATEGORY_APPS[category];
    if (!categoryDef) {
      res.status(200).json({
        apps: [],
        category,
        intent,
        cached: false,
        total: 0,
        message: `No apps found for category: ${category}. Try: payment, messaging, browser, food delivery, VPN, streaming.`,
      });
      return;
    }

    const appNames = categoryDef.apps;

    // Step 3: Enrich each app with Play Store data + HIBP (parallel)
    const allBreaches = await getHibpBreaches();

    const results = await Promise.allSettled(
      appNames.map(async (appName) => {
        const record = APP_DB[appName];
        if (!record) return null;

        const [psData, breachMatches] = await Promise.allSettled([
          fetchPlayStore(record.packageId, record.name),
          Promise.resolve(findBreaches(allBreaches, record.name)),
        ]);

        const ps = psData.status === "fulfilled" ? psData.value : null;
        const breaches = breachMatches.status === "fulfilled" ? breachMatches.value : [];

        // Adjust trust score for live HIBP breaches
        let trustScore = record.trustScore;
        if (breaches.length > 0) {
          trustScore = Math.max(5, trustScore - breaches.length * 5);
        }

        const result: AppResult = {
          name: record.name,
          packageId: record.packageId,
          category,
          trustScore,
          riskLevel: record.riskLevel,
          tagline: record.tagline,
          description: record.description,
          concerns: record.concerns,
          greenFlags: record.greenFlags,
          playRating: ps?.playRating ?? null,
          playRatingsCount: ps?.playRatingsCount ?? null,
          playDownloads: ps?.playDownloads ?? null,
          developer: ps?.developer ?? record.developer,
          playIcon: ps?.playIcon ?? null,
          price: ps?.price ?? "Free",
          breachCount: breaches.length,
          breaches: breaches.map((b) => ({
            title: b.Title,
            date: b.BreachDate,
            pwnCount: b.PwnCount,
            dataClasses: b.DataClasses.slice(0, 5),
          })),
        };
        return result;
      })
    );

    const apps: AppResult[] = results
      .filter((r): r is PromiseFulfilledResult<AppResult | null> => r.status === "fulfilled")
      .map((r) => r.value)
      .filter((a): a is AppResult => a !== null)
      .sort((a, b) => {
        // For safety intent, sort strictly by trustScore
        // For features intent, blend play rating with trust
        if (intent === "safety") return b.trustScore - a.trustScore;
        const aScore = b.trustScore * 0.7 + (b.playRating ?? 3) * 6;
        const bScore = a.trustScore * 0.7 + (a.playRating ?? 3) * 6;
        return aScore - bScore;
      });

    // Write to L1 (in-memory) and L2 (database) caches
    searchCache.set(cacheKey, { data: apps, category, intent, ts: Date.now() });
    setSearchCache(cacheKey, { apps, category, intent }, 6).catch(() => {});

    res.json({ apps, category, intent, cached: false, total: apps.length });
  } catch (err: any) {
    const isRateLimit = err?.status === 429 || err?.message?.includes("429");
    if (isRateLimit) {
      res.status(429).json({ error: "AI is busy — please wait 30 seconds and try again." });
      return;
    }
    res.status(500).json({ error: "Search failed", detail: err?.message });
  }
});

export default router;
