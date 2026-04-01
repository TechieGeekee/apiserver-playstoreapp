import OpenAI from "openai";

// Works on Replit (uses internal proxy) AND on standalone servers (direct API)
function createClient(): OpenAI {
  const replitBase = process.env.AI_INTEGRATIONS_OPENROUTER_BASE_URL;
  const directKey = process.env.OPENROUTER_API_KEY;

  if (replitBase) {
    // Running inside Replit — use the managed proxy (no API key needed)
    return new OpenAI({ baseURL: replitBase, apiKey: "replit" });
  }

  if (directKey) {
    // Running standalone (Raspberry Pi, VPS, etc.) — direct OpenRouter API
    return new OpenAI({
      baseURL: "https://openrouter.ai/api/v1",
      apiKey: directKey,
    });
  }

  throw new Error(
    "No OpenRouter credentials found. Set OPENROUTER_API_KEY to run outside Replit."
  );
}

export const openrouter = createClient();
