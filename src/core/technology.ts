import type { CrawlPage } from "../types.js";

export function detectTechnologies(pages: CrawlPage[]): string[] {
  const found = new Set<string>();
  const headers = pages.map((p) => Object.values(p.headers).join(" ")).join(" ").toLowerCase();
  const body = pages.slice(0, 5).map((p) => p.body).join("\n").toLowerCase();
  if (headers.includes("express")) found.add("Express");
  if (headers.includes("nginx")) found.add("Nginx");
  if (headers.includes("cloudflare")) found.add("Cloudflare");
  if (headers.includes("vercel")) found.add("Vercel");
  if (headers.includes("netlify")) found.add("Netlify");
  if (body.includes("wp-content")) found.add("WordPress");
  if (body.includes("__next")) found.add("Next.js");
  if (body.includes("data-reactroot") || body.includes("react")) found.add("React");
  if (body.includes("vue")) found.add("Vue");
  return [...found].sort();
}
