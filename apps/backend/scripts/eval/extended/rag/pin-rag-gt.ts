import * as fs from "node:fs";
import * as path from "node:path";
import { createHash } from "node:crypto";
import { RAG_GROUND_TRUTH } from "./ragGroundTruth";
const f = path.join(__dirname, "..", "..", "..", "..", "..", "..", "results", "extended-evaluation", "ground-truth.sha256");
const h = createHash("sha256").update(JSON.stringify(RAG_GROUND_TRUTH)).digest("hex");
const pin = fs.existsSync(f) ? JSON.parse(fs.readFileSync(f, "utf8")) : {};
if (pin.rag && pin.rag !== h) { console.error(`RAG ground truth changed: ${h} != pinned ${pin.rag}`); process.exit(1); }
if (!pin.rag) fs.writeFileSync(f, JSON.stringify({ ...pin, rag: h, ragPinnedAt: new Date().toISOString() }, null, 1));
console.log("rag ground truth sha256", h);
