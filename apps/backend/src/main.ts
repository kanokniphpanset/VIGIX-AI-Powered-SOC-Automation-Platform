import "reflect-metadata";
import express from "express";
import cors from "cors";
import dotenv from "dotenv";

dotenv.config();

import { alertController, incidentController, siemWebhookController } from "./infrastructure/config/container";
import { buildAlertRoutes } from "./presentation/http/routes/alert.routes";
import { buildIncidentRoutes } from "./presentation/http/routes/incident.routes";
import { buildWebhookRoutes } from "./presentation/http/routes/webhook.routes";

const app = express();
app.use(cors());
app.use(express.json());

app.use("/api/v1/alerts", buildAlertRoutes(alertController));
app.use("/api/v1/incidents", buildIncidentRoutes(incidentController));
app.use("/api/v1/webhooks", buildWebhookRoutes(siemWebhookController));

app.get("/api/v1/health", (_req, res) => {
  res.json({ status: "ok", service: "soar-backend", timestamp: new Date().toISOString() });
});

const PORT = process.env.BACKEND_PORT ? Number(process.env.BACKEND_PORT) : 4000;

app.listen(PORT, () => {
  console.log(`soar-backend listening on http://localhost:${PORT}`);
});
