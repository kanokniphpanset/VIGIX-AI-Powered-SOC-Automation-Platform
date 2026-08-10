import axios from "axios";

/**
 * Shared HTTP client for all module API services.
 * Base URL comes from VITE_API_URL (see .env.example) so the backend
 * host is swappable without touching call sites.
 */
export const httpClient = axios.create({
  baseURL: import.meta.env.VITE_API_URL ?? "http://localhost:4000/api/v1",
  timeout: 10000,
});
