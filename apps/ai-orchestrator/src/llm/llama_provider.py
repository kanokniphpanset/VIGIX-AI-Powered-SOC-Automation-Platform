import httpx
from .provider_interface import ILlmProvider


class LlamaProvider(ILlmProvider):
    """
    Talks to any OpenAI-compatible chat endpoint — Ollama (`ollama serve`,
    default http://localhost:11434/v1, no auth) or a gateway fronting
    multiple backends (e.g. Bifrost routing to vLLM/llama.cpp nodes, which
    requires a bearer token) both work unmodified. If the endpoint isn't
    reachable, callers should catch the exception and fall back to a
    heuristic summary rather than crash the pipeline.
    """

    def __init__(self, base_url: str, model: str, timeout_seconds: float = 120.0, api_key: str | None = None):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.api_key = api_key

    async def complete(self, system_prompt: str, user_prompt: str) -> str:
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            response = await client.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    "temperature": 0.2,
                },
            )
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]
