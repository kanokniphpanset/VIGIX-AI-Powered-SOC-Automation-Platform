import httpx
from .provider_interface import ILlmProvider


class LlamaProvider(ILlmProvider):
    """
    Talks to Llama 3.1 8B Instruct via any OpenAI-compatible chat endpoint —
    Ollama (`ollama serve`, default http://localhost:11434/v1) or vLLM both work
    unmodified. If the endpoint isn't reachable, callers should catch the
    exception and fall back to a heuristic summary rather than crash the pipeline.
    """

    def __init__(self, base_url: str, model: str):
        self.base_url = base_url.rstrip("/")
        self.model = model

    async def complete(self, system_prompt: str, user_prompt: str) -> str:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{self.base_url}/chat/completions",
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
