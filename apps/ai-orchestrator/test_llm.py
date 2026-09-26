# test_llm.py
import asyncio
from dotenv import load_dotenv
load_dotenv()
import os
from src.llm.llama_provider import LlamaProvider

async def main():
    provider = LlamaProvider(
        base_url=os.getenv("LLM_BASE_URL"),
        model=os.getenv("LLM_MODEL"),
        api_key=os.getenv("LLM_API_KEY"),
        timeout_seconds=float(os.getenv("LLM_TIMEOUT_SECONDS", 120)),
    )
    result = await provider.complete("You are a helpful assistant.", "Say hello in Thai.")
    print(result)

asyncio.run(main())
