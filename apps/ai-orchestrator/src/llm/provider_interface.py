from abc import ABC, abstractmethod


class ILlmProvider(ABC):
    """
    Abstract LLM provider. LlmAnalystAgent depends only on this.
    Swap LlamaProvider for an OpenAI/Anthropic/vLLM provider by adding a
    new class here and pointing config/settings.py at it — nothing in
    the agent changes.
    """

    @abstractmethod
    async def complete(self, system_prompt: str, user_prompt: str) -> str:
        """Return the model's text completion for the given prompts."""
        raise NotImplementedError
