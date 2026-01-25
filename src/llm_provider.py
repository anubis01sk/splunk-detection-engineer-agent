#!/usr/bin/env python3
"""
Multi-LLM Provider Interface
============================

A unified abstraction layer for multiple LLM providers, enabling the Splunk SPL Agent
to use different models interchangeably based on configuration.

Supported Providers:
    - Claude (Anthropic) - Primary paid option
    - ChatGPT (OpenAI)
    - Gemini (Google)
    - Grok (xAI)
    - DeepSeek
    - Qwen (Alibaba)
    - Groq (FREE - recommended for testing)
    - Mistral (FREE - high token allowance)
    - OpenRouter (FREE - model variety)

Usage:
    from llm_provider import get_provider, LLMConfig
    
    # Load from config file
    provider = get_provider()
    
    # Or specify provider directly
    provider = get_provider(provider_name="groq")
    
    # Generate response
    response = provider.generate("What is the stats command in SPL?")
    
    # Generate with RAG context
    response = provider.generate_with_context(
        query="How do I calculate average?",
        context="[Retrieved documentation here]"
    )

Dependencies:
    pip install anthropic openai google-generativeai httpx pyyaml

Author: Claude (Anthropic)
"""

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Generator
import logging

import yaml

# Module-level logger - configuration is done by entry points (cli.py, server.py)
logger = logging.getLogger(__name__)


# =============================================================================
# CONFIGURATION
# =============================================================================

DEFAULT_CONFIG_PATH = Path(__file__).parent.parent / "config" / "config.yaml"

# System prompt for SPL query generation
SPL_SYSTEM_PROMPT = """You are an expert Splunk SPL (Search Processing Language) engineer. Your role is to help users write accurate, optimized, and production-ready SPL queries.

When generating SPL queries:
1. Use correct SPL syntax based on the provided documentation
2. Follow Splunk best practices for query performance
3. Include appropriate time ranges when relevant
4. Use field extraction and transformation commands correctly
5. Explain your reasoning and any assumptions made

When documentation context is provided, base your answers strictly on that documentation to ensure accuracy. If the documentation does not contain relevant information, clearly state this limitation.

Always format SPL queries in code blocks for clarity."""


@dataclass
class LLMConfig:
    """Configuration for LLM providers."""
    provider: str = "groq"  # Default to free provider
    
    # Claude settings
    claude_api_key: str = ""
    claude_model: str = "claude-sonnet-4-20250514"
    
    # OpenAI settings
    openai_api_key: str = ""
    openai_model: str = "gpt-4o"
    
    # Gemini settings
    gemini_api_key: str = ""
    gemini_model: str = "gemini-1.5-pro"
    
    # Grok settings (xAI - paid)
    grok_api_key: str = ""
    grok_model: str = "grok-2-latest"
    grok_base_url: str = "https://api.x.ai/v1"
    
    # DeepSeek settings
    deepseek_api_key: str = ""
    deepseek_model: str = "deepseek-chat"
    deepseek_base_url: str = "https://api.deepseek.com/v1"
    
    # Qwen settings
    qwen_api_key: str = ""
    qwen_model: str = "qwen-plus"
    
    # Groq settings (FREE - recommended)
    groq_api_key: str = ""
    groq_model: str = "llama-3.3-70b-versatile"
    groq_base_url: str = "https://api.groq.com/openai/v1"
    
    # Mistral settings (FREE - high token allowance)
    mistral_api_key: str = ""
    mistral_model: str = "mistral-small-latest"
    mistral_base_url: str = "https://api.mistral.ai/v1"
    
    # OpenRouter settings (FREE - model variety)
    openrouter_api_key: str = ""
    openrouter_model: str = "meta-llama/llama-3.3-70b-instruct:free"
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    
    # Common settings
    max_tokens: int = 4096
    temperature: float = 0.1
    max_retries: int = 3
    retry_delay: float = 1.0
    timeout: int = 120
    
    @classmethod
    def from_yaml(cls, path: Path = DEFAULT_CONFIG_PATH) -> "LLMConfig":
        """Load configuration from YAML file."""
        if not path.exists():
            logger.warning(f"Config file not found at {path}, using defaults")
            return cls()
        
        with open(path, "r") as f:
            data = yaml.safe_load(f) or {}
        
        return cls(
            provider=data.get("provider", "groq"),
            claude_api_key=data.get("claude", {}).get("api_key", ""),
            claude_model=data.get("claude", {}).get("model", "claude-sonnet-4-20250514"),
            openai_api_key=data.get("openai", {}).get("api_key", ""),
            openai_model=data.get("openai", {}).get("model", "gpt-4o"),
            gemini_api_key=data.get("gemini", {}).get("api_key", ""),
            gemini_model=data.get("gemini", {}).get("model", "gemini-1.5-pro"),
            grok_api_key=data.get("grok", {}).get("api_key", ""),
            grok_model=data.get("grok", {}).get("model", "grok-2-latest"),
            grok_base_url=data.get("grok", {}).get("base_url", "https://api.x.ai/v1"),
            deepseek_api_key=data.get("deepseek", {}).get("api_key", ""),
            deepseek_model=data.get("deepseek", {}).get("model", "deepseek-chat"),
            deepseek_base_url=data.get("deepseek", {}).get("base_url", "https://api.deepseek.com/v1"),
            qwen_api_key=data.get("qwen", {}).get("api_key", ""),
            qwen_model=data.get("qwen", {}).get("model", "qwen-plus"),
            groq_api_key=data.get("groq", {}).get("api_key", ""),
            groq_model=data.get("groq", {}).get("model", "llama-3.3-70b-versatile"),
            groq_base_url=data.get("groq", {}).get("base_url", "https://api.groq.com/openai/v1"),
            mistral_api_key=data.get("mistral", {}).get("api_key", ""),
            mistral_model=data.get("mistral", {}).get("model", "mistral-small-latest"),
            mistral_base_url=data.get("mistral", {}).get("base_url", "https://api.mistral.ai/v1"),
            openrouter_api_key=data.get("openrouter", {}).get("api_key", ""),
            openrouter_model=data.get("openrouter", {}).get("model", "meta-llama/llama-3.3-70b-instruct:free"),
            openrouter_base_url=data.get("openrouter", {}).get("base_url", "https://openrouter.ai/api/v1"),
            max_tokens=data.get("settings", {}).get("max_tokens", 4096),
            temperature=data.get("settings", {}).get("temperature", 0.1),
            max_retries=data.get("settings", {}).get("max_retries", 3),
            retry_delay=data.get("settings", {}).get("retry_delay", 1.0),
            timeout=data.get("settings", {}).get("timeout", 120),
        )


@dataclass
class LLMResponse:
    """Standardized response from LLM providers."""
    content: str
    model: str
    provider: str
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    latency_ms: float = 0.0
    finish_reason: str = ""
    raw_response: Optional[dict] = None


# =============================================================================
# ABSTRACT BASE CLASS
# =============================================================================

class LLMProvider(ABC):
    """Abstract base class for LLM providers."""
    
    def __init__(self, config: LLMConfig):
        self.config = config
        self._client = None
    
    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return the provider name."""
        pass
    
    @property
    @abstractmethod
    def model_name(self) -> str:
        """Return the model name being used."""
        pass
    
    @abstractmethod
    def _initialize_client(self):
        """Initialize the provider-specific client."""
        pass
    
    @abstractmethod
    def _generate_impl(self, messages: list[dict], system: str) -> LLMResponse:
        """Provider-specific generation implementation."""
        pass
    
    def generate(
        self,
        prompt: str,
        system_prompt: str = SPL_SYSTEM_PROMPT,
    ) -> LLMResponse:
        """
        Generate a response from the LLM.
        
        Args:
            prompt: The user's prompt/question.
            system_prompt: System instructions for the model.
            
        Returns:
            LLMResponse with the generated content.
        """
        if self._client is None:
            self._initialize_client()
        
        messages = [{"role": "user", "content": prompt}]
        
        last_error = None
        for attempt in range(self.config.max_retries):
            try:
                start_time = time.time()
                response = self._generate_impl(messages, system_prompt)
                response.latency_ms = (time.time() - start_time) * 1000
                return response
            except Exception as e:
                last_error = e
                logger.warning(
                    f"Attempt {attempt + 1}/{self.config.max_retries} failed: {e}"
                )
                if attempt < self.config.max_retries - 1:
                    time.sleep(self.config.retry_delay * (attempt + 1))
        
        raise RuntimeError(
            f"Failed after {self.config.max_retries} attempts: {last_error}"
        )
    
    def generate_with_context(
        self,
        query: str,
        context: str,
        system_prompt: str = SPL_SYSTEM_PROMPT,
    ) -> LLMResponse:
        """
        Generate a response with RAG context.
        
        Args:
            query: The user's question.
            context: Retrieved documentation context.
            system_prompt: System instructions for the model.
            
        Returns:
            LLMResponse with the generated content.
        """
        prompt = f"""Use the following Splunk documentation to answer the question accurately.

{context}

Question: {query}

Provide a detailed answer with working SPL examples where appropriate."""
        
        return self.generate(prompt, system_prompt)
    
    def generate_stream(
        self,
        prompt: str,
        system_prompt: str = SPL_SYSTEM_PROMPT,
    ) -> Generator[str, None, None]:
        """
        Generate a streaming response (if supported).
        
        Default implementation falls back to non-streaming.
        Override in subclasses for true streaming support.
        """
        response = self.generate(prompt, system_prompt)
        yield response.content
    
    def get_info(self) -> dict:
        """Return information about the provider and model."""
        return {
            "provider": self.provider_name,
            "model": self.model_name,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
        }


# =============================================================================
# GROQ PROVIDER (FREE - RECOMMENDED)
# =============================================================================

class GroqProvider(LLMProvider):
    """
    Groq provider implementation using OpenAI-compatible API.
    
    FREE TIER: 14,400 requests/day on Llama 3.1 8B, blazing fast inference.
    No credit card required.
    
    Available models:
        - llama-3.3-70b-versatile (recommended, 12K tokens/min free)
        - llama-3.1-8b-instant (fastest, 14,400 req/day free)
        - llama-3.1-70b-versatile (high quality)
        - mixtral-8x7b-32768 (32K context)
        - gemma2-9b-it (Google's model)
    
    Get API key at: https://console.groq.com/
    """
    
    @property
    def provider_name(self) -> str:
        return "groq"
    
    @property
    def model_name(self) -> str:
        return self.config.groq_model
    
    def _initialize_client(self):
        """Initialize the Groq client using OpenAI SDK."""
        try:
            import openai
        except ImportError:
            raise ImportError(
                "openai package not installed. Run: pip install openai"
            )
        
        if not self.config.groq_api_key:
            raise ValueError(
                "Groq API key not configured. Set it in config.yaml under groq.api_key\n"
                "Get your FREE API key at: https://console.groq.com/"
            )
        
        self._client = openai.OpenAI(
            api_key=self.config.groq_api_key,
            base_url=self.config.groq_base_url,
        )
        logger.info(f"Initialized Groq client with model: {self.model_name}")
    
    def _generate_impl(self, messages: list[dict], system: str) -> LLMResponse:
        """Generate response using Groq API."""
        full_messages = [{"role": "system", "content": system}] + messages
        
        response = self._client.chat.completions.create(
            model=self.model_name,
            messages=full_messages,
            max_tokens=self.config.max_tokens,
            temperature=self.config.temperature,
        )
        
        choice = response.choices[0]
        
        return LLMResponse(
            content=choice.message.content or "",
            model=response.model,
            provider=self.provider_name,
            input_tokens=response.usage.prompt_tokens if response.usage else 0,
            output_tokens=response.usage.completion_tokens if response.usage else 0,
            total_tokens=response.usage.total_tokens if response.usage else 0,
            finish_reason=choice.finish_reason or "",
            raw_response=response.model_dump() if hasattr(response, "model_dump") else None,
        )


# =============================================================================
# MISTRAL PROVIDER (FREE - HIGH TOKEN ALLOWANCE)
# =============================================================================

class MistralProvider(LLMProvider):
    """
    Mistral provider implementation using OpenAI-compatible API.
    
    FREE TIER (Experiment plan): 1 billion tokens/month, ~500K tokens/min.
    Phone verification required. Data may be used for training.
    
    Available models:
        - mistral-small-latest (recommended, fast and efficient)
        - mistral-medium-latest (balanced)
        - mistral-large-latest (most capable)
        - codestral-latest (code-focused)
        - open-mistral-7b (smallest)
        - open-mixtral-8x7b (MoE architecture)
    
    Get API key at: https://console.mistral.ai/
    """
    
    @property
    def provider_name(self) -> str:
        return "mistral"
    
    @property
    def model_name(self) -> str:
        return self.config.mistral_model
    
    def _initialize_client(self):
        """Initialize the Mistral client using OpenAI SDK."""
        try:
            import openai
        except ImportError:
            raise ImportError(
                "openai package not installed. Run: pip install openai"
            )
        
        if not self.config.mistral_api_key:
            raise ValueError(
                "Mistral API key not configured. Set it in config.yaml under mistral.api_key\n"
                "Get your FREE API key at: https://console.mistral.ai/"
            )
        
        self._client = openai.OpenAI(
            api_key=self.config.mistral_api_key,
            base_url=self.config.mistral_base_url,
        )
        logger.info(f"Initialized Mistral client with model: {self.model_name}")
    
    def _generate_impl(self, messages: list[dict], system: str) -> LLMResponse:
        """Generate response using Mistral API."""
        full_messages = [{"role": "system", "content": system}] + messages
        
        response = self._client.chat.completions.create(
            model=self.model_name,
            messages=full_messages,
            max_tokens=self.config.max_tokens,
            temperature=self.config.temperature,
        )
        
        choice = response.choices[0]
        
        return LLMResponse(
            content=choice.message.content or "",
            model=response.model,
            provider=self.provider_name,
            input_tokens=response.usage.prompt_tokens if response.usage else 0,
            output_tokens=response.usage.completion_tokens if response.usage else 0,
            total_tokens=response.usage.total_tokens if response.usage else 0,
            finish_reason=choice.finish_reason or "",
            raw_response=response.model_dump() if hasattr(response, "model_dump") else None,
        )


# =============================================================================
# OPENROUTER PROVIDER (FREE - MODEL VARIETY)
# =============================================================================

class OpenRouterProvider(LLMProvider):
    """
    OpenRouter provider implementation using OpenAI-compatible API.
    
    FREE TIER: 50 requests/day at 20 RPM, access to 25+ free models.
    No credit card required. $10 purchase unlocks 1000 req/day on free models.
    
    Available FREE models (append :free to model name):
        - meta-llama/llama-3.3-70b-instruct:free (recommended)
        - deepseek/deepseek-r1:free (reasoning)
        - google/gemini-2.0-flash-exp:free (experimental)
        - qwen/qwen3-coder-480b:free (code-focused)
        - microsoft/phi-3-mini-128k-instruct:free (small, fast)
    
    Get API key at: https://openrouter.ai/
    """
    
    @property
    def provider_name(self) -> str:
        return "openrouter"
    
    @property
    def model_name(self) -> str:
        return self.config.openrouter_model
    
    def _initialize_client(self):
        """Initialize the OpenRouter client using OpenAI SDK."""
        try:
            import openai
        except ImportError:
            raise ImportError(
                "openai package not installed. Run: pip install openai"
            )
        
        if not self.config.openrouter_api_key:
            raise ValueError(
                "OpenRouter API key not configured. Set it in config.yaml under openrouter.api_key\n"
                "Get your FREE API key at: https://openrouter.ai/"
            )
        
        self._client = openai.OpenAI(
            api_key=self.config.openrouter_api_key,
            base_url=self.config.openrouter_base_url,
            default_headers={
                "HTTP-Referer": "https://github.com/splunk-spl-agent",  # Required by OpenRouter
                "X-Title": "Splunk SPL Agent",  # Optional, shows in OpenRouter dashboard
            }
        )
        logger.info(f"Initialized OpenRouter client with model: {self.model_name}")
    
    def _generate_impl(self, messages: list[dict], system: str) -> LLMResponse:
        """Generate response using OpenRouter API."""
        full_messages = [{"role": "system", "content": system}] + messages
        
        response = self._client.chat.completions.create(
            model=self.model_name,
            messages=full_messages,
            max_tokens=self.config.max_tokens,
            temperature=self.config.temperature,
        )
        
        choice = response.choices[0]
        
        return LLMResponse(
            content=choice.message.content or "",
            model=response.model if response.model else self.model_name,
            provider=self.provider_name,
            input_tokens=response.usage.prompt_tokens if response.usage else 0,
            output_tokens=response.usage.completion_tokens if response.usage else 0,
            total_tokens=response.usage.total_tokens if response.usage else 0,
            finish_reason=choice.finish_reason or "",
            raw_response=response.model_dump() if hasattr(response, "model_dump") else None,
        )


# =============================================================================
# CLAUDE PROVIDER (PRIMARY - PAID)
# =============================================================================

class ClaudeProvider(LLMProvider):
    """Anthropic Claude provider implementation."""
    
    @property
    def provider_name(self) -> str:
        return "claude"
    
    @property
    def model_name(self) -> str:
        return self.config.claude_model
    
    def _initialize_client(self):
        """Initialize the Anthropic client."""
        try:
            import anthropic
        except ImportError:
            raise ImportError(
                "anthropic package not installed. Run: pip install anthropic"
            )
        
        if not self.config.claude_api_key:
            raise ValueError(
                "Claude API key not configured. Set it in config.yaml under claude.api_key"
            )
        
        self._client = anthropic.Anthropic(api_key=self.config.claude_api_key)
        logger.info(f"Initialized Claude client with model: {self.model_name}")
    
    def _generate_impl(self, messages: list[dict], system: str) -> LLMResponse:
        """Generate response using Claude API."""
        response = self._client.messages.create(
            model=self.model_name,
            max_tokens=self.config.max_tokens,
            temperature=self.config.temperature,
            system=system,
            messages=messages,
        )
        
        content = ""
        for block in response.content:
            if hasattr(block, "text"):
                content += block.text
        
        return LLMResponse(
            content=content,
            model=response.model,
            provider=self.provider_name,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            total_tokens=response.usage.input_tokens + response.usage.output_tokens,
            finish_reason=response.stop_reason or "",
            raw_response=response.model_dump() if hasattr(response, "model_dump") else None,
        )
    
    def generate_stream(
        self,
        prompt: str,
        system_prompt: str = SPL_SYSTEM_PROMPT,
    ) -> Generator[str, None, None]:
        """Generate streaming response using Claude API."""
        if self._client is None:
            self._initialize_client()
        
        messages = [{"role": "user", "content": prompt}]
        
        with self._client.messages.stream(
            model=self.model_name,
            max_tokens=self.config.max_tokens,
            temperature=self.config.temperature,
            system=system_prompt,
            messages=messages,
        ) as stream:
            for text in stream.text_stream:
                yield text


# =============================================================================
# OPENAI PROVIDER (ChatGPT - PAID)
# =============================================================================

class OpenAIProvider(LLMProvider):
    """OpenAI ChatGPT provider implementation."""
    
    @property
    def provider_name(self) -> str:
        return "openai"
    
    @property
    def model_name(self) -> str:
        return self.config.openai_model
    
    def _initialize_client(self):
        """Initialize the OpenAI client."""
        try:
            import openai
        except ImportError:
            raise ImportError(
                "openai package not installed. Run: pip install openai"
            )
        
        if not self.config.openai_api_key:
            raise ValueError(
                "OpenAI API key not configured. Set it in config.yaml under openai.api_key"
            )
        
        self._client = openai.OpenAI(api_key=self.config.openai_api_key)
        logger.info(f"Initialized OpenAI client with model: {self.model_name}")
    
    def _generate_impl(self, messages: list[dict], system: str) -> LLMResponse:
        """Generate response using OpenAI API."""
        full_messages = [{"role": "system", "content": system}] + messages
        
        response = self._client.chat.completions.create(
            model=self.model_name,
            messages=full_messages,
            max_tokens=self.config.max_tokens,
            temperature=self.config.temperature,
        )
        
        choice = response.choices[0]
        
        return LLMResponse(
            content=choice.message.content or "",
            model=response.model,
            provider=self.provider_name,
            input_tokens=response.usage.prompt_tokens if response.usage else 0,
            output_tokens=response.usage.completion_tokens if response.usage else 0,
            total_tokens=response.usage.total_tokens if response.usage else 0,
            finish_reason=choice.finish_reason or "",
            raw_response=response.model_dump() if hasattr(response, "model_dump") else None,
        )


# =============================================================================
# GEMINI PROVIDER (PAID, FREE TIER LIMITED)
# =============================================================================

class GeminiProvider(LLMProvider):
    """Google Gemini provider implementation."""
    
    @property
    def provider_name(self) -> str:
        return "gemini"
    
    @property
    def model_name(self) -> str:
        return self.config.gemini_model
    
    def _initialize_client(self):
        """Initialize the Gemini client."""
        try:
            import google.generativeai as genai
        except ImportError:
            raise ImportError(
                "google-generativeai package not installed. Run: pip install google-generativeai"
            )
        
        if not self.config.gemini_api_key:
            raise ValueError(
                "Gemini API key not configured. Set it in config.yaml under gemini.api_key"
            )
        
        genai.configure(api_key=self.config.gemini_api_key)
        self._client = genai.GenerativeModel(self.model_name)
        logger.info(f"Initialized Gemini client with model: {self.model_name}")
    
    def _generate_impl(self, messages: list[dict], system: str) -> LLMResponse:
        """Generate response using Gemini API."""
        # Gemini uses a different message format
        # Combine system prompt with user message
        user_content = messages[0]["content"] if messages else ""
        full_prompt = f"{system}\n\n{user_content}"
        
        response = self._client.generate_content(
            full_prompt,
            generation_config={
                "max_output_tokens": self.config.max_tokens,
                "temperature": self.config.temperature,
            }
        )
        
        # Extract token counts if available
        input_tokens = 0
        output_tokens = 0
        if hasattr(response, "usage_metadata"):
            input_tokens = getattr(response.usage_metadata, "prompt_token_count", 0)
            output_tokens = getattr(response.usage_metadata, "candidates_token_count", 0)
        
        return LLMResponse(
            content=response.text,
            model=self.model_name,
            provider=self.provider_name,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=input_tokens + output_tokens,
            finish_reason=response.candidates[0].finish_reason.name if response.candidates else "",
            raw_response=None,
        )


# =============================================================================
# GROK PROVIDER (xAI - PAID)
# =============================================================================

class GrokProvider(LLMProvider):
    """xAI Grok provider implementation using OpenAI-compatible API."""
    
    @property
    def provider_name(self) -> str:
        return "grok"
    
    @property
    def model_name(self) -> str:
        return self.config.grok_model
    
    def _initialize_client(self):
        """Initialize the Grok client using OpenAI SDK."""
        try:
            import openai
        except ImportError:
            raise ImportError(
                "openai package not installed. Run: pip install openai"
            )
        
        if not self.config.grok_api_key:
            raise ValueError(
                "Grok API key not configured. Set it in config.yaml under grok.api_key"
            )
        
        self._client = openai.OpenAI(
            api_key=self.config.grok_api_key,
            base_url=self.config.grok_base_url,
        )
        logger.info(f"Initialized Grok client with model: {self.model_name}")
    
    def _generate_impl(self, messages: list[dict], system: str) -> LLMResponse:
        """Generate response using Grok API."""
        full_messages = [{"role": "system", "content": system}] + messages
        
        response = self._client.chat.completions.create(
            model=self.model_name,
            messages=full_messages,
            max_tokens=self.config.max_tokens,
            temperature=self.config.temperature,
        )
        
        choice = response.choices[0]
        
        return LLMResponse(
            content=choice.message.content or "",
            model=response.model,
            provider=self.provider_name,
            input_tokens=response.usage.prompt_tokens if response.usage else 0,
            output_tokens=response.usage.completion_tokens if response.usage else 0,
            total_tokens=response.usage.total_tokens if response.usage else 0,
            finish_reason=choice.finish_reason or "",
            raw_response=response.model_dump() if hasattr(response, "model_dump") else None,
        )


# =============================================================================
# DEEPSEEK PROVIDER (PAID)
# =============================================================================

class DeepSeekProvider(LLMProvider):
    """DeepSeek provider implementation using OpenAI-compatible API."""
    
    @property
    def provider_name(self) -> str:
        return "deepseek"
    
    @property
    def model_name(self) -> str:
        return self.config.deepseek_model
    
    def _initialize_client(self):
        """Initialize the DeepSeek client using OpenAI SDK."""
        try:
            import openai
        except ImportError:
            raise ImportError(
                "openai package not installed. Run: pip install openai"
            )
        
        if not self.config.deepseek_api_key:
            raise ValueError(
                "DeepSeek API key not configured. Set it in config.yaml under deepseek.api_key"
            )
        
        self._client = openai.OpenAI(
            api_key=self.config.deepseek_api_key,
            base_url=self.config.deepseek_base_url,
        )
        logger.info(f"Initialized DeepSeek client with model: {self.model_name}")
    
    def _generate_impl(self, messages: list[dict], system: str) -> LLMResponse:
        """Generate response using DeepSeek API."""
        full_messages = [{"role": "system", "content": system}] + messages
        
        response = self._client.chat.completions.create(
            model=self.model_name,
            messages=full_messages,
            max_tokens=self.config.max_tokens,
            temperature=self.config.temperature,
        )
        
        choice = response.choices[0]
        
        return LLMResponse(
            content=choice.message.content or "",
            model=response.model,
            provider=self.provider_name,
            input_tokens=response.usage.prompt_tokens if response.usage else 0,
            output_tokens=response.usage.completion_tokens if response.usage else 0,
            total_tokens=response.usage.total_tokens if response.usage else 0,
            finish_reason=choice.finish_reason or "",
            raw_response=response.model_dump() if hasattr(response, "model_dump") else None,
        )


# =============================================================================
# QWEN PROVIDER (PAID)
# =============================================================================

class QwenProvider(LLMProvider):
    """Alibaba Qwen provider implementation using DashScope API."""
    
    @property
    def provider_name(self) -> str:
        return "qwen"
    
    @property
    def model_name(self) -> str:
        return self.config.qwen_model
    
    def _initialize_client(self):
        """Initialize the Qwen client."""
        try:
            import dashscope
        except ImportError:
            raise ImportError(
                "dashscope package not installed. Run: pip install dashscope"
            )
        
        if not self.config.qwen_api_key:
            raise ValueError(
                "Qwen API key not configured. Set it in config.yaml under qwen.api_key"
            )
        
        dashscope.api_key = self.config.qwen_api_key
        self._client = dashscope
        logger.info(f"Initialized Qwen client with model: {self.model_name}")
    
    def _generate_impl(self, messages: list[dict], system: str) -> LLMResponse:
        """Generate response using Qwen DashScope API."""
        from dashscope import Generation
        
        full_messages = [{"role": "system", "content": system}] + messages
        
        response = Generation.call(
            model=self.model_name,
            messages=full_messages,
            max_tokens=self.config.max_tokens,
            temperature=self.config.temperature,
            result_format="message",
        )
        
        if response.status_code != 200:
            raise RuntimeError(f"Qwen API error: {response.code} - {response.message}")
        
        content = response.output.choices[0].message.content
        
        return LLMResponse(
            content=content,
            model=self.model_name,
            provider=self.provider_name,
            input_tokens=response.usage.get("input_tokens", 0) if response.usage else 0,
            output_tokens=response.usage.get("output_tokens", 0) if response.usage else 0,
            total_tokens=response.usage.get("total_tokens", 0) if response.usage else 0,
            finish_reason=response.output.choices[0].finish_reason or "",
            raw_response=None,
        )


# =============================================================================
# PROVIDER FACTORY
# =============================================================================

PROVIDER_CLASSES = {
    # Free providers (recommended for testing)
    "groq": GroqProvider,
    "mistral": MistralProvider,
    "openrouter": OpenRouterProvider,
    # Paid providers
    "claude": ClaudeProvider,
    "openai": OpenAIProvider,
    "chatgpt": OpenAIProvider,  # Alias
    "gemini": GeminiProvider,
    "grok": GrokProvider,
    "deepseek": DeepSeekProvider,
    "qwen": QwenProvider,
}


def get_provider(
    provider_name: Optional[str] = None,
    config_path: Path = DEFAULT_CONFIG_PATH,
    config: Optional[LLMConfig] = None,
) -> LLMProvider:
    """
    Factory function to get an LLM provider instance.
    
    Args:
        provider_name: Override the provider from config. Options: groq, mistral,
                      openrouter, claude, openai, chatgpt, gemini, grok, deepseek, qwen
        config_path: Path to the configuration YAML file.
        config: Optional pre-loaded LLMConfig object.
        
    Returns:
        An initialized LLMProvider instance.
        
    Example:
        # Use default provider from config (groq)
        provider = get_provider()
        
        # Use specific provider
        provider = get_provider(provider_name="groq")
        
        # Use custom config
        config = LLMConfig(provider="openai", openai_api_key="sk-...")
        provider = get_provider(config=config)
    """
    if config is None:
        config = LLMConfig.from_yaml(config_path)
    
    name = (provider_name or config.provider).lower()
    
    if name not in PROVIDER_CLASSES:
        available = ", ".join(PROVIDER_CLASSES.keys())
        raise ValueError(f"Unknown provider: {name}. Available: {available}")
    
    provider_class = PROVIDER_CLASSES[name]
    return provider_class(config)


def list_providers() -> list[str]:
    """Return list of available provider names."""
    return list(set(PROVIDER_CLASSES.keys()) - {"chatgpt"})  # Exclude alias


def list_free_providers() -> list[str]:
    """Return list of free provider names."""
    return ["groq", "mistral", "openrouter"]


# =============================================================================
# CLI INTERFACE
# =============================================================================

def main():
    """CLI entry point for testing providers."""
    import sys
    
    if len(sys.argv) < 2:
        print("""
LLM Provider Interface
======================

Usage:
    python llm_provider.py test [provider]     Test a provider with a sample query
    python llm_provider.py list                List available providers
    python llm_provider.py free                List free providers
    python llm_provider.py info [provider]     Show provider info

Examples:
    python llm_provider.py test groq           Test Groq (free, recommended)
    python llm_provider.py test mistral        Test Mistral (free)
    python llm_provider.py test openrouter     Test OpenRouter (free)
    python llm_provider.py list

Free Providers (no credit card required):
    - groq       : 14,400 req/day, fastest inference, Llama 3.3 70B
    - mistral    : 1B tokens/month, phone verification required
    - openrouter : 50 req/day, 25+ free models available
""")
        sys.exit(0)
    
    command = sys.argv[1].lower()
    
    if command == "list":
        print("Available providers:")
        print("\n  FREE (no credit card):")
        for name in list_free_providers():
            print(f"    - {name}")
        print("\n  PAID:")
        for name in list_providers():
            if name not in list_free_providers():
                print(f"    - {name}")
        sys.exit(0)
    
    if command == "free":
        print("Free providers (no credit card required):")
        print("  - groq       : 14,400 req/day, fastest inference")
        print("  - mistral    : 1B tokens/month, phone verification")
        print("  - openrouter : 50 req/day, 25+ free models")
        sys.exit(0)
    
    if command == "info":
        provider_name = sys.argv[2] if len(sys.argv) > 2 else None
        try:
            provider = get_provider(provider_name=provider_name)
            info = provider.get_info()
            print(f"\nProvider Information:")
            for key, value in info.items():
                print(f"  {key}: {value}")
        except Exception as e:
            print(f"Error: {e}")
        sys.exit(0)
    
    if command == "test":
        provider_name = sys.argv[2] if len(sys.argv) > 2 else None
        
        try:
            print(f"\nInitializing provider: {provider_name or 'default'}...")
            provider = get_provider(provider_name=provider_name)
            
            print(f"Provider: {provider.provider_name}")
            print(f"Model: {provider.model_name}")
            
            test_query = "Write a simple SPL query to count events by sourcetype."
            print(f"\nTest query: {test_query}")
            print("\nGenerating response...\n")
            
            response = provider.generate(test_query)
            
            print("=" * 60)
            print(response.content)
            print("=" * 60)
            print(f"\nTokens: {response.input_tokens} in / {response.output_tokens} out")
            print(f"Latency: {response.latency_ms:.0f}ms")
            
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)
        
        sys.exit(0)
    
    print(f"Unknown command: {command}")
    sys.exit(1)


if __name__ == "__main__":
    main()
