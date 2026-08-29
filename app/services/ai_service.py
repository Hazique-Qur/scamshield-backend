from abc import ABC, abstractmethod
from typing import Optional
from app.core.config import settings


class AIProvider(ABC):
    @abstractmethod
    async def chat(self, prompt: str, system_prompt: str | None = None) -> str:
        pass

    @abstractmethod
    async def vision(self, image_path: str, prompt: str) -> str:
        pass


class MockProvider(AIProvider):
    async def chat(self, prompt: str, system_prompt: str | None = None) -> str:
        return "This is a mock AI response. Configure an AI provider for real analysis."

    async def vision(self, image_path: str, prompt: str) -> str:
        return "Mock vision analysis. Configure an AI provider for real analysis."


class AIService:
    def __init__(self):
        provider_name = (settings.ai_provider or "mock").lower()
        if provider_name == "gemini":
            self.provider = GeminiProvider()
        elif provider_name == "openai":
            self.provider = OpenAIProvider()
        elif provider_name == "ollama":
            self.provider = OllamaProvider()
        else:
            self.provider = MockProvider()

    async def chat(self, prompt: str, system_prompt: str | None = None) -> str:
        return await self.provider.chat(prompt, system_prompt)

    async def vision(self, image_path: str, prompt: str) -> str:
        return await self.provider.vision(image_path, prompt)


class GeminiProvider(AIProvider):
    async def chat(self, prompt: str, system_prompt: str | None = None) -> str:
        try:
            from google import genai
            client = genai.Client(api_key=settings.gemini_api_key)
            full_prompt = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt
            response = client.models.generate_content(
                model="gemini-3.6-flash",
                contents=full_prompt,
            )
            return response.text or ""
        except Exception:
            return "AI analysis unavailable."

    async def vision(self, image_path: str, prompt: str) -> str:
        try:
            from google import genai
            from PIL import Image
            import io
            client = genai.Client(api_key=settings.gemini_api_key)
            img = Image.open(image_path)
            img.thumbnail((1024, 1024))
            if img.mode != "RGB":
                img = img.convert("RGB")
            buf = io.BytesIO()
            img.save(buf, format="JPEG", quality=80)
            buf.seek(0)
            image_bytes = buf.read()
            response = client.models.generate_content(
                model="gemini-3.6-flash",
                contents=[
                    prompt,
                    genai.types.Part.from_bytes(data=image_bytes, mime_type="image/jpeg"),
                ],
            )
            return response.text or ""
        except Exception:
            return "Vision analysis unavailable."


class OpenAIProvider(AIProvider):
    async def chat(self, prompt: str, system_prompt: str | None = None) -> str:
        try:
            import openai
            client = openai.AsyncOpenAI(api_key=settings.openai_api_key)
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})
            response = await client.chat.completions.create(
                model="gpt-4o-mini",
                messages=messages,
            )
            return response.choices[0].message.content or ""
        except Exception:
            return "AI analysis unavailable."

    async def vision(self, image_path: str, prompt: str) -> str:
        try:
            import openai
            import base64
            client = openai.AsyncOpenAI(api_key=settings.openai_api_key)
            with open(image_path, "rb") as f:
                base64_image = base64.b64encode(f.read()).decode("utf-8")
            response = await client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": prompt},
                            {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{base64_image}"}},
                        ],
                    }
                ],
            )
            return response.choices[0].message.content or ""
        except Exception:
            return "Vision analysis unavailable."


class OllamaProvider(AIProvider):
    async def chat(self, prompt: str, system_prompt: str | None = None) -> str:
        try:
            import httpx
            async with httpx.AsyncClient(timeout=60.0) as client:
                payload = {"model": "llama3", "prompt": prompt, "stream": False}
                if system_prompt:
                    payload["system"] = system_prompt
                response = await client.post(f"{settings.ollama_base_url}/api/generate", json=payload)
                data = response.json()
                return data.get("response", "")
        except Exception:
            return "AI analysis unavailable."

    async def vision(self, image_path: str, prompt: str) -> str:
        try:
            import httpx
            import base64
            with open(image_path, "rb") as f:
                base64_image = base64.b64encode(f.read()).decode("utf-8")
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(
                    f"{settings.ollama_base_url}/api/generate",
                    json={
                        "model": "llava",
                        "prompt": prompt,
                        "images": [base64_image],
                        "stream": False,
                    },
                )
                data = response.json()
                if data.get("error"):
                    return f"Vision analysis unavailable: {data['error']}"
                return data.get("response", "Vision analysis unavailable.")
        except Exception as exc:
            return "Vision analysis unavailable."
