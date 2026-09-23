import httpx
import os

OLLAMA_BASE  = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")

async def query_llm(prompt: str) -> str:
    mode = os.getenv("AEGIS_AI_MODE", "disabled")

    if mode != "local":
        return "[AI disabled — AEGIS_AI_MODE=local set karo aur Ollama chalaao]"

    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.post(
            f"{OLLAMA_BASE}/api/generate",
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False
            }
        )
        resp.raise_for_status()
        return resp.json().get("response", "")
