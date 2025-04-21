#!/usr/bin/env python3
"""
Pick your engine at runtime:

- If USE_LOCAL=1 and models/Mistral‑7B‑Instruct‑GGUF.q4_0.gguf exists → use local LlamaCpp.
- Else → use OpenAI GPT‑4.
"""
import os
from langchain.llms import OpenAI, LlamaCpp

LOCAL_PATH = os.path.join(os.getcwd(), "models", "Mistral-7B-Instruct-GGUF.q4_0.gguf")

def get_llm():
    use_local = os.getenv("USE_LOCAL", "") == "1"
    if use_local and os.path.isfile(LOCAL_PATH):
        print(f"🔬 Using local Llama model at {LOCAL_PATH}")
        return LlamaCpp(model_path=LOCAL_PATH, n_threads=4, temperature=0.2)
    # fallback
    print("☁️  Falling back to OpenAI GPT‑4")
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise EnvironmentError("Missing OPENAI_API_KEY for cloud mode")
    return OpenAI(model_name="gpt-4", temperature=0.2)
