#!/usr/bin/env python3
"""
Benchmark GPT-4 (cloud) vs Mistral-7B (local) latencies
using langchain.llms.OpenAI, not chat_models.
"""
import asyncio, time, os
from langchain.llms import OpenAI
from langchain.llms import LlamaCpp
from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate

# Test parameters
TEST_LINE = "UNKNOWN AA-BB-CC-DD-EE-FF 192.168.1.100"
N_RUNS = 3

# Prompt (simple yes/no)
template = PromptTemplate(
    input_variables=["log_line"],
    template="New event: \"{log_line}\". Is this an anomaly? Respond 'yes' or 'no'.",
)

# Cloud LLM via OpenAI SDK
cloud_llm = OpenAI(model_name="gpt-4", temperature=0)
cloud_chain = LLMChain(llm=cloud_llm, prompt=template)

# Local LLM via llama-cpp-python
MODEL_PATH = os.path.join(os.getcwd(), "models", "Mistral-7B-Instruct-GGUF.q4_0.gguf")
local_llm = LlamaCpp(model_path=MODEL_PATH, n_threads=4, temperature=0)
local_chain = LLMChain(llm=local_llm, prompt=template)

async def bench(chain, name):
    # warm‑up
    await chain.apredict(log_line=TEST_LINE)
    times = []
    for _ in range(N_RUNS):
        t0 = time.time()
        await chain.apredict(log_line=TEST_LINE)
        times.append(time.time() - t0)
    print(f"{name}: runs={times}, avg={sum(times)/len(times):.2f}s")

async def main():
    print("\n🚀 Benchmarking…\n")
    await bench(cloud_chain, "Cloud GPT‑4")
    await bench(local_chain, "Local Mistral‑7B")
    print("\n🏁 Done.")
    
if __name__ == "__main__":
    asyncio.run(main())
