#!/usr/bin/env python3
"""
Sentinel AI Agent (Local LLM)
Uses llama-cpp-python + LangChain LlamaCpp to run a self‑hosted model.
"""
import os, json, asyncio
from langchain.llms import LlamaCpp
from langchain.chains import LLMChain, PromptTemplate
from langchain.memory import ConversationBufferMemory
from sentinel.quick_scan import main as quick_scan
from sentinel.anomaly_detector import score as is_anomaly
from sentinel.policy import enforce

MODEL_PATH = os.path.join(os.getcwd(), "models", "Mistral-7B-Instruct-GGUF.q4_0.gguf")

# 1️⃣  Initialize local LLM
llm = LlamaCpp(
    model_path=MODEL_PATH,
    n_threads=4,           # tune to your CPU
    temperature=0.1,
    max_tokens=512,
)

memory = ConversationBufferMemory(memory_key="chat_history", return_messages=True)

# 2️⃣  Define prompt
prompt = PromptTemplate(
    input_variables=["log_line","chat_history"],
    template="""
You are Sentinel, a network AI guardian running locally.
Chat history:
{chat_history}

New event: "{log_line}"
1) Is this an anomaly? true/false
2) If true, propose an action.

Respond ONLY in JSON:
{{"anomaly":<true|false>,"action":"<action description>"}}
""",
)

chain = LLMChain(llm=llm, prompt=prompt, memory=memory)

async def handle_line(line: str):
    if is_anomaly(line):
        resp = await chain.apredict(log_line=line)
        raw = json.loads(resp)
        decision = enforce(raw)
        print(f"🤖 Local agent decision: {decision}")
        if decision.get("requires_confirmation", True):
            print("❓  Needs your OK before execution.")
        else:
            print(f"✅ Auto‑exec: {decision['action']}")
    else:
        print(f"✅ ML says normal: {line}")

def run_agent():
    quick_scan()
    reports = sorted(os.listdir("sentinel_reports"))
    if not reports:
        print("⚠️  No scan reports found.")
        return
    latest = reports[-1]
    data = json.load(open(f"sentinel_reports/{latest}"))
    for mac, ip in data.get("unknown", []):
        line = f"UNKNOWN {mac} {ip}"
        asyncio.run(handle_line(line))

if __name__ == "__main__":
    run_agent()
