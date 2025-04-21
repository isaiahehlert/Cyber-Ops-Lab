#!/usr/bin/env python3
"""
Sentinel AI Agent — reasons over new events, but never acts without confirmation.
Usage:
  OPENAI_API_KEY=… python sentinel/agent.py
"""
import os, json, asyncio, datetime
from langchain.llms import OpenAI, LLMChain, PromptTemplate
from langchain.memory import ConversationBufferMemory
from sentinel.quick_scan import main as quick_scan
from sentinel.anomaly_detector import score as is_anomaly
from sentinel.policy import enforce

# Initialize LLM + memory
os.environ.setdefault("OPENAI_API_KEY","")
llm = OpenAI(model="gpt-4", temperature=0.2)
memory = ConversationBufferMemory(memory_key="chat_history", return_messages=True)

# Prompt template
prompt = PromptTemplate(
    input_variables=["log_line","chat_history"],
    template="""
You are Sentinel, a home‑network AI guardian.
Chat history:
{chat_history}

New event: "{log_line}"
1) Is this an anomaly? true/false
2) If true, propose an action.
Respond as JSON:
{{"anomaly":<true|false>,"action":"<action description>"}}
""",
)
chain = LLMChain(llm=llm, prompt=prompt, memory=memory)

async def handle_line(line: str):
    if is_anomaly(line):
        resp = await chain.apredict(log_line=line)
        raw = json.loads(resp)
        decision = enforce(raw)
        print(f"🤖 Decision (post‑policy): {decision}")
        if decision["requires_confirmation"]:
            print(f"❓  ACTION REQUIRES YOUR CONFIRMATION: {decision['action']}\n"
                  "    Run this manually or type 'make agent' again with CONFIRM=1")
        else:
            print(f"✅ Auto‑executing: {decision['action']}")
            # e.g., if decision['action'].startswith("log"):
            #    perform logging here
    else:
        print(f"✅ No anomaly detected by ML: {line}")

def run_agent():
    quick_scan()
    reports = sorted(os.listdir("sentinel_reports"))
    if not reports:
        print("⚠️  No reports found.")
        return
    latest = reports[-1]
    data = json.load(open(f"sentinel_reports/{latest}"))
    for mac, ip in data.get("unknown", []):
        line = f"UNKNOWN {mac} {ip}"
        asyncio.run(handle_line(line))

if __name__ == "__main__":
    run_agent()
