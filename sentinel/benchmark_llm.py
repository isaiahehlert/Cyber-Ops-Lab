#!/usr/bin/env python3
"""
Benchmark GPT-4 (cloud) vs local Mistral-7B agent latencies.
Runs each 3× on a synthetic “UNKNOWN …” log line.
"""
import asyncio, time
from sentinel.agent import chain as cloud_chain
from sentinel.agent_local import chain as local_chain

TEST_LINE = "UNKNOWN AA-BB-CC-DD-EE-FF 192.168.1.100"
N_RUNS = 3

async def bench_chain(chain, name):
    # warm up once
    await chain.apredict(log_line=TEST_LINE)
    latencies = []
    for _ in range(N_RUNS):
        start = time.time()
        await chain.apredict(log_line=TEST_LINE)
        latencies.append(time.time() - start)
    avg = sum(latencies) / len(latencies)
    print(f"{name}: runs={latencies}, avg={avg:.2f}s")

async def main():
    print("\n🚀  Benchmarking…\n")
    await bench_chain(cloud_chain, "Cloud GPT-4")
    await bench_chain(local_chain, "Local Mistral-7B")
    print("\n🏁  Done.")
    
if __name__ == "__main__":
    asyncio.run(main())
