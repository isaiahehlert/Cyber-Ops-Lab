"""
Stubbed network analyzer (raw sockets not permitted here)
"""
def run_analysis(snapshot, output_file=None):
    print("⚠️  Raw sockets aren’t permitted; skipping network analysis.")
    return []

# alias for the agent import
main = run_analysis
