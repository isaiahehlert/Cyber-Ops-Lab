import os

UNRECOGNIZED_LOG = "sentinel_reports/unrecognized_devices.log"
ALLOWLIST = "tools/allowlist.txt"
QUARANTINE = "tools/quarantined_macs.txt"

def load_existing(path):
    if not os.path.exists(path):
        return set()
    with open(path, "r") as f:
        return set(line.strip().split(",")[0] for line in f if line.strip())

def review_entries():
    if not os.path.exists(UNRECOGNIZED_LOG):
        print("[!] No unrecognized device log found.")
        return

    processed = set()
    allowlisted = load_existing(ALLOWLIST)
    quarantined = load_existing(QUARANTINE)

    with open(UNRECOGNIZED_LOG, "r") as f:
        lines = [line.strip() for line in f if line.strip()]

    if not lines:
        print("[✓] No unprocessed entries found.")
        return

    for line in lines:
        ip, mac = line.split(",")
        mac = mac.upper()

        if mac in allowlisted or mac in quarantined or mac in processed:
            continue  # Already handled

        print(f"\n�� IP: {ip}\n🆔 MAC: {mac}")
        choice = input("[A]llow, [Q]uarantine, [I]gnore? ").strip().upper()

        if choice == "A":
            label = input("📛 Enter device name: ").strip()
            with open(ALLOWLIST, "a") as f:
                f.write(f"{mac},{label}\n")
            print(f"✅ {mac} added to allowlist as '{label}'.")
        elif choice == "Q":
            with open(QUARANTINE, "a") as f:
                f.write(f"{mac}\n")
            print(f"🚫 {mac} added to quarantine list.")
        else:
            print("⏭️ Skipped.")
        processed.add(mac)

    print("\n[✓] Review complete.")

if __name__ == "__main__":
    review_entries()
