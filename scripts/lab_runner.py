import os

def run_dns_lookup():
    os.system("python3 scripts/dns_lookup.py")

def run_port_scanner():
    os.system("python3 scripts/port_scanner.py")

def run_ai_detector():
    print("\nAI/Bot Detector Mode:")
    print("1. Manual Input")
    print("2. Analyze Log File")
    sub_choice = input("Choose mode: ")

    if sub_choice == "1":
        os.system("python3 scripts/ai_detector.py")
    elif sub_choice == "2":
        path = input("Enter path to log file (e.g., logs/sample.log): ")
        os.system(f"python3 scripts/ai_detector.py {path}")
    else:
        print("Invalid selection. Returning to main menu...")

def main():
    while True:
        print("\n🧪 Cyber Ops Lab Launcher")
        print("1. DNS Lookup")
        print("2. Port Scanner")
        print("3. AI/Bot Detector")
        print("4. Exit")

        choice = input("\nSelect an option: ")

        if choice == "1":
            run_dns_lookup()
        elif choice == "2":
            run_port_scanner()
        elif choice == "3":
            run_ai_detector()
        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main()
