# 🛡️ Sentinel Security Dashboard

**Sentinel** is a lightweight security monitoring and attack-detection demonstration platform designed to simulate real-time security telemetry analysis.

It detects and visualizes common attack patterns including:

• SSH brute force attacks  
• SSH account takeover attempts  
• HTTP request spikes / potential DDoS activity  

The system demonstrates how telemetry ingestion, detection logic, and visualization layers interact in a modern security monitoring pipeline.

---

# ⚙️ Architecture

Sentinel consists of two components:

### 1️⃣ Monitoring Server
Runs on a host machine (Mac Mini in demo).

Responsibilities:

• Receive security telemetry over LAN  
• Run detection heuristics  
• Maintain event history  
• Display live dashboard  

Tech stack:

• Python  
• FastAPI  
• Uvicorn  
• Vanilla JS dashboard  

---

### 2️⃣ Attack Simulation Client
Runs on a separate machine (laptop).

Simulates adversary activity by sending telemetry events to the monitoring server.

Attack scenarios include:

• SSH brute force  
• SSH takeover sequence  
• HTTP burst / DDoS simulation  

---

# 🧠 Detection Logic

Sentinel applies heuristic detection rules to incoming telemetry.

### SSH Brute Force

Triggered when:
failed_attempts >= 5
Example detection:
5 failed SSH auth attempts from 192.168.1.25
---

### SSH Account Takeover

Triggered when:
failed_attempts >= 10
followed by successful login
Example:
10 failed SSH attempts followed by successful login
---

### HTTP Burst / DDoS Spike

Triggered when:
= 10 HTTP requests in rapid succession
Example:
peak burst 10 req/sec from 192.168.1.25
---

# 🖥️ Dashboard Features
<img width="1920" height="959" alt="Screenshot 2026-03-10 at 12 28 40 PM" src="https://github.com/user-attachments/assets/d12cf892-d189-4d9b-8db1-a835e230e0db" />


The Sentinel dashboard provides:

• live monitoring indicator  
• animated alert banners  
• event severity classification  
• detection history  
• source IP analysis  
• attack evidence summaries  

---

# 🧪 Demo Workflow

1️⃣ Start Sentinel server
uvicorn sentinel_demo.app.main:app –host 0.0.0.0 –port 8080 –reload
---

2️⃣ Launch dashboard
http://:8080
---

3️⃣ Run simulated attacks from client machine

### SSH brute force
python sentinel_demo/scripts/run_ssh_bruteforce.py –target 
### SSH takeover
python sentinel_demo/scripts/run_ssh_takeover.py –target 
### HTTP spike
python sentinel_demo/scripts/run_ddos.py –target 
---

# 📊 Example Detection Output
<img width="1905" height="959" alt="Screenshot 2026-03-10 at 12 39 01 PM" src="https://github.com/user-attachments/assets/6f3be617-158e-4784-9b9f-d43e56ec923f" />


ALERT: ssh_takeover detected

source_ip: 192.168.88.8
failed_attempts: 18
successful_login: true
severity: medium
---

# 🔬 Purpose

Sentinel was built as a demonstration of:

• security telemetry ingestion  
• detection heuristics  
• real-time monitoring dashboards  
• adversary simulation  

It is designed to clearly illustrate the interaction between detection systems and attack activity in a controlled environment.

---

# 👨‍💻 Developer

Isaiah Ehlert

Cybersecurity Researcher  
Sentinel Research Group

GitHub

https://github.com/isaiahehlert/Cyber-Ops-Lab

---

# ⚠️ Disclaimer

Sentinel is a **security research and demonstration platform** intended for educational use.

