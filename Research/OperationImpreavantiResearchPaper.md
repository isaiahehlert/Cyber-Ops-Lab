# Operation Impreavanti

*A ground-up design and implementation dossier for a local, explainable, open security fusion center*

| **Prepared for** | Prepared for the local fusion-center build project |
| --- | --- |
| **Date** | March 2026 |

*A ground-up design and implementation dossier for a local, open, explainable fusion-center stack.*

## Research Abstract

Operation Impreavanti is a ground-up design dossier for a local, open, explainable security fusion center built around a Raspberry Pi 4B 'brain', a Jetson Nano 'face', passive network observation, structured evidence layers, and bounded LLM assistance. The central thesis is that security tooling should discipline evidence into understanding without collapsing raw facts, analytical assessments, and machine-generated explanations into one opaque narrative.

The paper maps the design to current standards, critiques common industry failures, compares alternative architectures, proposes a phased implementation plan, catalogs open-source software, evaluates languages and model choices, and documents both the legal and operational boundaries required to keep the project useful rather than reckless.

> **Scope statement:** The design is for owned or explicitly authorized environments. It is local-first, metadata-first by default, passive where possible, and hostile to architectures that sacrifice availability or provenance for dashboard spectacle.

## Executive Summary

The proposed system keeps packet movement and analytical reasoning separate. The router routes. The Pi ingests, normalizes, scores, and stores. The Nano renders the operator interface. Optional stronger hosts handle heavy local inference or development, but the core telemetry path remains independent of them. This architecture reduces failure blast radius, keeps the live network stable, and makes the system easier to reason about under stress.

Version one emphasizes Suricata, Zeek, Loki, a small relational state store, Python-based enrichment logic, a TypeScript interface, endpoint inventory via osquery or Fleet, and carefully bounded model assistance. It explicitly refuses several seductive wrong turns: inline enforcement on weak hardware, permanent full packet capture, monolithic product worship, and LLM-as-oracle thinking.

The implementation plan is phased and evidence-driven. Foundations come first: network stability, remote recovery, service health, schemas, and storage. Richer enrichment, CTI integrations, packet-centric workflows, and heavier model use come later if and only if the initial system proves useful.

## How to Read This Dossier

The document is arranged as a long-form engineering monograph. Volumes I and II state the thesis, the scope, the standards mapping, and the architecture. Volumes III and IV explain how to build the system and why particular tools and languages are recommended. Volume V addresses law, history, and research method. Volume VI sets the roadmap. The appendices provide operational scaffolding: software catalogs, model matrices, filesystem analysis, file trees, schemas, runbooks, governance prompts, and analyst templates.

Readers seeking the fastest route to implementation should start with the roadmap, the base-OS chapters, the Pi/Nano build chapters, Appendix A, Appendix E, and Appendix F. Readers evaluating the design thesis should focus on Chapters 1&#8211;5 and 19&#8211;22. Readers primarily interested in model and tooling choices should focus on Chapters 14&#8211;18 and Appendices B&#8211;D.

> **Reading discipline:** This paper intentionally distinguishes facts, design decisions, and speculative options. The differences matter. Every future implementation choice should preserve that same discipline.

## Range-Based Table of Contents

Page ranges below refer to the final rendered document. Each entry names a range and summarizes what that section contributes to the build.

| **Pages** | **Section** | **Coverage** |
| --- | --- | --- |
| 2&#8211;9 | **Front Matter and Reading Guide** | Abstract, executive summary, reading guide, decision map, and the custom range-based table of contents. |
| 10&#8211;13 | The Mission, the Thesis, and the Refusal to Build Another Useless Dashboard | Operation Impreavanti is not a hobbyist pile of blinking widgets. It is a deliberate attempt to build a local, explainable, open, evidence-first security fusion center whose operator can understand what the system knows, why it knows it, and what it is still missing. |
| 14&#8211;18 | Threat Model, Scope Boundaries, and the Security Principles That Actually Matter | A useful fusion-center stack begins with a disciplined statement of what is being defended, what is being observed, what is legally and ethically off-limits, and what principles will govern design choices when trade-offs become painful. |
| 19&#8211;23 | Industry Standards, Schemas, and the Gap Between Guidance and Reality | Standards are useful when they discipline thinking and dangerous when they become compliance theater. This chapter maps the design to NIST, CISA, OCSF, STIX/TAXII, ATT&CK, D3FEND, and OpenTelemetry while also naming the operational gaps those standards do not fix by themselves. |
| 24&#8211;28 | Architecture Thesis: Pi as Brain, Nano as Face, Router as Packet Mover, and Nothing Inline That Should Not Be | This chapter states the system architecture plainly: passive where possible, modular everywhere, local first by default, and hostile to the idea that the same small board should simultaneously route multi-gigabit traffic, analyze events, host a GUI, and run a serious language model. |
| 29&#8211;33 | Data Model and Event Lifecycle: Facts, Entities, Assessments, and Explanations | The fusion center succeeds or fails on its internal model of truth. This chapter defines how raw observations become normalized events, how events become entities, how entities receive assessments, and how explanations remain separate from evidence. |
| 34&#8211;37 | Telemetry Strategy: What to Collect, What to Refuse, and How Not to Drown | Telemetry is not a virtue in itself. This chapter defines the collection strategy for version one, the rationale for metadata-first monitoring, and the retention boundaries that keep the system useful instead of voyeuristic and bloated. |
| 38&#8211;41 | Network Sensors: Suricata, Zeek, Arkime, and the Discipline of Passive Observation | This chapter defines the network sensor stack, explains why passive observation is the default, and shows how signature detections, protocol metadata, and selective packet retention complement rather than duplicate one another. |
| 42&#8211;45 | Endpoint, Asset, and Identity Context: The Missing Half of Most Cheap SIEM Dreams | Network telemetry without endpoint and asset context produces elegant confusion. This chapter explains how osquery, Fleet, Velociraptor, and simple inventory logic enrich the network picture without turning the project into an agent-sprawl circus. |
| 46&#8211;49 | Storage, Retention, and Query Design: Hot Logs, Curated State, and Cold History | Logs, entities, archives, and exports do not belong in the same bucket. This chapter designs a storage model that stays explainable, queryable, and resilient without pretending that one engine should do every job. |
| 50&#8211;53 | The Fusion Center Interface: Operator Flow, Explanation Layers, and Why Human Factors Beat Dashboard Confetti | The GUI is not decoration. It is the part of the system that determines whether evidence becomes action or just another gallery of panels. This chapter defines an interface that is entity-first, explanation-rich, and hostile to unlabeled certainty. |
| 54&#8211;57 | Setup Plan Part I: Base Linux, Host Roles, Hardening, and Orchestration | Before the clever parts arrive, the foundations must stop being sloppy. This chapter defines the operating-system choices, host preparation sequence, network assumptions, and service-orchestration posture for the full build. |
| 58&#8211;61 | **Setup Plan Part II: Building the Raspberry Pi Brain** | The Pi carries the serious operational burden of the project. This chapter defines the service stack, data flow, API boundaries, and implementation steps for the brain node that turns telemetry into structured security knowledge. |
| 62&#8211;65 | Setup Plan Part III: Building the Jetson Nano Interface and Operator Console | The Nano hosts the experience layer: the web interface, real-time views, investigator workflows, and the translation of structured security knowledge into something a human can use under pressure. |
| 66&#8211;69 | **The LLM Subsystem: Copilot, Not Oracle** | A local or hybrid language-model layer can make the fusion center vastly easier to use&#8212;if it stays in its lane. This chapter defines the role, safety boundaries, hardware realities, and model choices for early 2026. |
| 70&#8211;72 | Core Open Source Software Catalog: What Makes the Cut and Why | This chapter names the primary open-source components recommended for version one, explains their roles, and gives a candid discussion of strengths, costs, and fit. |
| 73&#8211;76 | Optional, Deferred, and Rejected Tools: Adjacent Power Without Architectural Sloppiness | Not every useful open-source security tool belongs in version one. This chapter surveys the surrounding ecosystem and explains what to adopt later, what to use sparingly, and what to avoid for this build. |
| 77&#8211;80 | Language, Runtime, and Framework Choices: What We Should Use and What We Should Decline | Languages are not personal brands here; they are operational commitments. This chapter recommends a language stack led by Python and TypeScript, with selective use of Go and a hard refusal to multiply runtimes without a measured reason. |
| 81&#8211;83 | Repository and File Structure Options: Monorepo, Split Repos, and the Cost of Clever Layouts | Code structure is not a purely aesthetic choice. It shapes onboarding, deployment, testing, and how readily the system can survive its own growth. This chapter proposes repository layouts and weighs their trade-offs. |
| 84&#8211;87 | Legal, Privacy, and Governance Analysis: Building the SIEM Without Building a Liability Machine | This chapter gives the legal and governance frame for the project: ownership, authorization, consent, minimization, exports, monitoring scope, and the practical implications of U.S. interception and stored-communications law for a local fusion-center build. |
| 88&#8211;90 | Historical Failures, Anti-Patterns, and the Weird Ways Good Intentions Rot | History supplies brutal case studies in what not to do. This chapter extracts design lessons from major incidents and from recurring anti-patterns in how monitoring systems are built, trusted, and misused. |
| 91&#8211;93 | Parallel Case Studies and Research Method: How We Test Whether the Design Is Actually Better | A research-grade build should not merely assert superiority. It should create comparative experiments. This chapter defines case-study structure, hypotheses, metrics, and side-by-side evaluation plans for the fusion-center design. |
| 94&#8211;96 | Detection Engineering Doctrine: Baselines, Scores, Suppressions, and Feedback Loops | Detection engineering is the craft that turns telemetry into operationally credible claims. This chapter defines the scoring model, suppression philosophy, ATT&CK mapping use, and the review loops that keep the system honest over time. |
| 97&#8211;100 | Roadmap: What We Will Build, What We Will Delay, What We May Explore, and What We Will Avoid | A design dossier that does not make sequencing decisions is just ambition in a trench coat. This chapter converts the thesis into phased execution with explicit yes, later, maybe, and no categories. |
| 101&#8211;103 | Conclusion: Operation Impreavanti as a Serious Local Fusion Center, Not a Toy | The closing chapter states plainly what this system is trying to become, why the architecture is arranged as it is, and what standards of rigor must continue to govern it if it is to remain useful rather than decorative. |
| 104&#8211;106 | Ninety-Day Build Plan, Milestones, and Acceptance Criteria | This appendix translates the architecture into a build calendar with weekly milestones, acceptance tests, and dependency notes. It is meant to be used, not admired. |
| 107&#8211;110 | Extended Open Source Software Catalog with Roles, Pros, Cons, and Fit | This appendix expands the tool survey into a practical catalog. It does not pretend every project must be adopted; it explains what each project is good for, where it fits, and where it does not. |
| 111&#8211;114 | LLM and Model Matrix for Early 2026: Best Fit, Frontier Capability, and Local Practicality | This appendix expands the model discussion into a working selection matrix. It distinguishes frontier capability from operational fit and keeps hardware reality firmly in view. |
| 115&#8211;117 | **Filesystem, Storage, and Cross-OS Portability Analysis** | This appendix addresses the user&#8217;s explicit filesystem concern and explains why live Linux data should remain on ext4 while cross-platform exchange uses a separate portability layer. |
| 118&#8211;120 | Repository Trees, Service Layouts, and File-Structure Options | This appendix provides concrete file-tree patterns for a monorepo-first implementation and discusses alternatives so the design can move from paper to code without improvising the entire project structure. |
| 121&#8211;124 | Example API Contracts, Event Schemas, and Evidence Objects | This appendix sketches the kinds of schemas and API objects the system should expose so that the Pi brain, Nano UI, and optional model layer remain contract-driven rather than ad hoc. |
| 125&#8211;127 | **Runbooks, Playbooks, and Break-Glass Procedures** | A fusion center is operationally credible only if it includes procedures for common failures and investigative motions. This appendix provides practical runbooks and response skeletons. |
| 128&#8211;130 | Governance Checklists, Consent Prompts, and Scenario Library Starters | This appendix offers practical governance prompts and a starter scenario library so the system can be deployed and evaluated without improvising the sensitive parts. |
| 131&#8211;133 | Prompt Library, Query Patterns, and Analyst Question Templates | This appendix provides example prompts and analyst queries so the model and the system are asked useful questions rather than vague cyber-mystical ones. |
| 134&#8211;136 | Glossary of Core Terms, Concepts, and Deliberately Precise Vocabulary | This glossary defines the key concepts used throughout the paper so the system&#8217;s terms remain stable across design, implementation, and operation. |
| 137&#8211;139 | Alternative Architecture Patterns and Why They Lost the Decision | This appendix records several architecture variants that were considered and explains, without diplomatic padding, why they were not chosen for the current mission. |
| 140&#8211;142 | Control Mapping: How the Architecture Relates to Standards, Tactics, and Defensive Techniques | This appendix maps core architectural decisions to standards and technique vocabularies so the system can be discussed in formal language without becoming enslaved to formalism. |
| 143&#8211;145 | Risk Register, Maintenance Debt, and the Problems We Should Expect to Meet in the Hallway | A good design dossier predicts its own likely failure modes. This appendix records operational risks, maintenance debt categories, and mitigation plans before the system accumulates them quietly. |
| 146&#8211;148 | Analyst Worksheets, Review Forms, and Reporting Templates | This appendix packages a set of reusable forms and review templates so the system does not force every investigation or monthly review to begin from a blank page. |
| 149&#8211;150 | Operating Maxims, Research Questions, and the Work Still Worth Doing | This final appendix records the short maxims and open research questions that should travel with the system as it evolves so the project does not forget what made it coherent in the first place. |

## Key Decisions at a Glance

| **Decision area** | **Recommended stance** | **Why it matters** |
| --- | --- | --- |
| Network posture | Passive observation, router stays primary | Monitoring failures must not become network outages |
| Evidence model | Facts -> events -> entities -> assessments -> explanations | Preserves provenance and auditability |
| Storage | Loki + relational state + cold archives | Fits different query and retention shapes |
| Languages | Python + TypeScript + SQL + small Bash | Keeps the runtime budget sane |
| Models | Optional copilot, never sole detector | Maintains reproducibility and safety |
| Filesystems | ext4 for live ops, exFAT for exchange | Balances reliability with cross-OS practicality |

**VOLUME I &#8212; STRATEGY, DOCTRINE, AND PROBLEM FRAMING**

**Chapter 1**

## The Mission, the Thesis, and the Refusal to Build Another Useless Dashboard

> *Operation Impreavanti is not a hobbyist pile of blinking widgets. It is a deliberate attempt to build a local, explainable, open, evidence-first security fusion center whose operator can understand what the system knows, why it knows it, and what it is still missing.*

### 1.1 Mission statement

The mission is simple to state and annoyingly difficult to execute: build a local-first, modular, analyst-centered security operations appliance that combines network telemetry, endpoint state, enrichment logic, timeline context, and carefully bounded LLM assistance into a single system that is actually useful under stress. The appliance must work in a small lab, must scale conceptually beyond the lab, and must remain understandable after the honeymoon phase wears off. If the design only looks clever during the first week and becomes an archaeological dig after month three, the design has failed.

The dominant pattern in the commercial SIEM market is to sell ingestion, rules, dashboards, and a feeling of coverage. The operator gets pages of panels, a flood of alerts, and a monthly bill large enough to make the spreadsheet sweat. What is frequently missing is a rigorous explanation layer, a coherent local data model, an explicit theory of evidence, and a humane interface for making investigative sense of weak signals. Operation Impreavanti begins by rejecting the fantasy that more logs automatically create more understanding. Logs are sediment. Security is interpretation.

This document therefore treats the system as an epistemic machine rather than a pile of agents. The question is not merely what can be collected; the question is what can be known, how confidently it can be known, how quickly that knowledge can be revised, and how transparently that revision can be shown to the human operator. That framing matters because security work is adversarial, incomplete, and time-constrained. A system that emits ungrounded confidence is worse than a system that admits uncertainty.

> **Core thesis:** Facts, assessments, and model-generated explanations must remain separate layers. Raw observation is not the same thing as correlation, and correlation is not the same thing as interpretation. Once those layers blur together, the operator loses the ability to audit the machine.

### 1.2 Why this project exists

Industry-standard guidance already emphasizes risk-based governance, continuous monitoring, and meaningful detection over decorative telemetry. NIST CSF 2.0 explicitly broadens cyber risk management beyond critical infrastructure and adds a first-class Govern function; NIST&#8217;s continuous-monitoring guidance frames monitoring as decision support rather than a mere tooling exercise; and CISA&#8217;s event-logging guidance emphasizes data quality, retention, and utility rather than indiscriminate collection (Refs: R1, R2, R3, R4). Yet real deployments still routinely collapse into one of two pathologies: either they collect everything and understand little, or they collect too little and mistake silence for safety.

Operation Impreavanti exists because there is a gap between the standards literature and the lived reality of detection engineering. That gap has multiple causes. Commercial incentives reward ingest volume. Product teams reward feature surface area. Buyers reward box-checking. Operators reward whatever reduces pain this week. The result is a strange bazaar of alerting engines, cloud portals, semi-normalized schemas, threat feeds of dubious quality, and dashboards that look like airport departure boards after a solar storm. The irony is that most of the component technologies are individually excellent. The failure lies in composition and operator experience, not in the existence of telemetry itself.

A second reason for the project is sovereignty. A local fusion system gives the operator tighter control over data gravity, retention, enrichment boundaries, and what leaves the environment. That matters for privacy, legal exposure, cost discipline, and experimental freedom. It also matters for trust. When every analytical move requires a remote SaaS dependency, the operator is no longer operating a system; the operator is renting a behavior. For home labs, small teams, research rigs, or high-sensitivity enclaves, that is an unacceptable trade unless explicitly chosen.

### 1.3 What this project is and is not

**&#8226;** It is a defensive monitoring and analysis system for environments you own or are explicitly authorized to monitor.

**&#8226;** It is a fusion-center design: entity-centric, evidence-layered, explainable, and locally operable.

**&#8226;** It is not an excuse to capture every byte forever just because disks are cheap and curiosity is infinite.

**&#8226;** It is not a vendor parody built from open-source parts; the design goal is operational coherence, not ideological purity.

**&#8226;** It is not a replacement for patching, MFA, backups, segmentation, hardening, or judgment. It is an amplifier for judgment, not a substitute for it.

### 1.4 Reading guide

This paper is written as a full design dossier. It includes doctrine, architecture, software choices, implementation steps, legal analysis, case studies, alternative designs, language decisions, LLM recommendations, and appendices rich enough to actually build from. The opening volumes define what the system should be. The middle volumes explain how to build it. The later volumes attack our own assumptions, compare alternatives, and describe what we will consciously refuse to do. The appendices are not decorative; they are intended to function as operational scaffolding.

The tone of the paper is intentionally unsentimental. Bad ideas will not be padded with diplomatic foam. If a technology is fashionable but wrong for this build, it will be treated as wrong for this build. If a common industry practice is lazy, cost-maximizing, or analytically weak, it will be named as such. The point of a ground-up design exercise is not to preserve sacred cows. It is to eat them if necessary and use the bones for better architecture.

### 1.5 Decision preview

| **Decision area** | **Recommended stance** | **Reason** |
| --- | --- | --- |
| Data path | Out-of-band / passive | Do not inline the Pi or Jetson into a 2 Gbps production path; keep packet movement and analysis separate. |
| Normalization | OCSF-inspired, not OCSF-worship | Use open schema discipline without forcing every event through a brittle one-size-fits-all ceremony. |
| Storage | Hot logs + curated state + cold history | Loki for log search, small relational state for entities, Parquet-style archives later. |
| LLM role | Copilot, not judge | LLMs summarize, explain, and answer questions; they do not become the primary detection engine. |
| UI philosophy | Entity-first, evidence-layered | Operators investigate devices, domains, identities, and timelines&#8212;not just isolated alerts. |
| Filesystems | ext4 for live ops, exFAT for exchange | FAT32 is obsolete for this role; NTFS is acceptable for exchange, not ideal for Linux-native live data. |

**VOLUME I &#8212; STRATEGY, DOCTRINE, AND PROBLEM FRAMING**

**Chapter 2**

## Threat Model, Scope Boundaries, and the Security Principles That Actually Matter

> *A useful fusion-center stack begins with a disciplined statement of what is being defended, what is being observed, what is legally and ethically off-limits, and what principles will govern design choices when trade-offs become painful.*

### 2.1 Scope before tooling

Security projects fail early when scope is treated as a vibe rather than a boundary. A home or lab SIEM is not an abstract data vacuum; it is a system for a defined environment, a defined set of assets, a defined level of authority, and a defined set of questions. In Operation Impreavanti the initial protected environment is a private, authorized network containing a high-speed residential router, wireless mesh nodes, workstations, portable devices, a Raspberry Pi 4B acting as analysis brain, a Jetson Nano acting as interface host, and optional stronger hosts such as a Mac mini M4 for development or heavier local inference. The system&#8217;s job is to observe that environment, model it, and explain it. Its job is not to magically generalize into enterprise omniscience on day one.

That scope statement immediately answers several seductive but destructive urges. We do not attempt universal coverage. We do not collect every available packet because we can. We do not pretend that a home environment is legally identical to an employer-owned network. We do not assume that everyone whose device touches the network has silently agreed to deep inspection. We do not assume that consumer hardware can be bullied into performing like a rack-mounted sensor farm. Scope is therefore not administrative housekeeping; it is the first control against bad architecture.

> **Design rule:** Whenever a feature request cannot be tied to a specific asset class, risk question, response workflow, or measurable hypothesis, it should be treated as suspect until proven valuable.

### 2.2 Assets, adversaries, and abuse cases

The protected assets in this design fall into six buckets: connectivity, identity, endpoint integrity, data confidentiality, operational continuity, and interpretive trust. Connectivity means the ability of the router, mesh, and internal services to keep working. Identity means accounts, authentication tokens, API keys, and trust relationships. Endpoint integrity means the behavior of laptops, desktops, phones, and headless systems. Data confidentiality means local logs, metadata, credentials, and any content retained for investigation. Operational continuity means the ability to monitor and recover during failure. Interpretive trust means confidence that what the system presents is traceable to evidence rather than confident narrative fog.

The adversaries worth modeling include commodity malware, opportunistic botnet activity, malicious websites, credential theft, misconfiguration, household-device weirdness, supply-chain surprises, abusive browser extensions, malicious applications, lateral movement between trusted devices, and simple operator error. The last category deserves respect. Many incidents begin not with an external genius but with a local mistake plus a system that failed to surface it in time. The fusion center therefore treats 'self-inflicted weirdness' as a first-class abuse case rather than an embarrassing footnote.

| **Asset class** | **Representative failure mode** | **Visibility needed** | **Primary defense theme** |
| --- | --- | --- | --- |
| Router and wireless fabric | Misconfiguration, exposed admin plane, unstable backhaul | Config changes, DHCP/DNS behavior, management access, topology drift | Hardening + remote break-glass access + baseline comparison |
| Endpoints | Malware, credential theft, suspicious domains, persistence | Process, DNS, network sessions, package inventory, browser extensions | Endpoint telemetry + entity correlation |
| Local services and dashboards | Privilege creep, stale secrets, insecure defaults | Auth events, service health, config drift, API logs | Least privilege + auditability |
| Logs and evidence | Overcollection, data leakage, retention sprawl | Retention policy, access audit, export logs | Minimization + controlled export |
| Operator trust | False certainty, unlabeled enrichments, hallucinated explanations | Evidence lineage, provenance tags, confidence scores | Layer separation + explicit uncertainty |

### 2.3 Classical principles: what still survives contact with 2026

A distressing amount of security discourse behaves as though principles became obsolete when dashboards got prettier. They did not. Least privilege remains correct. Fail-safe defaults remain correct. Complete mediation remains correct. Separation of privilege remains correct. Economy of mechanism remains correct. These principles from Saltzer and Schroeder endure because they are about structure, not fashion (Ref: R42). A local fusion center violates them at its own peril. If every service runs as root because 'it is only a lab,' least privilege has been surrendered before the first alert fires. If logs are retained indefinitely because 'storage is cheap,' economy of mechanism and psychological acceptability both begin to rot. If the LLM is allowed to rewrite facts, complete mediation between evidence and interpretation has collapsed.

Security engineering is not the art of accumulating controls until nothing moves. It is the art of arranging constraints so that trustworthy movement remains possible. That is why a well-designed system often looks boring up close: clear interfaces, strong defaults, predictable identities, explicit retention boundaries, reversible changes, and separation between the data path and the analysis path. Boring systems are not lesser systems. They are the systems that still make sense under fatigue, during incident response, and three months after the original enthusiasm has evaporated (Ref: R43).

**&#8226;** Least privilege applies to services, users, tokens, and data exports.

**&#8226;** Fail-safe defaults mean sensors start from deny/closed assumptions where practical, not from permanent exposure.

**&#8226;** Complete mediation means every jump from raw fact to enrichment to explanation remains inspectable.

**&#8226;** Economy of mechanism means fewer languages, fewer moving parts, fewer one-off daemons, fewer undocumented exceptions.

**&#8226;** Psychological acceptability means the operator can actually understand what the system is doing.

### 2.4 The theory layer: observation, uncertainty, and decision

A fusion center is fundamentally a decision-support system operating under uncertainty. That places it closer to applied epistemology than to simple server administration. Every event enters the system as an observation with unknown relevance. The system then accumulates context, compares history, scores novelty, maps possible technique relationships, and eventually presents the operator with an assessment. This is an argument, not a raw fact. The system should say: here is what we observed, here is why it may matter, here is the confidence level, here is what we still do not know. Anything less honest trains the operator either to mistrust the dashboard or to trust it for the wrong reasons.

The decision cycle can be framed through Boyd&#8217;s OODA loop&#8212;observe, orient, decide, act&#8212;but with a critical modification. Modern detection systems often become trapped in observation and never truly orient. They see a great deal, label a little, and understand very little. Operation Impreavanti therefore makes orientation explicit: normalization, entity resolution, baseline comparison, local context, external enrichment, and explanation are all orientation work, not decoration (Ref: R45). If orientation is weak, decisions are noise with badges.

### 2.5 What we will monitor, what we will avoid, and why

The initial collection plan privileges high-value metadata over indiscriminate capture. DNS queries, TLS metadata, DHCP leases, IP/port flow patterns, Suricata alerts, Zeek protocol logs, health metrics, local service logs, endpoint inventory state, and selected endpoint events all qualify as high-yield sources. Full packet capture does not become the default. Instead, packet content is treated as an escalation asset: a rolling short-term buffer, selective capture for experiments, or targeted on-demand acquisition around an event window. This posture keeps storage sane, respects privacy, and prevents the common fate of drowning in payloads nobody has time to review.

We will avoid building a stealth surveillance toy. That means no covert capture against devices or users lacking authority, no long-term retention of unnecessary content, no background exfiltration of logs to third-party services by default, and no 'just in case' data hoarding divorced from explicit investigative value. We will also avoid the opposite error: collecting so little that the system cannot explain anything beyond a superficial alert. Minimization is not negligence. It is discrimination in the literal sense: choosing what information deserves to exist because it can support a real question later (Refs: R30, R31, R32, R33).

### 2.6 Scope control checklist

**1.** Enumerate protected assets and assign ownership or authority assumptions.

**2.** Document what telemetry categories are in scope for initial collection and which are deliberately deferred.

**3.** Define the expected operator questions the system must answer in version one.

**4.** Document who may access raw evidence, enriched state, and generated explanations.

**5.** Specify what data leaves the environment, under what triggers, and with what redaction rules.

**6.** Record what legal or consent constraints apply to non-owned devices or users in the environment.

> **Why this chapter matters:** Most architectural mistakes can be traced to one of three sins: undefined scope, undefined authority, or undefined decision criteria. If those remain fuzzy, the rest of the stack becomes expensive theater.

**VOLUME I &#8212; STRATEGY, DOCTRINE, AND PROBLEM FRAMING**

**Chapter 3**

## Industry Standards, Schemas, and the Gap Between Guidance and Reality

> *Standards are useful when they discipline thinking and dangerous when they become compliance theater. This chapter maps the design to NIST, CISA, OCSF, STIX/TAXII, ATT&CK, D3FEND, and OpenTelemetry while also naming the operational gaps those standards do not fix by themselves.*

### 3.1 Standards are necessary and insufficient

Standards provide a vocabulary for governance, a common skeleton for process, and a way to reason across teams without inventing a new dialect every quarter. NIST CSF 2.0 sharpens the governance dimension of cybersecurity and explicitly frames cybersecurity as a wider risk-management discipline rather than a narrow technical silo (Ref: R1). NIST&#8217;s continuous-monitoring publications place emphasis on ongoing assessment, decision support, and program maturity rather than the magical belief that monitoring tools alone create security (Refs: R2, R3). CISA&#8217;s logging guidance likewise emphasizes useful logging, retention discipline, and detection-oriented design rather than indiscriminate accumulation (Ref: R4). These are good and important documents. They also do not tell an operator exactly how to compose Suricata, Zeek, Loki, enrichment logic, and a local analyst interface on a Pi-and-Nano budget.

That gap matters because design is always local. Standards tell us what good programs tend to care about; they do not eliminate the need for an explicit system thesis. A fusion center that waves NIST around while emitting unauditable risk scores is still broken. A stack that ingests ATT&CK mappings into a dashboard but cannot explain why a device is risky is still broken. A schema that normalizes events beautifully while obscuring the original evidence is still broken. Operation Impreavanti therefore treats standards as constraints and lenses, not as substitutes for architecture.

### 3.2 NIST CSF 2.0 as control plane, not product brochure

CSF 2.0 provides an excellent top-level organizing frame: Govern, Identify, Protect, Detect, Respond, Recover (Ref: R1). For this project, Govern translates into design decisions about ownership, scope, retention, data egress, model use, and legal boundaries. Identify translates into asset inventory, service inventory, dependency inventory, and identity mapping. Protect translates into hardening, segmentation, secret handling, access control, and safe defaults. Detect translates into telemetry, baselines, rules, analytics, and triage. Respond translates into playbooks, analyst workflows, timelines, and evidence export. Recover translates into backups, reconstitution, configuration snapshots, and the ability to rebuild the stack without ritual sacrifice.

The mistake many organizations make is to treat a framework like a procurement checklist: we bought products that map to Detect and Respond, therefore maturity has occurred. That is brochure logic. CSF is more useful when treated as a design pressure. Does the proposed component strengthen governance? Does it improve detection without sabotaging recoverability? Does it create a brittle dependency that worsens recovery even while improving visibility? Those are the real questions. A small local fusion center can actually embody CSF more faithfully than a bloated commercial deployment if its decisions remain explicit and auditable.

| **Framework / standard** | **What it contributes** | **What it does not solve** | **How Impreavanti uses it** |
| --- | --- | --- | --- |
| NIST CSF 2.0 | Governance language and functional balance | Concrete system composition | Use as the top-level operating model |
| NIST SP 800-137 / 137A | Continuous monitoring maturity and assessment | Sensor-by-sensor architecture choices | Use for program design and review cadence |
| CISA logging guidance | Logging quality, retention, detection utility | Entity model and UI philosophy | Use to justify collection discipline |
| ATT&CK | Adversary behavior taxonomy | Evidence quality or confidence | Use as mapping vocabulary, not truth oracle |
| D3FEND | Defensive technique ontology | Implementation order or resource trade-offs | Use for countermeasure reasoning |
| OCSF | Open event schema and normalization discipline | All edge-case semantics | Adopt selectively and extend carefully |
| STIX/TAXII | Threat intel transport and data sharing | Local context or evidence provenance | Use only where threat-sharing actually helps |
| OpenTelemetry | Composable telemetry transport and collector patterns | Security semantics by itself | Borrow the pipeline discipline, not blind equivalence |

### 3.3 ATT&CK and D3FEND: useful maps, terrible substitutes for judgment

ATT&CK remains one of the most useful shared vocabularies for adversary behavior because it lets detections and observations be described in a way others can recognize (Ref: R5). D3FEND is useful for the opposite direction: describing defensive techniques and relationships (Ref: R6). The important caveat is that neither framework is evidence. A domain query is not malicious because one can imagine an ATT&CK technique connected to it. A Suricata alert is not meaningful because it can be painted with a D3FEND-friendly countermeasure label. These frameworks are ontologies for reasoning and communication, not automatic verdict engines.

The correct use of ATT&CK inside this project is therefore modest and disciplined. Detection rules may carry ATT&CK tags. Correlation views may group observations into possible tactic clusters. Case-study writeups may compare observed patterns with published techniques. But the operator interface must preserve the distinction between 'mapped to possible technique' and 'confirmed malicious behavior.' That distinction sounds obvious until one has watched a dashboard confidently paint half a network orange because someone bulk-tagged generic PowerShell activity as lateral movement. Ontologies are maps. The territory still needs evidence.

### 3.4 OCSF, STIX/TAXII, and the schema temptation

The Open Cybersecurity Schema Framework is attractive because it promises a cleaner world: events represented in consistent classes with predictable fields, easier interoperability, and less bespoke glue code (Ref: R7). That promise is real. So is the danger. Teams sometimes respond to schema pain by forcing everything through a normalization funnel so early and so aggressively that source nuance disappears. Network telemetry, endpoint state, identity data, and operator annotations do not naturally arrive with identical semantics. Over-normalization can produce an elegant corpse: perfectly shaped data that lost the weird details that actually mattered.

Operation Impreavanti therefore adopts an OCSF-inspired posture rather than doctrinaire purity. Normalize what materially improves queryability and cross-source joins. Preserve source-native context where it carries investigative value. Keep the original event payload accessible. Make the transformation explicit. That approach also aligns with how STIX and TAXII should be treated. STIX/TAXII are powerful for intelligence representation and transport when there is a real sharing or feed-ingestion use case (Refs: R8, R9). They are not mandatory for a local fusion system whose most important knowledge may be internal baselines and local observations. Use them where they reduce ambiguity; avoid them where they add ceremony without leverage.

### 3.5 OpenTelemetry and the danger of false equivalence

OpenTelemetry has become a major standard for instrumenting and shipping telemetry, especially in cloud-native and application-observability environments (Refs: R10, R11). Its collector model is valuable even outside traditional observability because it encourages composable pipelines, processors, exporters, and explicit routing. Those are good habits. The mistake would be to pretend that generic observability telemetry is interchangeable with security telemetry. It is not. Security work cares about evidence fidelity, provenance, suppression logic, enrichment boundaries, chain of custody, and investigative reconstruction in ways that typical application monitoring often does not.

The correct synthesis is pragmatic. We borrow pipeline ideas from OpenTelemetry. We may use OpenTelemetry-compatible mechanisms for some transport and internal metrics. But we do not collapse all security semantics into an observability worldview. Security telemetry is a cousin, not a clone. The system must remain opinionated about identity resolution, event lineage, risk scoring, and evidence preservation. Otherwise one ends up with a fashionable collector architecture that moves bytes beautifully while explaining very little.

### 3.6 Where the industry is still lacking

**&#8226;** Too many stacks are alert-centric rather than entity-centric, which fragments investigations and buries context.

**&#8226;** Many products sell explanation theater: colorful scores without transparent derivation.

**&#8226;** Schema discipline is often weak or inconsistent, making cross-tool correlation expensive and brittle.

**&#8226;** Cloud dependence is frequently treated as default even when data sovereignty and cost discipline argue otherwise.

**&#8226;** LLM features are often bolted on as marketing ornaments instead of grounded analytical subsystems with provenance.

**&#8226;** Operators still spend too much time translating between tools and too little time reasoning about evidence.

This project&#8217;s core claim is therefore not that standards are wrong. It is that standards need an operational philosophy to become real. The missing layer is composition: how telemetry becomes evidence, how evidence becomes entities, how entities become assessments, and how assessments become operator decisions without dissolving provenance. Operation Impreavanti attempts to fill precisely that layer.

> **Standards posture:** Map to the standards, use their vocabularies, and benefit from their maturity. But never let a framework bully the design into a bad local implementation just because a checklist looks cleaner that way.

**VOLUME I &#8212; STRATEGY, DOCTRINE, AND PROBLEM FRAMING**

**Chapter 4**

## Architecture Thesis: Pi as Brain, Nano as Face, Router as Packet Mover, and Nothing Inline That Should Not Be

> *This chapter states the system architecture plainly: passive where possible, modular everywhere, local first by default, and hostile to the idea that the same small board should simultaneously route multi-gigabit traffic, analyze events, host a GUI, and run a serious language model.*

[Picture 1 - embedded Word figure omitted from standalone Markdown]

> *Figure: recommended high-level architecture with the router as packet mover, Pi as brain, Nano as face, and optional stronger host outside the core telemetry path.*

### 4.1 The core split

The architectural split is simple enough to memorize and therefore hard to misuse. The Raspberry Pi 4B is the brain. It collects, normalizes, enriches, scores, and stores the system&#8217;s security knowledge. The Jetson Nano is the face. It hosts the main local web interface, interactive dashboards, graph views, operator workflows, and optional lightweight model-assisted explanation features. The router remains the packet mover. It should route, switch, provide Wi-Fi, enforce baseline firewalling, and otherwise stay out of the analytical hot path. This division is not merely tidy. It is what keeps performance, maintainability, and mental clarity from murdering one another in the garage.

The reason the split works is that the compute characteristics of these roles differ. Packet movement at multi-gigabit speeds wants hardware offload, purpose-built switching, and low-latency forwarding. Telemetry enrichment wants modest but steady CPU, storage discipline, and reliable services. A visual interface wants responsive rendering, websockets, caches, and human-centered design. Serious model inference wants still more memory and compute than either the Pi or the Nano offers comfortably. Once the roles are separated, each device can do one job well enough instead of four jobs badly.

### 4.2 Why we refuse inline analysis on this hardware

A recurring bad idea in hobbyist security architecture is to put the clever box directly in front of all traffic and declare victory. The problem is physics, not ideology. A Raspberry Pi 4B is an impressive little machine for orchestration, collection, and logic, but it is not a clean way to inline a 2 Gbps consumer network with heavy inspection, archival, and enrichment. The Jetson Nano is likewise interesting for GPU-oriented experiments, but as a general-purpose inline network choke point it is a poor fit. Forcing either board into the forwarding path would create fragility, degrade throughput, complicate failover, and ensure that every analysis hiccup becomes a network outage.

History is full of systems that became dangerous because a secondary function was shoved into the primary path. Early firewalls overloaded with content inspection, endpoint agents given too many responsibilities, logging pipelines that stalled production systems, and brittle proxy architectures that converted observability failure into availability failure all share the same sin: they confused 'important' with 'must be inline.' Operation Impreavanti rejects that confusion. The analysis system should watch the network and interpret the environment, not become a single fragile throat through which all life must pass.
> **Architectural commandment:** The monitoring stack must fail soft. If the Pi dies, the network should keep moving. If the Nano dies, the data plane should keep moving. If the GUI misbehaves, the evidence pipeline should keep collecting.

### 4.3 High-level component layout

At version one, the network looks like this: ISP connection terminates at the router; the router provides LAN and Wi-Fi; a managed switch or other mirror-capable point is introduced if passive network copies are desired; mirrored traffic, selected logs, and host telemetry reach the Pi; the Pi writes hot logs to Loki, enriched entity state to a small relational store, and optionally raw or semi-raw archives to cold storage; the Nano serves the operator interface and requests data from Pi-hosted APIs; optional stronger hosts supply development or heavyweight inference when needed. Remote break-glass access is handled through a controlled VPN path, not by exposing the analytical services casually to the internet.

This architecture is intentionally asymmetrical. The Pi becomes the trustworthy back-end locus because its work is mostly machine-to-machine, schedulable, and amenable to conservative resource control. The Nano becomes the user-facing locus because interface experimentation, front-end assets, graph rendering, and human-pace interactions benefit from being isolated from the collection pipeline. The operator should be able to restart the UI without disrupting ingestion. That alone is worth the split.

| **Component** | **Primary responsibilities** | **What it must not become** | **Failure posture** |
| --- | --- | --- | --- |
| Router | Routing, Wi-Fi, firewalling, DHCP/DNS handoff | The SIEM brain, the LLM host, or the main analytics engine | Network remains primary even if analytics is down |
| Raspberry Pi 4B | Collection, enrichment, scoring, storage APIs, scheduled jobs | Inline traffic choke point or flashy dashboard renderer | Continue collecting even if UI is unavailable |
| Jetson Nano | Web GUI, websockets, visualization, operator workflows | Primary source of truth for event storage | UI can fail without data loss |
| Optional stronger host | Heavy local inference, development, batch analytics | Permanent hidden dependency for core telemetry | Nice to have, not single point of required operation |
| External SSD | Cold history, model store, exports, backups | The only location of irreplaceable hot state | Useful for resilience, never sole critical source |

### 4.4 Data-path separation and trust zones

The design benefits from explicit trust zones. Zone 1 is the forwarding fabric: router, switches, Wi-Fi, VLANs if later introduced. Zone 2 is the sensor and analysis plane: the Pi, mirror inputs, local collectors, and databases. Zone 3 is the operator plane: the Nano-hosted interface, authenticated clients, exports, reports, and human annotations. Zone 4 is optional external enrichment: reputation lookups, documentation links, threat-intel pulls, or remote model APIs. By separating these zones conceptually, one can reason more cleanly about which credentials exist where, which failures are allowed to propagate, and which systems may ever contact the internet spontaneously.

This separation also supports a crucial design ethic: local sovereignty by default, selective egress by policy. External queries for reputation or threat intelligence should be deliberate and ideally proxied, cached, or manually triggered. Blindly sending every suspicious IP, domain, or hash to a remote service is not only a privacy problem; it is also an operational leak. One can easily teach third parties what one finds interesting. Good defensive architecture is not just about protecting against attackers. It is about protecting against one&#8217;s own software tattling unnecessarily.

### 4.5 Storage and service boundaries

Hot logs belong in a log store optimized for append-heavy ingest and query over labels or structured data, which is why Loki is attractive for the initial build (Ref: R15). Enriched state belongs in a smaller store optimized for entities, relationships, annotations, and point lookups. The system should not force every use case into a single storage engine simply because fewer logos feel cleaner. Logs and entity state serve different query shapes. Treating them identically leads either to awkward dashboards or awkward investigations.

Likewise, service boundaries matter more than whether everything technically fits inside one container compose file. A collector should collect. An enrichment API should enrich. A UI should render. A model service should explain. When components have crisp boundaries, it becomes possible to cache aggressively, to test deterministically, to swap parts later, and to constrain privileges. Monolithic convenience is emotionally pleasant for a week and strategically poisonous after that.

### 4.6 What we are explicitly not building

**&#8226;** Not an all-in-one monolithic SIEM appliance with one database to rule everything.

**&#8226;** Not an inline IPS gateway that can bring down the home network when the analytics stack sneezes.

**&#8226;** Not a permanent full-packet-capture archive of every device all the time.

**&#8226;** Not a cloud-first portal whose local components exist only to feed a vendor.

**&#8226;** Not an LLM-driven magic judge that replaces evidence with vibes.

These negations are not pessimism. They are the project&#8217;s immune system. Every ambitious build needs a list of seductive wrong turns to avoid. The history of overengineered security systems suggests that the fastest path to disappointment is to let each new capability arrive as a special case without refactoring the overall thesis. This chapter is the thesis. The rest of the document is a disciplined elaboration of it.

**VOLUME II &#8212; ARCHITECTURE, TELEMETRY, AND ANALYTICAL STRUCTURE**

**Chapter 5**

## Data Model and Event Lifecycle: Facts, Entities, Assessments, and Explanations

> *The fusion center succeeds or fails on its internal model of truth. This chapter defines how raw observations become normalized events, how events become entities, how entities receive assessments, and how explanations remain separate from evidence.*

[Picture 2 - embedded Word figure omitted from standalone Markdown]

> *Figure: evidence ladder showing the required separation between observations, normalized events, entities, assessments, explanations, and operator decisions.*

### 5.1 Why a local theory of data matters

Many detection stacks behave as though data modeling is an implementation detail. It is not. The system&#8217;s internal representation determines what can be correlated, what can be explained, what can be suppressed, what can be searched, and what can be exported without losing meaning. Weak data models produce constant friction: duplicate devices, contradictory timestamps, orphaned alerts, impossible joins, and explanations that cannot cite their own evidence. Strong models do the opposite. They make it obvious which observations relate to which device, account, service, or domain, and they allow higher-level logic to remain auditable instead of mystical.

Operation Impreavanti therefore centers the pipeline around four layers: raw observations, normalized events, entities and relationships, and assessments. A fifth layer&#8212;generated explanation&#8212;sits on top but is intentionally not allowed to collapse into the others. This layered structure sounds bureaucratic until one tries to investigate a suspicious domain query six days later and discovers that the domain was normalized but the device identity changed names twice, the alert referenced a transient IP rather than the endpoint, and the LLM summary failed to preserve the original evidence. The layered model prevents that kind of epistemic sludge.

### 5.2 Raw observations

Raw observations are source-native facts as emitted or captured: Suricata Eve JSON records, Zeek log rows, DHCP lease events, DNS responses, service logs, endpoint inventory output, package lists, process events, or configuration snapshots. A raw observation should remain accessible in its original form or a near-lossless representation. This preserves investigative reversibility. If the normalized model ever proves incomplete or incorrect, the system can revisit the raw event without relying on memory or friendly summaries. Raw data is the bedrock, but it is not the place where humans should spend most of their time.

Every raw observation should carry at minimum a source identifier, acquisition timestamp, observed timestamp if distinct, ingestion path, integrity hints where available, and a stable event ID or derived hash. These are not ornamental metadata. They are what allow the system to prove that a later interpretation was derived from something real rather than invented by a bad transform, an overenthusiastic parser, or a chatty model service.

### 5.3 Normalized events

Normalized events translate source-native observations into a common intermediate representation that supports joining, searching, and downstream scoring. The normalization step is where OCSF-inspired discipline helps, provided it is used with restraint (Ref: R7). An event should express who did what, when, where, with what protocol or context, and under what certainty. It should also point back to the raw observation. When multiple raw records participate in a single normalized event&#8212;say, a DNS query and its response&#8212;those parent links should be preserved.

The system does not need a doctrinaire universal schema on day one. It needs a stable and documented house schema for the categories it actually collects. A local schema can still map to OCSF classes or ATT&CK tags later. The important thing is that key fields remain predictable: `src_asset_id`, `dest_ip`, `dest_domain`, `network_protocol`, `event_category`, `confidence`, `raw_ref`, `first_seen`, `last_seen`, and so forth. Predictability buys simpler code, safer joins, and clearer UI widgets. Chaos buys pain.

### 5.4 Entities and relationships

Entities are the enduring objects the operator actually cares about: devices, users, IP addresses, domains, processes, services, packages, certificates, and sometimes collections such as incidents or campaigns. Relationships express how those entities connect: device A resolved domain B, account C authenticated to service D, certificate E was presented by host F, process G spawned process H, and so on. Entity modeling is what turns the system from an alert board into a fusion center. Without entities, one investigates discrete confetti. With entities, one investigates behavior over time.

Entity resolution deserves explicit logic because identities drift. IPs change, hostnames change, MAC addresses can be randomized, devices appear on Wi-Fi and Ethernet, and services may have multiple names. The system therefore needs reconciliation rules and confidence scores. It should be comfortable saying that two observations probably refer to the same device but with only medium confidence. Better an honest probabilistic join than a confident false merge that corrupts history. This is one of the places where analysts often appreciate transparency more than automation.

| **Layer** | **Primary object** | **Stored where** | **Human expectation** | **Failure if missing** |
| --- | --- | --- | --- | --- |
| Raw observation | Source-native record | Log/archive | Verifiable provenance | No way to audit transforms |
| Normalized event | Comparable machine-readable event | Log + event store | Cross-source joins | Correlation becomes brittle |
| Entity / relationship | Enduring investigative object | Relational or graph-friendly state store | Device/domain/user centric views | Dashboard degenerates into alert soup |
| Assessment | Scored analytical claim | State store with lineage | Prioritized risk and rationale | Noise overwhelms triage |
| Generated explanation | Human-readable narrative | UI cache / optional note store | Quick comprehension with citations | Operator either drowns in detail or trusts black-box prose |

### 5.5 Assessments and scoring

An assessment is a claim the system makes about significance. Examples include 'domain X is novel for device Y,' 'host Z exhibits beacon-like periodicity,' or 'this endpoint&#8217;s package inventory drifted in a way inconsistent with baseline.' Assessments should be explicit objects, not just colors on charts. They need fields for severity, confidence, rationale, supporting evidence, suppressions applied, ATT&CK or D3FEND mappings if useful, and expiry or review status. In other words, an assessment is a structured argument.

Crucially, scoring should remain interpretable. A simple weighted model that says novelty, sensitivity of asset, external reputation, frequency anomaly, and technique adjacency all contributed to a 74/100 risk score is far more valuable than an opaque ML output with a green shield icon. If a scoring feature cannot be defended in plain language, it does not belong in the primary decision loop. This is not anti-ML. It is anti-unaccountable machinery. The system may experiment with learned ranking later, but the default operational logic should remain legible.

### 5.6 Explanations as a separate layer

Generated explanations&#8212;whether written by templates, rules, or an LLM&#8212;must never overwrite or masquerade as evidence. They are a convenience layer. Their job is to compress context, translate specialist terms, suggest likely interpretations, and link the operator to supporting detail. They should carry provenance labels like 'derived from 6 raw events, 2 normalized events, and 1 prior assessment' or 'generated by model X at time Y using prompt template Z.' This sounds obsessive until one has seen a bad summary become the system of record simply because it was easier to read than the underlying logs.

The separation between evidence and explanation is also what makes bounded LLM use viable. A model can be helpful precisely because it is not deciding what the facts are. It can explain Suricata signatures, narrate a timeline, or contrast two hypotheses, but it should cite the structured record it is interpreting. The moment the model becomes the only place where insight exists, the system has traded comprehension for dependence.

### 5.7 Lifecycle states

**1.** Observed: raw event captured and integrity metadata assigned.

**2.** Normalized: source-native data mapped into the common event representation.

**3.** Resolved: event linked to one or more entities with stated confidence.

**4.** Assessed: rule, threshold, or analyst action generated a significance claim.

**5.** Explained: human-readable rationale or model-assisted summary attached.

**6.** Reviewed: analyst disposition added, possibly with note, suppression, or escalation.

**7.** Archived: state retained according to policy, with raw evidence and exports if needed.

These states are deliberately sequential but not irreversible. Any stage may be revisited if new context arrives. A domain once assessed as benign may become suspicious later. A device previously resolved with medium confidence may be split into two entities after new evidence. A good data model therefore allows revision without rewriting history. Append, annotate, supersede&#8212;do not silently mutate away the past.

> **Analytical discipline:** The system must always be able to answer three questions: What did we actually observe? What do we think it means? Why do we think that? If any layer cannot answer those, it is not mature enough for trust.

**VOLUME II &#8212; ARCHITECTURE, TELEMETRY, AND ANALYTICAL STRUCTURE**

**Chapter 6**

## Telemetry Strategy: What to Collect, What to Refuse, and How Not to Drown

> *Telemetry is not a virtue in itself. This chapter defines the collection strategy for version one, the rationale for metadata-first monitoring, and the retention boundaries that keep the system useful instead of voyeuristic and bloated.*

### 6.1 Telemetry as a budget, not a buffet

Every telemetry source imposes at least five costs: collection overhead, storage cost, parsing complexity, operator attention, and legal or privacy exposure. The correct question is therefore not 'can we collect it?' but 'what specific investigative question becomes answerable if we do?' This is precisely why CISA&#8217;s logging guidance emphasizes usefulness and detection outcomes rather than blind maximalism (Ref: R4). If a source cannot be tied to a question, a playbook, or a measurable hypothesis, it does not earn default collection status.

Operation Impreavanti begins from a metadata-first doctrine. Metadata often provides the best return on attention: who talked to what, when, how often, over which protocol, from which device, with what certificate, using which process or package context. This is enough to detect novelty, beaconing, suspicious destinations, asset drift, odd time-of-day patterns, protocol mismatches, and many forms of misconfiguration. Payload content may help in specific cases, but it is a poor default because it expands storage, privacy exposure, and review burden far faster than it expands understanding.

### 6.2 Version-one collection set

| **Source** | **Version-one status** | **Why included** | **What question it answers first** |
| --- | --- | --- | --- |
| Suricata Eve alerts and metadata | Include | Protocol-aware detection and signatures | Did we see known-bad or suspicious network behavior? |
| Zeek DNS / conn / ssl / x509 / http / weird logs | Include | Behavioral context and protocol evidence | What did the network actually do? |
| DHCP leases and router topology state | Include | Asset presence and change tracking | Which device had which address and when? |
| Local DNS resolver logs (if centralized) | Include if feasible | Name-resolution baseline and policy | What names are devices asking for? |
| osquery or Fleet inventory snapshots | Include | Endpoint context | What software, packages, users, and configs exist? |
| Service health and application logs for the stack itself | Include | Self-observability | Is the monitoring system healthy and trustworthy? |
| Full packet capture | Defer / targeted only | High value for specific cases but costly by default | What content or protocol nuance do we need right now? |
| Keystroke, screen, or content surveillance | Refuse | Misaligned with scope, legality, and trust | None that justify the cost in this environment |

### 6.3 Metadata-first and when content is justified

Metadata-first does not mean payload-blind fundamentalism. It means the system assumes that most questions can be answered or at least prioritized by metadata, and that payload capture should be triggered when the marginal investigative value is clear. Good examples include short rolling ring buffers for incident windows, temporary packet capture around a host with unusual TLS failures, reproducing an application bug, or validating a suspected protocol misuse. Bad examples include retaining all household traffic forever because 'later analysis might be neat.' Neat is not a retention policy.

The practical discipline here is to treat content as a gated mode. The operator should be able to enable a short-duration or target-limited capture, label why it was activated, and expire it automatically. This preserves analytical power without normalizing indiscriminate surveillance. The approach also makes the legal analysis cleaner because the default state of the system is one of restraint rather than ambient interception.

### 6.4 Source quality, not just source quantity

A small number of high-quality sources beats a large number of unreliable ones. High quality means: stable timestamps, clear semantics, useful identifiers, manageable cardinality, reliable delivery, parseable structure, and actual investigative leverage. Source quality also includes calibration. A low-fidelity threat feed or noisy signature set can damage the whole program by wasting analyst time and eroding trust. Likewise, a richly detailed but constantly broken parser becomes a maintenance sinkhole.

This chapter therefore recommends a 'gold before copper' sequence. Stabilize and understand the gold sources first: network metadata, endpoint inventory, authentication logs if available, and the stack&#8217;s own health. Only then extend into copper sources like niche application logs, browser telemetry, or experimental host events. Mature systems expand outward from a reliable core. Immature systems expand inward from chaos.

### 6.5 Retention tiers

Retention must follow utility and sensitivity, not sentiment. Hot retention serves active investigations and dashboards. Warm retention serves trend comparison and medium-horizon review. Cold retention serves audit or case reconstruction. Not every source belongs in every tier. For example, normalized alert metadata may justify longer retention than raw packet fragments. Entity state may justify very long retention if compact and annotated. Sensitive exported evidence may justify shorter retention but stronger protection. The policy must be written down because unbounded retention is how small labs quietly become accidental archives.

**&#8226;** Hot: 7&#8211;30 days for high-volume logs used in dashboards and active triage.

**&#8226;** Warm: 30&#8211;180 days for normalized events, entity history, and selected alert context.

**&#8226;** Cold: snapshot or compressed exports for cases, quarterly reviews, and designated forensic bundles.

**&#8226;** Ephemeral: ring-buffer packet capture or debug traces with strict expiry.

**&#8226;** Never by default: indiscriminate long-term payload retention for all household traffic.

### 6.6 Data minimization and privacy engineering

The FTC&#8217;s business guidance repeatedly emphasizes data minimization, security proportionality, and safe disposal because retaining unnecessary data increases both compliance and breach risk (Ref: R30). Those principles apply cleanly here. If the system can answer the operational question without persisting a sensitive field, do not persist it. If a field is only needed temporarily for correlation, derive the necessary feature and purge the raw value when the window closes. If a destination query to a third-party reputation service would leak sensitive internal context, cache or proxy the lookup instead.

A privacy-aware fusion center is not less useful. It is more disciplined. It knows what it needs, what it does not, and why each retained artifact exists. That discipline also improves operator focus. The more junk one collects, the more one must justify, protect, and eventually clean up.

### 6.7 Telemetry acceptance criteria

**1.** The source answers a defined investigative or operational question.

**2.** The source can be parsed and stored without destabilizing the system.

**3.** The source has clear retention and access rules.

**4.** The source adds incremental value beyond what existing sources already provide.

**5.** The source can be tied to entities or timelines in a way a human will actually use.

**6.** The legal and privacy implications are documented before collection begins.

> **Collection doctrine:** Collect enough to explain. Refuse enough to remain lawful, sane, and maintainable. 'More' is not a strategy.

**VOLUME II &#8212; ARCHITECTURE, TELEMETRY, AND ANALYTICAL STRUCTURE**

**Chapter 7**

## Network Sensors: Suricata, Zeek, Arkime, and the Discipline of Passive Observation

> *This chapter defines the network sensor stack, explains why passive observation is the default, and shows how signature detections, protocol metadata, and selective packet retention complement rather than duplicate one another.*

### 7.1 Why Suricata and Zeek belong together
Suricata and Zeek are not rivals in this architecture. They are different species of sensor. Suricata excels at fast signature and protocol-aware detection with structured Eve output, making it valuable for known-bad patterns, suspicious behaviors, and high-level flow metadata (Ref: R12). Zeek excels at rich protocol logging and behavioral visibility, making it valuable for context, baseline analysis, and reconstruction of what a device did over time (Refs: R13, R14). One says, 'this pattern matches something interesting.' The other says, 'here is the structured story of the connection.' Together they provide far more operational leverage than either alone.

A common mistake is to deploy one tool and demand that it become the other. When Suricata is expected to provide full behavioral investigation, users complain about limited context. When Zeek is expected to act like a signature-heavy IPS, users complain that it is not screaming loudly enough. The answer is not to complain at the tools for being themselves. The answer is to compose them with intent and preserve their respective evidence shapes.

### 7.2 Suricata role and configuration posture

Suricata should be deployed in detection-first, metadata-rich mode, not as a default inline blocker. Its output should include alerts, flow metadata, TLS and DNS details where supported, file and protocol metadata only where operationally justified, and a rule policy tuned for the environment. Because Suricata is actively maintained, including recent stable releases and security fixes in the 8.x line, it remains a strong foundation for the network-detection portion of the stack (Ref: R12). The operative word is foundation, not dictator. Suricata alerts are inputs to analysis, not final truth.

Rule management matters more than it is fashionable to admit. Good rule hygiene means selecting sensible rulesets, pruning noisy families, tracking updates, documenting local disables, and distinguishing 'interesting to watch' from 'high-confidence bad.' The fusion center should treat Suricata signatures as one evidence stream among several. A signature that repeatedly fires on benign streaming or VR traffic deserves tuning, not worship. Overly noisy rulesets do not make a deployment serious. They make it unusable.

### 7.3 Zeek role and configuration posture

Zeek should be used to generate durable protocol context: connection logs, DNS activity, TLS certificate metadata, HTTP metadata where present, x509 details, and 'weird' logs that capture protocol anomalies. Zeek&#8217;s strength lies in giving the analyst structured artifacts that remain useful long after the packet stream has passed. It also benefits from a mature package ecosystem, allowing the build to extend cautiously when a need is justified (Refs: R13, R14). The recommended posture is conservative enablement: start with core logs, validate value, and expand deliberately.

The Zeek temptation is the inverse of the Suricata temptation. Because Zeek can produce rich logs, operators are tempted to enable everything. Resist that urge. Zeek should be configured to produce logs the human and the storage budget will actually use. DNS, connections, TLS, x509, notices, and weird logs usually earn their place. Every additional log family should be justified by either a case-study need, a detection hypothesis, or a recurring investigative pain point.

### 7.4 Arkime and packet retention as escalation tooling

Arkime, formerly Moloch, is worth discussing precisely because it embodies a tempting path: retain packet data in a way that makes later search and retrieval far easier (Ref: R22). That capability is real and can be extremely valuable in incident reconstruction. It is also dangerous as a default assumption in a privacy-sensitive local build. The right stance for version one is not 'never Arkime.' It is 'Arkime later if the environment, storage budget, and retention policy justify packet-centric workflows.' That is a subtle but important difference.

If Arkime enters the design later, it should do so with ring-buffer or scoped retention logic, clear access control, and documented escalation criteria. In other words, packet-centric workflows must be policy-backed exceptions or controlled modes, not ambient behavior. This is one of the places where security engineering must protect the operator from their own future curiosity.

| **Tool** | **Best at** | **Weakness if used alone** | **Version-one role** |
| --- | --- | --- | --- |
| Suricata | Detection signatures, protocol-aware alerts, fast network metadata | Can lack rich investigative context | Primary network IDS and alert stream |
| Zeek | Behavioral protocol context, timelines, rich structured metadata | Not a signature-centric screamer by default | Primary network evidence and baseline stream |
| Arkime | Packet indexing and retrieval | Storage-heavy and privacy-sensitive if defaulted | Deferred / optional escalation layer |
| tcpdump / short PCAP | Ad hoc targeted capture | Manual and easy to mishandle if overused | Controlled debug and incident tool |
| Managed switch mirror/SPAN | Passive duplication of traffic | Hardware dependency | Preferred acquisition method when available |

### 7.5 Passive observation methods

The cleanest network visibility in this architecture comes from passive duplication, typically via a mirror or SPAN port on a managed switch. That lets the Pi observe traffic without participating in forwarding. If the environment lacks a mirror-capable switch, the design may begin with narrower visibility: router logs, DNS logs, endpoint telemetry, or selective captures from key hosts. Imperfect but honest visibility is better than heroic inline hacks that destabilize the network. The system can mature as the physical network matures.

Passive observation also improves legal posture and failure characteristics. It makes clear that the sensor is an observer, not a required transit point. That matters both technically and conceptually. When the observer fails, the observed network should continue existing. One should not have to choose between detection and availability on a home or research network unless one enjoys manufacturing self-inflicted outages for character development.

### 7.6 Known anti-patterns

**&#8226;** Running Suricata inline on underpowered hardware and then wondering why gaming, updates, or VR traffic become miserable.

**&#8226;** Deploying Zeek everywhere with every package enabled before a single baseline question has been answered.

**&#8226;** Keeping every packet forever because disk prices feel lower than the price of future regret.

**&#8226;** Treating every Suricata signature as malicious rather than as a claim requiring context.

**&#8226;** Failing to document mirror-port topology and then blaming the sensors for blind spots caused by network design.

### 7.7 Minimal viable sensor plan

**1.** Deploy Suricata in passive mode and validate Eve output path.

**2.** Deploy Zeek with core logs only: conn, dns, ssl, x509, weird, notice as appropriate.

**3.** Mirror only the traffic segment that yields the most analytical value at first.

**4.** Tag all sensor outputs with source IDs and timestamps aligned to a reliable time base.

**5.** Build dashboards around device-domain relationships and alert-to-context drilldowns before adding more sensors.

**6.** Introduce packet capture only after retention, access, and justification rules exist.

> **Sensor philosophy:** Use Suricata to detect, Zeek to explain, and packet capture only when the question is specific enough to deserve that much intimacy.

**VOLUME II &#8212; ARCHITECTURE, TELEMETRY, AND ANALYTICAL STRUCTURE**

**Chapter 8**

## Endpoint, Asset, and Identity Context: The Missing Half of Most Cheap SIEM Dreams

> *Network telemetry without endpoint and asset context produces elegant confusion. This chapter explains how osquery, Fleet, Velociraptor, and simple inventory logic enrich the network picture without turning the project into an agent-sprawl circus.*

### 8.1 Why network data alone is not enough

A domain lookup is more meaningful when one knows which device initiated it, what packages are installed on that device, which user last logged in, what browser extensions are present, whether the host is supposed to be doing development or media streaming, and whether its baseline has recently changed. Network telemetry provides motion. Endpoint and asset context provide biography. Without that biography, the operator is left trying to interpret IPs and hostnames as though they were complete descriptions of system behavior. They are not.

The trouble is that endpoint data is where many otherwise elegant monitoring projects lose their composure. Agents multiply, permissions expand, update cadences diverge, operating systems disagree, and the difference between 'useful context' and 'intrusive host instrumentation' becomes blurry. Operation Impreavanti therefore approaches endpoint enrichment with the same discipline used for network collection: start with the smallest high-value context set that answers real questions, and prefer structured inventories over performative omniscience.

### 8.2 osquery and Fleet as the inventory spine

osquery remains one of the cleanest ways to expose host state as queryable tables across Linux, macOS, and Windows, which makes it particularly attractive for a cross-OS design (Ref: R21). Fleet adds management, scheduling, and a practical control plane for those queries. In this project, osquery or Fleet-backed osquery is not treated as a universal EDR replacement. It is treated as the inventory and state spine: users, processes, launch items or services, packages, browser extensions, kernel modules where relevant, USB history if justified, scheduled tasks, and configuration facts that help network events become intelligible.

This distinction matters. When teams adopt osquery with an EDR fantasy, disappointment follows. When they adopt it as a flexible, cross-platform, SQL-shaped host observation layer, it becomes a delightfully sharp tool. The fusion center can ask: which device has a browser extension matching a suspicious pattern? Which macOS host recently changed launch agents? Which Windows box has a new scheduled task? Which Linux system suddenly installed a compiler or tunneling tool? These are context questions, and osquery is built for them.

### 8.3 Velociraptor and the high-power but high-careful tier

Velociraptor deserves respect because it offers an extremely capable endpoint-collection and DFIR platform with rich artifact logic and cross-platform reach (Ref: R24). It is the sort of tool that can make a small lab feel surprisingly formidable. It is also the sort of tool that can exceed the project&#8217;s initial needs if deployed indiscriminately. For version one, Velociraptor is best treated as an escalation or investigative tier: available for targeted collection, hunts, or deeper host interrogation after the lighter inventory spine has already indicated something interesting.

The principle is not anti-power; it is anti-default excess. Fleet/osquery answers the recurring baseline questions cheaply. Velociraptor answers the deeper forensic questions when the operator truly needs them. This layering keeps agent sprawl controlled and makes it easier to explain to future maintainers why each host-level tool exists.

### 8.4 Asset inventory and the reality of drifting names

An asset inventory need not begin as a CMDB cathedral. It can start as a disciplined local source of truth containing device IDs, human names, roles, owners, operating systems, expected network segments, sensitivity labels, and whether the device is allowed or expected to produce certain traffic patterns. What matters is not the grandeur of the inventory but its usefulness and update discipline. The inventory is the key that turns a raw IP into 'Scar 18 used for gaming and development' or 'household phone belonging to a low-privilege user.' That translation dramatically improves triage.

Because names drift, the inventory must treat device identity as plural: observed MACs, hostnames, expected IP ranges, osquery host UUIDs, certificates where useful, and manual aliases. The system should prefer stable internal IDs and allow observed identifiers to attach over time. This is especially important in networks containing Wi-Fi devices, Apple hardware with privacy behaviors, or systems that jump between wired and wireless connections.

| **Context source** | **Primary value** | **Cost/complexity** | **Version-one recommendation** |
| --- | --- | --- | --- |
| osquery | Cross-platform host state via queryable tables | Low to moderate | Strong yes |
| Fleet | Management plane for osquery and posture queries | Moderate | Yes if more than a few hosts |
| Velociraptor | Deep DFIR and targeted host collection | Moderate to high | Optional escalation tier |
| Manual asset registry | Human-readable role and ownership context | Low | Mandatory even if simple |
| IdP / auth logs | User and identity context | Depends on environment | Include when feasible without overbuilding |

### 8.5 Identity context without enterprise cosplay

In a small local environment, identity context may be messier than in an enterprise but it is still worth modeling. At minimum, the system should know which local or cloud identities plausibly map to which devices and services, where admin privilege exists, and which accounts can touch the stack itself. Authentication and authorization matter not because the home lab is a miniature corporation, but because many incidents and misconfigurations are identity-shaped. Break-glass VPN access, UI roles, API keys, service accounts, and admin logins deserve explicit modeling.

The system should resist the urge to build a fake enterprise IAM program with no actual backing process. Identity context here means enough structure to answer meaningful questions: who can log into the stack, which host is associated with which human, which secrets exist, and where privileged actions can occur. That is enough to make investigations smarter without turning the project into a governance musical.

### 8.6 Minimal viable endpoint enrichment plan

**1.** Establish a local asset registry with stable internal IDs and human labels.

**2.** Deploy osquery to key Linux, macOS, and Windows hosts for inventory and low-friction state queries.

**3.** Use Fleet if the number of hosts or query schedules justifies centralized management.

**4.** Reserve Velociraptor for deeper host investigations, hunts, or case-study exercises.

**5.** Map identities, service accounts, API keys, and admin paths relevant to the stack itself.

**6.** Continuously reconcile network observations with asset and host inventory to improve entity resolution.

> **Endpoint doctrine:** The goal is not to transform every host into a forensic science experiment. The goal is to give the network story enough endpoint and identity context that the story becomes specific, falsifiable, and operationally useful.

**VOLUME II &#8212; ARCHITECTURE, TELEMETRY, AND ANALYTICAL STRUCTURE**

**Chapter 9**

## Storage, Retention, and Query Design: Hot Logs, Curated State, and Cold History

> *Logs, entities, archives, and exports do not belong in the same bucket. This chapter designs a storage model that stays explainable, queryable, and resilient without pretending that one engine should do every job.*

### 9.1 Why one database is not the answer

The temptation to solve the whole stack with a single database usually comes from aesthetic desire rather than operational fit. Logs want append-heavy ingest, compression, labels, and windowed query patterns. Entity state wants indexed joins, annotation fields, change history, and transactional consistency. Cold archives want cheap durable storage and batch-oriented access. Exports want packaging and immutability. Forcing all of these into one engine is a ritual of suffering disguised as simplification.

Loki is attractive for hot logs precisely because it does not try to be a general-purpose OLTP database; it is built for log storage and retrieval patterns common to observability and event streams (Ref: R15). A smaller relational store&#8212;PostgreSQL or even SQLite in some constrained cases&#8212;better serves entity state, annotations, and operational metadata. Cold archives can sit on structured files, compressed bundles, or later Parquet-like stores. This multi-store design is not overengineering. It is respect for workload shape.

### 9.2 Hot, warm, cold, and exported evidence

The storage architecture should have at least four conceptual classes. Hot logs serve dashboards and recent investigations. Warm curated state stores entities, relationships, enrichments, scores, and analyst notes. Cold history preserves compressed event slices, configuration snapshots, and artifacts needed for later study. Exported evidence packages selected data for reports, case folders, or external review. These classes may share hardware initially, but they should remain distinct in policy and directory structure. Confusion about storage class is how accidental evidence sprawl starts.

| **Class** | **Typical contents** | **Retention window** | **Primary store** |
| --- | --- | --- | --- |
| Hot logs | Suricata Eve, Zeek logs, service logs, health metrics | 7&#8211;30 days | Loki |
| Warm curated state | Entities, relationships, scores, notes, suppressions | 30&#8211;365 days or more | PostgreSQL / SQLite |
| Cold history | Compressed bundles, selected raw logs, snapshots, model artifacts | Quarterly to annual as justified | External SSD or structured archive |
| Exports | Case folders, PDFs, CSVs, JSON bundles, redacted evidence | Per case / policy | Controlled export directory with audit log |

### 9.3 Filesystems and cross-OS portability

The project should be built on Linux-native filesystems for live operation. ext4 remains the sensible default for the Pi, the Nano, and any always-on Linux data volume because it is well-understood, journaled, performant enough for this class of workload, and administratively boring in the good way. exFAT earns a role not as the live database substrate but as an exchange format for removable media or cross-OS transfer when that convenience is genuinely needed. FAT32 should be treated as obsolete for this role because of its file-size limits and general unsuitability for modern archives. NTFS can be tolerated for interoperability in mixed environments, but it should not be the first choice for Linux-native operational state.

The user explicitly requested cross-OS usability if possible, and the correct response is nuance rather than magical thinking. A single filesystem choice should not be forced to solve both operational integrity and maximum portability. Use ext4 for live systems. If the external 2 TB SSD must shuttle exports or selected artifacts among Linux, macOS, and Windows machines, carve an exchange partition in exFAT. Keep live databases and hot state on the Linux-native side. This split is simpler, safer, and less cursed than trying to run the entire project off a compromise filesystem just because three operating systems are invited to the party.

### 9.4 Query design and the operator's reality

Query design is where good storage decisions become visible. The operator will ask questions such as: which devices contacted new domains in the last 24 hours; what changed on the Scar 18 this week; which alerts reference the same domain or certificate; what hosts show similar TLS anomalies; which package or extension changes preceded a suspicious outbound pattern. Some of these are log queries, some are relational joins, and some are hybrid flows requiring both. The system should not force the operator to know where every fact lives before beginning the question. The UI and API layer must bridge that gap responsibly.

That bridging is one of the reasons a curated state layer matters. The Pi should materialize the common cross-source relationships so that routine investigative queries do not require expensive ad hoc stitching at UI time. The dashboard can then behave more like a coherent analyst surface and less like a cockpit of unrelated search bars.

### 9.5 Backups, snapshots, and rebuildability

A fusion center that cannot be rebuilt is a future incident wearing nice charts. Configuration, rules, dashboards, schemas, playbooks, and enrichment logic should all be backed up as code or exportable artifacts. Databases should have backup routines sized to the environment. External SSD snapshots should be disciplined rather than haphazard. The system should be reconstructable from a repository, a small secrets set, and a documented restore procedure. If it takes a s&#233;ance to rebuild the stack, the project has failed its recoverability test.

**&#8226;** Back up configuration and dashboards as text whenever possible.

**&#8226;** Snapshot warm state and critical archives to the external SSD on a schedule.

**&#8226;** Test restores, not just backups; unrehearsed backups are emotional support backups.

**&#8226;** Avoid making the external SSD the only copy of active data.

**&#8226;** Record data-retention and deletion procedures so old archives do not become archaeological hazards.

### 9.6 Storage anti-patterns

**&#8226;** Using a single search engine for logs, entity state, notes, and archives because 'search everywhere' sounds nice.

**&#8226;** Keeping raw evidence without preserving the transforms that generated assessments.

**&#8226;** Letting hot log retention grow until queries become expensive and dashboards become sluggish.

**&#8226;** Building exports manually with no manifest, no redaction process, and no audit trail.

**&#8226;** Treating removable media as a magical answer to backup strategy rather than one component of it.

> **Storage posture:** Design around query shape and evidence lifecycle. Logs are not cases, cases are not entities, and removable storage is not governance.

**VOLUME II &#8212; ARCHITECTURE, TELEMETRY, AND ANALYTICAL STRUCTURE**

**Chapter 10**

## The Fusion Center Interface: Operator Flow, Explanation Layers, and Why Human Factors Beat Dashboard Confetti

> *The GUI is not decoration. It is the part of the system that determines whether evidence becomes action or just another gallery of panels. This chapter defines an interface that is entity-first, explanation-rich, and hostile to unlabeled certainty.*

### 10.1 UI as analytical instrument

A security interface is an instrument panel, not a mural. Its job is to compress complexity without lying, to highlight what deserves attention without flattening nuance, and to preserve drilldown paths from summary to source evidence. Most poor security dashboards fail because they optimize for spectacle rather than cognition. They cram unrelated metrics into the same screen, mistake movement for insight, and assume the analyst will happily cross-reference ten panels while tired. The result is not observability. It is screen furniture.

Operation Impreavanti therefore treats the GUI as a first-class subsystem. The Nano hosts the interface because rendering, navigation, websockets, and interaction patterns deserve room to evolve independently of collection logic. The UI should feel like a research console rather than a status-wall template. That means layers, not clutter; explanations, not just scores; and evidence links everywhere an assertion appears.

### 10.2 Entity-first navigation
The primary navigational object should usually be an entity: a device, domain, IP, user, service, certificate, or incident. Alerts attach to entities rather than replacing them. Timelines attach to entities. Explanations attach to entities. This design is not just cleaner; it reflects how investigations actually unfold. Analysts ask, 'what is going on with this host?' or 'why does this domain keep showing up across devices?' They do not experience the world as a pile of isolated severities.

An entity page should therefore include identity metadata, current risk posture, recent observations, related alerts, historical baselines, enrichment results, raw-evidence links, and the machine-generated explanation panel. It should also show what changed. Static summaries are less useful than differential summaries. Operators care deeply about the delta between now and normal.

### 10.3 Explanation layering

Every important panel should separate three things visually: observed facts, analytical assessment, and generated explanation. Facts might include 'Device Scar18 queried domain X eight times in 30 minutes,' 'Suricata rule Y fired twice,' and 'Domain X was first seen on this network today.' Assessment might include 'novel external domain + medium anomaly score + medium-risk reputation.' Explanation might then say, 'This pattern is notable because it combines novelty with increased request frequency from a high-value device; likely causes include software update endpoints, telemetry, or suspicious beaconing; verify via DNS history and process context.'

That separation protects the user from the oldest dashboard trick in the book: hiding uncertainty behind typography. A clean interface can make nonsense look authoritative. The system must therefore surface confidence, provenance, and missing information explicitly. If a model summary exists, it should say it is a summary. If a score is heuristic, it should say so. If a panel lacks enough evidence, it should admit that rather than pretending a sparse graph is a conclusion.

### 10.4 Core screens

| **Screen** | **Purpose** | **Must show** | **Must avoid** |
| --- | --- | --- | --- |
| Overview | System-wide situational awareness | Top entities, new domains, sensor health, active cases, notable deltas | Meaningless vanity charts |
| Entity inspector | Deep dive into a device/domain/user | Identity, timeline, relationships, scores, evidence links, explanation | Alert spam with no context |
| Timeline | Chronological reconstruction | Ordered events with filters and entity pivots | Unsortable noise piles |
| Relationship graph | Cross-entity navigation | Devices, domains, IPs, services, and link metadata | Decorative webs with no drilldown |
| Case workspace | Analyst note-taking and review | Selected evidence, narrative, dispositions, exports | Unversioned ad hoc text blobs |
| Health/ops | Stack reliability | Queue lag, ingest status, disk use, sensor freshness | Security claims derived from missing data |

### 10.5 Interaction design for understanding

Hover cards, inline definitions, glossary links, provenance toggles, and drilldowns matter more than they first appear. The user asked for a system where highlighting an element defines what it is, where it came from, why it matters, and what risk level it carries. That is exactly right. Security interfaces routinely assume a level of context memory that real humans do not maintain under pressure. A good fusion center teaches as it operates. If a graph node represents a certificate, a hover should define certificate relevance, show first and last seen, and expose why it is currently interesting. If a score is high, the score card should show its components rather than asking the user to accept it on faith.

This human-factor layer is not cosmetic. It is how the system expands operator capability rather than just operator workload. When definitions, rationale, and source links live beside the data, the interface becomes a live handbook as well as a console. That design also improves onboarding and maintenance because the system explains itself as it is used.

### 10.6 Flashing lights, but with self-respect

The user requested live graphs, interactive dashboards, and even some flashing-light fusion-center energy. That can be done without becoming tacky. Motion should mean state change, not mere existence. Animation should indicate new evidence, changing severity, queue lag, or active analyst attention. Color should be restrained and semantically stable. Red should mean something expensive. Yellow should mean watch. Blue and neutral tones can carry context, baselines, and health. The interface should feel like a serious instrument that happens to be satisfying, not a casino machine for suspicious DNS.

**&#8226;** Use animation sparingly and only for change, alert arrival, or health degradation.

**&#8226;** Prefer semantic color palettes with consistent meanings across screens.

**&#8226;** Make drilldowns one click from every summary panel.

**&#8226;** Support keyboard navigation and low-friction filtering; analysts should not have to mouse-dance through ten menus.

**&#8226;** Let the interface explain itself with definitions and evidence sources inline.

### 10.7 Grafana versus custom UI

Grafana is excellent as an instrumentation and dashboard layer, especially when paired with Loki, but it should not become the whole product. It is very good at panels, filters, and shared dashboards. It is less ideal as the sole interface for entity-centric investigation, nuanced analyst workflows, or provenance-rich explanations. The correct relationship is complementary. Grafana powers mature dashboard and log views. The custom Nano-hosted UI becomes the operator surface that integrates entities, cases, notes, explanations, and guidance. This keeps us from trying to force a general dashboard tool to become a bespoke investigative workbench.

> **UI doctrine:** A great fusion-center interface does not try to impress the wall. It tries to reduce time-to-understanding for the operator. Everything else is garnish.

**VOLUME III &#8212; IMPLEMENTATION PLAN, BUILD ORDER, AND SERVICE COMPOSITION**

**Chapter 11**

## Setup Plan Part I: Base Linux, Host Roles, Hardening, and Orchestration

> *Before the clever parts arrive, the foundations must stop being sloppy. This chapter defines the operating-system choices, host preparation sequence, network assumptions, and service-orchestration posture for the full build.*

### 11.1 Distribution choices and what 'Linux-first' means here

The build is Linux-first for the always-on nodes because Linux provides the most natural environment for the chosen collectors, agents, container tooling, storage practices, and automation posture. Raspberry Pi OS or another Debian-family ARM distribution is the pragmatic choice for the Pi. The Jetson Nano likewise benefits from a Linux distribution aligned with its hardware support. Linux-first does not mean Linux-only. The system&#8217;s artifacts, dashboards, exports, endpoint visibility, and optional management surfaces must remain usable from macOS and Windows clients. It simply means the services that make the fusion center breathe should live where their open-source ecosystem is strongest.

This distinction matters for planning. One should not contort the core stack into a lowest-common-denominator operating system in the name of cross-platform symbolism. Cross-platform usability belongs at the boundaries&#8212;web UI, export formats, agents, queries, API contracts, and exchange partitions&#8212;not at the heart of the service plane. The heart should be boring, stable, well-documented Linux.

### 11.2 Host role matrix

| **Host** | **Role** | **Minimum build goal** | **Notes** |
| --- | --- | --- | --- |
| Raspberry Pi 4B | Brain / ingest / enrichment / state | Linux, Docker/Compose, Loki, collectors, API, DB | Prefer wired Ethernet and stable power |
| Jetson Nano | GUI / operator console | Linux, reverse proxy, frontend app, websockets | Keep UI separate from collection pipeline |
| Router | Forwarding and network services | Stable firmware, VPN break-glass, sane DNS/DHCP | Do not overload with SIEM logic |
| Optional workstation or Mac mini M4 | Build, batch analytics, heavier local inference | Dev tools, model runtime, large exports | Should not be mandatory for core telemetry |
| External 2 TB SSD | Cold storage, exchange, backup target | Partition plan, backup schedule, archive discipline | Do not make it the sole live store |

### 11.3 Base hardening sequence

**1.** Install the chosen Linux distribution with minimal packages.

**2.** Apply updates immediately and enable automatic security updates where appropriate.

**3.** Create named administrative accounts and disable casual default credentials.

**4.** Set hostname, time synchronization, and predictable networking.

**5.** Harden SSH with key-based access, restricted users, and audit logging.

**6.** Mount storage with intentional paths and permissions.

**7.** Install only the services needed for the node&#8217;s role.

**8.** Document every deviation from defaults in version-controlled configuration.

This sequence is deliberately dull because infrastructure dignity begins in the dull places. Time synchronization is not glamorous until your correlation windows are wrong. Predictable networking is not glamorous until the wrong certificate appears tied to the wrong host. Restricted SSH is not glamorous until a forgotten default credential becomes a story. Small systems are often sabotaged by the belief that small means informal. In fact, small is where formal discipline is cheapest to adopt and easiest to keep.

### 11.4 Containers, systemd, and the 'don't fetishize one tool' rule

Containers are useful in this project because they simplify packaging, dependency management, and repeatable deployment for services like Grafana, Loki, and custom APIs. Docker Compose remains a pragmatic choice for a two-node homelab-style build because it is familiar, well-supported, and operationally understandable. Podman is a valid alternative for operators who prefer rootless or daemonless patterns, but the critical design rule is not the brand of container runtime. It is that network-capture components that need privileged access should be treated carefully, and not everything must be containerized just because containers exist.

Some services belong happily in containers. Some low-level host integrations&#8212;particularly capture, certain kernel-facing agents, or edge drivers&#8212;may be saner as native systemd services. The point is to keep operational truth simple. Choose the packaging model that yields reliable startup, understandable logs, and clean upgrades. Avoid the ideological mistake of turning 'containers everywhere' into a religion. Religions are bad at debugging.

### 11.5 Network assumptions and dependencies

The base build assumes a stable LAN, the ability to run at least one wired node, and ideally access to a mirror-capable switch or another passive visibility method. It assumes the router continues to handle routing and Wi-Fi, and that VPN-based remote management exists as a break-glass path rather than as a permanent dependency. It assumes that the Pi and Nano can be given predictable addresses or hostnames and that the operator is willing to keep a small asset inventory. These are modest assumptions, and they should remain modest. The build should not require enterprise-grade fabric to justify its existence.

The architecture should also assume that intermittent failure will happen. Power glitches, service restarts, log backpressure, corrupted caches, bad rule updates, and weird consumer-router behavior are normal in the lifespan of a small system. The build process should therefore produce nodes that restart cleanly, recover from missing downstream services, and expose health checks that distinguish between missing data and hostile activity.

### 11.6 Secrets and configuration discipline

Secrets management in a small lab need not involve a full enterprise vault on day one, but it must still be intentional. API keys, VPN configs, service credentials, and signing secrets should never be hardcoded into repositories or sprayed across random home directories. Use environment files with strict permissions, encrypted notes where justified, and a defined backup-and-rotation practice. The stack should be reconstructable without secrets becoming folklore. Folklore is not an access-control model.

**&#8226;** Keep deployment configuration in version control, but keep secrets out of the repository.

**&#8226;** Separate environment-specific values from reusable service definitions.

**&#8226;** Name ports, networks, and services consistently across Compose files and UI code.

**&#8226;** Document how to rotate each secret and what breaks when it changes.

**&#8226;** Audit for accidental secret exposure in logs, exported configs, and screenshots.

### 11.7 Build-order logic

The order of operations matters more than ambitious minds prefer. First stabilize the network and remote recovery path. Then build the Pi base OS and storage layout. Then stand up the log and state layers. Then add sensors. Then add enrichment and scoring. Then add the UI. Then add model-assisted explanation. That order is not conservative for its own sake. It exists because each later layer depends on the earlier one being trustworthy. Building the pretty front-end before the evidence plumbing is stable is a guaranteed way to feel productive while manufacturing future disappointment.

> **Foundations doctrine:** The early build should optimize for rebuildability, deterministic startup, and clear host roles. Cleverness before foundations is just a slower route to weird outages.

**VOLUME III &#8212; IMPLEMENTATION PLAN, BUILD ORDER, AND SERVICE COMPOSITION**

**Chapter 12**

## Setup Plan Part II: Building the Raspberry Pi Brain

> *The Pi carries the serious operational burden of the project. This chapter defines the service stack, data flow, API boundaries, and implementation steps for the brain node that turns telemetry into structured security knowledge.*

### 12.1 Service map for the Pi

The Pi runs the back-end services that create security knowledge. At minimum this includes: a log collector or router for incoming records; Loki for hot log storage; a relational store for entities and assessments; a custom enrichment and scoring API, likely written in Python with FastAPI; scheduled jobs for baseline generation, suppression maintenance, and archival; and optional connectors for endpoint inventory. If Grafana is deployed on the Pi rather than the Nano for convenience in an early build, it should still be treated as infrastructural instrumentation rather than the main investigative surface.

The heart of the Pi build is not any one service. It is the pipeline discipline. Ingest should be idempotent where possible. Parsers should attach source IDs and normalization status. Entity resolvers should be testable. Scoring should be explainable. Archives should be scheduled rather than improvised. Health endpoints should make it obvious when a downstream dependency has stalled. A small node can carry all of this if the services are composed cleanly and not asked to render a cyberpunk wallboard at the same time.

### 12.2 Recommended implementation language

Python is the correct primary language for the Pi brain. It is not chosen because it is trendy. It is chosen because it is the best practical compromise for parsing, orchestration, HTTP APIs, data manipulation, glue logic, rule expression, rapid iteration, and the long tail of integration work this project requires. Python also has excellent libraries for structured data, scheduling, testing, and later model integration. The custom enrichment layer should therefore be Python-first unless and until a measured performance bottleneck says otherwise.

That recommendation comes with discipline. Python should be used intentionally, with typed interfaces where reasonable, explicit schema definitions, tests around transforms, and a bias toward boring dependency choices. The answer to Python&#8217;s flexibility is not to abandon it for a different language. The answer is to impose structure so the codebase does not turn into a notebook graveyard.

### 12.3 Proposed Pi-side service list

| **Service** | **Likely implementation** | **Role** | **Notes** |
| --- | --- | --- | --- |
| Log router / collector | Grafana Alloy or compatible collector | Receive and route logs/metrics | Prefer Alloy over deprecated Grafana Agent Flow (Refs: R16, R17) |
| Loki | Containerized service | Hot log storage | Keep retention explicit |
| Entity / assessment DB | PostgreSQL or SQLite | Structured state | PostgreSQL preferred if concurrency grows |
| Enrichment API | Python + FastAPI | Normalize, score, resolve entities, expose APIs | Core custom logic lives here |
| Scheduler | Python worker / cron / APScheduler | Baselines, rollups, archives | Keep jobs observable |
| Endpoint inventory connector | Python + osquery/Fleet integration | Fetch host state | Do not overbuild on day one |

### 12.4 Step-by-step Pi build

**1.** Prepare and harden the OS, storage, networking, and time sync.

**2.** Install container tooling and define a minimal Compose baseline.

**3.** Bring up Loki and a simple log-ingest path, then validate queryability.

**4.** Stand up the relational store and define the initial schema for entities, relationships, and assessments.

**5.** Implement the enrichment API with endpoints for ingest, entity lookup, timeline retrieval, and risk summaries.

**6.** Integrate Suricata and Zeek outputs, starting with a small set of normalized event classes.

**7.** Add scheduler jobs for novelty detection, baseline snapshots, and archive rotation.

**8.** Expose health endpoints and dashboards for the pipeline itself before adding more source types.

### 12.5 Schema-first implementation

The enrichment API should begin with explicit schemas&#8212;Pydantic models or a similar typed layer&#8212;for raw-source wrappers, normalized events, entities, relationships, assessments, and explanations. This is not bureaucracy. It is the cheapest insurance against downstream confusion. When schemas are explicit, transforms become testable and UI contracts remain stable. When schemas are implicit, every new feature becomes a guess about what an event 'probably' contains. Guesses are contagious and expensive.

The relational state model should be deliberately modest at first: tables for entities, aliases or observed identifiers, relationships, assessments, notes, source inventory, and suppression rules. More can be added later. Version one does not need a grand graph database if the same relationships can be represented clearly in tables and projected into graph views on demand. Graph databases are wonderful when truly needed and comically overused when they are not.

### 12.6 Baselines, novelty, and scheduled intelligence

A key job of the Pi is to compute what changed and what is normal. This means scheduled rollups: per-device domain baselines, new external IP counts, certificate reuse patterns, unusual time-of-day activity, package drift, failed-connection spikes, or service-health deviations. These scheduled views are where much of the system&#8217;s intelligence will originate. Raw events tell the story of the moment. Baselines tell the story of difference. Difference is where attention begins.

These rollups should be cheap enough to run regularly and explicit enough to be explained. A novelty function should not be a mystical black box. It should say, for example, that a domain is new for the environment, or new for a specific device, or unusually frequent relative to that device&#8217;s history. Transparent novelty is better than an inscrutable anomaly score that nobody will defend when it matters.

### 12.7 Testing and observability of the brain

The Pi&#8217;s software stack should test itself in layers. Unit tests validate parsers and scoring functions. Integration tests validate end-to-end ingest and API responses on sample data. Health dashboards validate queue freshness, ingestion lag, job success, disk usage, and schema or rule version. The stack should also include a small corpus of fixture events so that upgrades can be judged against known expectations rather than vibes. This is where research-grade discipline stops the project from becoming a succession of unreviewed 'little tweaks.'

**&#8226;** Every transform gets fixture tests with representative source data.

**&#8226;** Every scheduled job emits success/failure and freshness metrics.

**&#8226;** Every API endpoint used by the UI has contract tests.

**&#8226;** Every rule or scoring change should note rationale and expected effect.

**&#8226;** Every archive job should log what moved, what was deleted, and what was retained.

> **Pi doctrine:** The brain node is where rigor lives: schemas, transforms, baselines, scores, and APIs. If it becomes sloppy, the whole project becomes decorative fiction.

**VOLUME III &#8212; IMPLEMENTATION PLAN, BUILD ORDER, AND SERVICE COMPOSITION**

**Chapter 13**

## Setup Plan Part III: Building the Jetson Nano Interface and Operator Console

> *The Nano hosts the experience layer: the web interface, real-time views, investigator workflows, and the translation of structured security knowledge into something a human can use under pressure.*

### 13.1 Why the UI deserves its own machine

Separating the UI onto the Nano is not just a neat hardware trick. It protects the evidence pipeline from front-end experimentation and lets the interface evolve with fewer operational consequences. Front-end work is naturally iterative: components change, graph libraries misbehave, assets grow, caching strategies evolve, and live-update patterns are tuned over time. None of that should threaten the ingest or scoring path. The UI can crash, restart, or be replaced while the Pi keeps collecting and reasoning. That is healthy architecture.

The Nano also creates a psychologically important distinction between truth and presentation. The Pi owns state. The Nano renders state. The user should never have to wonder whether reloading the dashboard changed the evidence model. That separation is one of the cheapest ways to preserve trust.

### 13.2 Front-end language and framework recommendation

TypeScript is the right choice for the Nano&#8217;s custom interface. More precisely: TypeScript over JavaScript, with a modern component framework such as React, Svelte, or another front-end system the operator can maintain competently. TypeScript&#8217;s real advantage here is not fashion but contract discipline. The UI will consume structured APIs for entities, timelines, scores, graphs, and explanations. Static typing at the boundary reduces a whole class of quiet breakage and makes the interface code more self-documenting. The project needs fewer surprises, not more freedom to invent them.

The front-end stack should remain modest. There is no need to build a micro-frontend circus. A single application with routed views, a state store, websocket subscriptions for live updates, and a small design system is sufficient. The goal is explainable operator flow, not framework tourism.

### 13.3 Reverse proxy, auth, and deployment posture

The Nano should serve the interface behind a reverse proxy such as Nginx or Caddy, with TLS for local access where reasonable and a clean path for authentication if the system eventually adds multiple roles. The proxy can also mediate requests to Pi-hosted APIs, simplifying browser security policy and allowing one stable origin for the user. This keeps deployment tidy and makes it easier to add caching, compression, and static asset handling without modifying the analytical services themselves.
The interface should not be casually exposed to the internet. Remote access belongs behind the established VPN path or other deliberate access control. This is a fusion center, not a public website with an unusual hobby.

### 13.4 Interface modules

| **Module** | **Primary responsibility** | **Data source** | **Notes** |
| --- | --- | --- | --- |
| Overview dashboard | Summarize posture and changes | Pi APIs + Grafana panels | Blend live and historical context |
| Entity inspector | Deep-dive entity analysis | Pi API | Core investigative screen |
| Timeline view | Chronological reconstruction | Pi API | Must support filtering and export |
| Relationship graph | Topology and cross-entity linkage | Pi API | Use with restraint; clarity over visual chaos |
| Case workspace | Notes, dispositions, evidence curation | Pi API + local cache | Prepare for export and review |
| Glossary / explainer layer | Definitions and rationale | Static content + Pi metadata | Teach while operating |

### 13.5 Making the interface understandable

The user explicitly asked for a system where hovering or selecting an item reveals what it is, where it came from, why it matters, and what its risk level is. That requirement should drive component design. Every important object in the UI should have an inspector card with standard fields: object type, canonical ID, observed aliases, first seen, last seen, evidence sources, current score, confidence, and explanatory notes. Consistency matters. If every entity card behaves differently, the interface becomes a scavenger hunt.

Tooltips should not be afterthoughts. They should carry definitions, schema hints, and operational meaning. For example, a 'medium confidence' badge should explain what confidence measures in this system. A 'new-to-environment domain' label should explain how the baseline window was computed. The UI should teach the operator how the system thinks without forcing them to open a manual in another tab.

### 13.6 Live updates, caching, and performance

Live interfaces feel powerful when they remain legible and calm. Websockets or server-sent events can power new-alert badges, health changes, queue lag warnings, and timeline growth. Not every panel needs real-time repainting. Aggressive live updates across all screens usually create noise and needless client work. The right posture is selective liveness: the overview and incident-related panels update actively; historical views update on demand or on gentle intervals. Cache computed summaries where sensible. The user should feel like the system is awake, not twitching.

Because the Nano&#8217;s hardware is finite, performance discipline matters. Use code splitting, small bundles, server-side caching for heavy summaries, and lazy-loading for graph-heavy views. A smooth, predictable interface beats a maximal interface that stutters whenever a graph decides to feel artistic.

### 13.7 Build sequence for the UI

**1.** Stand up the reverse proxy and a simple health page.

**2.** Create a typed API client against the Pi endpoints.

**3.** Implement the overview and entity inspector first; these carry the most analytical value.

**4.** Add timeline and relationship views once the data contracts are stable.

**5.** Add glossary overlays, evidence provenance panels, and note-taking workflows.

**6.** Integrate optional embedded Grafana panels only where they genuinely help.

**7.** Add visual polish and limited animation after comprehension is already strong.

> **Nano doctrine:** The interface node should make the system comprehensible, not merely visible. Strong UI is part of detection engineering because poor comprehension is a detection failure in slow motion.

**VOLUME III &#8212; IMPLEMENTATION PLAN, BUILD ORDER, AND SERVICE COMPOSITION**

**Chapter 14**

## The LLM Subsystem: Copilot, Not Oracle

> *A local or hybrid language-model layer can make the fusion center vastly easier to use&#8212;if it stays in its lane. This chapter defines the role, safety boundaries, hardware realities, and model choices for early 2026.*

### 14.1 The right job for the model

The correct role for an LLM in Operation Impreavanti is not to decide what happened. It is to help humans understand what the system already knows, what it suspects, what changed, and what questions remain open. Concretely, the model should summarize timelines, explain detections in plain language, draft case notes, compare competing hypotheses, generate search pivots, and answer user questions over grounded local context. Those are valuable tasks because they compress cognition without seizing authority.

The wrong role is inline judgement. The model should not be asked to sit inside the ingest path and label every event, rewrite raw evidence into a single truth, or become the only place where meaning exists. That is a recipe for latency, cost, brittle prompts, and hallucinated certainty. The system&#8217;s core detector logic must remain source-grounded, reproducible, and testable without a model in the loop. The model is an analyst&#8217;s translator and research assistant, not the court of final appeal.

> **Model boundary:** Facts come from sensors and transforms. Scores come from explicit logic. The LLM adds explanation, comparison, and question-answering over grounded context.
### 14.2 Grounding and retrieval

The model must never be fed raw chaos and told to 'figure it out.' It should receive curated context packets drawn from the Pi&#8217;s structured stores: entity records, timeline slices, alert summaries, reputation lookups, baseline deltas, local asset notes, and relevant documentation. This is a retrieval-augmented workflow, not because RAG is fashionable, but because it constrains the model to the environment&#8217;s evidence. The output should cite the objects it used or at least expose clickable evidence references in the UI. That is how one keeps the model helpful rather than theatrical.

A practical pattern is two-stage interaction. Stage one: the Pi assembles a compact context object for the question or selected entity. Stage two: the model running locally or remotely produces an explanation, hypothesis comparison, or operator-facing summary. The output is then shown beside the facts, not in place of them. This pattern is also computationally sane because most of the heavy lifting remains data engineering, not token theater.

### 14.3 Local hardware reality

A Raspberry Pi 4B is not a serious local-LLM inference host for this project. A Jetson Nano is not, by itself, a satisfying frontier-model inference host either. Tiny quantized models can run, and they can even be useful for lightweight summaries or UI niceties, but neither device should be forced to impersonate a modern high-context reasoning engine. That does not make the project AI-poor. It means the architecture should separate the existence of a model layer from the fantasy that every model must run everywhere. If a stronger local host such as a Mac mini M4 is available, it becomes the obvious place for heavier local inference or batch reasoning experiments.

The external 2 TB SSD is useful here not because it magically creates compute, but because it gives a clean place to store model weights, vector indexes, embeddings, archived prompt contexts, and generated report artifacts. Storage helps the LLM subsystem. It does not replace memory bandwidth or arithmetic throughput. This distinction is worth stating because the AI market runs on people confusing the two.

### 14.4 Model-selection logic: best fit versus most advanced

As of early 2026, the frontier model landscape includes strong proprietary options such as GPT-5.4, Claude Sonnet 4.6, and Gemini 2.5 Pro, alongside increasingly capable open or open-weight families such as Gemma 3, Qwen2.5 and QwQ-32B, Qwen3-Coder, DeepSeek-R1 and its distilled variants, Mistral Large 3 and smaller Mistral open models, and Meta&#8217;s Llama family (Refs: R34&#8211;R41). The most advanced model overall is not automatically the best fit for this build. The correct model depends on latency tolerance, privacy boundary, context length needs, budget, hardware, licensing, coding versus reasoning emphasis, and whether the system requires offline operation.

For example, a frontier API model may be best for deep comparative analysis, long-form report drafting, or one-off strategic reasoning when external processing is acceptable. An open local model may be best for routine summaries where data sovereignty matters more than maximal brilliance. A coder-tuned open model may be best for generating interface scaffolding or schema migrations. A small local model may be best for UI-side glossary explanations or low-stakes paraphrases. 'Best' without context is marketing. We are building engineering.

| **Model family** | **Strengths relevant to this project** | **Weaknesses / cautions** | **Best-fit role** |
| --- | --- | --- | --- |
| GPT-5.4 / GPT-5 class | High-end reasoning, synthesis, strong coding assistance | API dependence, cost, external processing | Strategic analysis, report drafting, hard questions |
| Claude Sonnet 4.6 | Very long-context analysis and polished writing | External processing, vendor boundary | Large evidence reviews and nuanced summaries |
| Gemini 2.5 Pro | Large context, strong multimodal/document reasoning | External processing unless self-hosting options evolve | Comparative review of long dossiers and dashboards |
| Gemma 3 | Open-weight, efficient, strong multilingual and long-context for local work | Still bounded by local hardware limits | Private local summaries on stronger local hosts |
| DeepSeek-R1 distills | Strong reasoning flavor in distilled open variants | Resource demands vary; verify licensing and hosting comfort | Reasoned hypothesis comparison on local workstation |
| QwQ-32B / Qwen2.5 / Qwen3-Coder | Good open reasoning and coding options | Needs stronger hardware than Pi/Nano for satisfying use | Development copilot, code generation, deeper local reasoning |
| Mistral open/small models | Good latency and deployability options | May trade absolute depth for speed | Fast local assistant and UI explainer |
| Tiny 1B&#8211;4B quantized models | Run on modest hardware | Limited nuance and reliability | Glossary, paraphrase, low-risk explanation helpers only |

### 14.5 Recommended model architecture for version one

Version one should support three model modes. First, a no-model mode in which the stack remains fully useful through rules, explanations templates, and operator workflows. This is non-negotiable. Second, a small local-assistant mode suitable for glossary text, UI help, short summaries, and low-risk explanation assists. Third, an optional heavyweight mode that targets a stronger local host or trusted external API for deep analysis or report drafting. This tiered design ensures the project does not collapse into dependency panic if the preferred model is unavailable.

This chapter recommends that the Nano host only the UI-side client or thin model gateway, not the primary heavy inference engine. The Pi provides retrieval context. The stronger model, when used, runs either on a more capable local machine or through an explicitly approved external API boundary. In other words: the Nano can host the conversation interface; it should not be forced to be a frontier model barn.

### 14.6 Safety, provenance, and prompt discipline

**&#8226;** Never let a model mutate evidence records silently.

**&#8226;** Tag all model outputs with model identity, time, and grounded context scope.

**&#8226;** Prefer structured prompts over improvisational prose where repeatability matters.

**&#8226;** Keep separate prompts for explanation, hypothesis generation, note drafting, and code assistance.

**&#8226;** Expose supporting evidence links beside every model-generated analytical statement.

**&#8226;** Allow the operator to ask 'why did the model say that?' and answer with context objects, not vibes.

### 14.7 What the LLM should never do

**&#8226;** Act as the sole detector of maliciousness on raw event streams.

**&#8226;** Auto-dismiss or auto-escalate alerts without traceable rule-based logic.

**&#8226;** Invent asset context or identity mappings not present in the data.

**&#8226;** Send sensitive evidence to remote APIs by default.

**&#8226;** Replace the glossary, documentation, or schema references with inconsistent ad hoc definitions.

> **LLM doctrine:** Use the model where language is the problem: summarization, explanation, comparison, drafting, and question-answering. Do not use the model where evidence and reproducibility are the problem.

**VOLUME IV &#8212; TOOLING, LANGUAGES, AND SYSTEM DESIGN CHOICES**

**Chapter 15**

## Core Open Source Software Catalog: What Makes the Cut and Why

> *This chapter names the primary open-source components recommended for version one, explains their roles, and gives a candid discussion of strengths, costs, and fit.*

### 15.1 Selection criteria

Open-source components enter the core build only if they satisfy four tests. First, they must solve a real problem in the architecture rather than merely looking impressive in a screenshot. Second, they must be alive enough&#8212;technically and socially&#8212;to justify dependence. Third, they must fit the hardware and operational profile of the build. Fourth, they must compose cleanly with the rest of the stack. A tool can be excellent in isolation and still be wrong here. Selection is not a popularity contest; it is a fit test.

This chapter focuses on the core stack rather than every interesting project in the ecosystem. Those adjacent or deferred tools appear later. The core set should stay small enough that one operator can actually understand it. Complexity budgets are real. Spend them where leverage is highest.

### 15.2 Core-stack matrix

| **Project** | **Role in Impreavanti** | **Why it earns inclusion** | **Primary cautions** |
| --- | --- | --- | --- |
| Suricata | Network IDS and protocol-aware alert stream | Mature, fast, structured output, active maintenance | Rule hygiene and noise management are essential |
| Zeek | Rich network protocol context and evidence | Excellent metadata and behavioral visibility | Can become log-spam if enabled indiscriminately |
| Grafana Loki | Hot log storage and search | Strong fit for log workloads and dashboard integration | Needs retention discipline and proper auth/proxy posture |
| Grafana Alloy | Log/metric collection and routing | Modern successor path over deprecated Grafana Agent | Do not overcomplicate pipelines early |
| Grafana | Operational dashboards and supporting panels | Fast path to useful instrumentation views | Not the whole investigative product |
| osquery | Cross-platform endpoint state collection | Structured host context with queryable tables | Needs scheduled query discipline |
| Fleet | osquery management plane | Makes cross-host posture and query management far saner | Optional overhead for very tiny environments |
| FastAPI + Python | Custom enrichment and scoring layer | Rapid, typed, integration-friendly, maintainable | Requires code discipline and testing |
| PostgreSQL | Curated entity and assessment state | Reliable transactional store for structured data | Slightly heavier than SQLite but worth it if growth is expected |
| Nginx or Caddy | Reverse proxy and interface edge | Simple control over UI origin, TLS, and proxying | Should stay boring and well documented |

### 15.3 Why these tools complement each other

The chosen core tools solve distinct layers of the problem. Suricata and Zeek provide network evidence of different kinds. Alloy routes telemetry. Loki stores hot logs. PostgreSQL or another relational store preserves curated state. FastAPI implements the project&#8217;s actual intelligence glue. Grafana gives quick dashboards. The reverse proxy unifies the user-facing surface. osquery and Fleet enrich the host story. This is not a random shopping cart. It is a layered composition in which each tool has a clearly bounded reason to exist.

That complementarity is precisely why this build should outperform the common 'one giant open-source platform' impulse in clarity and resilience. The composable stack is easier to reason about because the responsibilities are distinct. When a problem occurs, the operator knows whether it is ingest, storage, enrichment, or presentation. Diagnosis is faster when the architecture has dignity.

### 15.4 Why not simply use a monolithic SIEM platform

Monolithic open-source SIEM or XDR platforms are attractive because they promise to reduce integration work. That promise is real. So are the trade-offs: more opinionated data models, heavier system requirements, steeper operational complexity, less flexible explanation design, and sometimes a tendency to make the operator live inside the platform&#8217;s worldview. For this project, a composable stack wins because the thesis is not just 'collect and alert.' The thesis is to create a local, explainable, entity-centric fusion center with custom logic as a first-class citizen. That is easier when the system is assembled around explicit interfaces rather than absorbed into a single do-everything chassis.

### 15.5 Operational maturity signals

When evaluating open-source software, the project should care about more than GitHub stars. Mature release cadence, security response, documentation quality, migration guidance, and governance clarity matter. Suricata&#8217;s recent 8.x stable line and security releases show active maintenance (Ref: R12). Zeek&#8217;s long-term documentation and package ecosystem signal maturity (Refs: R13, R14). Grafana&#8217;s explicit EOL guidance for Grafana Agent Flow is exactly the kind of governance signal an operator should appreciate rather than fear because it helps avoid accidental dependency on sunset software (Refs: R16, R17). A project that tells you nothing about its future is not mysterious. It is risky.

**&#8226;** Prefer projects that document upgrade and migration paths.

**&#8226;** Treat archived or effectively abandoned repositories as warning signs even if the software still 'works.'

**&#8226;** Value documentation quality almost as much as raw capability.

**&#8226;** Separate the popularity of a project from its fit for the current architecture.

**&#8226;** Re-evaluate core dependencies annually; open source is not static just because it is open.

> **Core-tools doctrine:** Choose projects for sharp, bounded roles. A smaller set of well-fitted tools beats a glorious pile of overlapping capabilities.

**VOLUME IV &#8212; TOOLING, LANGUAGES, AND SYSTEM DESIGN CHOICES**

**Chapter 16**

## Optional, Deferred, and Rejected Tools: Adjacent Power Without Architectural Sloppiness

> *Not every useful open-source security tool belongs in version one. This chapter surveys the surrounding ecosystem and explains what to adopt later, what to use sparingly, and what to avoid for this build.*

### 16.1 Deferred because valuable, not because bad

The most important distinction in this chapter is between 'rejected' and 'deferred.' Many excellent tools are simply not the right first move. The project gains nothing by pretending otherwise. Version one should remain buildable, explainable, and maintainable by one determined operator. Tools that improve packet-centric investigation, case management, timeline analysis, or threat-intelligence sharing may absolutely have a future here. They just do not all get to move in on day one.

### 16.2 Adjacent tools survey

| **Project** | **Potential value** | **Why not core day one** | **Recommended status** |
| --- | --- | --- | --- |
| Arkime | Packet indexing and retrieval | Storage/privacy overhead and policy complexity | Deferred optional |
| Timesketch | Collaborative timeline analysis | More useful once cases and exports mature | Deferred optional |
| Velociraptor | Deep DFIR endpoint capability | Powerful but more than needed for always-on baseline | Optional escalation |
| OpenCTI | Threat-intelligence graph and case-oriented CTI workflows | Heavy dependency stack and larger governance surface | Deferred later-stage |
| TheHive / Cortex | Case management and analyzers | Ecosystem/governance shifts, not necessary before custom case workspace exists | Selective later evaluation |
| Wazuh | Open-source XDR/SIEM package | Heavier monolithic path than this architecture wants | Compare, but not core |
| CyberChef | Analyst utility for transforms and decoding | Great tool, but not a platform component | Operator adjunct |
| Sigma | Portable detection-rule syntax | Needs translation and discipline rather than blind import | Adopt for rule portability |
| MISP warninglists | False-positive suppression context | Useful but should enrich rather than dominate logic | Yes, lightweight integration |

### 16.3 Wazuh and the monolith temptation

Wazuh is worth examining because it embodies a legitimate alternative philosophy: a more packaged, all-in-one open platform covering host monitoring, detection, dashboards, and a broad operational surface (Ref: R25). For some teams that is the correct answer. For Operation Impreavanti, however, Wazuh is more valuable as a comparison point than as the foundation. Its strength is integration convenience. Its weakness in this context is that it pulls the project back toward a monolithic product worldview precisely where we want custom analytical logic, explicit data layers, and a UI that is not beholden to one platform&#8217;s defaults.

The lesson is not 'Wazuh bad.' The lesson is that every platform encodes a philosophy. Our philosophy is composable, evidence-layered, and local-first with custom logic in the middle. Wazuh may still provide ideas, dashboards, or case-study comparisons. It simply does not win the architecture contest for this mission.

### 16.4 OpenCTI, TheHive, and when not to summon a whole doctrine at once

OpenCTI is a serious and capable threat-intelligence platform, but it carries a substantial supporting stack and assumes a level of CTI workflow maturity that version one does not need (Ref: R18). TheHive and Cortex bring case-management and analyzer concepts that can be extremely useful, yet the state of their ecosystem and governance should be evaluated carefully rather than adopted reflexively (Refs: R27, R28, R29). The user asked for a system that fuses many tools into one coherent experience. The correct response is not to bolt in every heavyweight ecosystem at once. It is to build the coherent experience first and introduce heavyweight subsystems only when the surrounding process can genuinely use them.

This is a historical lesson as much as an engineering one. Many security programs import enterprise-scale tooling before they have enterprise-scale investigative discipline. The result is procedural theater: cases are opened because the platform allows it, intel objects are created because they are possible, and analysts spend more time feeding the system than learning from it. Operation Impreavanti should refuse that fate.

### 16.5 Utility tools that belong near the operator

Some tools are not core services and should not be forced into the service plane, yet they remain very valuable. CyberChef is the canonical example: a superb analyst workbench for decoding, transforming, and inspecting data, but not something that needs to be permanently wired into the ingest path (Ref: R26). Similar logic applies to ad hoc PCAP viewers, local notebooks, or one-off forensic scripts. These are operator companions, not architecture pillars. Respecting that distinction keeps the system lean and the analyst powerful.

### 16.6 Rejection criteria

**&#8226;** Reject tools that duplicate existing capability without materially improving evidence quality or operator flow.

**&#8226;** Reject tools whose operational burden exceeds their likely use in the first year.
**&#8226;** Reject tools that require architectural compromises inconsistent with passive, local-first design.

**&#8226;** Reject tools whose governance, maintenance, or licensing status creates avoidable strategic risk.

**&#8226;** Reject tools that encourage dependence on unlabeled opaque scoring or vendor-specific worldview lock-in.

> **Deferred-tools doctrine:** Good architecture is partly the art of postponement. A tool can be interesting, even excellent, and still be wrong for now.

**VOLUME IV &#8212; TOOLING, LANGUAGES, AND SYSTEM DESIGN CHOICES**

**Chapter 17**

## Language, Runtime, and Framework Choices: What We Should Use and What We Should Decline

> *Languages are not personal brands here; they are operational commitments. This chapter recommends a language stack led by Python and TypeScript, with selective use of Go and a hard refusal to multiply runtimes without a measured reason.*

### 17.1 The primary language stack

The recommended language stack is intentionally small. Python is the primary back-end and integration language. TypeScript is the primary front-end language. SQL is the data query and reporting substrate. Bash handles thin operational glue, bootstrap scripts, and administration where appropriate. YAML, TOML, and JSON serve configuration and interchange. Go is reserved for edge cases where a specific service would materially benefit from its deployment simplicity or concurrency profile. This stack is enough. More is a tax.

The decision to center Python reflects the actual work of the project: parsing, enrichment, connectors, scheduled jobs, APIs, data manipulation, test harnesses, and model orchestration. The decision to center TypeScript reflects the needs of the UI: typed contracts, maintainable state, component systems, and graph-heavy interaction. There is no prize for using seven languages where two and a half would do.

### 17.2 Why mostly Python

Python wins the back-end contest because this is not a kernel project or a high-frequency trading engine. It is a compositional security system. Most of its value lies in clean transformations, good schemas, transparent business logic, and broad library support. Python makes all of that easier and faster than lower-level alternatives, provided the code is written with discipline. FastAPI, pydantic-style models, Pandas where justified, SQLAlchemy or a lightweight database layer, and well-structured workers create a pleasant and productive environment for this class of system.

The usual objections to Python&#8212;performance, dynamic sloppiness, packaging pain&#8212;are real but manageable. Performance bottlenecks should be measured, not imagined. Dynamic sloppiness is controlled through type hints, schema validation, and tests. Packaging pain is reduced through containerization and careful dependency selection. None of these justify pre-emptively jumping to a more cumbersome language for the whole build.

### 17.3 Why TypeScript, not plain JavaScript

The UI will consume structured data from many endpoints: timelines, entity graphs, assessment objects, glossary entries, and model-generated explanation records. Type safety at those edges pays for itself quickly. TypeScript is therefore not optional ornamentation; it is a way to prevent UI drift from silently corrupting analytical meaning. In a security interface, subtle mismatches are expensive. A status flag misread by the front end is not a minor bug if it changes what the operator believes.

TypeScript also makes component reuse more honest because shared interfaces remain explicit. The project should choose one front-end framework and live with it rather than inviting framework churn as a hobby. React has ecosystem breadth; Svelte has appealing simplicity. Either can work. The architecture cares more about typed contracts, maintainable state, and sober component design than about which front-end tribe gets to feel superior that week.

### 17.4 Where Go belongs

Go belongs where operational simplicity and concurrency actually justify it: a small sidecar service, a high-throughput parser, a lightweight exporter, or a utility where static binaries and low-overhead deployment are attractive. Go does not need to be the default just because it makes cloud engineers feel industrious. In this project, Go is a selective instrument, not the mother tongue. Use it when it materially improves a specific boundary. Do not drag it in because 'real systems use Go now.' Real systems use the right tool for the right choke point.

| **Language/runtime** | **Use it for** | **Avoid using it for** | **Reason** |
| --- | --- | --- | --- |
| Python | Enrichment APIs, connectors, jobs, tests, model orchestration | Hot-path packet forwarding or premature micro-optimizations | Best overall fit for logic-rich backend work |
| TypeScript | UI, typed API clients, interactive dashboards | Server-side analytical core | Strong contracts for interface-heavy work |
| SQL | Queries, reports, materialized views, migrations | General business logic | Data belongs near declarative query power |
| Bash | Bootstrap, admin glue, maintenance scripts | Large application logic | Great servant, terrible architecture |
| Go | Targeted utilities and exporters | Default language for everything | Use surgically where it clearly helps |
| Java/C++/Rust | Only if a very specific subsystem demands it | Version-one core stack | Too much complexity for current mission unless justified |

### 17.5 Languages we should actively avoid for v1

**&#8226;** Pure Bash as application architecture: too brittle, too opaque, and too easy to regret.

**&#8226;** Java for the main stack: powerful but operationally heavier than this build requires.

**&#8226;** C++ for custom services: more foot-guns and maintenance burden than the mission justifies.

**&#8226;** Premature Rust in the core path unless a very specific safety/performance case exists; admirable is not the same as practical.

**&#8226;** Framework-driven polyglot sprawl where every service is someone's favorite language experiment.

### 17.6 Runtime hygiene

Each additional runtime introduces operational obligations: package management, vulnerability tracking, debugging habits, base images, and developer onboarding costs. These are real even in a small environment. The project should therefore enforce a runtime budget just as it enforces a telemetry budget. If a new service requires a new language or framework, the burden of proof lies with the proposer. 'It seemed cool' is not enough.

> **Language doctrine:** Use the fewest languages that let the system remain expressive, testable, and fast enough. Every extra runtime is a future maintenance invoice.

**VOLUME IV &#8212; TOOLING, LANGUAGES, AND SYSTEM DESIGN CHOICES**

**Chapter 18**

## Repository and File Structure Options: Monorepo, Split Repos, and the Cost of Clever Layouts

> *Code structure is not a purely aesthetic choice. It shapes onboarding, deployment, testing, and how readily the system can survive its own growth. This chapter proposes repository layouts and weighs their trade-offs.*

### 18.1 Why repository structure deserves design

Many projects treat repository layout as an afterthought, which is a charming way to ensure six months of confusion. Repository structure determines how configuration is versioned, how services share schemas, where infrastructure definitions live, how tests are organized, and how easy it is to rebuild the system from scratch. Because Operation Impreavanti spans Pi-side services, Nano-side UI, scripts, docs, and optional model infrastructure, a lazy repository layout would quickly become a source of friction.

The design must support both serious documentation and real implementation. A research-grade paper that cannot map cleanly onto a repository is a nice essay with deployment fantasies. Conversely, a clever repo that no human can navigate is not engineering maturity; it is future archaeology.

### 18.2 Monorepo option

A monorepo is the recommended default for version one. It keeps the Pi services, Nano UI, shared schemas, infrastructure definitions, documentation, and tests in one place. That reduces coordination tax, makes cross-service changes easier, and supports the reality that one operator may maintain most of the system. Shared types, example events, API contracts, and deployment scripts become easier to evolve when the whole system lives under one version history.

The danger of monorepos is not size in the abstract. It is sloppiness in internal boundaries. A monorepo without module discipline becomes a pile. But a disciplined monorepo can be the best of both worlds: one source of truth, many clearly bounded components.

### 18.3 Split-repo option

A split-repo design becomes attractive if the project grows into genuinely distinct teams or if one subsystem&#8212;say the front end&#8212;begins to evolve at a rhythm and ownership model very different from the back end. The price is coordination overhead. Shared schema versions become contracts to manage. Tooling becomes more fragmented. Cross-repo changes slow down. For a v1 to v2 research build, those costs usually outweigh the benefits. Split repos are therefore a later-stage possibility, not a starting virtue.

| **Layout** | **Advantages** | **Disadvantages** | **Recommendation** |
| --- | --- | --- | --- |
| Single monorepo | Shared schemas, unified docs, simpler rebuilds, easy cross-service changes | Requires module discipline and tooling hygiene | Recommended for v1 |
| Backend and frontend split | Clearer ownership boundaries | Version skew and coordination overhead | Possible later if teams diverge |
| Per-service repositories | Strict isolation | Operational overhead and contract sprawl | Not recommended early |
| Docs separate from code | Independent publishing path | Danger of drift between design and reality | Avoid if possible |

### 18.4 Proposed monorepo tree

The repository should organize around bounded domains rather than random technical miscellany. One top-level directory for backend services, one for the UI, one for infra and deployment, one for sample data and schemas, one for documentation and this paper, and one for scripts and utilities is usually sufficient. Within backend services, keep collectors, enrichment API, workers, and shared libraries distinct. Within the UI, keep pages, components, stores, graph logic, and glossary content distinct. This is not revolutionary. It is readable.

### 18.5 Configuration and environment strategy

Environment-specific configuration should live in dedicated config paths, not sprinkled through source code. Sample environment files should be committed with safe defaults and placeholders. Production or lab-specific secrets should be externalized. Migrations, seed data, and fixture datasets should have their own homes. The point is to ensure a new operator can answer 'what is configuration, what is code, what is data, and what is generated output?' without opening a Ouija board.

### 18.6 File naming, schemas, and generated artifacts

**&#8226;** Use human-readable service names and avoid cute abbreviations that only make sense for a week.

**&#8226;** Version schemas and example payloads deliberately; they are contracts, not scratchpads.

**&#8226;** Keep generated artifacts out of source control unless they are canonical fixtures or documentation assets.

**&#8226;** Separate notes and runbooks from code, but keep them in the same repo so drift stays visible.

**&#8226;** Treat exported evidence bundles as outputs, not working state.

> **Repository doctrine:** Choose the structure that makes truth easiest to find and rebuild. Elegant file trees that nobody can operate are just decorative entropy.

**VOLUME V &#8212; LAW, GOVERNANCE, HISTORY, AND EXPERIMENTAL METHOD**

**Chapter 19**

## Legal, Privacy, and Governance Analysis: Building the SIEM Without Building a Liability Machine

> *This chapter gives the legal and governance frame for the project: ownership, authorization, consent, minimization, exports, monitoring scope, and the practical implications of U.S. interception and stored-communications law for a local fusion-center build.*

### 19.1 Not legal advice, still legally serious

This chapter is not individualized legal advice. It is an engineering-facing legal analysis meant to shape the design so the system avoids avoidable stupidity. The core principle is simple: operate only within owned or explicitly authorized environments, collect only what is justified, make user and device boundaries explicit, and treat sensitive retention and third-party egress as design decisions rather than incidental by-products. A security build that ignores legal posture is not more advanced. It is merely more reckless.

### 19.2 Ownership, authorization, and who gets monitored

The first legal question is authority. If the operator owns the network and the monitoring systems, that matters. If other users&#8217; devices or traffic are involved, that also matters. Home or mixed-use environments are precisely where lazy assumptions become dangerous because not every device, account, or communication belongs exclusively to one person. The architecture should therefore distinguish between infrastructure monitoring, device telemetry for devices under direct authority, and more sensitive categories such as payload capture or user-content observation. These are not the same act, either technically or legally.

From a governance perspective, the safest posture is to document which devices are considered administratively managed, which are guest or external, what level of collection applies to each class, and what users have been informed about or have agreed to. Segmentation can enforce those decisions technically. If a household phone or guest device is not part of the managed estate, the build should not quietly drag it into deep endpoint telemetry just because it joined Wi-Fi. Good governance begins with clear lines.

### 19.3 Interception law and why payload humility matters

The U.S. Wiretap Act, codified at 18 U.S.C. &#167; 2511, makes interception of electronic communications a legally sensitive act and is precisely why indiscriminate content capture should not be the default design posture (Ref: R31). State law can be stricter still; California&#8217;s all-party consent rules are a common example of the way local law can narrow what a monitoring operator should assume is acceptable (Ref: R33). This does not mean network monitoring is impossible. It means one should differentiate between metadata-centric operational monitoring and content interception, document the justification for any deeper capture, and avoid normalizing ambient packet-content retention where it is not essential.

Engineering implication: metadata-first design is not merely elegant. It is legally intelligent. If DNS metadata, flow metadata, TLS metadata, asset baselines, and endpoint state answer the majority of security questions, the system can remain powerful while greatly reducing interception risk. When packet capture is required, it should be narrow, time-bounded, justified, and access-controlled. The design should make the default lawful restraint easier than casual overreach.

### 19.4 Stored data, account access, and internal boundaries

The Stored Communications Act, including 18 U.S.C. &#167; 2701, creates additional risk when accessing stored communications or hosted account content outside proper authority (Ref: R32). Engineering implication: the fusion center should be careful about ingesting or scraping cloud mailboxes, message stores, or synced content without explicit authority, and should separate infrastructure telemetry from content repositories. The same logic applies to harvested browser data, chat histories, or synchronized personal storage. Because something is technically reachable from a managed endpoint does not automatically make it an appropriate telemetry source.

Put differently: avoid turning the SIEM into a side-channel browser into users&#8217; stored content. That is not required for the present architecture and introduces legal and trust risk with mediocre security benefit. Focus on the signals that support security decisions without drifting into curiosity-driven collection.

### 19.5 FTC-style privacy and security principles as engineering constraints

FTC guidance on privacy and data security repeatedly emphasizes collecting only what is needed, protecting it, and disposing of it when no longer necessary (Ref: R30). Those themes align perfectly with this project&#8217;s technical goals. Data minimization reduces storage burden, breach fallout, and cognitive clutter. Purpose limitation clarifies why each telemetry source exists. Secure disposal prevents old debug traces or evidence bundles from turning into quiet liabilities. Governance is therefore not a bolt-on policy layer. It is the architecture&#8217;s memory and self-restraint.

| **Governance question** | **Practical design answer** | **Why it matters** |
| --- | --- | --- |
| Who is monitored? | Managed assets only by default; guests and non-managed users segmented or minimized | Prevents silent scope creep |
| What is collected? | Metadata-first, payload only under controlled justification | Reduces interception and privacy risk |
| How long is it kept? | Tiered retention with written policy | Limits liability and storage sprawl |
| Who can query raw evidence? | Restricted roles with audit trail | Protects sensitive data and case integrity |
| What leaves the environment? | Explicit export controls and optional manual gating | Prevents intelligence leakage and unnecessary third-party exposure |
| How are users informed? | Written notice / household policy / consent where appropriate | Strengthens legal and ethical posture |

### 19.6 Exports, sharing, and external enrichment

External reputation lookups and threat-intelligence enrichment can be useful, but they also transmit information about what the operator observed and found interesting. That can be acceptable, but it should be deliberate. The system should therefore support manual or policy-controlled enrichment, caching of common results, and redaction or hashing where possible before external queries. Likewise, case exports should include manifests, timestamps, and sensitivity markings. Evidence bundles are not souvenirs; they are controlled artifacts.

### 19.7 Policy minimums for this project

**1.** Document scope: which networks, devices, and users are managed or in-scope.

**2.** Document data categories: metadata, endpoint state, packet capture, exports, annotations, model interactions.

**3.** Document retention windows and deletion procedures by data class.

**4.** Document who may access raw evidence, curated state, and UI-level explanations.

**5.** Document when third-party enrichment is allowed and what safeguards apply.

**6.** Document notice, consent, or administrative authority assumptions for monitored devices and users.

A project that writes down these answers is already ahead of most ad hoc monitoring stacks. The law is not a theatrical enemy of engineering here. It is a forcing function for better design.

> **Legal doctrine:** The safest architecture is the one whose powerful features require deliberate activation, not the one whose dangerous features happen silently by default.

**VOLUME V &#8212; LAW, GOVERNANCE, HISTORY, AND EXPERIMENTAL METHOD**

**Chapter 20**

## Historical Failures, Anti-Patterns, and the Weird Ways Good Intentions Rot

> *History supplies brutal case studies in what not to do. This chapter extracts design lessons from major incidents and from recurring anti-patterns in how monitoring systems are built, trusted, and misused.*

### 20.1 Why history matters

Security architecture that ignores history tends to rediscover failure in expensive ways. Major breaches and operational disasters are not interesting only because of the attackers involved; they are interesting because they reveal what organizations believed would be enough and what those beliefs failed to account for. A research-grade design should therefore treat incidents as design literature. They are messy, but they are honest.

### 20.2 Asset blindness and patch theater

Equifax remains a canonical reminder that asset inventory, patch discipline, and certificate or monitoring hygiene are not glamorous but are existential. The lesson for this project is straightforward: if the fusion center cannot tell you what systems exist, what versions or packages they run, and what changed recently, it is already weaker than it thinks. This is why asset inventory and endpoint context appear so early in the architecture. Security programs routinely claim maturity while still being unable to answer basic asset questions with confidence.

### 20.3 Alert overload and trust collapse

Incidents and red-team retrospectives repeatedly show that organizations can possess relevant alerts and still fail because the alerting environment is too noisy, too fragmented, or too poorly explained to support action. This is the great dirty secret of many SIEM deployments: not that they see nothing, but that they see too much badly. The operator stops believing in urgency because the system has trained them to expect clutter. This is one of the main reasons Operation Impreavanti insists on explainable scoring, entity-first navigation, and suppression discipline. Alert overload is not just a tuning problem. It is a human-factors failure with technical roots.

### 20.4 Supply chain and trust boundaries

The SolarWinds era burned into the industry the fact that trusted software and management channels can become adversary delivery mechanisms. That lesson affects this project in at least three ways. First, inventory must include dependencies and update paths, not just hosts. Second, monitoring the health and behavior of the monitoring stack itself is mandatory. Third, the architecture should avoid making a single product or external service the epistemic center of the universe. If the whole fusion center becomes dependent on one opaque upstream component, then compromise or failure there becomes cognitive compromise locally.

### 20.5 Ransomware and the myth of the perfect perimeter

Ransomware history&#8212;from opportunistic worms to human-operated intrusions&#8212;repeatedly demonstrates that once identity, lateral movement, and operational blind spots combine, the perimeter becomes a nostalgic story rather than a defense. Colonial Pipeline&#8217;s public lessons about remote access and identity control, and countless ransomware cases about weak segmentation and backup assumptions, reinforce the need to treat internal context, privilege paths, and recovery readiness as central concerns rather than side quests. A fusion center that only watches north-south internet traffic and ignores internal posture is blind in a very modern way.

### 20.6 Anti-pattern catalog

**&#8226;** Single-pane-of-glass theater: one huge dashboard pretending to be understanding.

**&#8226;** Rule hoarding: importing signatures forever and tuning almost none of them.

**&#8226;** Data hoarding: retaining everything because deletion feels scary.

**&#8226;** Monolith worship: assuming one platform can satisfy every analytical need elegantly.

**&#8226;** Model mysticism: trusting AI summaries that cannot cite the evidence they summarize.

**&#8226;** Operator blame: designing a bad system and then blaming analysts for missing what the system obscured.

**&#8226;** Normalization fetish: polishing events into schema compliance while losing source nuance.

**&#8226;** Perimeter nostalgia: acting as though modern incidents cannot come from inside trusted paths.

### 20.7 Historical lessons translated into design rules

| **Historical lesson** | **Design rule in Impreavanti** |
| --- | --- |
| Asset blindness kills response | Maintain live asset, package, and role context |
| Noisy alerts destroy trust | Prioritize explainable scoring and suppression review |
| Trusted software can betray you | Monitor the stack itself and avoid epistemic monocultures |
| Perimeters are porous | Model internal entities and lateral context, not just internet edges |
| Retention without governance becomes liability | Tier retention and gate packet content |
| Recovery is part of security | Treat rebuildability and backups as first-class requirements |

History does not eliminate uncertainty, but it does give us permission to stop pretending that certain mistakes are novel. We know how systems fail when they are too noisy, too opaque, too centralized, too trusting of a single view, or too casual about data governance. The point of this project is to internalize those lessons rather than repeat them with shinier interfaces.

> **Historical doctrine:** Every famous breach is partly a case study in architecture. If we ignore the architectural lesson and only memorize the attack name, we learn almost nothing.

**VOLUME V &#8212; LAW, GOVERNANCE, HISTORY, AND EXPERIMENTAL METHOD**

**Chapter 21**

## Parallel Case Studies and Research Method: How We Test Whether the Design Is Actually Better

> *A research-grade build should not merely assert superiority. It should create comparative experiments. This chapter defines case-study structure, hypotheses, metrics, and side-by-side evaluation plans for the fusion-center design.*

### 21.1 The need for comparative method

It is easy to claim that an entity-first, explanation-rich, local fusion center is better than a conventional alert board. It is harder and more respectable to test that claim. Operation Impreavanti therefore proposes parallel case studies in which the same underlying events are investigated under different interface and pipeline conditions. This produces evidence not merely about detection but about operator understanding, time-to-triage, false-positive handling, and confidence calibration.

### 21.2 Core research questions

**1.** Does an entity-first UI reduce time-to-understanding compared with an alert-centric dashboard?

**2.** Does explanation layering improve triage quality without causing overtrust?

**3.** Does metadata-first collection preserve enough analytical value for most version-one tasks?

**4.** Does a local-first architecture reduce operational and privacy risk compared with cloud-heavy designs?

**5.** Do bounded LLM explanations improve analyst throughput when evidence provenance is preserved?

### 21.3 Suggested case-study pairs

| **Case-study pair** | **Comparison logic** | **Primary metrics** |
| --- | --- | --- |
| Entity-first UI vs alert-first UI | Same evidence, different operator surface | Time-to-triage, user confidence, missed context |
| Metadata-first vs packet-heavy workflow | Same scenario, different collection philosophy | Storage cost, privacy burden, investigation completeness |
| No-model vs model-assisted explanation | Same evidence, different explanation layer | Comprehension speed, explanation accuracy, overtrust rate |
| Composable stack vs monolithic platform | Same telemetry goals, different architecture | Flexibility, maintenance burden, clarity of ownership |
| Manual enrichment vs cached policy-driven enrichment | Same suspicious artifact, different external-query control | Latency, data leakage, repeatability |

### 21.4 Metrics that matter

Good metrics are not vanity metrics. The project should measure median time-to-first-understanding, time-to-useful-pivot, number of UI context switches, false-positive suppression burden, operator confidence calibration, reproducibility of conclusions, storage growth by data class, and the percentage of model statements that can be traced to explicit evidence objects. These metrics align with the system&#8217;s actual thesis. A thousand colorful charts about CPU temperature and alert counts will not answer whether the design improved reasoning.

Some metrics should be qualitative but structured: analyst notes on cognitive load, clarity of provenance, frustration points, and whether the system surfaced enough context to make a sane decision. Human factors are part of the system&#8217;s output. Treating them as anecdotal rather than measured is one reason so many security tools remain painful long after they are technically functional.

### 21.5 Parallel scenario library

A useful evaluation program requires a scenario library. Examples include: a benign but novel software-update domain; suspicious periodic DNS lookups from one host; a temporary TLS certificate anomaly; package drift on a sensitive endpoint; misconfigured service causing noisy connections; simulated credential-use anomaly; deliberate rule-noise injection to test suppression logic; and a controlled packet-capture escalation exercise. These scenarios should mix true positives, benign anomalies, misconfiguration, and normal-but-rare events. Otherwise the evaluation becomes a cartoon where every interesting thing is malicious.

### 21.6 Theory translated into method

From a theoretical standpoint, the system is making claims about epistemic efficiency: that better structuring of evidence and explanation yields better decisions under uncertainty. The empirical method therefore has to test uncertainty handling, not just raw detection presence. This is why confidence calibration, evidence traceability, and explanation usefulness matter. The project is not merely building a tool. It is testing a model of analyst-machine cooperation.

### 21.7 Case-study documentation template

**1.** Scenario description and intended lesson

**2.** Telemetry available and intentionally unavailable

**3.** Detection or anomaly trigger

**4.** Operator tasks and success criteria

**5.** Comparative condition (e.g., with/without model, alert-first/entity-first)

**6.** Measured metrics

**7.** Observed outcomes

**8.** Design implications and next changes

> **Research doctrine:** Claims about security tooling should be tested in structured comparisons. Otherwise we are just writing fan fiction about our own architecture.

**VOLUME V &#8212; LAW, GOVERNANCE, HISTORY, AND EXPERIMENTAL METHOD**

**Chapter 22**

## Detection Engineering Doctrine: Baselines, Scores, Suppressions, and Feedback Loops

> *Detection engineering is the craft that turns telemetry into operationally credible claims. This chapter defines the scoring model, suppression philosophy, ATT&CK mapping use, and the review loops that keep the system honest over time.*

### 22.1 Detection is argument, not oracle

A detection is a structured argument that a condition deserves attention. Good detections are specific, testable, and explainable. Bad detections are vague, brittle, and noisy. The fusion center should therefore treat every rule, threshold, novelty signal, or model-assisted summary as an argument with premises. Those premises may be signatures, baselines, context facts, or relationship patterns. The operator should be able to inspect them. If not, the detection is not yet mature enough for central use.

### 22.2 Detection sources

**&#8226;** Signature-based detections from Suricata and comparable tools.

**&#8226;** Behavioral deviations computed from Zeek metadata and baselines.

**&#8226;** Endpoint-state changes such as package, service, or launch-item drift.

**&#8226;** Cross-source correlation such as suspicious domain + sensitive host + new package change.

**&#8226;** Operator-defined watchlists and case-derived recurrence patterns.

**&#8226;** Model-generated hypotheses only as secondary prompts, never as sole primary detections.

### 22.3 Scoring model

The scoring model should remain weighted and interpretable. Possible features include asset sensitivity, environmental novelty, per-host novelty, protocol mismatch, rule severity, external-reputation result, baseline deviation magnitude, recurrence frequency, and suppression history. Each feature should contribute a visible amount to the final score. The precise weights can evolve, but the system should always be able to show the decomposition. A score without decomposition is theater with arithmetic.

| **Feature** | **Example contribution** | **Interpretive note** |
| --- | --- | --- |
| Asset sensitivity | +0 to +20 | Important hosts deserve more scrutiny for the same anomaly |
| New-to-environment artifact | +0 to +15 | Novelty matters but is not guilt |
| New-to-host artifact | +0 to +10 | Useful for device-centric baselines |
| Suricata severity or confidence | +0 to +20 | Use as one input, not total verdict |
| Frequency or periodicity anomaly | +0 to +15 | Helpful for beacon-like behavior |
| External reputation / intel | +0 to +10 or suppression | Treat with skepticism and caching |
| Correlated local changes | +0 to +10 | Package/user/config drift can strengthen significance |
| Known-benign suppression | -0 to -40 | Reduces noise when well justified |

### 22.4 Suppression as maintenance, not surrender

Suppression is often treated as a guilty concession: proof that the detection was flawed. That attitude is childish. Real environments contain recurring benign weirdness, update noise, local infrastructure quirks, and application behaviors that will trigger generic rules. Mature detection engineering therefore maintains suppression and allowlist logic with the same seriousness used for detections. MISP warninglists can help, but local suppressions will matter just as much because the environment&#8217;s own habits are often the dominant source of noise (Ref: R19).

Suppression rules should be specific, documented, reviewable, and reversible. A suppression must say why it exists, who approved it, what evidence supported it, and when it should be revisited. Blanket suppressions with no review horizon are how blind spots become tradition.

### 22.5 ATT&CK tagging and rule portability

ATT&CK and Sigma are useful here in bounded ways. ATT&CK tags help communicate what a detection may relate to. Sigma offers a portable rule expression format that can support translation or documentation workflows (Refs: R5, R20). But portability should not erase local truth. Rules need environmental context, host-role awareness, and data-source quality checks. A rule imported because it looked authoritative online is not a mature detection. It is an unexploded maintenance device.

### 22.6 Review loops

**1.** Daily or active-period review of new high-score assessments and stack health.

**2.** Weekly suppression and noise review.

**3.** Monthly baseline and detection-quality review against recent cases and false positives.

**4.** Quarterly architecture review: source quality, retention, performance, and tool health.

**5.** Post-incident detection retrospective: what was missed, what was overcounted, what must change.

These loops matter because detection quality decays. Environments change, software changes, rules age, and human expectations drift. The system should therefore institutionalize its own criticism. A fusion center that cannot learn from its misses is just a very organized way to repeat them.

> **Detection doctrine:** Prefer fewer detections that explain themselves over many detections that merely occupy the screen. Quality is measured in decisions improved, not in rows emitted.

**VOLUME VI &#8212; EXECUTION ROADMAP, OPERATIONS, AND LONGER-HORIZON OPTIONS**

**Chapter 23**

## Roadmap: What We Will Build, What We Will Delay, What We May Explore, and What We Will Avoid

> *A design dossier that does not make sequencing decisions is just ambition in a trench coat. This chapter converts the thesis into phased execution with explicit yes, later, maybe, and no categories.*

[Picture 3 - embedded Word figure omitted from standalone Markdown]

> *Figure: phased roadmap emphasizing foundations first, then enrichment, then advanced options.*

### 23.1 Phase structure

The roadmap is organized around three execution phases and one anti-roadmap. Phase One is the minimal credible fusion center: Pi brain, Nano face, core sensors, hot logs, curated state, entity views, and bounded explanation support. Phase Two adds deeper enrichment, endpoint maturity, selected packet-centric capability, and improved case workflows. Phase Three explores advanced analytics, threat-intelligence integrations, stronger local inference, and selective automation. The anti-roadmap is just as important: a list of things we deliberately refuse to do unless the evidence changes.

| **Phase** | **Primary deliverables** | **Primary risk if rushed** |
| --- | --- | --- |
| Phase One | Pi + Nano foundations, Suricata, Zeek, Loki, entity store, UI, basic scoring | Overbuilding before evidence paths are stable |
| Phase Two | Endpoint maturity, richer graphs, better cases, selected packet escalation, richer enrichments | Complexity outruns operator understanding |
| Phase Three | Heavier analytics, CTI integrations, stronger model workflows, mature exports | Platform creep and philosophical drift |
| Anti-roadmap | Things we will not do casually | Without this, the project becomes a feature landfill |

### 23.2 Phase One: minimal credible fusion center

**1.** Stabilize router configuration, VPN break-glass access, and predictable host addressing.

**2.** Deploy Pi base services: Loki, relational state store, enrichment API, scheduled jobs.

**3.** Deploy Suricata and Zeek in passive mode with conservative logging profiles.

**4.** Deploy Nano-hosted UI with overview, entity inspector, timeline, and health screens.

**5.** Integrate osquery or initial endpoint inventory for key hosts.

**6.** Implement interpretable scoring, suppression management, and evidence-linked explanations.

**7.** Define retention policy and backup/export paths.

**8.** Test scenario library with at least three parallel case studies.

### 23.3 Phase Two: deliberate expansion

Phase Two should begin only after the system is already useful. That is a subtle but crucial criterion. Expansion without demonstrated utility is just optimism wearing containers. Once the core is stable, Phase Two can introduce deeper endpoint integration, improved relationship views, richer reporting, targeted packet-capture workflows, stronger note-taking and case packaging, and limited external enrichment with caching and policy controls. If a managed switch or better mirror capability becomes available, network visibility can mature here as well.

### 23.4 Phase Three: advanced options

Phase Three is where the project may justify heavier additions such as OpenCTI for local intelligence graphing, Timesketch for richer timeline workflows, selective use of Arkime for packet reconstruction, or stronger local model infrastructure on more capable hardware. By this stage the project should already know why each addition exists, what question it answers, and what burden it imposes. Mature systems add power from position, not from insecurity.

### 23.5 The anti-roadmap

**&#8226;** We will not place the Pi or Nano inline as a mandatory traffic choke point.

**&#8226;** We will not store full packet content by default for the whole environment.

**&#8226;** We will not let the LLM become the source of truth for detections.

**&#8226;** We will not multiply languages and frameworks because doing so feels sophisticated.

**&#8226;** We will not bolt on heavyweight ecosystems merely because they are popular in enterprise diagrams.

**&#8226;** We will not treat retention and consent as paperwork for later.

### 23.6 Operational cadence

Once deployed, the system should operate on a rhythm. Daily or active-use reviews inspect new notable entities and stack health. Weekly reviews tune noise and examine drift. Monthly reviews revisit baselines, retention costs, and roadmapped changes. Quarterly reviews address dependency health, architecture fit, and whether the current stack still serves the original thesis. This cadence keeps the project from becoming either neglected infrastructure or a perpetual unfinished experiment.

> **Roadmap doctrine:** Build what increases understanding now. Delay what merely increases possibility. Refuse what increases risk without earning operational leverage.

**VOLUME VI &#8212; EXECUTION ROADMAP, OPERATIONS, AND LONGER-HORIZON OPTIONS**

**Chapter 24**

## Conclusion: Operation Impreavanti as a Serious Local Fusion Center, Not a Toy

> *The closing chapter states plainly what this system is trying to become, why the architecture is arranged as it is, and what standards of rigor must continue to govern it if it is to remain useful rather than decorative.*

### 24.1 What has been established

This dossier has argued for a local, open, explainable security fusion center built around passive observation, layered evidence, a Pi-hosted analytical brain, a Nano-hosted operator face, and a bounded model-assistance layer that explains rather than decrees. It has laid out the logic behind metadata-first monitoring, selective normalization, entity-centric investigation, interpretable scoring, and storage shaped around evidence lifecycles rather than logo count. It has named core tools, deferred tools, languages to prefer, languages to decline, filesystems to choose, and legal boundaries to respect. It has also made the less glamorous but more important point that governance and architecture are inseparable.

### 24.2 Why the architecture is arranged this way

The architecture is arranged this way because composition is the true problem being solved. The industry has plenty of sensors, plenty of platforms, and now plenty of AI-flavored helpers. What it often lacks is a coherent local theory of how evidence becomes knowledge without becoming a black box or a cost trap. Operation Impreavanti attempts to answer that by drawing hard boundaries. The router moves packets. The Pi turns telemetry into structured knowledge. The Nano turns structured knowledge into operator comprehension. The model translates and compares but does not rule. That separation is not aesthetic minimalism. It is operational self-respect.

### 24.3 What will determine success

Success will not be measured by how futuristic the screenshots look. It will be measured by whether the system reduces time-to-understanding, preserves provenance, keeps noise manageable, respects boundaries, survives its own upgrades, and remains rebuildable by the person operating it. Success also means being willing to prune the stack, not just add to it. Mature systems know how to say no. They know when a tempting integration is merely another source of entropy.

### 24.4 Final design rules

**&#8226;** Keep the data path and the analysis path separate.

**&#8226;** Preserve raw evidence and show transforms honestly.

**&#8226;** Prefer entities and timelines over alert confetti.

**&#8226;** Use the model to explain, compare, and draft&#8212;not to replace evidence.

**&#8226;** Let standards guide the design, but never let standards excuse bad local implementation.

**&#8226;** Collect enough to explain and no more than you can justify.

**&#8226;** Treat repository structure, storage policy, and legal posture as engineering decisions.

**&#8226;** Refactor ruthlessly when convenience starts to erode clarity.

If these rules hold, the system can grow without losing itself. If they do not, the project will slowly become what it originally set out not to be: another impressive-looking dashboard whose main output is operator fatigue. The whole point of this exercise is to refuse that fate. Operation Impreavanti should become the sort of system that makes the operator more precise, more informed, and more resilient under uncertainty. Anything less is just digital stage lighting.

> **Final thesis:** A good fusion center is not the place where all data goes. It is the place where evidence is disciplined into understanding without losing its chain of meaning.

**APPENDICES &#8212; IMPLEMENTATION SCAFFOLDING**

**Chapter Appendix A**

## Ninety-Day Build Plan, Milestones, and Acceptance Criteria

> *This appendix translates the architecture into a build calendar with weekly milestones, acceptance tests, and dependency notes. It is meant to be used, not admired.*

### A.1 Week-by-week implementation plan

| **Week** | **Primary objective** | **Key tasks** | **Exit criteria** |
| --- | --- | --- | --- |
| 1 | Stabilize network foundation | Finalize router config, verify VPN break-glass, document addressing, verify WAN/LAN assumptions | Remote access works and address plan is documented |
| 2 | Prepare Pi and Nano base OS | Install Linux, harden SSH, update packages, attach storage, configure time sync | Both nodes patched, reachable, and documented |
| 3 | Container and deployment baseline | Install container runtime, create compose layout, define secrets handling | Compose baseline starts cleanly on both nodes |
| 4 | Hot-log layer | Deploy Loki and first collector path; validate log ingest and queries | Sample logs searchable with stable labels |
| 5 | Network sensors | Deploy Suricata and Zeek with minimal profiles; validate output | Both sensors emit trustworthy data |
| 6 | Entity/state database | Stand up relational store and initial schemas | Entities and events can be stored and retrieved |
| 7 | Enrichment API v1 | Implement normalization, lookup, timeline, and risk endpoints | API returns typed responses for core scenarios |
| 8 | UI v1 skeleton | Deploy reverse proxy, front-end shell, overview screen, health screen | Nano serves UI with Pi data |
| 9 | Entity inspector and timeline | Implement detail views, evidence links, and change-focused summaries | At least one full investigation path works end-to-end |
| 10 | Endpoint enrichment | Deploy osquery/Fleet or equivalent on key hosts; link to entities | Network events can pivot to host context |
| 11 | Scoring and suppression | Implement weighted scoring, suppression rules, and rationale rendering | High-signal scenarios surface with explainable scores |
| 12 | Model-assist pilot | Add optional LLM explanation mode using grounded context | Model summaries cite local context and remain optional |
| 13 | Case studies and hardening | Run scenario library, capture lessons, patch rough edges, document recovery steps | Three comparative case studies completed and documented |

### A.2 Acceptance checklist by subsystem

**&#8226;** Router and remote access: stable, documented, and recoverable from outside the home network.

**&#8226;** Pi brain: restart-safe, health-checked, with logs, state store, enrichment API, and backups.

**&#8226;** Nano UI: accessible, responsive, and capable of entity-centric investigation without Grafana dependence.

**&#8226;** Sensors: Suricata and Zeek outputs ingested, timestamp-aligned, and tied to entities.

**&#8226;** Endpoint context: at least a subset of critical hosts queryable for inventory and drift.

**&#8226;** Legal/governance: scope, retention, and access policy written down before broad telemetry expansion.

**&#8226;** Model layer: optional, bounded, and grounded; no hard dependency for core detection or investigation.

### A.3 Common blockers and responses

| **Blocker** | **Likely cause** | **Recommended response** |
| --- | --- | --- |
| Noisy detections | Untuned rules or environment-specific benign traffic | Review signatures, create documented suppressions, validate against scenario library |
| Low-value dashboards | UI built before entity model matured | Refocus on entity inspector and timeline, reduce vanity panels |
| Performance drag on Pi | Too many services or overly heavy queries | Trim logs, optimize jobs, move non-critical workloads off-node |
| Unclear device identities | Weak asset registry and drifting identifiers | Strengthen inventory, alias mapping, and host-side identifiers |
| LLM summaries feel magical or wrong | Insufficient grounding or poor prompt discipline | Tighten context objects, expose provenance, demote model authority |
| Storage bloat | Retention without policy or payload creep | Enforce hot/warm/cold tiers and content-capture gates |

> **Execution note:** A build plan is only honest if it includes exit criteria and known failure modes. Otherwise it is just a wish list with dates attached.

**APPENDICES &#8212; TOOLING REFERENCE**

**Chapter Appendix B**

## Extended Open Source Software Catalog with Roles, Pros, Cons, and Fit

> *This appendix expands the tool survey into a practical catalog. It does not pretend every project must be adopted; it explains what each project is good for, where it fits, and where it does not.*

### B.1 Catalog legend

Fit categories in this appendix are: Core (recommended for version one), Optional (useful but not required), Deferred (valuable later when process maturity catches up), Adjunct (operator tool rather than platform component), and Avoid for now (misaligned with architecture, burden, or hardware). Licenses and project status should always be re-verified before packaging or redistribution.

### B.2 Core and adjacent software catalog

| **Project** | **Category** | **Fit** | **Primary role** | **Strengths** | **Cautions** |
| --- | --- | --- | --- | --- | --- |
| Suricata | Network detection | Core | IDS / network metadata | Mature, fast, structured Eve output | Needs rule tuning |
| Zeek | Network evidence | Core | Protocol and behavior logs | Rich context and timeline value | Can over-log if undisciplined |
| Grafana Loki | Log store | Core | Hot log query layer | Good fit for log workloads | Needs auth/proxy/retention care |
| Grafana Alloy | Collection | Core | Routing logs and metrics | Modern collector path | Avoid pipeline overcomplexity |
| Grafana | Dashboards | Core-adjacent | Ops dashboards and supporting views | Fast operational visibility | Should not become the whole product |
| FastAPI | Backend framework | Core | Enrichment and state APIs | Typed, productive, Python-native | Needs disciplined contracts |
| PostgreSQL | Structured store | Core | Entities and assessments | Reliable transactional behavior | Heavier than SQLite |
| SQLite | Structured store | Optional | Tiny environments or prototypes | Simple and portable | Limited concurrency for growth |
| osquery | Endpoint context | Core | Cross-platform host state | SQL-shaped, very flexible | Requires query hygiene |
| Fleet | Endpoint management | Optional/Core | osquery control plane | Makes host querying sane at scale | Extra moving parts |
| Velociraptor | DFIR | Optional | Targeted endpoint collection and hunts | Extremely capable | More power than v1 requires |
| Arkime | Packet analysis | Deferred | Searchable packet retention | Excellent for reconstruction | Storage/privacy burden |
| Timesketch | Timeline analysis | Deferred | Collaborative timeline work | Strong post-case review value | Not necessary before cases mature |
| MISP Warninglists | Intel hygiene | Optional/Core-adjacent | Benign-pattern suppression | Reduces false positives | Should not dominate local logic |
| Sigma | Rule portability | Optional | Detection syntax interchange | Useful abstraction and sharing | Still needs environment tuning |
| OpenCTI | Threat intel platform | Deferred | CTI graph and workflows | Powerful and extensible | Heavy stack and process burden |
| TheHive | Case management | Deferred | Investigation coordination | Structured case workflows | Evaluate ecosystem/governance carefully |
| Cortex | Analyzers | Deferred | Automated analyzers and responders | Many integrations | Needs careful curation |
| Wazuh | Integrated platform | Compare / Avoid v1 | Open XDR/SIEM platform | Broad feature surface | Wrong architecture philosophy for v1 |
| CyberChef | Analyst utility | Adjunct | Transforms, decoding, parsing | Extremely useful at the keyboard | Not a core service |
| OpenSearch / Elasticsearch | Search engine | Deferred | Large-scale log and search workloads | Powerful ecosystem | Heavier than needed initially |
| Prometheus | Metrics store | Optional | Service metrics | Useful if metrics expand | Do not multiply data stores casually |
| Nginx | Proxy | Core | UI and API edge | Stable and boring | Keep configs simple |
| Caddy | Proxy | Optional/Core | UI and API edge | Pleasant config and TLS handling | Choose one proxy, not both |
| Docker Compose | Orchestration | Core | Service startup and packaging | Pragmatic and readable | Document dependencies clearly |
| Podman | Orchestration/runtime | Optional | Alternative container model | Rootless-friendly | Do not switch runtimes casually |
| Git | Version control | Core | Source of truth for code/config/docs | Foundational | Requires disciplined commit hygiene |
| Ansible | Automation | Optional | Repeatable host config | Great when the build grows | May be overkill very early |
| Ruff / mypy / pytest | Python hygiene | Core | Linting, typing, tests | Keeps Python honest | Must actually be enforced |
| pnpm / npm | Front-end tooling | Core | TypeScript dependency management | Standard ecosystem fit | Keep lockfiles committed |
| Ollama / llama.cpp style runtimes | Model serving | Optional | Local LLM inference on stronger hosts | Convenient local inference path | Not magic on weak hardware |

### B.3 Shortlist by mission type

| **Mission type** | **Minimal tool set** | **Why** |
| --- | --- | --- |
| Network-centric baseline | Suricata, Zeek, Loki, Grafana, FastAPI | Covers most visibility and explanation needs |
| Host-aware local SOC | Above plus osquery/Fleet | Adds asset and endpoint context |
| DFIR-leaning lab | Above plus Velociraptor and targeted PCAP | Supports deeper host and packet investigation |
| CTI-heavy research lab | Above plus OpenCTI later | Only justified once local evidence workflows are mature |
| Operator utility bench | Add CyberChef and ad hoc notebooks | Great for analysis without polluting the core stack |

> **Catalog doctrine:** A project catalog is not a shopping spree. It is a map of capability, burden, and fit. The clever move is often to choose less.

**APPENDICES &#8212; MODEL AND INTELLIGENCE REFERENCE**

**Chapter Appendix C**

## LLM and Model Matrix for Early 2026: Best Fit, Frontier Capability, and Local Practicality

> *This appendix expands the model discussion into a working selection matrix. It distinguishes frontier capability from operational fit and keeps hardware reality firmly in view.*

### C.1 Model-selection dimensions

**&#8226;** Reasoning quality and calibration

**&#8226;** Context length and retrieval friendliness

**&#8226;** Coding usefulness for building the stack

**&#8226;** Local deployability and hardware appetite

**&#8226;** Licensing and commercial-use implications

**&#8226;** Privacy boundary and data-sovereignty fit

**&#8226;** Latency and cost profile

**&#8226;** Strength in long-form explanation versus terse summaries

### C.2 Frontier and open-model matrix

| **Model family** | **Type** | **Operational strengths** | **Operational cautions** | **Recommended use in Impreavanti** |
| --- | --- | --- | --- | --- |
| GPT-5.4 / GPT-5 family | Proprietary API frontier | Excellent synthesis, strong coding and strategic analysis | External processing and cost | Deep research, report drafting, thorny architecture questions |
| Claude Sonnet 4.6 | Proprietary API frontier | Very strong long-context analysis and polished writing | External processing and vendor boundary | Long dossier review, comparative reasoning |
| Gemini 2.5 Pro | Proprietary API frontier | Large context, strong document and multimodal reasoning | External processing and service dependence | Comparing long evidence bundles and documentation |
| Gemma 3 | Open-weight | Strong local-friendly family for private deployments, long context | Still needs meaningful local compute for best experience | Local summaries and grounded Q&A on stronger host |
| DeepSeek-R1 / distills | Open/open-weight reasoning family | Reasoning-oriented outputs and strong distilled variants | Resource needs vary; careful evaluation required | Hypothesis comparison and offline reasoning experiments |
| QwQ-32B | Open/open-weight reasoning model | Good reasoning flavor in an open package | Not realistic on Pi/Nano-class hardware | Local reasoning on workstation or server |
| Qwen2.5 family | Open/open-weight general family | Broad size range and good practicality | Choose sizes carefully to avoid overpromising local performance | Flexible local assistant choice |
| Qwen3-Coder | Open/open-weight coding model | Strong coding and agentic coding utility | Needs stronger hardware for satisfying throughput | Generating scaffolding, migrations, dev assistance |
| Mistral Large 3 | Frontier-ish proprietary/open-ish depending tier | Strong reasoning and long context | Deployment and licensing mode vary by channel | Strategic reasoning and writing if available |
| Mistral Small / Ministral class | Open/lightweight family | Lower latency and easier local deployment | Less depth than frontier giants | Fast local helper and UI explainer |
| Llama 3.3 / related open Meta family | Open-weight general family | Popular ecosystem and tooling support | Need current benchmarking against alternatives | Optional local baseline if ecosystem fit is strong |
| Tiny 1B&#8211;4B quantized models | Local lightweight | Run on modest hardware, low latency | Limited nuance, weak on hard reasoning | Glossary cards, simple restatements, low-risk microtasks |

### C.3 Practical hosting recommendations

| **Host class** | **Realistic model tier** | **Good uses** | **Bad uses** |
| --- | --- | --- | --- |
| Raspberry Pi 4B | Tiny quantized only | Maybe toy-level or glossary-like helpers | Do not expect meaningful investigative reasoning |
| Jetson Nano | Tiny-to-small quantized helpers | UI explanations, low-risk summaries, experimentation | Do not crown it the main analyst brain |
| Mac mini M4 or stronger local host | Mid-size open models and some heavier workflows | Local private summaries, coding help, deeper reasoning | Still not a magic substitute for frontier cloud at every size |
| Remote API provider | Frontier proprietary models | Strategic analysis, long-form synthesis, hard report drafting | Do not send sensitive data by default |

### C.4 Prompt classes to keep separate

**1.** Explain an event or assessment in plain language.

**2.** Compare two hypotheses about observed behavior.

**3.** Draft a case note or weekly summary from grounded evidence.

**4.** Propose follow-up pivots or searches for the analyst.

**5.** Generate or review code and config for the stack itself.

**6.** Summarize changes to a specific entity over a defined time window.

Separating prompt classes matters because it clarifies what success and failure look like. A model good at prose summary may still be weak at code review. A model good at code may still be too terse or brittle for analyst explanation. The system should keep prompts and evaluation datasets per use case. 'One universal cyber prompt' is a myth marketed to people who enjoy future debugging pain.

> **Model-selection doctrine:** Pick the smallest model that reliably solves the actual task inside the required privacy boundary. 'Most advanced' and 'best for this job' are not synonyms.

**APPENDICES &#8212; STORAGE, FILESYSTEMS, AND PORTABILITY**

**Chapter Appendix D**

## Filesystem, Storage, and Cross-OS Portability Analysis

> *This appendix addresses the user&#8217;s explicit filesystem concern and explains why live Linux data should remain on ext4 while cross-platform exchange uses a separate portability layer.*

### D.1 Design objective

The storage design must satisfy two different goals that should not be collapsed into one filesystem: first, stable Linux-native operation for databases, logs, and services; second, practical cross-OS portability for exports and archives. The wrong move is to force one compromise filesystem to carry both missions and then act surprised when it performs or behaves poorly.

### D.2 Filesystem comparison

| **Filesystem** | **Best use here** | **Strengths** | **Weaknesses** | **Recommendation** |
| --- | --- | --- | --- | --- |
| ext4 | Live Linux services and hot/warm data | Journaled, stable, boring, well supported | Not native read/write everywhere outside Linux | Primary operational choice |
| exFAT | Cross-OS exchange partition | Broad compatibility across Linux, macOS, Windows | Weaker metadata/journaling story for live service state | Use only for exchange/export |
| NTFS | Interoperability with Windows-heavy workflows | Good Windows support and large files | Less ideal as Linux-native live store; extra driver considerations | Acceptable for selected exchange, not core live ops |
| FAT32 | Legacy boot or tiny compatibility edge cases | Everywhere support | 4 GB file limit and outdated for serious archives | Avoid for this project |
| APFS/HFS+ | macOS-local storage | Native on Apple systems | Not a sensible default for Linux services | Use only on Apple hosts if needed |
| Btrfs/ZFS | Advanced local snapshots if expertise exists | Checksums and richer snapshot features | More operational complexity than v1 needs | Possible later, not default |

### D.3 Recommended partition strategy for the external 2 TB SSD

**1.** Partition 1: Linux-native ext4 volume for cold archives, local model files, backups, and large structured exports used by the Pi or a Linux host.

**2.** Partition 2: Smaller exFAT exchange volume for moving selected case bundles, PDFs, CSVs, and sanitized exports among Linux, macOS, and Windows systems.

**3.** Optional encrypted container or partition for especially sensitive evidence or credentials.

**4.** Document mount points and intended use so the wrong class of data does not drift into the wrong partition.

This split protects the project from the classic portability mistake. Live operational data remains on the filesystem built for the operating environment. Human convenience uses the exchange partition. That is cleaner than trying to convince a running Linux service stack to love a portability filesystem for its day job.

### D.4 Data-placement rules

**&#8226;** Databases and hot logs stay on Linux-native storage.

**&#8226;** Exports for review or transfer go to the exchange partition only after packaging and, when needed, redaction.

**&#8226;** Model weights and embeddings go on the Linux-native archive side unless a stronger host has its own managed store.

**&#8226;** Never use the exchange partition as the sole backup target for critical operational state.

**&#8226;** Treat removable media as governed storage, not as a mystery junk drawer.

### D.5 Portability without corruption

Cross-OS usability is often sabotaged not by the filesystem itself but by discipline failures: unplugging drives without clean unmounts, storing active databases on removable media, mixing temporary and canonical copies, or forgetting which system has the latest truth. The remedy is not exotic technology. It is a written data-placement policy and a habit of treating exchange media as a copy boundary, not a live-service substrate.

> **Storage doctrine:** One filesystem should not be forced to solve every human and machine need at once. Operational integrity first, portability second, and clear boundaries between them.

**APPENDICES &#8212; CODE AND REPOSITORY SCAFFOLDING**

**Chapter Appendix E**

## Repository Trees, Service Layouts, and File-Structure Options

> *This appendix provides concrete file-tree patterns for a monorepo-first implementation and discusses alternatives so the design can move from paper to code without improvising the entire project structure.*

### E.1 Recommended monorepo tree

The following structure assumes a single repository with bounded domains rather than random technical clutter. It is designed to keep Pi services, Nano UI, schemas, docs, infra, and examples in one coherent place.

> operation-impreavanti/<br>docs/<br>paper/<br>architecture/<br>runbooks/<br>scenarios/<br>infra/<br>compose/<br>proxy/<br>provisioning/<br>backups/<br>schemas/<br>events/<br>entities/<br>assessments/<br>api/<br>fixtures/<br>services/<br>ingest-router/<br>enrichment-api/<br>workers/<br>common/<br>ui/<br>app/<br>components/<br>graphs/<br>stores/<br>glossary/<br>tests/<br>notebooks/<br>research/<br>one-off-analysis/<br>scripts/<br>bootstrap/<br>migrations/<br>maintenance/<br>exports/<br>.gitignore<br>.env.example<br>compose.yaml<br>README.md

### E.2 Why this structure works

**&#8226;** Documentation lives with the code, reducing design drift.

**&#8226;** Schemas are central and reusable across backend and frontend.

**&#8226;** Services remain bounded without requiring multiple repositories.

**&#8226;** UI assets and logic stay separate from Pi-side backend services.

**&#8226;** Infrastructure and automation are visible, versioned, and reproducible.

### E.3 Alternative: backend and UI split

> impreavanti-backend/<br>services/<br>schemas/<br>infra/<br>tests/<br>impreavanti-ui/<br>src/<br>public/<br>tests/<br>shared-api-contracts/

This split becomes defensible if the interface and the analytical back end truly start moving at different velocities or under different ownership. The price is contract versioning, duplicated context, and more coordination overhead. For a one-operator or small-team v1, the monorepo is still superior.

### E.4 Service-internal layout recommendations

| **Service type** | **Suggested layout** | **Why** |
| --- | --- | --- |
| Python API service | app/, models/, routes/, services/, repositories/, tests/ | Keeps transport, logic, persistence, and contracts distinct |
| Worker/scheduler | jobs/, tasks/, connectors/, tests/ | Separates scheduled logic from reusable adapters |
| UI app | routes/, components/, lib/, stores/, api/, tests/ | Supports predictable front-end growth |
| Schema package | events/, entities/, assessments/, glossary/ | Provides single source of type truth |

### E.5 Naming conventions

**&#8226;** Use explicit names like `entity_timeline_service.py`, not vague names like `helper2.py`.

**&#8226;** Name routes by resource and action, not by internal joke or implementation detail.

**&#8226;** Use stable, human-readable IDs for schemas and migrations.

**&#8226;** Avoid abbreviations unless they are industry standard and unambiguous.

**&#8226;** Keep generated artifacts and exports out of the main source tree except for curated fixtures.

> **Repo doctrine:** A clean repository is not mere aesthetics. It shortens rebuild time, reduces operator confusion, and makes the paper&#8217;s architecture materially real.

**APPENDICES &#8212; SCHEMAS, APIS, AND EVIDENCE CONTRACTS**

**Chapter Appendix F**

## Example API Contracts, Event Schemas, and Evidence Objects

> *This appendix sketches the kinds of schemas and API objects the system should expose so that the Pi brain, Nano UI, and optional model layer remain contract-driven rather than ad hoc.*

### F.1 Core object families

**&#8226;** RawObservation

**&#8226;** NormalizedEvent

**&#8226;** Entity

**&#8226;** Relationship

**&#8226;** Assessment

**&#8226;** Explanation

**&#8226;** TimelineSlice

**&#8226;** CaseNote

**&#8226;** SuppressionRule

**&#8226;** HealthStatus

### F.2 Example normalized event

> {<br>"event_id": "evt_01J...",<br>"source": "zeek_dns",<br>"observed_at": "2026-03-08T21:13:11Z",<br>"ingested_at": "2026-03-08T21:13:12Z",<br>"event_category": "network.dns.query",<br>"src_asset_id": "asset_scar18",<br>"src_ip": "192.168.88.11",<br>"dest_domain": "example-update.net",<br>"transport": "udp",<br>"query_type": "A",<br>"confidence": 0.94,<br>"raw_ref": ["zeek:dns:2026-03-08:row-1983"]<br>}

### F.3 Example entity

> {<br>"entity_id": "asset_scar18",<br>"entity_type": "device",<br>"display_name": "Scar 18",<br>"role": "development-workstation",<br>"sensitivity": "high",<br>"aliases": ["SCAR18", "scar18.local", "192.168.88.11"],<br>"first_seen": "2026-03-01T10:00:00Z",<br>"last_seen": "2026-03-08T21:13:11Z",<br>"owner": "primary-operator"<br>}

### F.4 Example assessment

> {<br>"assessment_id": "asm_01J...",<br>"entity_id": "asset_scar18",<br>"assessment_type": "novel_domain_activity",<br>"severity": "medium",<br>"confidence": 0.72,<br>"score": 67,<br>"factors": [<br>{"name": "new_to_environment", "weight": 15},<br>{"name": "new_to_host", "weight": 10},<br>{"name": "sensitive_asset", "weight": 12},<br>{"name": "moderate_frequency_spike", "weight": 9}<br>],<br>"supporting_events": ["evt_01J...", "evt_01K..."],<br>"rationale": "Novel domain activity from a high-value workstation exceeded baseline.",<br>"status": "open"<br>}

### F.5 Example explanation object

> {<br>"explanation_id": "exp_01J...",<br>"assessment_id": "asm_01J...",<br>"generator": "local-llm:gemma3-12b",<br>"created_at": "2026-03-08T21:14:00Z",<br>"summary": "Scar 18 contacted a domain not previously seen on the network. The activity is moderately unusual for this host and occurred alongside a short burst in DNS frequency.",<br>"cites": ["asm_01J...", "evt_01J...", "evt_01K..."],<br>"uncertainty": "This may reflect a benign software update or telemetry endpoint; process context should be checked."<br>}

### F.6 Suggested API surface

| **Endpoint** | **Purpose** | **Typical consumer** |
| --- | --- | --- |
| GET /health | Service liveness and dependency state | Ops dashboards and proxy health checks || POST /ingest/suricata | Receive normalized Suricata payloads or wrappers | Collectors |
| POST /ingest/zeek | Receive normalized Zeek payloads or wrappers | Collectors |
| GET /entities/{id} | Fetch entity details | UI entity inspector |
| GET /entities/{id}/timeline | Timeline slice for a single entity | UI timeline view |
| GET /assessments/open | Current notable assessments | Overview dashboard |
| GET /search | Search across entities/assessments/events | UI global search |
| POST /explain | Generate grounded explanation over supplied context object | UI model-assist panel |

These examples are illustrative rather than final, but they show the central point: the UI and the model layer should consume explicit objects with stable meanings. The fastest way to corrupt a fusion-center build is to let every component invent its own semi-structured truth about what an event or assessment 'basically' is.

> **Schema doctrine:** Contracts are part of the security posture. When interfaces are vague, every downstream claim becomes less reliable.

**APPENDICES &#8212; OPERATIONS AND RESPONSE**

**Chapter Appendix G**

## Runbooks, Playbooks, and Break-Glass Procedures

> *A fusion center is operationally credible only if it includes procedures for common failures and investigative motions. This appendix provides practical runbooks and response skeletons.*

### G.1 Stack-health runbook

**1.** Check Pi and Nano reachability, disk space, time sync, and service health endpoints.

**2.** Verify Loki ingest freshness and query recent known-good logs.

**3.** Verify enrichment API health and database connectivity.

**4.** Verify UI proxy routing and websocket updates.

**5.** If ingest is stale, inspect collectors and service logs before touching UI components.

**6.** Document cause, fix, and any data gaps introduced during the outage.

### G.2 Notable entity investigation runbook

**1.** Open entity inspector and confirm identity and asset role.

**2.** Review recent assessments, scores, and factor decomposition.

**3.** Open the timeline and compare current activity to recent baseline.

**4.** Pivot to related domains, IPs, certificates, and endpoint inventory where available.

**5.** If ambiguity remains, decide whether packet capture or deeper endpoint collection is justified.

**6.** Record disposition: benign, suspicious, confirmed issue, or needs follow-up.
### G.3 Model-output review checklist

**&#8226;** Does the explanation cite the underlying assessment or events?

**&#8226;** Does the explanation overstate certainty beyond the evidence?

**&#8226;** Are key unknowns and alternative explanations named?

**&#8226;** Can the operator reproduce the explanation from visible data?

**&#8226;** Should the output be stored as a note, or discarded as transient assistance?

### G.4 Break-glass remote access procedure

**1.** Activate the configured VPN path from a remote device.

**2.** Verify access to the router and the Nano/Pi management endpoints.

**3.** Check stack health before making changes.

**4.** If router access is required, prefer the documented management IP rather than local DNS shortcuts.

**5.** Make the minimal corrective change and record what was altered.

**6.** Disconnect remote access once recovery is complete.

### G.5 Evidence export procedure

**1.** Select the relevant entity, timeline window, and supporting assessments.

**2.** Export raw references, normalized summaries, and analyst notes together.

**3.** Redact unnecessary personal or benign third-party data before wider sharing.

**4.** Write a manifest describing included files, time windows, and hash values where useful.

**5.** Place the export on the designated archive or exchange path, not in random desktop folders.

### G.6 Incident types to pre-build

| **Incident type** | **Minimum prepared material** | **Why it helps** |
| --- | --- | --- |
| Suspicious external domain | Triage checklist, domain-history view, enrichment pivots | Common, ambiguous, high-frequency use case |
| Endpoint drift or persistence suspicion | Host-query pack, timeline template, escalation notes | Bridges network and endpoint context |
| Sensor outage | Health runbook, restore order, gap documentation template | Monitoring failure is itself an incident |
| Remote access recovery | VPN instructions, management IPs, credential handling notes | Break-glass paths only matter if rehearsed |
| Export for external review | Manifest template, redaction checklist, archive rules | Protects evidence integrity and privacy |

> **Operations doctrine:** A system becomes trustworthy when its operators know what to do on an ordinary bad day. Runbooks are where that trust is rehearsed.

**APPENDICES &#8212; GOVERNANCE AND EXPERIMENTAL TOOLS**

**Chapter Appendix H**

## Governance Checklists, Consent Prompts, and Scenario Library Starters

> *This appendix offers practical governance prompts and a starter scenario library so the system can be deployed and evaluated without improvising the sensitive parts.*

### H.1 Governance checklist

**&#8226;** List all in-scope devices and classify them as managed, guest, or external.

**&#8226;** Record who has administrative authority over each managed device class.

**&#8226;** Record what telemetry categories apply to each device class.

**&#8226;** Record retention windows and who may access each data class.

**&#8226;** Record whether external enrichment is enabled and under what controls.

**&#8226;** Record notice or consent assumptions for non-operator users whose devices may appear in telemetry.

### H.2 Example household / lab notice prompts

**&#8226;** This network uses operational monitoring for security, troubleshooting, and asset management.

**&#8226;** Managed systems may produce metadata and inventory telemetry to a local monitoring stack.

**&#8226;** Deep content capture is not the default and, when used, should be justified, limited, and documented.

**&#8226;** Guests and unmanaged devices should be placed on the appropriate segment with minimized monitoring.

**&#8226;** Questions about what is collected, retained, or exported should be answerable in writing.

### H.3 Scenario starter set

| **Scenario** | **What it tests** | **Expected lesson** |
| --- | --- | --- |
| Novel benign domain | Novelty scoring without false panic | Not all novelty is bad, but it must be explainable |
| Bursting DNS from one host | Frequency anomaly and entity correlation | Behavioral context matters more than raw counts |
| Package drift plus new outbound destination | Cross-source enrichment | Endpoint context sharpens network meaning |
| Bad Suricata rule noise | Suppression discipline | Noise must be managed, not merely endured |
| Temporary packet-capture escalation | Policy-controlled deeper collection | Escalation should be narrow and justified |
| Model-assisted summary review | Bounded LLM usefulness | Model output must remain grounded and reviewable |

### H.4 Comparative-evaluation note form

> Scenario:<br>Compared conditions:<br>Primary evidence sources:<br>Key analyst actions:<br>Outcome:<br>What the entity-first view clarified:<br>What remained confusing:<br>Did the model help or hinder:<br>What should change in the design:

> **Governance note:** The most dangerous parts of monitoring projects are often the parts nobody bothered to write down because they seemed obvious. Write them down anyway.

**APPENDICES &#8212; LANGUAGE, PROMPTS, AND ANALYST AIDS**

**Chapter Appendix I**

## Prompt Library, Query Patterns, and Analyst Question Templates

> *This appendix provides example prompts and analyst queries so the model and the system are asked useful questions rather than vague cyber-mystical ones.*

### I.1 Why prompt libraries matter

Model use becomes dramatically more reliable when the organization stops improvising prompts from mood alone. A prompt library creates repeatability, makes evaluation easier, and clarifies which tasks are actually safe to delegate to the model. The prompts below are framed for grounded use over structured local context objects rather than raw, unconstrained event sludge.

### I.2 Explanation prompts

> You are assisting with a local security investigation.<br>Use only the supplied context objects.<br>Task: explain why this assessment matters in plain language.<br>Requirements:<br>- state the observed facts first<br>- state the assessment and confidence second<br>- list at least two benign explanations if plausible<br>- list any missing evidence that would reduce uncertainty<br>- cite the entity IDs and assessment IDs you relied on

### I.3 Comparison prompts

> Compare two hypotheses for the following entity timeline:<br>Hypothesis A: benign software update or telemetry<br>Hypothesis B: suspicious beaconing or command-and-control precursor<br>Use only the supplied facts.<br>Return:<br>1. evidence supporting A<br>2. evidence supporting B<br>3. evidence missing for each<br>4. provisional leaning with confidence

### I.4 Operator query templates

**&#8226;** What changed for this device in the last 24 hours relative to its seven-day baseline?

**&#8226;** Which new external domains appeared today, grouped by originating device and score?

**&#8226;** Show me all open assessments touching devices classified as high sensitivity.

**&#8226;** Compare this host&#8217;s recent DNS activity to its historical norm and highlight the biggest differences.

**&#8226;** What suppressions affected this assessment and should any of them be reconsidered?

**&#8226;** Draft a concise note explaining why this entity is worth review and what to check next.

### I.5 Prompt anti-patterns

**&#8226;** Tell me everything suspicious on the network. (Too vague, no scope, invites nonsense.)

**&#8226;** Decide if this is malicious. (Requests certainty where evidence may not support it.)

**&#8226;** Summarize all logs from the last week. (Needlessly huge and context-poor.)

**&#8226;** Act as a SOC analyst and give the final answer. (Asks the model to overstep the evidence boundary.)

**&#8226;** Ignore uncertainty and just tell me what to do. (Very funny right up until it is disastrous.)

### I.6 Query patterns for the structured APIs

| **Question type** | **Best API/query path** | **Why** |
| --- | --- | --- |
| Single entity review | GET /entities/{id} + /timeline | Fastest path to coherent local context |
| Global trend review | Dashboard summaries + filtered search | Avoids manual entity hopping |
| Suppression audit | Assessment list + suppression metadata | Requires rationale, not just counts |
| Case export | Entity + timeline + note bundle generation | Preserves evidence continuity |
| Model-assisted explanation | POST /explain with curated context | Keeps model grounded |

> **Prompt doctrine:** When asking questions of a model or a system, precision is not pedantry. It is how you keep interpretation tethered to the evidence.

**APPENDICES &#8212; TERMINOLOGY AND REFERENCE MATERIAL**

**Chapter Appendix J**

## Glossary of Core Terms, Concepts, and Deliberately Precise Vocabulary

> *This glossary defines the key concepts used throughout the paper so the system&#8217;s terms remain stable across design, implementation, and operation.*

### J.1 Glossary

| **Term** | **Meaning in this paper** |
| --- | --- |
| Assessment | A structured analytical claim about the significance of an entity, event, or pattern. |
| Baseline | A recorded expectation of normal or typical behavior against which changes are compared. |
| Brain node | The Pi-hosted backend services that ingest, enrich, score, and store security knowledge. |
| Cold history | Longer-term archives and snapshots preserved outside the hot operational path. |
| Context object | The curated bundle of facts passed to the model or UI for explanation or rendering. |
| Entity | A durable investigative object such as a device, user, domain, IP, service, or certificate. |
| Evidence | Observed facts and their directly traceable derivatives, distinct from interpretation. |
| Explanation | Human-readable narrative built over evidence and assessments, not a replacement for them. |
| Exchange partition | A cross-OS storage area intended for transport and exports, not live database state. |
| Fusion center | An analyst-centered system that combines multiple evidence sources into coherent operational understanding. |
| Grounded model use | Model outputs constrained by structured local context rather than unconstrained improvisation. |
| Hot logs | Recent high-volume logs used for active dashboards and immediate triage. |
| Inline | Placed directly in the live traffic path such that failure can affect availability. |
| Managed asset | A device or system under explicit administrative authority for the purposes of this project. |
| Metadata-first | A collection strategy that prioritizes structured communication facts over payload content by default. |
| Monorepo | A single repository containing multiple bounded services, schemas, docs, and infrastructure definitions. |
| Novelty | A measure of how new or unusual an artifact or behavior is for the environment or a specific entity. |
| Operator plane | The user-facing interface and workflow layer where analysts interact with the system. |
| Passive observation | Collecting or receiving copies of data without acting as a mandatory transit point. |
| Raw observation | Source-native recorded event before normalization. |
| Suppression | A documented reduction or dismissal rule for known-benign or low-value noise patterns. |
| Timeline slice | A bounded chronological view of events and assessments for a selected entity or case. |
| Warm curated state | Structured entities, relationships, scores, and notes retained longer than raw hot logs. |

Precision in vocabulary is an underrated security control. Teams that use the same words to mean different things frequently build systems that appear aligned while quietly disagreeing at every layer. This glossary exists to reduce that drift.

> **Glossary note:** If a project cannot define its own important words, it is not ready to automate decisions with them.

**APPENDICES &#8212; COMPARATIVE ARCHITECTURE NOTES**

**Chapter Appendix K**

## Alternative Architecture Patterns and Why They Lost the Decision

> *This appendix records several architecture variants that were considered and explains, without diplomatic padding, why they were not chosen for the current mission.*

### K.1 Alternatives considered

| **Alternative pattern** | **Appeal** | **Why it lost** | **When it might win** |
| --- | --- | --- | --- |
| Inline Pi firewall/IDS gateway | Looks elegant and centralized | Bad fit for 2 Gbps home fiber and brittle failure profile | Small isolated lab with lower throughput and intentional inline experimentation |
| Single monolithic SIEM platform | Faster initial dashboard gratification | Less custom logic freedom, heavier stack, weaker evidence-layer separation | Team that values packaged integration over architectural autonomy |
| All-cloud telemetry and analysis | Huge compute and easy access | Data sovereignty, cost, and external dependency risk | Org already standardized on cloud SOC workflows and comfortable with egress |
| Packet-capture-first design | Richest possible raw evidence | Storage, privacy, and review burden explode early | Short-term forensic lab or very narrow protected environment |
| LLM-first investigation console | Feels futuristic and seductive | Evidence provenance and reproducibility collapse if overused | Only as a thin layer over a mature structured backend |
| Graph-database-everything | Beautiful relationship demos | Overkill and complexity before basic entities are stable | Later if relationship depth truly outgrows relational simplicity |
| Per-service split repositories from day one | Strict separation and ownership fantasy | Too much coordination overhead for a small build | Larger team with genuinely independent service ownership |
| Cross-platform compromise filesystem for all data | One drive to rule all OSs | Bad fit for Linux live ops | Rarely the best choice; exchange partitions are cleaner |

### K.2 Decision meta-rules

**&#8226;** Prefer architectures that fail soft rather than fail closed on the live network.

**&#8226;** Prefer local truth and explicit contracts over magical central platforms.

**&#8226;** Prefer the simplest structure that preserves future extensibility.

**&#8226;** Prefer evidence fidelity over impressive animation or speculative automation.

**&#8226;** Prefer optionality at the boundaries rather than chaos at the core.

### K.3 Why recording the rejected options matters

Design memory is strategic. Teams frequently revisit already rejected ideas because the original reasoning was never written down, only remembered by one enthusiastic builder until memory rotted. Recording why an option lost makes the project more intellectually honest and operationally durable. Future changes can then challenge a past decision explicitly rather than accidentally repeating the same debate with less context.

> **Architecture-memory doctrine:** A rejected idea with recorded reasoning is not dead weight. It is organizational memory and a future debugging gift.

**APPENDICES &#8212; STANDARDS AND CONTROL MAPPING**

**Chapter Appendix L**

## Control Mapping: How the Architecture Relates to Standards, Tactics, and Defensive Techniques

> *This appendix maps core architectural decisions to standards and technique vocabularies so the system can be discussed in formal language without becoming enslaved to formalism.*

### L.1 Mapping philosophy

Mappings are aids to communication, audit, and design review. They are not substitutes for evidence. The tables below are therefore deliberately high level. They show where the architecture aligns with standards and defensive logic, not a fantasy of one-to-one certainty between a local event and a grand taxonomy.

### L.2 Component-to-framework mapping

| **Component / practice** | **CSF function(s)** | **Continuous-monitoring role** | **ATT&CK / D3FEND relevance** | **Notes** |
| --- | --- | --- | --- | --- |
| Asset registry and endpoint inventory | Identify, Govern | Supports scoping and baseline review | Supports technique context, asset targeting, hardening | Inventory is a prerequisite for meaningful detection |
| Router hardening and VPN break-glass | Protect, Recover | Maintains administrative resilience | Supports secure administration and remote recovery | Availability and recoverability matter |
| Suricata passive deployment | Detect | Provides event stream for ongoing monitoring | Maps to multiple ATT&CK-aligned detections depending on rule | Never treat one alert as full proof |
| Zeek metadata logging | Detect | Behavioral and protocol visibility | Provides context for ATT&CK mappings and D3FEND responses | Strong evidence layer |
| Loki hot-log layer | Detect, Respond | Fast retrieval and triage | Supports analyst retrieval rather than direct tactic labeling | Operational utility over taxonomy purity |
| Entity store and scoring | Detect, Respond, Govern | Converts data into reviewable significance | Supports behavior clustering and response prioritization | Interpretability is central |
| Case notes and exports | Respond, Recover, Govern | Preserves institutional memory and evidence packaging | Supports post-incident analysis | Good notes are part of resilience |
| Retention tiers and minimization | Govern, Protect | Controls data risk and review window | Indirectly supports defensive sustainability | Security includes restraint |
| Bounded LLM explanations | Detect, Respond | Improves comprehension of monitored evidence | No direct technique mapping; explanation layer only | Keep model out of authority path |

### L.3 Detection-type mapping

| **Detection class** | **Example evidence** | **ATT&CK flavor** | **Why the mapping is approximate** |
| --- | --- | --- | --- |
| Novel domain on sensitive host | DNS + host role + baseline | May relate to command and control or benign updates | Novelty alone is not a technique verdict |
| Periodic DNS beacons | Zeek DNS cadence + recurrence | May suggest beaconing or remote service polling | Need host/process context to reduce false claims |
| New admin service exposure | Port metadata + config drift | May support lateral movement or remote administration misuse | Could also be normal maintenance |
| Persistence-like host drift | Launch items / scheduled tasks / services | May map toward persistence techniques | Requires endpoint evidence and change context |
| Rule-hit cluster across devices | Suricata alerts + shared domain/IP | May imply shared infrastructure or false-positive rule family | Clustering is useful but not dispositive |

### L.4 Why this mapping remains humble

One of the easiest ways to embarrass a detection program is to overclaim what a mapping proves. ATT&CK tags can help structure discussion. D3FEND references can help structure defensive thinking. CSF mappings can help governance review. None of them should trick the operator into believing that categorization equals certainty. The whole design of Operation Impreavanti is meant to resist that very slide.

> **Mapping doctrine:** Map for communication, not for self-deception. Framework tags should illuminate reasoning, not replace it.

**APPENDICES &#8212; RISK, MAINTENANCE, AND LONG-TERM OPERABILITY**

**Chapter Appendix M**

## Risk Register, Maintenance Debt, and the Problems We Should Expect to Meet in the Hallway

> *A good design dossier predicts its own likely failure modes. This appendix records operational risks, maintenance debt categories, and mitigation plans before the system accumulates them quietly.*

### M.1 Risk register

| **Risk** | **Likelihood** | **Impact** | **Early warning signs** | **Mitigation** |
| --- | --- | --- | --- | --- |
| Sensor noise erodes trust | High | High | Analysts ignore alerts, suppressions grow chaotic | Weekly noise review and scenario-driven tuning |
| Storage creep | High | Medium | Disk growth outpaces retention assumptions | Hot/warm/cold enforcement and archive jobs |
| Model overreach | Medium | High | Users quote summaries instead of evidence | UI provenance labels and no-model workflows |
| Pi performance saturation | Medium | Medium | Queue lag, slow APIs, skipped jobs | Trim sources, optimize jobs, offload heavy tasks |
| Unclear asset ownership | Medium | High | Investigations stall on who/what a device is | Maintain asset registry and role labels |
| Dependency rot | Medium | Medium | Outdated images, deprecations, unclear upgrades | Quarterly dependency review |
| Legal/consent drift | Low to medium | High | New users/devices appear without scope update | Governance checklist on every expansion |
| Backup theater | Medium | High | Backups exist but restores are untested | Quarterly restore drills |
| UI complexity creep | Medium | Medium | Screens multiply, clarity drops | Entity-first design review and feature pruning |
| Single-operator fragility | High | Medium | Knowledge lives only in one brain | Document runbooks, repo hygiene, architecture notes |

### M.2 Maintenance debt categories

**&#8226;** Untested transforms and scoring changes

**&#8226;** Unreviewed suppressions

**&#8226;** Stale endpoint query packs or schema definitions

**&#8226;** Undocumented dashboard logic

**&#8226;** Reverse-proxy or TLS drift

**&#8226;** Aging base images and packages

**&#8226;** Outdated model prompts that no longer match the evidence objects

**&#8226;** Archive paths and retention rules nobody has revisited in months

### M.3 Quarterly review questions

**1.** Which components are carrying more burden than originally intended?

**2.** Which alerts or assessments no longer earn their keep?

**3.** Which UI panels clarified investigations and which merely existed?

**4.** Where did provenance become hard to trace?

**5.** What data did we collect that we never meaningfully used?

**6.** What part of the stack would hurt the most to rebuild today, and why?

### M.4 Decommission and pruning

Pruning is a sign of maturity. If a data source, panel, job, or tool has not justified its existence, it should be retired cleanly. Decommissioning should include migration or archival notes, impact analysis, and deletion of dead configuration. The project should never become a museum of experiments that nobody trusts but nobody dares to remove.

> **Maintenance doctrine:** The quality of a security stack is defined as much by what it can retire cleanly as by what it can add ambitiously.

**APPENDICES &#8212; ANALYST FORMS AND REPORTING TEMPLATES**

**Chapter Appendix N**

## Analyst Worksheets, Review Forms, and Reporting Templates

> *This appendix packages a set of reusable forms and review templates so the system does not force every investigation or monthly review to begin from a blank page.*

### N.1 Entity review worksheet

> Entity ID:<br>Display name:<br>Role / sensitivity:<br>Why reviewed now:<br>Recent assessments:<br>Key evidence links:<br>What changed from baseline:<br>Most plausible benign explanation:<br>Most plausible suspicious explanation:<br>What evidence is still missing:<br>Disposition:<br>Next action:

### N.2 Weekly noise and suppression review form

| **Field** | **Guidance for reviewer** |
| --- | --- |
| Suppression or rule name | State the exact rule, filter, or suppression under review. |
| Origin | Explain why it was created and by whom. |
| Noise pattern | Describe the benign activity or recurring false-positive source. |
| Current justification | Why should this remain suppressed today? |
| Evidence sampled | List the events or timelines reviewed to validate the decision. |
| Risk of over-suppression | Could this hide a real issue under certain conditions? |
| Decision | Keep, tighten, remove, or replace. |
| Review due date | Set the next time this decision must be revisited. |

### N.3 Monthly architecture review prompts

**&#8226;** What part of the stack was most useful this month, and why?

**&#8226;** Which data sources cost the most attention relative to value?

**&#8226;** Did any screen or graph repeatedly confuse rather than clarify?

**&#8226;** Which scores or explanations felt least trustworthy, and why?
**&#8226;** Where did the project drift from its documented scope or retention assumptions?

**&#8226;** What should be removed before the next thing is added?

### N.4 Incident-summary template

> Incident title:<br>Date/time window:<br>Primary entity or entities:<br>Trigger:<br>Summary of observed facts:<br>Assessment and confidence:<br>What made this notable:<br>What was ruled out:<br>What additional evidence was collected:<br>Final disposition:<br>Suggested tuning or architecture changes:<br>Retention/export decision:

### N.5 Quarterly dependency review table

| **Dependency** | **Current version** | **Health signal to review** | **Decision options** |
| --- | --- | --- | --- |
| Suricata | Record deployed version | Release cadence, ruleset health, false-positive burden | Upgrade, hold, tune, or replace rule subsets |
| Zeek | Record deployed version | Package compatibility, log utility, parser stability | Upgrade, simplify, or extend |
| Loki/Alloy/Grafana | Record deployed version | Deprecation notices, auth posture, resource cost | Upgrade, refactor dashboards, trim pipelines |
| UI framework and libraries | Record deployed version | Security advisories and maintenance cost | Upgrade, consolidate, or prune |
| Model runtime | Record deployed version | Actual usefulness versus cost and complexity | Retain, move, or demote |
| Custom APIs and schemas | Record internal version | Test coverage, drift, and operator trust | Refactor, split, or stabilize contracts |

Templates are not glamorous, but they are where good intentions turn into repeatable practice. A system with forms and review prompts is far less likely to become dependent on memory, improvisation, and one person's private mental model.

> **Template doctrine:** Every investigation should begin with structure, not amnesia. Reusable forms are part of analytical maturity.

**APPENDICES &#8212; OPERATING MAXIMS AND FUTURE RESEARCH**

**Chapter Appendix O**

## Operating Maxims, Research Questions, and the Work Still Worth Doing

> *This final appendix records the short maxims and open research questions that should travel with the system as it evolves so the project does not forget what made it coherent in the first place.*

### O.1 Operating maxims

**&#8226;** Do not confuse more data with more understanding.

**&#8226;** Keep evidence closer to the operator than the explanation is.

**&#8226;** If a score cannot explain itself, demote it.

**&#8226;** If a feature creates new failure coupling, make it earn the right to exist.

**&#8226;** Every suppression is a future blind spot unless reviewed.

**&#8226;** The stack itself is part of the attack surface and part of the evidence story.

**&#8226;** Local sovereignty is a capability, not an ideology.

**&#8226;** The prettiest dashboard in the room can still be epistemically bankrupt.

### O.2 Open research questions

**1.** What is the smallest local model that still improves analyst comprehension measurably in this workflow?

**2.** How much packet content is actually needed beyond metadata for the scenario library planned here?

**3.** Can explanation-layer design improve confidence calibration without increasing overtrust?

**4.** At what scale does the relational entity store truly need graph-native backing?

**5.** Which enrichments most increase value per byte of data egress to third parties?

**6.** How should the system represent uncertainty visually without either burying it or dramatizing it?

A system that writes down its open questions stays alive in the right way. It does not pretend to be finished; it becomes finishable in successive honest versions.

> **Closing maxim:** Build the system that still tells the truth about itself after the excitement has worn off.

### References

The references below include the primary standards, project documentation, legal sources, and model announcements used to ground this dossier. URLs are preserved so the document remains practically useful.

**R1.** NIST, The Cybersecurity Framework (CSF) 2.0, February 26, 2024. https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20

**R2.** NIST SP 800-137, Information Security Continuous Monitoring (ISCM) for Federal Information Systems and Organizations, September 2011. https://csrc.nist.gov/pubs/sp/800/137/final

**R3.** NIST SP 800-137A, Assessing Information Security Continuous Monitoring (ISCM) Programs, May 2020. https://csrc.nist.gov/pubs/sp/800/137/a/final

**R4.** CISA et al., Best Practices for Event Logging and Threat Detection, August 21, 2024. https://www.cisa.gov/resources-tools/resources/best-practices-event-logging-and-threat-detection

**R5.** MITRE ATT&CK Framework. https://attack.mitre.org/

**R6.** MITRE D3FEND. https://d3fend.mitre.org/

**R7.** Open Cybersecurity Schema Framework (OCSF) Overview. https://ocsf.io/

**R8.** OASIS, STIX Version 2.1 OASIS Standard, June 10, 2021. https://www.oasis-open.org/standard/stix-version-2-1/

**R9.** OASIS, TAXII Version 2.1 OASIS Standard, June 10, 2021. https://www.oasis-open.org/standard/taxii2-1/

**R10.** OpenTelemetry Documentation and Collector Overview. https://opentelemetry.io/docs/collector/

**R11.** OpenTelemetry Documentation Overview. https://opentelemetry.io/docs/

**R12.** Suricata Features and Release Information, stable 8.0.3 released January 13, 2026. https://suricata.io/features/ and https://suricata.io/download/

**R13.** Zeek Documentation (LTS 8.0.6) and Installing Zeek. https://docs.zeek.org/en/lts/ and https://docs.zeek.org/en/v6.1.1/install.html

**R14.** Zeek Package Manager Documentation. https://docs.zeek.org/projects/package-manager/

**R15.** Grafana Loki Documentation, Install Loki. https://grafana.com/docs/loki/latest/setup/install/

**R16.** Grafana Alloy Documentation, Install Alloy. https://grafana.com/docs/alloy/latest/set-up/install/

**R17.** Grafana Agent Flow EOL notice, November 1, 2025. https://grafana.com/docs/agent/latest/flow/get-started/install/

**R18.** OpenCTI Documentation, Installation and deployment. https://docs.opencti.io/latest/deployment/installation/

**R19.** MISP Warninglists project. https://misp.github.io/misp-warninglists/ and https://github.com/MISP/misp-warninglists

**R20.** Sigma Specification repository. https://github.com/SigmaHQ/sigma-specification

**R21.** Fleet / osquery cross-platform table documentation (Linux, macOS, Windows). Example: https://fleetdm.com/tables/platform_info

**R22.** Arkime Docker documentation and project rename background. https://arkime.com/docker and https://arkime.com/arkimeetus

**R23.** Timesketch, collaborative forensic timeline analysis. https://timesketch.org/ and https://github.com/google/timesketch

**R24.** Velociraptor Documentation. https://docs.velociraptor.app/

**R25.** Wazuh, Open Source XDR / SIEM platform overview. https://wazuh.com/

**R26.** CyberChef GitHub repository. https://github.com/gchq/CyberChef

**R27.** TheHive documentation and platform pages. https://docs.strangebee.com/ and https://strangebee.com/thehive/

**R28.** Archived TheHive open-source repository, archived Dec 5, 2025. https://github.com/TheHive-Project/TheHive

**R29.** Cortex by StrangeBee. https://strangebee.com/cortex/

**R30.** FTC business guidance on Privacy and Security; data minimization and data lifecycle security. https://www.ftc.gov/business-guidance/privacy-security and https://www.ftc.gov/business-guidance/resources/start-security-guide-business

**R31.** 18 U.S.C. &#167; 2511, Interception and disclosure of wire, oral, or electronic communications prohibited. https://www.law.cornell.edu/uscode/text/18/2511

**R32.** 18 U.S.C. &#167; 2701, Unlawful access to stored communications. https://www.law.cornell.edu/uscode/text/18/2701

**R33.** California Penal Code &#167; 632 and related legislative material regarding all-party consent. https://codes.findlaw.com/ca/penal-code/pen-sect-632/ and https://www.leginfo.ca.gov/pub/15-16/bill/asm/ab_1651-1700/ab_1671_bill_20160816_amended_sen_v93.htm

**R34.** Google DeepMind / Google AI Developer docs: Gemini 2.0 and 2.5 models. https://blog.google/technology/google-deepmind/gemini-model-updates-february-2025/, https://ai.google.dev/models/gemini, and https://ai.google.dev/gemini-api/docs/changelog

**R35.** Google Gemma 3 announcement. https://blog.google/innovation-and-ai/technology/developers-tools/gemma-3/

**R36.** DeepSeek-R1 official repository and model documentation. https://github.com/deepseek-ai/DeepSeek-R1

**R37.** Qwen model blog posts for Qwen2.5, QwQ-32B, and Qwen3-Coder. https://qwenlm.github.io/blog/qwen2.5/, https://qwenlm.github.io/blog/qwq-32b/, https://qwenlm.github.io/blog/qwen3-coder/

**R38.** Mistral model documentation for Mistral Large 3 and open models overview. https://docs.mistral.ai/models/mistral-large-3-25-12 and https://docs.mistral.ai/getting-started/models

**R39.** OpenAI model announcements: GPT-5 for developers and GPT-5.4. https://openai.com/index/introducing-gpt-5-for-developers and https://openai.com/index/introducing-gpt-5-4/

**R40.** Anthropic Claude Sonnet 4.6 announcement and model page. https://www.anthropic.com/news/claude-sonnet-4-6 and https://www.anthropic.com/claude/sonnet

**R41.** Meta Open Source AI overview and secondary documentation about Llama 3.3 availability. https://ai.meta.com/opensourceAI/ and https://www.aboutamazon.com/news/aws/meta-llama-3-2-models-AWS-generative-ai/

**R42.** Saltzer, Jerome H., and Michael D. Schroeder. 'The Protection of Information in Computer Systems.' Proceedings of the IEEE 63, no. 9 (1975): 1278&#8211;1308.

**R43.** Anderson, Ross. Security Engineering: A Guide to Building Dependable Distributed Systems, 3rd ed. Wiley, 2020.

**R44.** Shannon, Claude E. 'Communication Theory of Secrecy Systems.' Bell System Technical Journal 28, no. 4 (1949): 656&#8211;715.

**R45.** Boyd, John R. The Essence of Winning and Losing. Unpublished briefing, various editions.

**R46.** Reason, James. Human Error. Cambridge University Press, 1990.

**R47.** Vaughan, Diane. The Challenger Launch Decision: Risky Technology, Culture, and Deviance at NASA. University of Chicago Press, 1996.

**R48.** RFC 7258, 'Pervasive Monitoring Is an Attack,' May 2014.

**R49.** Cheswick, William R.; Bellovin, Steven M.; and Rubin, Aviel D. Firewalls and Internet Security, 2nd ed. Addison-Wesley, 2003.