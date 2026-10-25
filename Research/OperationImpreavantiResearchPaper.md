# Operation Impreavanti

## A deployment-oriented reference architecture for an evidence-first security fusion center

| Document field | Value |
| --- | --- |
| Revision | 2.0 - deployment architecture |
| Review date | 24 October 2026 |
| Scope | Generic reference design for owned or authorized environments |
| Status | Design and documentation review; no operational deployment or hardware benchmark is claimed |
| Previous edition | [Original March 2026 monograph, preserved unchanged](Archive/OperationImpreavantiResearchPaper-v1-March2026.md) |

> **Architecture decision:** Keep forwarding, DNS, evidence processing, presentation, and language-model inference as distinct responsibilities. Use Tailscale for explicitly authorized connectivity, Pi-hole with dnscrypt-proxy for controlled DNS, and a dedicated NVIDIA-equipped host for local inference. The model assists the analyst; it does not control the network or manufacture evidence.

## Abstract

Operation Impreavanti is a local-first security-analysis design that separates observations, deterministic assessments, and language-model explanations. This revision turns the earlier conceptual dossier into a more concrete deployment specification. It retains the original emphasis on passive observation, provenance, restrained collection, and human review while adding an explicit access-control model, an encrypted-upstream DNS deployment, a dedicated inference tier, and failure-oriented acceptance tests.

The reference topology uses a Raspberry Pi-class Linux node for modest collection and orchestration, independently managed DNS services, an optional dedicated packet sensor, and a maintained operator interface. A Windows 11 workstation with a supported NVIDIA GPU is the primary inference implementation described here. Native Linux remains a valid server-oriented alternative. An RTX 3080 is an acceptable reuse tier, but its 10 GB or 12 GB memory configurations constrain model residency and context capacity; a 24 GB class GPU is the preferred expansion tier, not a requirement for initial functionality.[^gpu3080][^gpu3090][^ollama-gpu]

The paper does not claim line-rate inspection on a Raspberry Pi, immunity to prompt injection, or a validated production deployment. Its deliverable is a set of explicit boundaries, implementation examples, measurement requirements, and recovery decisions. The complete system must remain useful when inference is unavailable.

## Navigation

- [1. What changes in this revision](#1-what-changes-in-this-revision)
- [2. Scope, evidence, and threat model](#2-scope-evidence-and-threat-model)
- [3. Reference topology and failure domains](#3-reference-topology-and-failure-domains)
- [4. Tailscale deployment and access policy](#4-tailscale-deployment-and-access-policy)
- [5. Pi-hole and dnscrypt-proxy deployment](#5-pi-hole-and-dnscrypt-proxy-deployment)
- [6. DNS evidence and detection engineering](#6-dns-evidence-and-detection-engineering)
- [7. Collection, storage, and capacity](#7-collection-storage-and-capacity)
- [8. Dedicated inference hardware](#8-dedicated-inference-hardware)
- [9. Windows and Linux runtime deployment](#9-windows-and-linux-runtime-deployment)
- [10. Retrieval, prompt injection, and model authority](#10-retrieval-prompt-injection-and-model-authority)
- [11. Interfaces and evidence contracts](#11-interfaces-and-evidence-contracts)
- [12. Validation and acceptance tests](#12-validation-and-acceptance-tests)
- [13. Deployment order and recovery](#13-deployment-order-and-recovery)
- [14. Maintenance, cost, and residual risk](#14-maintenance-cost-and-residual-risk)
- [15. Conclusion](#15-conclusion)
- [References](#references)

## 1. What changes in this revision

The original monograph contains the project's design rationale, alternative architectures, standards discussion, and extensive appendices. It remains available as an unchanged historical edition. The following decisions supersede its deployment assumptions; readers should use this revision for the proposed build and the archive for background, not combine conflicting defaults.

| Earlier gap or assumption | Revised decision | Reason |
| --- | --- | --- |
| Remote access described mainly as a controlled VPN path | Specify Tailscale node roles, grants, management boundaries, and negative tests | Connectivity without authorization design is incomplete |
| No integrated resolver deployment | Add Pi-hole plus dnscrypt-proxy and explicit bootstrap/failure handling | DNS is both infrastructure and a bounded evidence source |
| Optional stronger host, exemplified by a Mac mini M4 | Make dedicated NVIDIA inference a defined tier; document native Windows and Linux options | Hardware suitability must follow workload and memory budgets |
| Pi described as the location for most back-end functions | Use a small initial service set; scale out heavy storage and capture after measurement | A list of compatible applications is not a capacity plan |
| Jetson Nano treated as a general operator host | Treat the original Nano as a legacy display candidate, not an administration trust anchor | Its NVIDIA software branch has reached end of life |
| Page-number table of contents and an omitted Word figure | Replace with GitHub navigation and explicit text diagrams | The Markdown document must stand alone |
| General model-safety principles | Add a narrow inference gateway, evidence-ID validation, and adversarial fixtures | Grounding does not itself enforce authority boundaries |

NVIDIA identifies JetPack 4.6.6 / L4T 32.7.6 as the final release of that branch, which includes the original Jetson Nano.[^jetson] This is not a statement about the newer Jetson Orin Nano. A legacy Nano can remain an isolated demonstration display, but sensitive sessions require a maintained operating system and browser. Without a verified maintenance path, use synthetic or non-sensitive output on it.

The earlier legal and standards chapters are retained in the archive, not revalidated or expanded by this revision. The operating premise remains collection from owned or explicitly authorized systems, minimal retention, and no automatic destructive response.

## 2. Scope, evidence, and threat model

### 2.1 What the paper establishes

This is a reference architecture and literature-based engineering assessment. Product documentation establishes intended interfaces and constraints. Memory and storage calculations are planning estimates. Policy examples are templates. Acceptance criteria are proposed experiments, not results.

No throughput, detection accuracy, GPU tokens-per-second, failover time, or prompt-injection resistance was measured on a deployed system for this paper. A version manifest must be created during implementation, including operating systems, drivers, packages, configuration revisions, model artifacts, and rule revisions. A linked documentation page is not a permanent compatibility guarantee.

### 2.2 Assets and adversaries

Protected assets include evidence integrity, operator accounts, management credentials, resolver availability, analytical state, and any sensitive context submitted for inference. Relevant failure sources include compromised clients, hostile log contents, stolen administrative sessions, malicious dependencies, resource exhaustion, and ordinary operator mistakes.

A telemetry source is not trusted merely because its transport is authenticated. A compromised endpoint can send misleading observations. Likewise, a model-generated sentence is not a sensor observation. The design must preserve these distinctions through ingestion, storage, display, and export.

### 2.3 Invariants

1. Router forwarding must not depend on analytics or inference.
2. DNS availability has its own service objective and recovery path.
3. Raw observations are preserved separately from normalized fields and assessments.
4. LLM failure must not stop deterministic detection or evidence ingestion.
5. Routine clients receive necessary DNS access, not administration rights.
6. Model output cannot directly change firewall rules, DNS policy, accounts, or evidence.
7. A dashboard must show missing coverage as missing coverage, not as a clean bill of health.

These are proposed design requirements. Their satisfaction must be demonstrated by the tests in Section 12.

## 3. Reference topology and failure domains

### 3.1 Logical architecture

```text
                           +----------------------+
Internet ----------------->| Router / switch / AP |------> Ordinary clients
                           +----------+-----------+
                                      |
                         optional mirror/TAP copy
                                      v
                           +----------------------+
                           | Dedicated sensor     |
                           | Suricata and/or Zeek |
                           +----------+-----------+
                                      | authenticated evidence ingest
                                      v
+--------------------+     +----------------------+     +----------------------+
| Resolver service   |---->| Core / evidence node |<----| Maintained console   |
| Pi-hole            | logs| ingest, state, rules | API | read-only by default |
| dnscrypt-proxy     |     | retrieval, audit     |     +----------------------+
+--------------------+     +----------+-----------+
                                      | bounded, authorized context
                                      v
                           +----------------------+
                           | Inference host       |
                           | gateway -> local LLM |
                           | NVIDIA GPU           |
                           +----------------------+

Tailscale: authenticated connectivity between explicitly permitted roles.
Host firewalls and LAN/VLAN policy: constrain non-tailnet paths as well.
```

This is a logical design, not a claim about installed equipment. Logical roles can share hardware in a pilot, but shared hardware also shares power, storage pressure, kernel compromise, and reboot failures.

### 3.2 Role and placement matrix

| Role | Initial placement | Responsibility | Explicit exclusion |
| --- | --- | --- | --- |
| Forwarding | Existing maintained router and switching fabric | Routing, DHCP, Wi-Fi, segmentation | LLM inference and analytical storage |
| Resolver | Small maintained Linux host | Pi-hole, dnscrypt-proxy, bounded local export | General browsing, packet inspection, model runtime |
| Core | Pi 4B-class Linux node for a modest pilot | Typed ingest, state, rules, retrieval, health | Assumed multi-gigabit inspection capacity |
| Sensor | Separate supported Linux host when required | Observe selected mirror/TAP traffic and emit records | Routing production traffic through the sensor |
| Console | Maintained browser/device | Evidence views and authenticated analyst actions | Direct database access or model-management access |
| Inference | Dedicated x86-64 NVIDIA workstation | Bounded local language-model requests | Router, resolver, or core availability dependency |
| Recovery | Independent maintained access path | Configuration restoration and credential recovery | Reliance on the failed service being repaired |

A cost-constrained pilot may colocate resolver and core roles. That configuration must be labeled a single failure domain and resource-limited accordingly. It is not equivalent to a physically separate resolver. The recommended mature topology separates them when resolver continuity matters.

### 3.3 Correct interpretation of failure

The original principle that a failed analytics node should not stop forwarding remains valid. However, if that node is also the sole resolver, its failure can stop new name resolution even while the router continues forwarding packets. This is a dependency implied by the proposed topology, not a product defect.

| Failure | Intended behavior |
| --- | --- |
| GPU host unavailable | Evidence collection and rules continue; explanation requests show unavailable or expire |
| Console unavailable | Core and resolver continue; no evidence should depend on an open browser |
| Core unavailable | Sources retain a bounded spool; resolver continues in the separated topology |
| Primary resolver unavailable | Second equivalently filtered resolver is used, or a documented outage is reported |
| Mirror input lost | Sensor health reports loss of visibility; no inference that traffic became safe |
| Tailnet unavailable | No promise of continued remote access; local recovery remains possible |

## 4. Tailscale deployment and access policy

### 4.1 Purpose and limits

Tailscale provides the reference overlay for administration and service-to-service communication. Its grants specify permitted sources, destinations, and network capabilities.[^tailscale-grants] The overlay does not automatically make every enrolled device an administrator, provide application-level roles, or prevent access through a separate local-network route.

The recommended default is no internet-exposed dashboard, resolver, inference API, or database. Use host-local bindings or narrowly permitted service endpoints. Keep native LAN restrictions aligned with tailnet policy. A laptop denied over Tailscale must not obtain the same service by connecting to the host's ordinary Ethernet address.

### 4.2 Enrollment sequence

Use the supported installation process for each operating system.[^tailscale-start] Record the enrolled node, role, software version, and recovery owner. Approve server tags deliberately; restrict who can assign tags. Keep reusable enrollment keys and administrative API credentials out of Git, logs, and inference context.

Establish an independent administrative session before changing access policy. Export the existing policy privately, validate the proposed change, and test it on a noncritical node first. Decide explicitly how server key expiry and reauthentication are handled; uninterrupted access and indefinite credentials are different goals.

On the resolver, avoid automatically accepting the very tailnet DNS configuration that points back to itself. Tailscale's Pi-hole guide documents this setup pattern.[^tailscale-pihole] For an already enrolled Linux resolver, review existing preferences before applying the equivalent supported setting:

```bash
sudo tailscale set --accept-dns=false
tailscale status
tailscale ip -4
```

A working independent resolver/bootstrap arrangement is still needed. Disabling automatic tailnet DNS acceptance does not create an upstream resolver by itself.

### 4.3 Role-based reference policy

The following is a **standalone illustrative policy**, not a safe replacement for an existing tailnet policy. It intentionally omits exit-node internet access, subnet routes, Tailscale SSH rules, and unrelated services. Those require separate review. Tags are example role names, not identifiers from an operating environment.

```json
{
  "tagOwners": {
    "tag:impreavanti-admin": ["autogroup:admin"],
    "tag:impreavanti-client": ["autogroup:admin"],
    "tag:impreavanti-console": ["autogroup:admin"],
    "tag:impreavanti-core": ["autogroup:admin"],
    "tag:impreavanti-dns": ["autogroup:admin"],
    "tag:impreavanti-sensor": ["autogroup:admin"],
    "tag:impreavanti-inference": ["autogroup:admin"]
  },
  "grants": [
    {
      "src": [
        "tag:impreavanti-admin",
        "tag:impreavanti-client",
        "tag:impreavanti-console",
        "tag:impreavanti-core",
        "tag:impreavanti-sensor",
        "tag:impreavanti-inference"
      ],
      "dst": ["tag:impreavanti-dns"],
      "ip": ["udp:53", "tcp:53"]
    },
    {
      "src": ["tag:impreavanti-sensor", "tag:impreavanti-dns"],
      "dst": ["tag:impreavanti-core"],
      "ip": ["tcp:443"]
    },
    {
      "src": ["tag:impreavanti-console"],
      "dst": ["tag:impreavanti-core"],
      "ip": ["tcp:443"]
    },
    {
      "src": ["tag:impreavanti-core"],
      "dst": ["tag:impreavanti-inference"],
      "ip": ["tcp:443"]
    },
    {
      "src": ["tag:impreavanti-admin"],
      "dst": ["tag:impreavanti-core", "tag:impreavanti-dns"],
      "ip": ["tcp:22", "tcp:443"]
    },
    {
      "src": ["tag:impreavanti-admin"],
      "dst": ["tag:impreavanti-inference"],
      "ip": ["tcp:443"]
    }
  ]
}
```

Network access to port 443 is not read-only authorization. The core must separately distinguish source ingestion, console queries, and administrator operations. Likewise, the inference gateway must authenticate the caller and enforce a narrow API even after the overlay permits the connection.

Grants permit access; a restrictive-looking new grant does not override another rule that already allows broader access.[^tailscale-grants] Review the complete effective policy, including existing ACLs, other grants, tags, shared devices, and approved routes. Ordinary clients should not receive the admin tag.

The example allows ordinary OpenSSH transport to selected Linux nodes. It does not enable or configure Tailscale SSH. Windows RDP is deliberately absent. Add either capability only with its own authentication policy and recovery justification.

### 4.4 DNS and exit-node integration

Configure the resolver's Tailscale address as an approved nameserver only after reachability has been tested. DNS override changes resolution policy, not all internet routing. If an exit node is used, explicitly decide whether the private resolver should remain active and configure the documented **Use with exit node** option accordingly.[^tailscale-dns]

Do not install a competing encrypted-DNS client merely to add another security label. It can create an unintended resolver path. Test system DNS, browser-managed DNS, and application-specific behavior independently.

Multiple nameservers are not a guaranteed ordered primary/backup list. Clients or Tailscale may race or reorder requests.[^tailscale-dns] Any resolver advertised as redundancy must enforce the intended filtering policy. An unfiltered public resolver alongside Pi-hole can bypass filtering during normal operation, not only during failure.

### 4.5 Private service exposure

Tailscale Serve can expose a local HTTP service privately over the tailnet, subject to access policy; Funnel is the distinct public-exposure feature.[^serve] The reference design does not require Funnel. HTTPS certificates and name-publication implications should be reviewed before enabling managed HTTPS.

For a tested, authenticated inference gateway already listening locally on port 8765:

```bash
tailscale serve --bg --https=443 http://127.0.0.1:8765
tailscale serve status
tailscale funnel status
```

These commands do not create the gateway or its authentication. The gateway is an implementation requirement, not software included with this paper. Inspect the resulting Serve/Funnel configuration and verify that no public exposure was enabled. The documented background mode persists across service restarts, but it does not ensure that the gateway or model runtime started successfully.[^serve-cli]

## 5. Pi-hole and dnscrypt-proxy deployment

### 5.1 Functional separation

The component name is **dnscrypt-proxy**. It supports encrypted upstream DNS transports; the name does not mean every configuration uses the DNSCrypt protocol rather than DNS-over-HTTPS. Pi-hole's own documentation provides a dnscrypt-proxy integration guide.[^pihole-dnscrypt][^dnscrypt-config]

```text
Remote authorized client
    -> Tailscale-encrypted connection
    -> Pi-hole DNS listener, TCP/UDP 53
    -> loopback dnscrypt-proxy listener, example port 5053
    -> selected encrypted DNS upstream

Approved local client
    -> local-network DNS connection to Pi-hole
    -> same loopback and encrypted-upstream path
```

The local-network client-to-Pi-hole leg is not encrypted merely because dnscrypt-proxy encrypts the upstream leg. Tailscale protects the overlay leg for clients actually using it. DNSSEC validation, encrypted transport, domain filtering, and user anonymity are separate properties.

Pi-hole does not inspect every HTTPS response or establish that a blocked query represented a successful infection attempt. An application may use direct addresses, its own resolver, or an allowed domain. Any enforcement objective beyond ordinary DNS policy needs corresponding endpoint and network controls.

### 5.2 Preflight and ownership

Before installing or changing a resolver:

- Record current resolver addresses, DHCP/DHCPv6 and router-advertisement behavior, listener ownership, and the rollback route.
- Keep a maintained local console or independent management path.
- Identify the installed distribution, package version, service unit, and whether socket activation is used.
- Reserve storage and bounded logging so analytics cannot fill the resolver's disk.

Useful inspection commands on a systemd-based Linux host are:

```bash
sudo ss -lntup
systemctl cat dnscrypt-proxy.service
systemctl cat dnscrypt-proxy.socket
systemctl status pihole-FTL.service --no-pager
```

A missing socket unit means the socket-activated example below is not the applicable deployment path. Do not create a conflicting second listener just to make a copied recipe resemble a different package.

### 5.3 Socket-activated example

For a distribution package that provides `dnscrypt-proxy.socket`, Pi-hole documents a loopback-only alternate port to avoid conflict with FTL on port 53.[^pihole-dnscrypt] An example systemd drop-in is:

```ini
[Socket]
ListenStream=
ListenDatagram=
ListenStream=127.0.0.1:5053
ListenDatagram=127.0.0.1:5053
```

In that deployment, dnscrypt-proxy's corresponding configuration uses:

```toml
# Overlay fragment, not a complete configuration file.
# Preserve the distribution's verified resolver-source configuration.
listen_addresses = []

# Required substitution before use: select and verify an approved
# resolver name from the configured resolver source.
server_names = ['REPLACE_WITH_APPROVED_RESOLVER_NAME']
```

The resolver placeholder is intentionally nondeployable. Select a real resolver, verify its transport and operating policy, and validate the installed package's effective configuration before restarting services. Explicit server selection and automatic resolver-property filtering are not interchangeable; the upstream example notes that `require_*` filters do not apply to explicitly listed `server_names`.[^dnscrypt-config]

For a non-socket-activated installation, the service itself can own `127.0.0.1:5053` through `listen_addresses`. Use one listener-ownership model, not both. Startup flags, paths, privilege dropping, and resolver-source files must follow the selected package.

After the proxy responds correctly, the documented Pi-hole v6 upstream setting is:

```bash
sudo pihole-FTL --config dns.upstreams '["127.0.0.1#5053"]'
```

Review all existing upstream entries; leaving an unintended alternative can defeat the intended path. Apply changes during a controlled window and recheck actual listeners afterward. This paper does not replace the package's complete installation and validation instructions.

### 5.4 Listener exposure and host firewall

The dnscrypt-proxy listener remains loopback-only. Pi-hole accepts queries only from intended clients and interfaces. Tailnet clients may need a Pi-hole listening mode different from the default local-subnet mode; Pi-hole documents the relevant behavior and firewall cautions.[^pihole-config]

Do not use an unrestricted listener as a substitute for correctly designed access control. Tailnet policy and the host firewall should permit only required TCP/UDP 53 traffic. Protect the administration interface separately, including its IPv6 exposure. No WAN port-forward to DNS or the administration UI is required.

Colocating an untrusted application on the resolver host weakens this design because localhost is then shared with that application. A loopback listener is not a per-process authorization mechanism.

### 5.5 Bootstrap, time, and dependency loops

Document how the resolver obtains the information needed to start: upstream endpoint addresses, resolver lists, certificate validation time, and necessary software updates. Do not configure Pi-hole, dnscrypt-proxy, the host resolver, and tailnet DNS so that each waits for another service in a cycle.

Cold-start testing is mandatory. A warm cache can conceal a dependency loop. Record any bootstrap DNS or connectivity probes permitted by the actual proxy configuration, and distinguish them from ordinary client-query forwarding. An assertion that every startup packet is encrypted requires observation, not just a selected encrypted upstream.

### 5.6 Functional checks and failure behavior

On the resolver, test both transports to the proxy and then to Pi-hole:

```bash
dig @127.0.0.1 -p 5053 example.com A +time=2 +tries=1
dig @127.0.0.1 -p 5053 example.com A +tcp +time=2 +tries=1
dig @127.0.0.1 -p 53 example.com A +time=2 +tries=1
dig @127.0.0.1 -p 53 example.com A +tcp +time=2 +tries=1
```

Repeat from an authorized tailnet client and from an authorized local client. Use a controlled test domain with a known answer and a separate deliberately denied fixture. Checking an `AAAA` record is not the same as testing DNS transport over IPv6; test the IPv6 transport path separately when enabled.

For resilience, either deploy a second independently powered, equivalently filtered resolver or document a single-resolver outage as an accepted limitation. A second resolver on the same host is not protection against that host failing. Backup restoration is not automatic failover. Neither is a public unfiltered resolver a policy-equivalent backup.

## 6. DNS evidence and detection engineering

### 6.1 Collect bounded observations

DNS is a useful source of domain activity, response status, filtering decisions, and changes in behavior. It does not reveal every connection or identify the responsible process by itself. Correlate it with endpoint and network evidence where available.

A proposed normalized record includes:

| Field | Purpose |
| --- | --- |
| `event_id`, `schema_version` | Stable reference and parsing contract |
| `observed_at`, `received_at` | Separate observation time from ingestion delay |
| `source_id`, `source_type` | Identify the reporting system and its limitations |
| `client_ref`, `identity_basis` | Preserve how an address was associated with an asset |
| `query_name`, `query_type` | Record only the detail permitted by retention policy |
| `response_code`, `policy_action` | Distinguish failed resolution from filtering |
| `resolver_ref`, `latency_ms` | Support dependency and performance analysis |
| `raw_ref`, `parser_version` | Permit review of the original observation and transform |

When a router forwards requests on behalf of clients, the resolver may see the router rather than the original device. Mark that identity limitation. Do not silently assign shared/NATed observations to a person. Similarly, an IP-to-asset association needs a validity interval, not a permanent join on a reused address.

### 6.2 Export without granting control

Prefer a local export component that sends an approved subset of records to the core. Give the exporter its own restricted ingestion identity. Do not place the resolver's administrative password in the console or model context.

Pi-hole v6 uses session-based API authentication rather than assuming the legacy static-token workflow.[^pihole-api] An application password is not automatically a read-only credential. Where sufficient read-only scope is unavailable, keep collection local and export only necessary observations through a restricted interface. Do not query or copy a live database in a way that bypasses its supported consistency mechanisms.

### 6.3 Rules before explanations

Initial analytical candidates are domain novelty, repeated failures, unusual query bursts, policy changes, and relevant endpoint/network corroboration. These are proposed detection hypotheses, not malware verdicts. Each rule should state its inputs, time window, threshold rationale, exclusions, and evidence links.

A blocked domain is not automatically a confirmed command-and-control connection. High query volume can be legitimate software behavior. A newly observed domain can reflect an ordinary update. Surface corroboration and uncertainty before asking a language model to explain the result.

No rule or model in the initial design automatically updates the blocklist. Blocklist changes require an authenticated operator action, a reason, a revision record, and rollback capability.

### 6.4 Privacy and retention

Set an explicit query-history policy rather than inheriting an unnoticed default. Pi-hole documents both database retention and privacy levels.[^pihole-config][^pihole-privacy] Reducing detail changes the evidence available for analysis; that tradeoff belongs in the design record.

A proposed pilot might retain detailed DNS evidence for seven days and longer-lived aggregates only when justified. Those are design options, not universal requirements. Retention must include exports, prompts, embeddings, backups, and derived reports; deleting a source log does not automatically remove copies elsewhere.

## 7. Collection, storage, and capacity

### 7.1 A realistic Pi role

Start with collection, a small typed API, deterministic rules, a bounded spool, and SQLite or another appropriately sized state store. Add PostgreSQL when concurrency and operational needs justify it. Add Loki and broader search when measured data volume requires them, rather than treating every named component as mandatory on day one.

The Pi's suitability depends on memory, storage, event rate, parser cost, and retention. There is no measured claim here that it can simultaneously run full Suricata, Zeek, Loki, PostgreSQL, vector search, and continuous model inference at arbitrary traffic rates.

For sustained or high-volume packet inspection, use a separate sensor sized against representative traffic. Suricata documents capture statistics and packet-loss analysis; Zeek documents distributing analysis across workers when a single worker reaches its capacity.[^suricata][^zeek] A successful process start is not evidence of complete capture.

### 7.2 Observation placement

A mirror/TAP supplies a copy of traffic visible at a particular point. It does not guarantee visibility into every switched segment or reveal plaintext inside encrypted tunnels. When observing Tailscale or encrypted DNS from outside their endpoints, the sensor generally sees transport metadata rather than the inner application contents. Resolver and endpoint observations therefore complement passive packet observation; they are not redundant.

Keep a capture interface separate from the management path where possible. Define the monitored segments, directionality, oversubscription, timestamp source, and known blind spots. Track dropped packets and stale sensors in the interface.

### 7.3 Capacity math instead of optimistic labels

For average event rate `r`, mean serialized size `s`, and retention `d` days:

```text
Uncompressed event payload bytes = r * s * 86400 * d
```

For illustration only, 100 events/second at 1,000 bytes/event produces 8.64 GB/day of payload, or 60.48 GB over seven days, before indexes, duplicated stores, metadata, backups, and filesystem overhead. Compression may reduce some terms, but must be measured. The example is arithmetic, not a benchmark or a required workload.

A pilot must record event rate, parsing latency, queue depth, resident memory, write volume, storage growth, and query latency. Increase source coverage only after the current envelope is sustainable.

### 7.4 Authentication and storage boundaries

Loki does not provide an included authentication layer; place an authenticating gateway in front of it.[^loki-auth] Keep databases and internal collectors off public listeners. Operator interfaces should query a scoped API, not inherit database credentials.

Use durable local filesystems supported by the selected services. For a Windows inference host, native model files can remain on NTFS; Linux service state should use a supported Linux filesystem. A removable exchange volume is not a live database or the only backup. Model downloads are replaceable; evidence and configuration histories may not be.

## 8. Dedicated inference hardware

### 8.1 The decision is workload-first

The primary inference tier is a dedicated x86-64 workstation with an NVIDIA GPU, separate from resolver and core availability. This replaces the Mac mini example as the preferred implementation for this revision. It is not a benchmark claim that every NVIDIA desktop outperforms every Apple-silicon configuration.

An Apple-silicon system with sufficient unified memory may accommodate a model that exceeds a particular discrete GPU's VRAM. Conversely, a compatible NVIDIA runtime may offer a better fit for the selected CUDA workload. The comparison requires a specific model, quantization, context, concurrency, and actual measurements. A machine's product category alone is insufficient.

### 8.2 Hardware tiers

| Tier | Proposed configuration | Intended use | Limitation |
| --- | --- | --- | --- |
| Reuse / pilot | RTX 3080 10 GB or 12 GB; 32-64 GB host RAM; SSD | Small quantized models, bounded context, one active request | Model/context headroom is limited |
| Preferred expansion | 24 GB VRAM class, such as RTX 3090; 64 GB RAM; NVMe | Larger working set, more context, evaluated concurrency | Fit and responsiveness still require measurement |
| Intermediate option | Supported 16 GB NVIDIA card | More headroom than 10/12 GB, potentially different efficiency | Not equivalent to 24 GB capacity |
| Existing Apple-silicon alternative | Adequate unified memory and supported runtime | Reuse where measured performance meets objectives | Not the baseline in this deployment revision |

The 3080's official memory variants are 10 GB and 12 GB; the 3090 has 24 GB.[^gpu3080][^gpu3090] Ollama lists both families among supported NVIDIA GPUs.[^ollama-gpu] The RAM and storage sizes above are engineering recommendations, not product requirements or purchase quotations. A 2 TB NVMe model/cache volume is a reasonable planning allowance where multiple artifacts will be retained, not a minimum needed to start.

For new procurement, prioritize sufficient VRAM and reliable sustained operation over gaming frame rates. Inspect the exact board variant, cooling, power connectors, PSU requirements, condition, and driver support. No used-market price or performance-per-dollar winner is asserted here.

### 8.3 Memory accounting

A useful first approximation is:

```text
VRAM needed = model weights
            + runtime/quantization overhead
            + attention KV cache
            + compute buffers
            + display/other allocations
            + operating headroom
```

At exactly four bits per parameter, eight billion parameters represent 4 GB of weight bits; fourteen billion represent 7 GB; thirty-two billion represent 16 GB; seventy billion represent 35 GB. These are decimal, weight-only lower-bound calculations. Actual artifacts, mixed-precision tensors, scales, buffers, and runtime behavior change the requirement. A 4 GB model download is not a promise of a 4 GB runtime footprint.

For a conventional transformer with a full per-layer KV cache, an illustrative cache estimate is:

```text
KV bytes = 2 * layers * KV_heads * head_dimension
           * cached_tokens * bytes_per_element * concurrent_sequences
```

A hypothetical 32-layer model with 8 KV heads, head dimension 128, 8,192 cached tokens, and 2-byte elements uses approximately 1 GiB for that cache at one sequence. Four such sequences require approximately 4 GiB before other memory. This example must not be applied unchanged to different attention architectures or cache representations.

Ollama documents increasing memory requirements with context length and parallel requests, and exposes runtime residency through `ollama ps`.[^ollama-context][^ollama-faq] Check actual placement; CPU offload may permit execution but change latency substantially.

### 8.4 Model-selection gate

Begin evaluation with a maintained instruction model in roughly the 7B-9B quantized class, one request at a time, and a bounded 4K-8K context. This is a starting hypothesis for testing on a 3080, not a guarantee that every such model fits or meets quality goals. Evaluate a larger model only after the evidence tasks demonstrate a useful benefit.

Record publisher, license, artifact digest, tokenizer/template, quantization, runtime, context, and evaluation results. Avoid unreviewed remote-code execution during model loading. Keep runtime and model artifacts separate in the manifest so either can be rolled back without silently changing the other.

The benchmark set should include timeline summarization, competing hypotheses, malformed records, unsupported conclusions, citation matching, prompt injection, and explicit abstention. Measure task completion and evidence fidelity, not only tokens per second.

## 9. Windows and Linux runtime deployment

### 9.1 Native Windows baseline

Ollama supports native Windows operation with NVIDIA acceleration and a local API.[^ollama-windows] A supported Windows 11 installation is a reasonable baseline. WSL is not required merely to run a local model.

Use a dedicated service or operator identity, maintained drivers, protected storage, and a documented restart mechanism. Do not turn off antivirus, firewalling, or updates as a generic performance optimization. The core should tolerate maintenance and restarts rather than requiring the workstation to remain permanently unpatched.

Ollama's normal desktop application runs in the background, but that is not proof of unattended readiness before login. A production implementation must demonstrate behavior across boot, logout, runtime crash, GPU driver recovery, and update installation. A pilot may use supervised manual startup; label it accordingly.

### 9.2 Conservative runtime example

After reviewing the installed runtime documentation, a native PowerShell session can set bounded initial values before starting the server:

```powershell
# Pilot session settings; not an unattended Windows service installer.
$env:OLLAMA_HOST = "127.0.0.1:11434"
$env:OLLAMA_CONTEXT_LENGTH = "4096"
$env:OLLAMA_NUM_PARALLEL = "1"
$env:OLLAMA_MAX_LOADED_MODELS = "1"
$env:OLLAMA_MAX_QUEUE = "4"
ollama serve
```

Do not start a second server on the same port while the tray application is already serving. Session environment variables are not a persistent service configuration. Configure the actual service identity separately for unattended operation and test it. The queue and context values are proposed conservative pilot settings, not performance recommendations for every model.[^ollama-faq]

Inspect local operation from another terminal:

```powershell
nvidia-smi
ollama ps
Invoke-RestMethod -Uri "http://127.0.0.1:11434/api/tags" -Method Get
Get-NetTCPConnection -State Listen |
    Where-Object { $_.LocalPort -in 11434,8765 }
```

These checks establish local process/listener observations. They do not demonstrate remote authorization, offline inference, or protection against a compromised local process.

### 9.3 Do not publish the raw model API

Ollama documents that its local API does not require authentication.[^ollama-auth] Keep it on loopback and place a separately implemented gateway in front of it. The proposed external endpoint is HTTPS on port 443 through Tailscale Serve or an equivalent authenticated private reverse proxy, not an exposed raw 11434 listener.

The gateway must constrain caller identity, route, model identity, context size, maximum output, concurrency, queue length, and timeout. It must not pass arbitrary model-management, model-download, or tool-execution requests through to the runtime. A firewall allowing only the core is useful, but does not replace route and payload validation.

Loopback protects network ingress, not other local users or processes. The inference machine therefore should not double as a malware-execution sandbox. Its administrator remains able to inspect or alter the runtime and must be treated as trusted.

### 9.4 Local inference must be demonstrated

Ollama distinguishes local and cloud model access, including cloud-backed requests that can be initiated through a local API.[^ollama-api][^ollama-auth] Consequently, `localhost` in a request does not alone prove that the evidence stayed on the workstation.

Use an allowlisted local model artifact, exclude cloud identifiers and provider credentials, restrict service egress according to the deployment policy, and repeat representative inference with internet egress unavailable after artifacts are provisioned. Schedule model and software updates through a separately authorized maintenance process. Verify observed traffic rather than relying only on branding.

### 9.5 Linux and WSL alternatives

For a dedicated always-on server, native Linux may offer simpler service lifecycle management. Windows remains appropriate when it is the maintained host environment and native inference satisfies the workload. Neither operating-system choice is a substitute for measured reliability.

Microsoft documents CUDA support inside WSL and separate networking modes.[^wsl-cuda][^wsl-network] Use WSL when a required runtime or container workflow benefits from it, not reflexively. It adds a guest lifecycle and networking configuration that must be tested. Do not assume Windows, WSL, containers, and Tailscale all share the same listener exposure or firewall boundary.

## 10. Retrieval, prompt injection, and model authority

### 10.1 Evidence packet construction

The core assembles a small, bounded packet from a case or timeline. Retrieval should use source IDs, time filters, entities, and explicit analyst scope before optional semantic ranking. Large raw log dumps waste context and expand the opportunity for hostile input to influence the response.

A request should include the question, allowed evidence IDs, relevant observations, rule explanations, known gaps, and an output schema. Do not include enrollment tokens, administrator credentials, whole password stores, or unrelated private data. Embedding and indexing pipelines must observe the same scope and retention limits as the original records.

### 10.2 Untrusted text remains untrusted

A hostname, HTTP header, command line, document excerpt, or log message can contain instructions aimed at the model. Treat retrieved text as data, not as authority to override the task. Prompt-injection risk is documented by OWASP; neither a strong prompt nor retrieval alone is a complete boundary.[^prompt-injection]

The primary boundary is capability restriction: the model receives no shell, direct database write path, DNS administration credential, firewall API, or tailnet administration token. It may propose an action in text. An authenticated operator must perform or approve a separately implemented action through a different path.

The first version should not implement autonomous response. That is a deliberate scope decision, not a missing feature to bypass with a permissive agent framework.

### 10.3 Output validation

Structured output helps enforce response shape, and Ollama documents schema-based outputs.[^ollama-structured] Shape is not truth. The application must validate that cited IDs exist, belong to the submitted evidence set, and are available to the requesting operator. It should flag unsupported claims rather than silently discarding inconvenient validation failures.

A proposed result shape is:

```json
{
  "assessment_status": "insufficient_evidence",
  "summary": "The available observations do not establish compromise.",
  "claims": [
    {
      "text": "A new domain was observed during the selected interval.",
      "evidence_ids": ["fixture-event-001"],
      "kind": "observation"
    }
  ],
  "hypotheses": [],
  "limitations": ["No endpoint process attribution is available."],
  "suggested_checks": ["Review the associated endpoint timeline."]
}
```

This is synthetic example data, not a reported incident. Record model digest, prompt revision, context digest, decoding settings, runtime version, and timing with the output. Low temperature can improve consistency but does not establish determinism or factual accuracy.

### 10.4 Resource and outage behavior

Use bounded request bodies, queue limits, deadlines, and output-token limits. A model timeout should produce an unavailable explanation, not an empty finding that appears benign. Do not retry indefinitely or enqueue one model job for every DNS request.

The core remains the source of evidence and deterministic assessments. Model output is an attached analytical artifact with a separate status, provenance, and retention rule. Operators must be able to complete a case without the model.

## 11. Interfaces and evidence contracts

### 11.1 Proposed API surface

These endpoints describe an implementation contract; this revision does not claim that the repository's historical demonstration code already implements them.

| Endpoint | Caller | Required behavior |
| --- | --- | --- |
| `POST /v1/events` | Authorized source/exporter | Validate schema, limit rate and size, assign provenance, deduplicate |
| `GET /v1/entities/{id}` | Authorized analyst | Return scoped entity history and identity confidence |
| `GET /v1/cases/{id}/timeline` | Authorized analyst | Preserve original time, received time, and source gaps |
| `POST /v1/explanations` | Authorized analyst through core | Create a bounded asynchronous explanation request |
| `GET /v1/explanations/{id}` | Authorized analyst | Return explicit pending/success/failure status and cited evidence |
| `GET /health/ready` | Authorized health checker | Report dependency readiness without secrets |

The inference gateway's implementation should accept only the subset of requests needed for explanation. The console must not become a generic runtime proxy. Changes to observations, annotations, suppressions, and configuration should have distinct permissions and audit trails.

### 11.2 Evidence handling

Preserve source-native records where justified, along with normalization status and parser revision. Use stable IDs and content digests to make changes detectable. A digest proves neither that the originating sensor was truthful nor that an event happened as described; it supports integrity comparison of the stored bytes.

Separate observations, asset associations, rule assessments, analyst notes, and model outputs. Corrected parsing should generate a new transformation revision without quietly replacing the original evidence. Unknown or malformed fields should remain visible as parsing issues.

### 11.3 Suggested implementation layout

```text
impreavanti/
  docs/                 architecture decisions, operations, source register
  schemas/              versioned event and explanation contracts
  collectors/           source-specific adapters and bounded exporters
  core/                 ingest, entity resolution, deterministic assessments
  gateway/              constrained local-inference interface
  console/              evidence-first user interface
  policies/             generic access-control templates, no live credentials
  fixtures/             synthetic records, malformed inputs, injection examples
  tests/                unit, contract, isolation, recovery, performance
  manifests/            runtime/model/rule identities, no secrets
```

This is a proposed software layout, not a directory inventory of the current repository. Deployment values, keys, private addresses, and operational logs belong outside a public research publication.

## 12. Validation and acceptance tests

### 12.1 Status and measurement discipline

**Every operational test below is unexecuted in this research revision.** A future test record must contain date, exact configuration, expected result, observation, raw evidence location, reviewer, and disposition. A failed or inconclusive result must not be silently recorded as a pass.

Use a reproducible synthetic workload before exposing production dependencies. Set workload-specific service objectives in advance. Starting evaluation at 100 events/second, one inference request, and a 4K context is a proposed fixture, not a claim that those are the correct final capacities.

### 12.2 Acceptance matrix

| ID | Test | Pass evidence |
| --- | --- | --- |
| NET-01 | Authorized DNS over overlay | TCP and UDP queries reach the approved resolver |
| NET-02 | Ordinary client restrictions | Client cannot reach DNS administration, SSH, core API, or inference gateway |
| NET-03 | Native LAN bypass | The same prohibited services are unavailable through ordinary LAN addresses |
| NET-04 | Correct service paths | Exporter reaches ingest; console reaches authorized read API; core reaches inference gateway |
| NET-05 | Policy breadth | Review and negative tests identify no broader rule bypassing the intended restrictions |
| NET-06 | Public exposure | Authorized external checks find no published resolver, dashboard, gateway, or raw model API |
| DNS-01 | Intended upstream | Queries traverse Pi-hole and the selected encrypted proxy path |
| DNS-02 | Filtering fixture | Deliberately denied domain is denied while a controlled permitted domain resolves |
| DNS-03 | IPv6 behavior | Enabled IPv6 transport follows policy; AAAA lookup alone is not accepted as proof |
| DNS-04 | Cold boot | Resolver starts without a circular DNS/bootstrap dependency |
| DNS-05 | Upstream interruption | Failure is visible; no unapproved plaintext or unfiltered query fallback |
| DNS-06 | Resolver failover | Secondary filtering is equivalent, or the single-resolver limitation is explicitly accepted |
| DNS-07 | Exit-node changes | Private resolver behavior remains as specified during selected exit-node transitions |
| DATA-01 | Identity accuracy | NAT/shared identities are marked ambiguous rather than assigned without evidence |
| DATA-02 | Backpressure | Bounded source spool and queue overflow produce explicit loss/failure signals |
| DATA-03 | Capture capacity | Representative traffic is measured with packet-drop and sensor-health statistics |
| DATA-04 | Storage pressure | Retention and capacity alarms work without disrupting resolver service |
| DATA-05 | Restore | State and configuration restore from an independent backup with integrity checks |
| LLM-01 | GPU residency | Exact model/context placement and memory are observed, not inferred from GPU presence |
| LLM-02 | Local-only inference | Preprovisioned local model completes the task with external egress unavailable |
| LLM-03 | Authorization | Non-core clients cannot invoke gateway; raw runtime remains unreachable remotely |
| LLM-04 | Injection fixture | Hostile evidence cannot cause tool execution or configuration mutation |
| LLM-05 | Citation integrity | Missing, unauthorized, or invented evidence IDs are rejected or visibly flagged |
| LLM-06 | Quality evaluation | Held-out tasks score evidence fidelity, abstention, and analyst usefulness |
| LLM-07 | Host lifecycle | Logout, reboot, driver/runtime failure, and updates have recorded outcomes |
| LLM-08 | Graceful degradation | Collection and deterministic analysis continue while inference is unavailable |

### 12.3 Benchmark record

Record model artifact, quantization, runtime and driver versions, CPU, RAM, exact GPU/VRAM, context length, request count, prompt/output lengths, and background workload. Measure cold and warm time-to-first-token, full completion latency, throughput, peak memory, offload, failure rate, and wall power where relevant.

Separate raw performance from quality. A fast model that invents evidence is not an acceptable improvement. Use held-out cases and explicit scoring criteria; avoid tuning the benchmark until the preferred model wins. An evaluation outcome belongs in a later results section, not retroactively implied by this design document.

## 13. Deployment order and recovery

### 13.1 Staged rollout

| Stage | Deliverable | Gate before proceeding |
| --- | --- | --- |
| 0. Baseline | Asset/role inventory, version manifest, private rollback records | Independent administration and restore materials available |
| 1. Resolver | Standalone Pi-hole and dnscrypt-proxy path | Cold boot, filtering, failure, and listener checks |
| 2. Overlay | Tailscale enrollment and reviewed access policy | Positive and negative tests over overlay and LAN |
| 3. Core | Small ingest/state/API pipeline with synthetic events | Schema, provenance, queue, storage, and restore tests |
| 4. Telemetry | Approved DNS/endpoint sources; optional dedicated sensor | Coverage limits, event rate, loss, and retention measured |
| 5. Inference | Dedicated GPU runtime and constrained gateway | Local-only, authorization, memory, and lifecycle tests |
| 6. Analyst workflow | Evidence views, explanations, annotations | Held-out quality and injection evaluation |
| 7. Operational review | Documented residual risk and ownership | No critical failed or unreviewed acceptance gate |

Do not switch all clients to a new DNS service merely because it answered one query. Do not add every sensor at once. Do not introduce inference before the evidence pipeline is independently useful.

### 13.2 Rollback procedures

**DNS change:** preserve the prior known-good resolver configuration; restore it deliberately when needed; record whether recovery temporarily changes filtering. An emergency availability exception must not masquerade as the normal secure configuration.

**Access-policy change:** retain a private known-good policy and independent administrator route. Use the provider's validation and staged testing before publication. If access is lost, recover through the independent route rather than opening every port.

**Model/runtime change:** keep the previous artifact identity, runtime package, and evaluation results. A failed model update should disable explanations or restore the previous runtime, not interrupt ingestion.

**Core failure:** restore configuration and state, reconcile source spools, and document gaps. A reconstructed timeline should not conceal the period when evidence was unavailable.

### 13.3 Recovery independence

A backup on the same SSD is not recovery from that SSD failing. A remote console reachable only through the broken DNS path is not an independent break-glass route. Identify power, storage, identity-provider, network, and credential dependencies explicitly. Test recovery with synthetic data before a real incident makes improvisation expensive.

## 14. Maintenance, cost, and residual risk

### 14.1 Maintenance budget

Maintain operating systems, VPN clients, resolver packages, model runtimes, drivers, browsers, and dependencies. Pin identities for reproducibility while still having a controlled update process; pinning forever is not a security strategy. Test the relevant acceptance subset after changes.

Record ownership for DNS policy, administrative access, evidence retention, model approval, and recovery. Keep health indicators separate from security findings: a GPU out-of-memory event is an availability problem, not evidence of an intrusion.

### 14.2 Cost model

No live hardware quotation is included. The architecture allows an existing 3080-class system to establish whether the model layer is useful before purchasing a larger GPU. For new procurement, compare model fit, sustained performance, efficiency, cooling, maintenance, and total system cost, not only the graphics-card price.

A 24 GB GPU is the preferred capacity target for expansion, but a newer 16 GB option may be preferable under different power, price, or availability constraints. A 3080 is not rejected; it is assigned a workload consistent with its memory budget. A high-memory Mac remains a legitimate alternative when measured against the same tasks.

Energy should be measured at the wall. As an arithmetic illustration, an additional average 100 W used continuously for 30 days is 72 kWh. Multiply by the actual local tariff; do not substitute graphics-card maximum power for measured average system draw. On-demand inference is possible because the rest of the architecture does not require it to stay online.

### 14.3 Risk register

| Risk | Consequence | Control or explicit limitation |
| --- | --- | --- |
| Single resolver failure | New names stop resolving | Independent second resolver or accepted outage/recovery objective |
| Broad tailnet grant | Unnecessary lateral access | Effective-policy review and negative tests |
| Native LAN bypass | Overlay restrictions circumvented | Segmentation, binding, host firewall, repeated local tests |
| Resolver/core colocation | Analytical load affects infrastructure | Separate hosts or documented shared failure domain |
| Raw model API exposure | Unauthorized inference/model operations | Loopback runtime and constrained authenticated gateway |
| Cloud model invoked through local API | Evidence leaves intended boundary | Local artifact allowlist, restricted egress, offline test |
| Prompt injection | Misleading output or attempted action | Untrusted-input treatment, no tools, validation, human review |
| Evidence identity ambiguity | Incorrect attribution | Validity intervals and explicit uncertainty |
| Legacy Nano software | Weak operator endpoint | Maintained replacement or isolated non-sensitive display |
| GPU VRAM exhaustion | Offload, stalls, or failed requests | Bounded model/context/concurrency and measured headroom |
| Silent packet loss | Incomplete analytical coverage | Capture statistics and visible coverage status |
| Unmaintained dependencies | Security and reliability regressions | Version manifest, update ownership, regression tests |

## 15. Conclusion

Operation Impreavanti should be judged by evidence quality, explainability, safe failure, and repeatable deployment rather than dashboard density. The revised design makes Tailscale an explicit access-control layer, Pi-hole plus dnscrypt-proxy a deliberate DNS service, and a dedicated NVIDIA workstation an independently replaceable inference tier.

A Windows 11 host with an RTX 3080 can support a useful pilot when the selected model, context, and workload fit. For expansion, 24 GB of VRAM offers a more useful capacity target than treating a gaming performance label as an LLM specification. The Raspberry Pi remains a modest core/orchestration option, not an assumed all-in-one high-throughput sensor. The original Jetson Nano is no longer treated as a default high-trust administration endpoint.

The decisive improvement is not the addition of more products. It is a set of explicit contracts: what each component may access, what it records, what it cannot conclude, how it fails, and how that failure is tested. The remaining work is implementation and measurement. This paper supplies the design and acceptance gates, not invented results.

## References

Primary project documentation and manufacturer specifications reviewed for this revision on 24 October 2026. Dynamic documentation can change. Version-specific implementation work must record exact releases and retain the corresponding configuration and evidence.

[^gpu3080]: NVIDIA. [GeForce RTX 3080 family specifications](https://www.nvidia.com/en-us/geforce/graphics-cards/30-series/rtx-3080-3080ti/). Includes 10 GB and 12 GB variants.
[^gpu3090]: NVIDIA. [GeForce RTX 3090 family specifications](https://www.nvidia.com/en-us/geforce/graphics-cards/30-series/rtx-3090-3090ti/). Includes 24 GB memory specification.
[^ollama-gpu]: Ollama. [Hardware support](https://docs.ollama.com/gpu).
[^jetson]: NVIDIA. [Jetson Linux R32.7.6 and JetPack 4 end-of-life notice](https://developer.nvidia.com/embedded/linux-tegra-r3276).
[^tailscale-grants]: Tailscale. [Grants syntax](https://tailscale.com/docs/reference/syntax/grants).
[^tailscale-start]: Tailscale. [Quickstart](https://tailscale.com/docs/how-to/quickstart).
[^tailscale-pihole]: Tailscale. [Pi-hole integration using a Raspberry Pi](https://tailscale.com/docs/solutions/block-ads-all-devices-anywhere-using-raspberry-pi).
[^tailscale-dns]: Tailscale. [DNS in Tailscale](https://tailscale.com/docs/reference/dns-in-tailscale). Includes exit-node behavior and resolver ordering.
[^serve]: Tailscale. [Tailscale Serve](https://tailscale.com/docs/features/tailscale-serve).
[^serve-cli]: Tailscale. [Serve command reference](https://tailscale.com/docs/reference/tailscale-cli/serve).
[^pihole-dnscrypt]: Pi-hole. [dnscrypt-proxy integration guide](https://docs.pi-hole.net/guides/dns/dnscrypt-proxy/).
[^dnscrypt-config]: DNSCrypt project. [dnscrypt-proxy example configuration](https://github.com/DNSCrypt/dnscrypt-proxy/blob/master/dnscrypt-proxy/example-dnscrypt-proxy.toml). Inspected file blob: `686a73e8b6235a079ebe23ec4534480242641502`.
[^pihole-config]: Pi-hole. [FTL configuration reference](https://docs.pi-hole.net/ftldns/configfile/).
[^pihole-api]: Pi-hole. [API authentication](https://docs.pi-hole.net/api/auth/).
[^pihole-privacy]: Pi-hole. [Privacy levels](https://docs.pi-hole.net/ftldns/privacylevels/).
[^suricata]: Open Information Security Foundation. [Suricata 8.0.0 statistics and packet-loss analysis](https://docs.suricata.io/en/suricata-8.0.0/performance/statistics.html). Versioned reference, not a recommendation to deploy an outdated patch level.
[^zeek]: Zeek project. [Cluster setup and worker architecture](https://docs.zeek.org/en/current/cluster-setup.html).
[^loki-auth]: Grafana Labs. [Loki authentication](https://grafana.com/docs/loki/latest/operations/authentication/).
[^ollama-context]: Ollama. [Context length](https://docs.ollama.com/context-length).
[^ollama-faq]: Ollama. [FAQ: configuration, residency, concurrency, and memory](https://docs.ollama.com/faq).
[^ollama-windows]: Ollama. [Windows deployment](https://docs.ollama.com/windows).
[^ollama-auth]: Ollama. [API authentication](https://docs.ollama.com/api/authentication).
[^ollama-api]: Ollama. [API introduction and local/cloud endpoints](https://docs.ollama.com/api/introduction).
[^wsl-cuda]: Microsoft. [NVIDIA CUDA in WSL](https://learn.microsoft.com/en-us/windows/ai/directml/gpu-cuda-in-wsl).
[^wsl-network]: Microsoft. [WSL networking](https://learn.microsoft.com/en-us/windows/wsl/networking).
[^prompt-injection]: OWASP GenAI Security Project. [LLM01: Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/).
[^ollama-structured]: Ollama. [Structured outputs](https://docs.ollama.com/capabilities/structured-outputs).
