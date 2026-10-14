# Post-Quantum Cryptography: A Primer

> A concise overview for technical & IT professionals — covering the quantum threat, NIST standardization status, crypto-agility, and the TLS migration path. Prepared for participants of the **TRUST-Network of WHO**.

---

## 1. Why Post-Quantum Cryptography?

A sufficiently large **quantum computer** breaks the hard mathematical problems that underpin today's public-key cryptography:

| Problem | Algorithms at risk | Quantum attack |
|---|---|---|
| Integer factorization | RSA | Shor's algorithm |
| Discrete logarithm (incl. ECC) | DH, ECDH, DSA, ECDSA, EdDSA | Shor's algorithm |

Once a cryptographically relevant quantum computer exists, an attacker can:
- **Forge signatures** and impersonate identities,
- **Derive session keys** from recorded traffic, and
- **Decrypt** previously captured ciphertext.

Symmetric crypto (AES, SHA-2/3) is far less affected — Grover's algorithm only gives a quadratic speed-up, so doubling the key length restores the security level (e.g. **AES-256** is considered quantum-safe).

### The "Q-day" and Harvest-Now-Decrypt-Later (HNDL)

Adversaries are already **recording encrypted traffic today** so they can decrypt it once a quantum computer arrives. This means data with a long protection horizon is **already at risk**, even though no quantum computer exists yet. The milestone at which a quantum computer can break real-world RSA/ECC is informally called **Q-day**; estimates range from the early 2030s to the 2040s, but the HNDL threat means the effective deadline is **now** for long-lived data.

---

## 2. NIST Post-Quantum Standardization

NIST ran a multi-round competition (2016–2024) to select quantum-resistant public-key algorithms. The first standards were finalized in **August 2024**; a second wave is still in progress.

### Standardized (finalized)

| FIPS | Algorithm | Former name | Family | Purpose |
|---|---|---|---|---|
| **FIPS 203** | **ML-KEM** | CRYSTALS-Kyber | Module-lattice | Key encapsulation (KEM) |
| **FIPS 204** | **ML-DSA** | CRYSTALS-Dilithium | Module-lattice | Digital signatures |
| **FIPS 205** | **SLH-DSA** | SPHINCS+ | Hash-based | Digital signatures (stateless, conservative) |

### In progress / upcoming

| Algorithm | Former name | Family | Purpose | Notes |
|---|---|---|---|---|
| **FN-DSA** | Falcon | Lattice (NTRU) | Digital signatures | To be published as **FIPS 206**; smallest signatures, fast verification |
| **HQC** | — | Code-based | KEM | Selected by NIST as a **backup KEM** to ML-KEM (different hardness assumption); standardization in progress |
| **FrodoKEM** | — | Lattice | KEM | Chosen by **ISO** (not NIST); for special use cases |
| **Classic McEliece** | — | Code-based | KEM | NIST waiting on ISO; very large public keys, niche use only |

> **Take-away:** ML-KEM and ML-DSA are the primary workhorses for the transition. SLH-DSA is the conservative fallback (hash-based, well-trusted but large). HQC and FN-DSA are still maturing.

---

## 3. The Five PQC Algorithm Families

| Family | Hard problem | Examples | Trade-offs |
|---|---|---|---|
| **Lattice-based** | Shortest/Closest Vector Problem | ML-KEM, ML-DSA, FN-DSA, FrodoKEM | Good performance & key sizes; moderate theoretical confidence |
| **Hash-based** | Hash preimage resistance | SLH-DSA (SPHINCS+), XMSS, LMS | Very conservative security; **large signatures** |
| **Code-based** | Syndrome decoding | Classic McEliece, HQC, BIKE | McEliece: huge public keys; HQC: balanced |
| **Multivariate** | Solving multivariate quadratic systems | (e.g. Rainbow — broken) | Historically fragile; little NIST support |
| **Isogeny-based** | Supersingular isogeny paths | SIDH/SIKE — **broken** | Effectively out of the running |

Only **lattice-** and **hash-based** schemes have made it to finalized FIPS standards; **code-based** HQC is on deck as a KEM alternative.

---

## 4. Hybrid Schemes — the Recommended Transition Path

Because PQC algorithms are new and less battle-tested than RSA/ECC, the recommended approach during the transition is a **hybrid** combining one classical and one post-quantum algorithm. Security holds as long as **at least one** of the two components remains unbroken.

**Key exchange — the concrete hybrid to use now:**
- **`X25519MLKEM768`** — hybrid of Curve25519 (classical) + ML-KEM-768 (PQC). Supported by:
  - OpenSSL 3.5.0+
  - Go v1.24 crypto library (and software built on it, e.g. Traefik v3.5)
  - liboqs 0.11.0+ (via the OQS-OpenSSL provider)
  - wolfSSL 5.7.4+

**Signatures** — hybrid compositions (e.g. ML-DSA + ECDSA, SLH-DSA + Ed25519) are defined in IETF drafts and supported via `liboqs` providers, but standardization of named TLS cipher suites is still catching up.

> Both BSI (TR-02102) and NIST recommend hybrids for the transition period until PQC maturity grows.

---

## 5. Migration & Crypto-Agility

### What is crypto-agility?
The ability to **swap cryptographic algorithms, key sizes, and protocols** through configuration rather than re-engineering — so that a future migration to PQC (or away from a broken scheme) can happen with minimal downtime.

Concretely this means (per BSI TR-02102-1):
- Cryptographic methods in **interchangeable, clearly separated modules**
- Algorithm selection **not hard-coded** — configurable via authorized interfaces
- Functions to **deactivate, replace, and migrate** persistent data to new methods
- **Documented migration paths** for switching schemes
- Hardware **reserves** in performance and storage for the larger PQC key/signature sizes

### Migration playbook (high level)

1. **Inventory** — find every place crypto is used (TLS endpoints, code signing, VPN/IPSec, cert authorities, stored secrets, backups, KMS/HSM, archived data).
2. **Classify by protection horizon** — which data must stay confidential beyond ~2030–2031? Those are your first targets.
3. **Assess crypto-agility** — is the algorithm pluggable, or hard-coded? Flag the latter for refactor.
4. **Pilot hybrid** — start with TLS using `X25519MLKEM768` on a non-critical service.
5. **Roll out** progressively; monitor interop, performance (larger keys/messages), and failures.
6. **Plan for re-keying & re-encryption** of long-lived persistent data.
7. **Update procurement & standards** — require PQC readiness from vendors and in architecture review.

---

## 6. Practical Pointers

- **TLS 1.3** is required for hybrid PQC key exchange (TLS 1.2 cipher suites don't carry the PQC KEM). Make sure your stack supports and negotiates TLS 1.3.
- **Larger payloads** — ML-KEM public keys (~1184 bytes for 768) and ML-DSA signatures (~3300 bytes) are much bigger than X25519/ECDSA. Test for message-size limits, handshake fragmentation, and certificate-bundle growth.
- **Performance** — lattice ops are generally competitive with ECC, but hash-based signatures (SLH-DSA) are slow to sign. Profile before wide rollout.
- **Side-channel caution** — PQC schemes are newer and less analyzed for side-channel/fault-injection resistance than classical crypto. This is exactly why **hybrid** is recommended during the transition.
- **Don't roll your own** — use established libraries (OpenSSL, Bouncy Castle, liboqs, wolfSSL); bespoke PQC implementations need expert review.

---

## 7. Key References

| Source | What it gives you |
|---|---|
| **NIST PQC project** — https://csrc.nist.gov/projects/post-quantum-cryptography | Standardization status, FIPS 203/204/205 |
| **ETSI TR 103 619** — [Migration strategies and recommendations to Quantum Safe schemes](https://www.etsi.org/deliver/etsi_tr/103600_103699/103619/01.01.01_60/tr_103619v010101p.pdf) (V1.1.1, 2020-07) | Three-stage migration framework: inventory → plan → execution; migration checklists; Mosca's theorem |
| **ETSI GR QSC 004** — Quantum-Safe threat assessment | Threat landscape and rationale for migration |
| **ETSI EG 203 310** — Quantum Computing Impact on security of ICT Systems | Business continuity and algorithm selection recommendations |
| **ETSI TR 103 617** — [Quantum-Safe Virtual Private Networks](https://www.etsi.org/deliver/etsi_tr/103600_103699/103617/) | QS VPN for isolating security domains during migration |
| **ETSI TR 103 305-1** — Critical Security Controls for Effective Cyber Defence | Methods for crypto asset inventory compilation |
| **ETSI/IQC Quantum Safe Cryptography Conference** — [2026 edition](https://www.etsi.org/events/2592-etsi-iqc-qsc-conference-2026/) | Annual forum on PQC transition; "Wait & see is not an option" |
| **BSI TR-02102-1** (2025-01) — Cryptographic Mechanisms: Recommendations and Key Lengths | Approved algorithms, key lengths |
| **BSI TR-02102-2** — TLS | Allowed cipher suites for TLS 1.2/1.3 |
| **IETF `draft-ietf-tls-pqc`** | Hybrid TLS named groups (X25519MLKEM768, etc.) |
| **IETF `draft-ietf-lamps-pq-composite-sigs`** | Composite/hybrid X.509 signatures |
| **RFC 9881 / 9935 / 9909** | Algorithm identifiers for ML-DSA / ML-KEM / SLH-DSA in X.509 |
| **liboqs / Open Quantum Safe** — https://openquantumsafe.org | Reference open-source PQC implementations + OpenSSL provider |
| **EJBCA** — https://www.ejbca.org | Open-source CA with ML-DSA / FN-DSA support; free PQC Lab Test Drive |

---

## 8. PQC Algorithms Suitable for TLS

TLS uses cryptography in three distinct roles. PQC affects each one differently.

### 8.1 Key exchange (replaces ECDHE / DHE) — use a KEM

This is where the quantum threat bites hardest, because the session key is what protects record traffic — exactly the target of Harvest-Now-Decrypt-Later.

- **TLS 1.3 is mandatory.** TLS 1.2 cipher suites cannot carry a PQC KEM; the named-group extension that signals ML-KEM only exists in TLS 1.3 (RFC 9180 family / IETF `draft-ietf-tls-pqc`). BSI TR-02102-2 and other standards bodies repeat: *"If a hybrid implementation of classical and post-quantum cryptography is used (requires TLS 1.3), then the classical part must comply with the applicable key-length requirements."*
- **Recommended today: the hybrid group `X25519MLKEM768`** (Curve25519 classical + ML-KEM-768 PQC). It is the only concrete hybrid that is both standardized in the IETF TLS registry and broadly supported:
  - OpenSSL 3.5.0+
  - Go v1.24 crypto/tls (and software built on it, e.g. Traefik v3.5)
  - liboqs 0.11.0+ (via the OQS-OpenSSL provider)
  - wolfSSL 5.7.4+
- **Other hybrids being standardized** (IETF `draft-ietf-tls-pqc`): `secp256r1MLKEM768`, `secp384r1MLKEM1024`, `X448MLKEM768`, `X448MLKEM1024`. Useful when you must satisfy BSI's preference for Brainpool/NIST curves in the classical component.
- **Pure ML-KEM (no classical component) is not recommended** during the transition: it lacks the maturity of ECC for side-channel / fault-injection resistance, and eliminates the classical safety net.
- **HQC, FrodoKEM, Classic McEliece** — not yet finalized, large public keys (Classic McEliece public keys are ~1 MB). Not suitable for production TLS today.

| KEM option | Status | Use for TLS now? |
|---|---|---|
| `X25519MLKEM768` | Standardized hybrid | **Yes — primary choice** |
| `secp256r1MLKEM768` | IETF draft, supported in OpenSSL 3.5+ | Yes, if BSI-curve preference required |
| ML-KEM-768 alone | FIPS 203 | No — maturity risk, no classical fallback |
| HQC | NIST round 4 (not finalized) | No |
| FrodoKEM / Classic McEliece | ISO track / niche | No (huge keys) |

### 8.2 Authentication / signatures (replaces RSA / ECDSA in certificates)

This is the harder long-term problem because certificates live for months/years and CA chains must all agree on the algorithm.

- **ML-DSA** (FIPS 204) — the primary recommendation. Signatures ~3.3 KB (ML-DSA-65). Available in OpenSSL 3.5+, liboqs 0.12+, wolfSSL 5.8+, Bouncy Castle 1.86.
- **SLH-DSA** (FIPS 205) — conservative, hash-based, but signatures are **7–50 KB**. Too large for a normal TLS handshake (will blow past MTU and force fragmentation). Reserve for code signing, long-term archives, and root CAs where signature size doesn't matter.
- **FN-DSA** (Falcon, future FIPS 206) — smallest PQC signatures (~660 B for FN-DSA-512), fast verification. Promising for TLS but not yet finalized.
- **Composite / hybrid signatures** (IETF `draft-ietf-lamps-pq-composite-sigs`) — e.g. `ML-DSA-65 + ECDSA-P256`, or `ML-DSA-65 + Ed25519`. This is the **right transition choice for certificates**: you get classical maturity plus PQC future-proofing in a single X.509 object.

| Signature option | Cert sig size | Use for TLS certs? |
|---|---|---|
| ML-DSA-65 | ~3.3 KB | **Yes — primary**, ideally as composite with ECDSA |
| ML-DSA-87 | ~4.6 KB | Yes (higher security) |
| SLH-DSA-128s | ~7.8 KB | Marginal — too large for handshake |
| SLH-DSA-256f | ~50 KB | **No** — use for code signing / roots only |
| FN-DSA-512 | ~660 B | Promising, not yet finalized |
| Composite ML-DSA + ECDSA | ~3.4 KB | **Recommended transition form** |

### 8.3 Record encryption (symmetric) — already quantum-safe

No change. AES-256-GCM (preferred), AES-128-GCM, CHACHA20-POLY1305. Grover only halves the effective security, so AES-256 stays at 128-bit quantum security. BSI TR-02102-1 recommends AES-256 against Grover.

### 8.4 NOT suitable for TLS

- **HQC, FrodoKEM, Classic McEliece** — not finalized; McEliece keys are ~1 MB
- **LMS / XMSS** — stateful hash-based signatures; meant for code signing / firmware, not interactive TLS (state management breaks if a signature is ever replayed)
- **Picnic, Rainbow (broken), GeMSS** — not viable

### 8.5 Recommended TLS configuration today

```
Protocol:     TLS 1.3 only
Key exchange: X25519MLKEM768   (hybrid — protects against HNDL)
Symmetric:    TLS_AES_256_GCM_SHA384  (fallback: TLS_CHACHA20_POLY1305_SHA256)
Server cert:  ML-DSA-65 (composite with ECDSA-P256 once CAs support it)
              — interim: ECDSA-P256/384 (classical component must meet
                minimum key lengths per BSI TR-02102-1: RSA/DH ≥3000 bit,
                ECC ≥250 bit)
Client cert:  same as server (mTLS)
```

### 8.6 Piloting `X25519MLKEM768` with OpenSSL

Prereq: OpenSSL ≥ 3.5.0 (built with the `oqsprovider` or native ML-KEM support).

```bash
# 1. Check the group is available on your OpenSSL build
openssl list -tls-groups | grep -i mlkem

# 2. Test handshake against a known PQC-enabled test endpoint
openssl s_client -connect test.openquantumsafe.org:6061 \
  -groups X25519MLKEM768 \
  -servername test.openquantumsafe.org </dev/null

# 3. Stand up a local test server using a self-signed cert
openssl req -x509 -newkey ec:<(openssl ecparam -name prime256v1) \
  -keyout server.key -out server.crt -days 365 -nodes \
  -subj "/CN=pqc-pilot.local"

# Run the server forcing the hybrid group
openssl s_server -accept 8443 -cert server.crt -key server.key \
  -groups X25519MLKEM768 -www

# From another terminal, connect and verify the negotiated group
openssl s_client -connect localhost:8443 -groups X25519MLKEM768 </dev/null \
  | grep -E "Server Temp Key|Peer signature type|Cipher"
```

For a Go service (Go ≥ 1.24):

```go
cfg := &tls.Config{
    MinVersion: tls.VersionTLS13,
    // Go 1.24+ enables X25519MLKEM768 automatically when both sides support it.
    // To force it, set CurvePreferences:
    CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
}
```

NGINX (≥ 1.27.4 built against OpenSSL 3.5+):

```nginx
ssl_protocols       TLSv1.3;
ssl_ecdh_curve      X25519MLKEM768:secp256r1;
ssl_cipher_suite    TLS_AES_256_GCM_SHA384;
```

> **Pilot tip:** run the hybrid group alongside the classical group in a preference list (`X25519MLKEM768:secp256r1`). Clients that support the hybrid will use it; legacy clients fall back to `secp256r1` and stay connected. This gives you a zero-downtime rollout path.

---

## 9. Organizational Impact of Migrating TLS to PQC

The migration framework below follows **ETSI TR 103 619** — *"CYBER; Migration strategies and recommendations to Quantum Safe schemes"* ([V1.1.1, 2020-07](https://www.etsi.org/deliver/etsi_tr/103600_103699/103619/01.01.01_60/tr_103619v010101p.pdf)). ETSI defines the migration target as the **Fully Quantum Safe Cryptographic State (FQSCS)** — the state wherein *all* cryptographic assets use Quantum Safe Cryptography — and breaks the path into three stages: **(1) Inventory compilation, (2) Preparation of the migration plan, (3) Migration execution**.

> **ETSI's key message** (from the [2026 ETSI/IQC Quantum Safe Cryptography Conference](https://www.etsi.org/newsroom/news/wait-see-is-not-an-option-q-day-is-here/)): *"Wait & see is not an option: Q-day is here."* Migration takes time, the quantum transition is highly complex, and **cryptographic agility** is a prerequisite. Post-quantum cryptography alone is not sufficient — long-term resilience requires a broader strategy incorporating crypto-agility, trust diversity, defence-in-depth, and new approaches to trust establishment and key management.

### 9.1 Stage 1 — Inventory compilation

> *"Migration cannot be planned without prior knowledge of the assets in the organization that will be impacted by a Quantum Computer."* — ETSI TR 103 619, clause 5.2

ETSI requires a full inventory of cryptographic assets and processes before any planning can begin. The inventory should capture assets in all forms — hardware and software — and their dependencies on organizational infrastructure, hardware, and supply-chain components. If an asset is not under the organization's direct control (e.g. app-store-signed software, third-party TLS endpoints), the inventory must identify the party liable for its migration.

The inventory should be compiled using at least one of:
- The **checklist questions in Annex A** of ETSI TR 103 619 (see below)
- The methods described in **[ETSI TR 103 305-1](https://www.etsi.org/deliver/etsi_tr/103300_103399/10330501/)** — Critical Security Controls for Effective Cyber Defence

#### ETSI inventory checklist categories (Annex A.1)

| Category | What to capture |
|---|---|
| **Risk assessment** | What risks will information disclosure create (monetary, compliance, legal, reputation)? How long must confidentiality be maintained per asset? Are keys/certs issued to third parties? Can damage from crypto service degradation be quantified? Is there a plan to protect encrypted assets in case of crypto failure? |
| **Data assessment** | What data classes are subject to encryption (PII, trade secrets, government classified)? How long must confidentiality hold per class? Is encrypted data deleted on schedule? What are the consequences of disclosure? Is encrypted data normally exposed to attackers (in transit, public cloud)? |
| **Cryptographic assessment** | For each key: strength, algorithm binding, usage (signature/encryption/application-specific)? Effective strength against classical and quantum attacks? Issuance and expiration dates? Are all keys inventoried and locatable? Are keys easy to revoke and reissue? |
| **Infrastructure inventory** | What crypto libraries and protocol libraries are in use? What keys, by what applications? Who is authorized to manage which keys/modules/devices? What certificates are issued and by whom? What crypto hardware is in use? Which applications use which libraries, keys, and protocols? |
| **Supplier inventory** | Do CA agreements hold the CA to an SLA for timely reissuance? Can/will application vendors re-sign applications timely? Do revocation/reissuance requests get priority? What obligations do data custodians have in case of algorithm breach? Are CSRs retained for reissuance? Are software vendors obligated to timely crypto-breach fixes? |

**For TLS specifically**, the inventory must cover: every TLS endpoint, every certificate, every library/runtime that terminates TLS, every programmatic TLS client (SDKs, mobile apps, IoT), every partner/B2B integration, every load balancer, middlebox, and proxy in the TLS path.

**Practical tools:** scan with `sslyze --tlsv1_3` or Nmap NSE `ssl-enum-ciphers`; pull cert inventories from your CA (e.g. EJBCA), cloud certificate managers (AWS ACM, GCP Certificate Manager, Azure Key Vault), and Kubernetes cert-manager (`kubectl get certificates -A`).

#### Roots of trust

ETSI emphasizes that the inventory must identify the **root of trust** for each asset — the trust anchor that underpins its security. ETSI defines several forms (clause 5.2):
- **Root of Trust for Verification (RTV)** — verifies digital signatures associated with software/firmware
- **Root of Trust for Storage (RTS)** — protected repository for keying material (often the HSM)
- **Policy Enforcement Engine** — enforces security policy capabilities
- **Root of Trust for Measurement (RTM)** — measures system state (cryptographic hash of platform elements)
- **Root of Trust for Reporting (RTR)** — for remote attestation services

The inventory must also assess whether each device can **generate and store a key pair** for the Quantum Safe solution that will replace the current one (clause 5.2, Note 6). Many HSMs offer crypto-agility only *within the same cryptographic family* (e.g. changing the ECC curve), not across families (e.g. from ECC to lattice-based) — this limitation must be recorded.

#### Governance — board-level activity

ETSI is explicit (clauses 5.3, 6.8, 7.3): **migration is a board-level (senior strategic management) activity**. The framework requires:

1. **Appoint a migration inventory manager** — a single manager responsible for compiling the inventory, reporting to the migration planning manager.
2. **Appoint a migration manager** — a single manager with responsibility for executing the migration, with knowledge of the overall business and access to all parts of the organization.
3. **Allocate budget** — for inventory compilation, migration planning, and execution, including the cost of downtime management. *"The compilation of the inventory can incur significant cost (financial, temporal, organizational and for technical provisions) if no equivalent inventory already exists."*
4. **Manage downtime** — the plan may require pausing parts of the organization; this must be approved before entering execution.

### 9.2 Stage 2 — Preparation of the migration plan

> *"The migration plan should include: a full inventory of assets; for each asset — whether it will be migrated, when, and an orderly sequence of migration of inter-dependent assets; the migration solution chosen (full QS crypto or hybrid); testing including dependency testing."* — ETSI TR 103 619, clause 6.1

#### Migration planning principles (ETSI clause 6.1)

- **Not all assets will need migration.** Some can be retired or made obsolete through redesign.
- **Sequence matters.** If asset A depends on asset B, then B must be migrated before A. Dependencies identified in the inventory drive the migration order.
- **Choose full QS or hybrid per asset.** ETSI notes that *"hybrid solutions are a way-point on the path to QSC and do not represent the end state"* (Annex B) — hybrid solutions must themselves eventually be migrated to FQSCS.
- **Backwards compatibility.** If a phased migration requires backwards compatibility, the application must support both classical and QS algorithms — either via individual classical and QS end-entity certificates, or via hybrid certificates, depending on the crypto-agility of the relying parties.
- **Dependency testing** is stressed — not just functional testing but testing of cryptographic dependencies across the supply chain.

#### PKI considerations (ETSI clause 6.1 & 6.4) — deeper treatment

This is one of the two hardest blockers (the other is HSM, §9.3). ETSI is explicit:

> *"For any PKI in the inventory, and the Public Key Certificates (PKCs) that implement it, every entity in the PKI will need new PKCs that contain Quantum Safe public keys."* — clause 6.1

> *"A certificate chain that relies on a classical trust anchor cannot be considered Quantum Safe."* — clause 6.4, Note 3

> *"Any certificate that has been signed using a classical algorithm, and all certificates below it in the chain, can potentially be replaced with a certificate forged by a quantum attacker."* — clause 6.4, Note 2

What needs to happen for PQC certs to flow:

1. **CA software upgrade.** [EJBCA](https://www.ejbca.org/) Community 9.x / Enterprise 9.6+ support ML-DSA (Dilithium) and FN-DSA (Falcon) for Root CAs, Issuing CAs, and end entities. Keyfactor offers a free **[PQC Lab Test Drive](https://docs.keyfactor.com/test-drives/latest/keyfactor-pqc-lab-test-drive)** on Azure (30-day SaaS) to practice issuing ML-DSA certs via CMP/EST/ACME/REST and signing artifacts with SignServer. **Caveat:** as of EJBCA 9.6.2, HSM Crypto Tokens require the **Enterprise Edition** — Community Edition users must either buy Enterprise or deactivate HSM tokens (see §9.3).
2. **Certificate profile changes.** New X.509 profiles with ML-DSA or composite (ML-DSA + ECDSA) signature algorithms. Algorithm identifiers are standardized in [RFC 9881](https://datatracker.ietf.org/doc/html/rfc9881) (ML-DSA), [RFC 9935](https://datatracker.ietf.org/doc/html/rfc9935) (ML-KEM), [RFC 9909](https://datatracker.ietf.org/doc/html/rfc9909) (SLH-DSA). ETSI notes (clause 6.4) that *"it is straightforward to include a Quantum Safe public key in the Subject Key Info field of an X.509 end-entity certificate provided that the Quantum Safe algorithm has a corresponding algorithm ID and the CA knows how to encode the public key"* and that *"experiments have shown that many existing cryptographic libraries are able to handle large certificates."*
3. **CA/Browser Forum & root program updates.** Public CAs can't issue ML-DSA certs to the public Web PKI until the Baseline Requirements and root-store policies (Apple, Microsoft, Mozilla, Google) recognize ML-DSA. Expect first public PQC root certificates in 2026–2027. Until then, **public-facing TLS services cannot yet present PQC certs to browsers** — focus PQC PKI pilots on internal services first.
4. **PKI entity capability assessment.** ETSI (clause 6.1) requires that the plan *"identify the ability of any PKI entity to handle certificates containing the larger Quantum Safe public keys and signatures. If any PKI entity cannot handle QSC primitives these entities should be marked for replacement."* This applies to CAs, RAs, validation libraries, OCSP responders, and CRL distributors alike.
5. **Trust anchor migration.** A PKI updated to QS needs new trust anchors and certificate chains containing QS signatures. During a phased migration, the PKI must support both classical and QS signing algorithms — via parallel certificate chains or hybrid certificate chains depending on the crypto-agility of relying parties.
6. **Interplay between PKI upgrade and application upgrade.** ETSI (clause 6.1) warns: *"Migration planning should take into account the interplay between upgrading the PKI and upgrading the various applications that depend on it. There may be an order of operations necessary in order to minimize cost or downtime."*
7. **Crypto-agility for new/updated entities.** ETSI (clause 6.1): *"If a vulnerability is found in the Quantum Safe algorithm, it may be necessary to switch to a different Quantum Safe algorithm entirely... Ensuring cryptographic agility will make this significantly easier."*
8. **OCSP / CRL.** EJBCA can generate CRLs for PQC CAs; OCSP for PQC is still in development. Plan for CRL-based revocation during the transition.

| CA / service | Role | PQC status |
|---|---|---|
| **Public CAs** (DigiCert, Sectigo, Let's Encrypt, etc.) | Public TLS certs | RSA/ECDSA only. CA/Browser Forum baseline requirements and root-store policies still being updated. |
| **ACME-issued DV certs** (Let's Encrypt, etc.) | Automated DV certs | Same — no PQC key algorithms in standard ACME profiles. |
| **cert-manager (Kubernetes)** | Automated cert lifecycle | `privateKey.algorithm` only accepts `RSA` or `ECDSA`. Needs CRD/provider changes for ML-DSA. |
| **Cloud certificate managers** (AWS ACM, GCP Cert Manager, Azure Key Vault) | Managed TLS certs | Only RSA/ECDSA key types. No PQC. |
| **Internal private CAs** (EJBCA, etc.) | Internal services | EJBCA 9.x supports ML-DSA / FN-DSA — pilot PQC here first. |

#### Hardware-Based Security Environment (HBSE) — deeper treatment

This is the other hard blocker, and it's the one most teams underestimate. ETSI dedicates clause 6.3 to it:

> *"The Quantum Computing risk to the Hardware Based Security Environment (HBSE) is that the implementation of each may not be optimized for Quantum Safe Cryptography."* — ETSI TR 103 619, clause 6.3

> *"If any asset to be migrated is dependent on an HBSE, then that HBSE should be migrated to ensure it supports the algorithm and cryptographic key requirements of the migrated asset before the depending asset is migrated."* — ETSI TR 103 619, clause 6.3

ETSI also notes that the TPM specification (ISO/IEC 11889-1:2015) supports only RSA and ECC using prime curves — it is **not** Quantum Safe — and that fielded HSMs may have been in service for 10+ years and predate QSC evolution. Many HSMs offer crypto-agility only *within the same cryptographic family*, not across families.

| HSM vendor | PQC support status |
|---|---|
| **Thales Luna** (formerly SafeNet) | Luna 7.x firmware ≥7.13.0 / Luna 8.x — announced ML-KEM and ML-DSA support in firmware updates rolling out 2025–2026. Older Luna 5/6 cannot be upgraded. |
| **Thales PaymentServer / Atalla** | Payment-focused; PQC roadmap less clear; ask the vendor. |
| **Utimaco SecurityServer** | ML-KEM/ML-DSA in firmware via the "PQC extension pack" — available on newer CSE/QSE modules; older firmware versions don't have it. |
| **Entrust nShield** (formerly nCipher) | Announced PQC support in nShield 5.x firmware; `nShield as a Service` cloud HSM adding PQC algorithms in 2025–2026. |
| **AWS CloudHSM** | Backed by Luna; PQC support follows Thales firmware. Not yet generally available for ML-KEM/ML-DSA. |
| **Azure Dedicated HSM** | Same — Luna-based, follows Thales. |
| **GCP Cloud HSM** | Currently supports RSA/ECDSA only; no PQC algorithms in the managed service yet. |
| **AWS KMS / Azure Key Vault / GCP KMS** | Managed APIs only expose RSA and ECDSA key types. **No PQC key types.** You cannot create an ML-KEM or ML-DSA key in AWS KMS today. |
| **HashiCorp Vault** | PQC via PKCS#11 provider (liboqs) in software mode — not FIPS-validated, not HSM-backed for PQC. |

**The practical consequence** (per ETSI clause 6.3 — HBSE must be migrated *before* depending assets):

1. **CA private keys must be in an HSM.** If your HSM firmware doesn't support ML-DSA, your CA cannot sign ML-DSA certificates without violating the HSM mandate. Options: upgrade firmware, buy newer HSMs, or **hybrid key split** (classical ECDSA in HSM + PQC ML-DSA in software, combined into a composite signature) as a documented transition posture.
2. **High-security application keys** — same logic. You need PQC-capable HSM firmware before you can move a high-security service's TLS to a PQC or hybrid signature.
3. **Cloud KMS doesn't help yet.** AWS KMS, Azure Key Vault, and GCP KMS do not expose PQC key types. Flag this as a known gap in your security assessment and track the cloud providers' roadmaps.

**Recommendation:** Audit the HSM estate now (model, firmware, dependent applications). Engage vendors (Thales, Utimaco, Entrust) for PQC firmware roadmaps and FIPS 140-3 validation. Pilot composite signatures on an internal EJBCA Enterprise with an HSM-backed ECDSA key + software ML-DSA, documented as a formal risk acceptance. Push hyperscalers for PQC key types in KMS.

#### Key management during migration (ETSI clause 6.4)

ETSI notes that including a QS public key in an X.509 certificate is straightforward if the algorithm has an algorithm ID and the CA can encode it. The ease of use depends on whether the application allows algorithm negotiation (e.g. via the Signature Algorithms extension in TLS 1.3, RFC 8446). This capability *"suggests that migration using X.509 is possible now"* (clause 6.4).

Critical ETSI warnings:
- *"Any certificate that has been signed using a classical algorithm, and all certificates below it in the chain, can potentially be replaced with a certificate forged by a quantum attacker."* (Note 2)
- *"A certificate chain that relies on a classical trust anchor cannot be considered Quantum Safe."* (Note 3)

#### Trust management during migration (ETSI clause 6.5)

The roles and relationships in trust infrastructures remain constant through migration, but the technical means change. For example, a Root Authority may require face-to-face signing ceremonies — the scheduling of such ceremonies and the distribution of new keys and certificates throughout the infrastructure must be considered in the migration plan. The transfer of each root of trust to a Quantum Safe model is a key element of the plan.

#### Isolation approaches during migration (ETSI clause 6.6)

> *"Not all systems will be updated at the same time. As a part of a migration strategy sub-systems should be isolated as far as is possible to discrete security domains. Security domains that need to be interconnected may then be interconnected by Quantum Safe pathways, such as Quantum Safe VPNs as defined in [ETSI TR 103 617](https://www.etsi.org/deliver/etsi_tr/103600_103699/103617/)."* — clause 6.6

#### Access to non-QSC protected resources after migration (ETSI clause 6.7)

ETSI recognizes that it may be **economically infeasible** to migrate all encrypted assets. In such cases:
- Non-migrated assets should be **physically and logically quarantined** from external attack.
- A facsimile of the PKI should be maintained in the quarantine zone.
- Certificates may expire in quarantine — processes must allow cryptographic operations to continue even if normal protocols/policies fail.
- **Multi-generation assets** (e.g. patient health records, critical infrastructure) should *always* be migrated to the latest generation.

#### Disorderly transition planning (ETSI Annex A.2.2)

ETSI distinguishes **orderly** (planned) from **disorderly** (emergency) transitions. For disorderly transitions, the plan should address:
- **Table-top and simulation exercises** for crypto algorithm failure response
- **Supplier/partner agreement updates** to cover algorithm failure
- **Saved CSRs** retained for emergency certificate reissuance
- **CA agreement updates** to cover algorithm failure
- **Emergency software distribution** — arrangements to securely receive and deploy patches while network protocol and code signing crypto is insecure
- **E-risk / cyber insurance** for cryptographic algorithm failures

#### Supplier readiness (ETSI Annex A.2.1)

The plan should verify:
- Do all suppliers have **quantum readiness plans**?
- Is the organization and its supply chain **participating in standards groups** preparing for QSC? (e.g. [ETSI CYBER](https://www.etsi.org/committee/cyber), [ETSI/IQC QSC Conference](https://www.etsi.org/events/2592-etsi-iqc-qsc-conference-2026/))
- Are partners **testing and certifying** QSC algorithms and QSC-enabled products in advance?
- Are partners investigating or implementing **hybrid classical/PQC modes**?
- Will infrastructure support **rapid replacement** of crypto algorithms and protocols (crypto-agility)?
- Are partners **engaging with regulators** on use of PQC?

### 9.3 Stage 3 — Migration execution

> *"Only when the migration plan is in place can migration be implemented."* — ETSI TR 103 619, clause 6.2

ETSI's Stage 3 is about implementing the plan from Stage 2 against the inventory from Stage 1. Key elements:

**Migration management (clause 7.1):** Implement the plan. The elements of management are similar to any large project — but with the added dimension that every link in the chain of security with a QC vulnerability, or a dependence on an asset with a QC vulnerability, must be updated for migration to be considered a success.

**Mitigation management (clause 7.2):** Management checkpoints track progress. Where checkpoints are missed, mitigations from the plan are invoked. ETSI stresses the value of **simulation exercises** — they *"can uncover missing inventory elements (it is highly probable that the inventory will be incomplete, or that the supply chain has breaks that need to be found and mitigations designed into the plan)."*

**Business process requirements (clause 7.3):**
1. The migration manager should be given lead and responsibility for the process.
2. The migration manager should be given financial and organizational backing.
3. The migration manager should not stop partway through a phase of the migration plan.

### 9.4 Library & runtime upgrades

| Stack | Min version for `X25519MLKEM768` | Common reality |
|---|---|---|
| OpenSSL | 3.5.0+ | Many systems still on 1.1.1 (EOL) or 3.0.x |
| wolfSSL | 5.7.4+ (KEM) / 5.8.0+ (ML-DSA) | Embedded / appliance estate lags |
| Bouncy Castle Java | 1.86 (general) / FIPS 2.1.1 + PQC add-on | Java apps often pin older BC |
| Go | 1.24+ | Go runtimes upgrade relatively quickly |
| Traefik | 3.5+ | Built on Go 1.24 |
| NGINX | 1.27.4+ against OpenSSL 3.5 | Ingress controllers need rebuild |
| HAProxy | 3.0+ against OpenSSL 3.5 | Same |
| Java JSSE | JDK 17+ with BC provider, or JDK 21+ native | LTS lines lag |
| Browsers | Chrome 116+, Firefox 120+, Safari 17+ | Client side is largely ready |

**Cost:** every runtime that terminates TLS on behalf of a service (load balancers, sidecars, API gateways, ingress controllers) must be upgraded and revalidated. This is a multi-quarter program, not a patch. Per ETSI, the migration plan must account for the orderly sequence of inter-dependent assets and dependency testing.

### 9.5 Performance

| Component | Classical (ECDSA-P256 / X25519) | PQC (ML-DSA-65 / ML-KEM-768) | Hybrid |
|---|---|---|---|
| Public key | 32–64 B | 1184 B (ML-KEM-768) / 1952 B (ML-DSA-65) | sum |
| Ciphertext / signature | 64 B / 64 B | 1088 B (KEM ct) / 3309 B (DSA sig) | sum |
| Handshake overhead | ~1 KB | ~5–10 KB | ~6–11 KB |
| CPU (keygen / sign / verify) | fast | ML-DSA sign ~0.1 ms, verify ~0.05 ms on modern x86; ML-KEM encapsulate/decapsulate ~0.05 ms | ~2× classical |
| TLS handshake wall-clock | baseline | +5–15 ms | +10–20 ms |

ETSI (Annex B, FAQ) addresses hardware readiness directly: *"Can existing hardware cope with hybrid systems, in terms of memory, processing power, crypto agility? Not always. For symmetric key systems to cope with increased key size... the required combination of memory, i/o and processor bandwidth may not be available. Hardcoded systems with no crypto-agility may not be able to cope at all."*

**Risks:**
- **Handshake > MTU.** A hybrid cert chain (root + intermediate + leaf, each with ML-DSA + ECDSA sigs) can exceed 10 KB and fragment across multiple TCP segments. Middleboxes that block fragmented TLS will drop the handshake.
- **CPU on small instances.** Lattice operations are competitive with ECC on modern x86/ARM, but IoT and small VMs will feel the overhead. Benchmark before rollout.
- **Mitigations:** TLS session resumption (0-RTT), HTTP/2 connection reuse, connection pooling, hardware TLS offload.

### 9.6 Interop & client compatibility

Older clients (legacy browsers, old SDKs, IoT firmware, partner B2B integrations) won't negotiate `X25519MLKEM768` or verify ML-DSA certs. Strategies:
- **Offer classical fallback** in the group preference list: `X25519MLKEM768:secp256r1:x25519`. PQC-aware clients use the hybrid; legacy clients fall back to `secp256r1`.
- **Watch for downgrade risk.** An active attacker could strip the hybrid group to force classical. TLS 1.3's downgrade protection (RFC 8446 §4.1.3) mitigates this if both sides implement it correctly — verify your stack.
- **Partner onboarding.** For B2B TLS connections, coordinate rollout windows with partners. The partner's stack must support the same hybrid group.
- **Isolation.** ETSI (clause 6.6) recommends isolating sub-systems to discrete security domains during migration, interconnecting via Quantum Safe pathways (e.g. QS VPNs per [ETSI TR 103 617](https://www.etsi.org/deliver/etsi_tr/103600_103699/103617/)).

### 9.7 Middleboxes & network gear

Firewalls, IDS/IPS, WAFs, load balancers (F5 BIG-IP, Citrix ADC, AWS NLB/ALB, Azure App Gateway, GCP LB), proxies (Squid, Apache mod_proxy) may:
- Drop the `X25519MLKEM768` group as unknown → fallback works, but no PQC.
- Drop fragmented TLS handshakes > MTU → connection fails entirely.
- Perform TLS interception (SSL decryption) with their own cert chain — they need PQC-aware interception too.

**Action:** test each middlebox in the path before enabling PQC on a service. Load balancers and cloud-managed LBs are the most likely blockers — check vendor PQC firmware roadmaps.

### 9.8 ACME / cert-manager automation

Most ACME pipelines (cert-manager in Kubernetes, cloud-native certificate managers) currently request RSA or ECDSA keys only. To issue ML-DSA / composite certs automatically:
- cert-manager needs updated `Certificate` CRD supporting ML-DSA key algorithm + composite profiles.
- CA ACME account profiles need to accept PQC key types.
- The cert-manager `privateKey.algorithm` field needs new values (`ML-DSA`, `Composite`).

Until then, PQC cert issuance is a **manual or scripted** process via EJBCA CMP/REST — not yet integrated into automated cert lifecycles. This is a tooling gap to close. ETSI (Annex A.2.1) recommends verifying whether partners are *"investigating or implementing hybrid classical/PQC modes of operation"* and whether infrastructure *"will support rapid replacement of crypto algorithms and protocols"*.

### 9.9 Long-lived data & archived ciphertext

HNDL means traffic captured today is at risk tomorrow. For data already in transit, nothing can be done retroactively. For **stored data** encrypted or wrapped with RSA/ECC keys:
- Re-encrypt long-term stored secrets (backups, archives, KMS-wrapped data keys) with AES-256 (quantum-safe) wrapped by a PQC or hybrid key.
- Re-sign long-term archives with ML-DSA or composite signatures to preserve non-repudiation beyond Q-day.
- ETSI (clause 6.7): where it is economically infeasible to migrate all encrypted assets, non-migrated assets should be **quarantined** (physically and logically) and risk-managed. Multi-generation assets (patient health records, critical infrastructure) should *always* be migrated to the latest generation.
- ETSI (clause 6.2): *"Where the base state is that all data is encrypted and also subjected to cryptographically assured file integrity the non-QSC encryption should not be removed (i.e. go clear) prior to imposing the QSC based encryption mode."*

### 9.10 Crypto-agility

ETSI defines crypto-agility (clause 3.1) as *"the property that permits changing or upgrading cryptographic algorithms or parameters."* It is a prerequisite for migration — without it, switching to a different PQC algorithm (if a vulnerability is found in the current one) requires re-engineering.

Concrete refactor checklist:
- Remove hard-coded cipher suite strings and DH group IDs from application code; externalize to config.
- Wrap crypto in a provider interface (JCA `Provider`, Go `crypto/tls.Config`, OpenSSL `SSL_CTX` with config files) so algorithms can change without code edits.
- Add a "crypto config" configmap/secret consumed by all services.
- Document the migration path for each service (current algorithm → target hybrid → future pure PQC).
- Reserve CPU and memory headroom on containers running TLS — ETSI (Annex B) warns that *"hardcoded systems with no crypto-agility may not be able to cope at all"* with the larger PQC key sizes.

### 9.11 Mosca's Theorem — when to start

ETSI (Annex B, FAQ) references Mosca's framework for deciding when to act:

- **X** = the number of years the public key cryptography needs to remain unbroken (data protection horizon)
- **Y** = the number of years it will take to replace the current system with one that is Quantum Safe
- **Z** = the number of years it will take to break the current tools using quantum computers or other means
- **T** = the number of years it will take to develop trust in Quantum Safe algorithms

> *"If X + Y + T > Z, any data protected by that public key cryptographic system is at risk and immediate action needs to be taken."* — ETSI TR 103 619, Annex B

An organization can determine X and Y. Industry at large gives guidance on T and Z. The controllable element is Y — the migration time. As Dr. Michele Mosca stated at the [2026 ETSI/IQC Conference](https://www.etsi.org/newsroom/news/wait-see-is-not-an-option-q-day-is-here/): *"The goal is not to predict exactly when that future will arrive. The goal is to ensure that when it does, society is ready."*

### 9.12 Compliance, risk & architecture review

- Update the **security assessment** for every service moving to hybrid TLS. The new algorithms and the HSM/software key-split posture (if used) need to be reflected in your compliance declarations.
- Deviations (e.g. software-only PQC key because the HSM firmware isn't ready) must be documented as **formal risk acceptance** with a remediation date.
- New hybrid deployment patterns should be reviewed by your security/architecture governance.
- Cloud KMS gaps (no PQC key types) should be tracked as known gaps and linked to the cloud providers' roadmaps.
- ETSI (Annex A.2.2) recommends investigating **cyber insurance for cryptographic algorithm failures** and updating supplier/partner agreements to cover algorithm failure scenarios.

### 9.13 Skills, training & vendor management

The [2026 ETSI/IQC Conference](https://www.etsi.org/newsroom/news/wait-see-is-not-an-option-q-day-is-here/) highlighted a critical gap: *"there is a shortage of experts and engineers specialised in post-quantum cryptography"* and *"most resources have been dedicated to AI, resulting in a lack of PQC readiness at all levels, including at the board level."*

- Devs and ops need training on KEM APIs (not just key-agreement), hybrid cert chains, larger handshake payloads, and new failure modes (fragmentation, downgrade). New runbooks for PQC TLS troubleshooting.
- Push vendors (cloud providers, HSM vendors, LB vendors, CA vendors) for PQC roadmaps and FIPS-validated PQC. Write PQC readiness into procurement requirements and RFP scoring.
- ETSI (Annex A.2.1) recommends verifying supplier readiness plans, standards participation, and product testing as part of the migration plan.
- Engage with standards bodies: [ETSI CYBER](https://www.etsi.org/committee/cyber), the annual [ETSI/IQC Quantum Safe Cryptography Conference](https://www.etsi.org/events/2592-etsi-iqc-qsc-conference-2026/), NIST PQC project, IETF `draft-ietf-tls-pqc` and `draft-ietf-lamps-pq-composite-sigs`.

### 9.14 Timeline

| Phase | Activity | ETSI stage | Indicative duration |
|---|---|---|---|
| 0 — Now | Inventory compilation: crypto assets, HSM estate, CA estate, roots of trust, suppliers | Stage 1 | 1–3 months |
| 1 | Preparation of migration plan: sequence, dependencies, hybrid vs. full QS per asset, testing plan, budget, downtime plan, disorderly transition plan | Stage 2 | 3–6 months |
| 2 | Upgrade TLS libraries/runtimes to PQC-capable versions | Stage 3 | 6–12 months |
| 3 | Pilot internal hybrid TLS (X25519MLKEM768) on a non-critical service | Stage 3 | 3 months |
| 4 | Stand up internal PQC PKI (EJBCA Enterprise + HSM) issuing composite certs | Stage 3 | 6–12 months |
| 5 | Roll hybrid TLS across internal services (ordered by dependency) | Stage 3 | 12–24 months |
| 6 | Re-encrypt long-lived stored data; re-sign long-term archives; quarantine non-migrated assets | Stage 3 | parallel, 12–24 months |
| 7 | Public PQC certs once CA/Browser Forum supports ML-DSA | Stage 3 | 2026–2027 (external dependency) |
| 8 | Full PQC / FQSCS (drop classical component) once standards & HSMs mature | Stage 3 | 2028–2030+ |

Per ETSI's Mosca framework: if your data protection horizon (X) + migration time (Y) + trust-building time (T) exceeds the time to a viable quantum computer (Z), action is needed now. For most organizations with long-lived data, X + Y + T > Z is already true.

### 9.15 Common pitfalls

1. **"We'll just flip the cipher suite."** No — ETSI's three-stage framework shows the whole stack (inventory, plan, library, HSM, CA, LB, cert-manager, middleboxes, supply chain) must move together.
2. **Incomplete inventory.** ETSI (clause 7.2) warns it is *"highly probable that the inventory will be incomplete, or that the supply chain has breaks that need to be found."* Simulation exercises uncover these.
3. **Forgetting the HSM.** ETSI (clause 6.3) is explicit: the HBSE must be migrated *before* the depending asset. Discovering at go-live that your HSM can't sign ML-DSA is the most common PQC project failure.
4. **Downgrade to classical.** If the group preference list puts `secp256r1` first, PQC-aware clients may still pick it; order matters.
5. **Handshake fragmentation.** A 10 KB hybrid cert chain over a 1500-byte MTU middlebox silently breaks connections.
6. **Cert validity clocks.** PQC certs are new; cert-manager renewal timers and OCSP/CRL freshness need re-tuning.
7. **Public CAs can't issue PQC yet.** Don't plan public-facing PQC certs for 2026 — plan hybrid key exchange (which doesn't need a PQC cert) and internal PQC PKI.
8. **KMS isn't HSM.** AWS/GCP/Azure KMS are convenient but currently have no PQC key types and aren't a substitute for a PQC-capable HSM for high-security apps.
9. **Hybrid is not the end state.** ETSI (Annex B): *"Hybrid solutions are a way-point on the path to QSC and do not represent the end state... Hybrid solutions have themselves to be migrated to the end state."*
10. **No disorderly transition plan.** ETSI (Annex A.2.2) requires planning for emergency migration — table-top exercises, saved CSRs, CA agreement updates, emergency software distribution, and cyber insurance for algorithm failures.

---

## 10. TL;DR

- Quantum computers will break RSA and ECC; symmetric crypto is fine with longer keys (AES-256).
- NIST finalized **ML-KEM**, **ML-DSA**, and **SLH-DSA** (FIPS 203/204/205, Aug 2024); **FN-DSA** and **HQC** are still maturing.
- For **TLS**: use **`X25519MLKEM768`** hybrid key exchange (TLS 1.3 mandatory); use **ML-DSA** (ideally composite with ECDSA) for certs; AES-256-GCM for records is already quantum-safe.
- Use **hybrid** schemes during the transition — but remember ETSI's warning: *"hybrid solutions are a way-point on the path to QSC and do not represent the end state."*
- **Crypto-agility** is the enabling property (ETSI TR 103 619 §3.1): the ability to change or upgrade cryptographic algorithms or parameters without re-engineering.
- **ETSI's three-stage framework**: (1) Inventory compilation → (2) Preparation of the migration plan → (3) Migration execution. Migration is a **board-level activity** with a dedicated migration manager and budget.
- **Mosca's theorem** (ETSI Annex B): if X (data protection horizon) + Y (migration time) + T (trust-building time) > Z (time to quantum break), act now. For most organizations with long-lived data, this is already true.
- **The two hardest blockers are HSM and PKI**: audit your HSM firmware PQC readiness and your CA's ML-DSA issuance capability now — ETSI requires the HBSE to be migrated *before* any depending asset.
- Start now: inventory (ETSI Stage 1), plan with dependency ordering and disorderly-transition contingencies (Stage 2), then execute with simulation exercises to uncover inventory gaps (Stage 3).