# CT-Watchtower - technical specification

**Containerised monitoring of public Certificate Transparency logs with a multi-tenant rule engine, scoring, enrichment and threat intel feeds.**

| | |
|---|---|
| Document version | 1.0 |
| Status | A specification ready for implementation |
| Audience | the developer implementing the project |
| Working title / repo | `ct-watchtower` |
| Proposed license | Apache-2.0 |

---

## Table of contents

1. [Goal and scope](#1-goal-and-scope)
2. [System architecture](#2-system-architecture)
3. [Data sources and polite polling](#3-data-sources-and-polite-polling)
4. [Normalisation and the prefilter](#4-normalisation-and-the-prefilter)
5. [Tenant and rule model](#5-tenant-and-rule-model)
6. [The scoring engine](#6-the-scoring-engine)
7. [Enrichment](#7-enrichment)
8. [Alerting](#8-alerting)
9. [Data handling and being frugal with storage](#9-data-handling-and-being-frugal-with-storage)
10. [The HTTP API](#10-the-http-api)
11. [Exports: CSV, JSON, STIX, TAXII, MISP](#11-exports-csv-json-stix-taxii-misp)
12. [The user interface](#12-the-user-interface)
13. [Operation, containers, configuration](#13-operation-containers-configuration)
14. [The repository and publishing on GitHub](#14-the-repository-and-publishing-on-github)
15. [Quality assurance and rule tuning](#15-quality-assurance-and-rule-tuning)
16. [Law, data protection, ethics](#16-law-data-protection-ethics)
17. [Later stages and further ideas](#17-later-stages-and-further-ideas)
18. [Appendices](#18-appendices)

---

## 1. Goal and scope

### 1.1 What the system does

CT-Watchtower reads the public Certificate Transparency stream, checks every domain name appearing in it against tenant-specific rulesets, scores hits with a traceable score, enriches relevant findings with context data and serves the results as a UI, an API and machine-readable feeds.

Typical uses:

- **Brand protection / financial products** - spotting `paylio-security-login.top` shortly after the certificate was issued, so typically hours to days before the first phishing wave.
- **Online shopping** - fake shops with brand or category terms.
- **Your own identity / corporate** - domains containing your own company name, product name or a person's name.
- **Feed generation** - the findings as an IOC feed for a SIEM, a firewall, a DNS sinkhole or MISP.

### 1.2 What the system explicitly does **not** do

- No user management, no login, no roles. The application runs in a trusted network. Protection happens in front of it (a reverse proxy, a VPN, `bind: 127.0.0.1`).
- No active scanning of the domains found in standard operation. Optional active modules can be switched off explicitly and are **off** by default (see [§7.6](#76-active-modules-opt-in)).
- No storage of the complete CT stream. The project is deliberately designed as a filter, not as an archive (see [§9](#9-data-handling-and-being-frugal-with-storage)).
- No automated takedown. There are only aids for preparing an abuse report.

### 1.3 Non-functional goals

| Goal | Requirement |
|---|---|
| Throughput | processing the full Chrome log list stream on 4 vCPU / 8 GB RAM |
| Latency | certificate to finding in the UI: a median below 60 s from visibility in the log |
| Storage | under 5 GB of database size at 90 days of retention with a typical rule engine |
| Failure behaviour | a restart of any component without data loss and without gaps in the log progress |
| Dependencies | no paid APIs strictly required |

---

## 2. System architecture

### 2.1 Components

```
                  ┌───────────────────────────────────────────────────────┐
                  │                  CT logs (public)                     │
                  │  RFC 6962 get-entries  •  static-ct-api tiles         │
                  └──────────────────────────┬────────────────────────────┘
                                             │  HTTPS, throttled
                              ┌──────────────▼───────────────┐
                              │        ct-ingest (N)         │  checkpoints in Redis/DB
                              │  log sharding, backoff       │
                              └──────────────┬───────────────┘
                                             │ Redis stream  cert.raw  (MAXLEN ~ 200k)
                              ┌──────────────▼───────────────┐
                              │        normalizer            │  IDN, wildcards, eTLD+1,
                              │   + the global prefilter     │  dedupe filter, Aho-Corasick
                              └──────────────┬───────────────┘
                                             │ Redis stream  cert.candidate
                              ┌──────────────▼───────────────┐
                              │      scorer (N)              │  rulesets per tenant,
                              │   phase 1 scoring            │  score + explanation
                              └───────┬──────────────┬───────┘
                                      │              │ Redis stream  finding.enrich
                     PostgreSQL ◄─────┘              ▼
                          ▲                 ┌────────────────────┐
                          │                 │    enricher (N)    │ RDAP, DoH, ASN, GeoIP
                          │                 │  phase 2 scoring   │ cache + rate limits
                          │                 └─────────┬──────────┘
                          │                           │
                          ├───────────────────────────┘
                          │
        ┌─────────────────┼──────────────────┬──────────────────┐
        ▼                 ▼                  ▼                  ▼
   ┌─────────┐      ┌──────────┐      ┌────────────┐     ┌────────────┐
   │   api   │      │ notifier │      │ scheduler  │     │  exporter  │
   │ REST/SSE│      │ webhooks │      │ retention, │     │ CSV/JSON/  │
   │  + UI   │      │ mail,... │      │ aggregates │     │ STIX/TAXII │
   └─────────┘      └──────────┘      └────────────┘     └────────────┘
```

**Why it is split this way:** the ingest is network and I/O bound, the scoring is CPU bound, and the enrichment is bound by latency and rate limits. Separate processes allow independent scaling and keep a slow RDAP query from blocking the log progress.

### 2.2 Technology recommendation

| Building block | Recommendation | Reason / alternative |
|---|---|---|
| Backend language | Python 3.12, `asyncio` + `uvloop` | the best library situation for CT, RDAP, STIX. An alternative for `ct-ingest`: Go, if throughput becomes the bottleneck. |
| HTTP client | `httpx` (async, HTTP/2) | connection pooling, timeouts, retries |
| Validation | `pydantic` v2 | the rule schema, the configuration, API models |
| API | FastAPI + Uvicorn | the OpenAPI spec falls out for free |
| Bus | Redis Streams with consumer groups | lightweight, with `MAXLEN` as a natural backpressure brake. An alternative: NATS JetStream. |
| DB | PostgreSQL 16 | partitioning, JSONB, full text. For single-machine setups an optional SQLite profile. |
| Multi-pattern matching | `pyahocorasick` (a C extension) | tens of thousands of terms in one pass |
| Fuzzy matching | `rapidfuzz` | Damerau-Levenshtein in C++ |
| eTLD+1 | `tldextract` with a **locally maintained** public suffix list | no network access at runtime, see §3.5 |
| STIX | `stix2` (the OASIS reference library) | correct SDO serialisation |
| Frontend | HTMX + Alpine.js + Tailwind, server rendered | no build step, a small image. An alternative: React/Vite, if the team prefers that. |
| Metrics | `prometheus-client` | `/metrics` per service |

> **A note to the developers:** the choice of language is a recommendation, not a requirement. What matters are the interface contracts (the Redis stream message formats, the DB schema, the API specification) - those are defined language-neutrally.

### 2.3 Message formats on the bus

**Stream `cert.raw`** (from the ingest):

```json
{
  "v": 1,
  "log_id": "oak2026h1",
  "idx": 918273645,
  "seen_at": "2026-09-15T10:22:31.118Z",
  "not_before": "2026-09-15T10:20:00Z",
  "not_after": "2026-09-21T10:20:00Z",
  "issuer_cn": "E7",
  "issuer_o": "Let's Encrypt",
  "serial": "03a1...",
  "sha256": "9f2c...",
  "is_precert": true,
  "names": ["*.payli0-secure.top", "payli0-secure.top"]
}
```

The raw certificate is **not** passed on, only the fields needed for the scoring. That reduces the bus volume by orders of magnitude.

**Stream `cert.candidate`** (from the normalizer): as above, plus a preprocessed object per name:

```json
{
  "name": "payli0-secure.top",
  "unicode": "payli0-secure.top",
  "ascii": "payli0-secure.top",
  "is_idn": false,
  "wildcard": true,
  "labels": ["payli0-secure", "top"],
  "registrable": "payli0-secure.top",
  "subdomain": "",
  "tld": "top",
  "skeleton": "paylio-secure.top",
  "prefilter_hits": ["paylio"]
}
```

`skeleton` is the homoglyph-normalised form (see [§4.3](#43-the-homoglyph-skeleton)).

---

## 3. Data sources and polite polling

### 3.1 Two modes of operation

The ingest module supports two sources. Both can be chosen through the configuration; mode B is the recommended one for production.

**Mode A - the CertStream websocket (a quick start)**

A CertStream server in front delivers already parsed certificates over a websocket. That is connected with a few lines of code and suits the first phase of development very well.

Important: the historically well-known public endpoint of CaliDog is **not to be treated as reliable infrastructure** - it has repeatedly been unreachable for longer stretches in the past, and the original project is barely maintained any more. Whoever wants to use this mode in production runs an instance of their own. The recommended, actively maintained implementation: `certstream-server-go` (a drop-in compatible protocol, with a container available). It is taken into the compose file as an optional service.

The client has to:
- handle reconnects with exponential backoff and jitter,
- recognise heartbeat messages and count them as liveness,
- use the bandwidth-saving channel if the server offers one (hostnames only instead of complete certificates).

**Mode B - polling the CT logs directly (production)**

The ingest talks to the logs itself. That removes any dependency on intermediate infrastructure, and the progress is exactly controllable.

The log landscape is currently split in two, and both variants have to be supported:

| Variant | Access | Note |
|---|---|---|
| **RFC 6962** | `GET {url}ct/v1/get-sth`, `GET {url}ct/v1/get-entries?start=&end=` | classic, still widespread. Chrome accepts new RFC 6962 logs at least into the 2026s. |
| **static-ct-api (tiled logs)** | signed checkpoints, tiles under `/tile/...`, entries under `/tile/data/...` | the newer, CDN-friendly variant. Let's Encrypt runs its production logs (Sunlight-based) this way; its old RFC 6962 log was shut down in early 2026. |

**Where the log list comes from:** the authoritative list sits at `https://www.gstatic.com/ct/log_list/v3/all_logs_list.json`. The schema holds two arrays: `operators[].logs` (RFC 6962) and `operators[].tiled_logs` (static-ct-api). Evaluate both.

Requirements for the log list handler:
- Fetch it **once an hour** at most, cache the result on disk, use `ETag`/`If-Modified-Since`.
- Follow only logs in state `usable` (optionally `qualified` as well); skip `readonly`, `retired` and `rejected`.
- Filter shard logs by their validity period: logs whose `temporal_interval` ends in the past deliver no new certificates any more.
- Take new logs on automatically, deregister vanished ones cleanly (archive the checkpoint, do not delete it).
- The cached list is the **fallback**: if the fetch fails, the system keeps running with the last known list.

### 3.2 Polling discipline

These rules are binding. CT logs are free common-good infrastructure; impolite polling is a reason to be blocked.

1. **A checkpoint per log.** What gets persisted is `log_id`, `last_index`, `tree_size`, `updated_at`. After a restart it continues exactly there. Checkpoints live in PostgreSQL (durably), not only in Redis.
2. **The poll interval.** 30 s per log by default, configurable. Not below 10 s. On an unchanged tree head: double the interval up to 300 s at most, and reset it on a change.
3. **Respect the batch size.** RFC 6962 logs often return fewer entries than requested. What actually arrives is what counts, and the effective batch size is learned and stored per log.
4. **Limit the parallelism.** At most 2 simultaneous connections per log host, at most 4 connections per operator. A global semaphore as the upper bound.
5. **Backoff.** On HTTP 429 and 5xx: exponential backoff from 5 s up to 15 min, with ±20 % jitter. `Retry-After` always takes precedence. Three consecutive failures mark the log as `degraded` (a metric plus a display in the UI), ten as `suspended` for 30 min.
6. **The user agent.** Meaningful and with a way to make contact, `ct-watchtower/1.2 (+https://github.com/<org>/ct-watchtower)` for example. That is good practice and makes it easier for log operators to get in touch instead of blocking.
7. **Use HTTP/2 and keep-alive**, and reuse the connection pool per host.
8. **No catching up at any price.** If the checkpoint is more than `max_backlog` entries behind (2 million by default), it is not caught up at full force but at a throttled rate and with a warning. Optionally: a jump to the current log head with the gap recorded - for a phishing early-warning system, currency matters more than completeness. The behaviour is configurable (`backlog_policy: catch_up | skip_to_head`).

### 3.3 Backpressure

The Redis stream `cert.raw` is capped with `XADD ... MAXLEN ~ 200000`. In addition the ingest checks the stream length before every batch:

- `< 50 %` of the limit -> normal operation
- `50-80 %` -> double the poll interval
- `> 80 %` -> pause the polling, increment the metric `ingest_throttled_total`

That way a slow scorer loses no data; the log progress slows down instead, and picks up again automatically once the pressure is off.

### 3.4 Duplicates across logs

The same certificate typically appears in several logs, and a precertificate plus the final certificate are two entries for the same thing. Deduplication happens in the normalizer through the SHA-256 of the TBS certificate, or `(issuer, serial)` as a stand-in, in a Redis set with a 6 h TTL. Without that step the alert volume multiplies.

### 3.5 The public suffix list

The PSL is **not loaded from the network at runtime**. It ships as a file in the image and is updated by a weekly CI job (Dependabot-like, through a pull request). The reason: reproducible builds, no network access at startup, no silent change of behaviour in production.

---

## 4. Normalisation and the prefilter

### 4.1 Name handling

For every SAN entry and for the CN:

1. Trim, normalise to lower case.
2. Remove a leading `*.`, set the flag `wildcard = true`. The base name is what gets scored.
3. Remove the trailing dot.
4. Resolve IDN both ways: A-label (`xn--`) and U-label. Keep both forms, with the flag `is_idn`.
5. Discard invalid names (empty, an IP address only, `localhost`, internal names without a valid TLD).
6. Split into labels, separate into `registrable` (eTLD+1) and `subdomain` through the PSL.
7. Compute the homoglyph skeleton (see §4.3).

### 4.2 The prefilter - the most important performance building block

The CT stream is in the order of tens of thousands of certificates a minute, and rising (short-lived certificates push the volume up further). It would be fatal to evaluate the complete rule engine of every tenant for every name.

**A two-stage procedure:**

**Stage 1 - global, extremely cheap, across all tenants.** When the rules are loaded, a single Aho-Corasick automaton is built across *all* tenants, holding:
- every key term (`paylio`, `vantabank`, `vendora`, ...),
- every pre-generated typo permutation of the anchor terms,
- every lure term (`login`, `verify`, `account`, `security`, `wallet`, ...).

The automaton is applied against `name`, against `skeleton` and against the separator-free form (`paypa1secure`) - the last one catches separator tricks.

Plus cheap structural checks with no relation to the rules: the label count, the presence of punycode, a suspicious TLD, the length of the name.

Only names with at least one hit go into stage 2. The expected reduction: **over 99 %**.

**Stage 2 - per tenant, the complete rule evaluation**, including expensive fuzzy distances. It only runs on a fraction of the stream and is therefore uncritical.

> **A measurement requirement:** the developer should expose the pass rate of stage 1 as a metric (`prefilter_pass_ratio`). Above 2 % the rule engine is too unspecific and will produce noise later.

### 4.3 The homoglyph skeleton

The procedure follows the Unicode skeleton algorithm (UTS #39): every character is mapped onto its representative in the confusables table. Plus a small ASCII table for the most common mix-oria Unicode does not cover:

```
0 -> o    1 -> l    5 -> s    3 -> e    4 -> a    7 -> t    8 -> b
rn -> m   vv -> w   cl -> d   ii -> u   nn -> m
```

The confusables file ships in the image like the PSL and is updated through CI.

An example: `pаypa1.com` (with a Cyrillic `а`) -> the skeleton `paylio.com` -> an exact hit on the anchor term, and the `homoglyph` rule fires at full strength.

### 4.4 Deduplicating findings

Before a finding is written, it is checked whether `(tenant_id, registrable_domain)` was already seen in the last N hours (24 by default, configurable) - a Redis key with a TTL.

- **A hit:** no new record. Instead `UPDATE findings SET last_seen = now(), hit_count = hit_count + 1, cert_count = cert_count + 1`. A single `UPDATE` instead of an `INSERT` plus enrichment plus an alert.
- **No hit:** a new record, and the enrichment is set off.

That is the single most effective lever against storage growth: Let's Encrypt certificates are renewed every few days, so the same domain would otherwise turn up dozens of times.

**The exception:** if the score rises by more than `rescore_delta` (15 by default) against the stored value, the record is updated *and* another alert is raised - when a domain that was inconspicuous so far suddenly gets a certificate with brand subdomains, for instance.

---

## 5. Tenant and rule model

### 5.1 The basic concept

A **tenant** is a named monitoring context with a ruleset of its own, its own thresholds, its own alert targets and its own feeds. Examples: `banking`, `online-retail`, `own-identity`, `customer-miller-ltd`.

Tenants are entirely equal and independent. One certificate can produce findings in several tenants.

Rulesets live as **YAML files in the directory `rules/`** and therefore in the git repository. That is a deliberate decision:
- versioning, review and rollback come for free through git.
- Rulesets are shareable - the community can contribute rulesets.
- No configuration state sits exclusively in a database.

A file system watcher reloads changes during operation (a hot reload, with schema validation before activating; on a validation error the old ruleset stays active and a warning is produced). The UI can edit rules and writes into the same files while doing so.

### 5.2 A complete example of a ruleset

```yaml
# rules/banking.yaml
apiVersion: ctwatchtower/v1
kind: RuleSet

tenant:
  id: banking
  name: "Financial products and banking"
  description: "Phishing against payment providers and banks (invented brands)"
  enabled: true
  tlp: "clear"           # clear | green | amber | red - carried over into STIX and the exports

thresholds:
  persist: 35            # from here on anything is stored at all
  info: 45
  warning: 60
  alert: 80
  enrich_from: 50        # from here on it costs external queries
  feed_from: 60          # from here on it lands in the STIX/CSV feed

scoring:
  saturation_k: 40       # the saturation constant, see §6.2
  require_anchor: true   # without an anchor hit, `anchor_missing_cap` at most
  anchor_missing_cap: 20

# --------------------------- ANCHORS ---------------------------
# The terms that make the tenant concerned at all.
anchors:
  - terms: [paylio, kavano, kavano, stellax, zelo]
    weight: 30
    match:
      exact: true        # the term as part of a word
      fuzzy:             # Damerau-Levenshtein
        enabled: true
        max_distance: 2
        min_term_length: 5
      homoglyph: true
      permutations:      # dnstwist-like variants, generated at load time
        enabled: true
        kinds: [omission, insertion, transposition, replacement, hyphenation,
                bitsquatting, vowel_swap, repetition, double_char]

  - terms: [vantabank, northvault, northvault, ing, cardex, payro, northvault]
    weight: 32
    match: { exact: true, fuzzy: { enabled: true, max_distance: 2 }, homoglyph: true,
             permutations: { enabled: true } }

  - terms: [cardex, cardex, cardex, transfer]
    weight: 22
    match: { exact: true, homoglyph: true }

# ------------------------- LURE TERMS -------------------------
# Harmless on their own, strong together with an anchor.
lures:
  - terms: [login, signin, secure, safe, security, verify, verify,
            account, account, client, clientportal, update, update,
            confirm, confirm, auth, otp, pushotp, release, suspension,
            wallet, payment, payment, refund, refund]
    weight: 14

  - terms: [service, support, help, center, portal, online, my, my, app]
    weight: 7

# -------------------- STRUCTURAL TRAITS ----------------------
structure:

  label_count:                    # "the number of dots"
    description: "deep nesting is a strong phishing signal"
    baseline: 2                   # example.com = 2 labels = inconspicuous
    weight_per_extra_label: 8
    max_weight: 32
    # paylio.com.safe-login.top -> 5 labels -> 3 above the baseline -> 24 points

  brand_in_subdomain_only:
    description: "the brand sits in the subdomain, not in the registrable domain"
    weight: 35                    # a very strong signal
    # paylio.com.attacker.top  -> registrable = attacker.top, the brand only on the left

  hyphen_count:
    threshold: 2
    weight_per_hyphen: 5
    max_weight: 20

  total_length:
    threshold: 25
    weight_per_char: 0.5
    max_weight: 15

  digit_ratio:
    threshold: 0.15
    weight: 10

  shannon_entropy:
    description: "DGA-like random names"
    threshold: 3.6                # measured on the registrable label
    weight: 12

  punycode:
    weight: 18
    only_if_anchor_matched: true  # otherwise too many legitimate IDN

  numeric_lookalike:
    description: "digit substitution like payli0, vantab4nk"
    weight: 20

# ---------------------------- TLDs ---------------------------
tlds:
  groups:
    - name: "high-risk"
      weight: 25
      list: [top, xyz, cfd, sbs, icu, rest, click, live, quest, bond, cyou,
             lol, mom, zip, mov, buzz, work, fit, beauty, makeup, skin, hair]
    - name: "elevated"
      weight: 14
      list: [online, site, shop, store, info, biz, pro, link, club, space,
             website, tech, host, fun, today]
    - name: "free_historically"
      weight: 20
      list: [tk, ml, ga, cf, gq]
    - name: "regional_unexpected"
      weight: 10
      description: "ccTLDs unexpected for the brands this tenant watches"
      list: [ru, cn, br, in, ir, kp, su, tw]
  default_weight: 0
  # A negative weight for TLDs with a strong registration check
  overrides:
    - tld: [de, ch, at, bank, insurance]
      weight: -10

# --------------------- CERTIFICATE TRAITS --------------------
certificate:
  san_count:
    threshold: 20
    weight: 10
    description: "bulk certificates across many hostnames"

  san_brand_fanout:
    description: "one certificate with several brand-like names"
    min_matching_sans: 3
    weight: 25

  validity_days:
    description: "a very short validity is normal today, a very long one is not"
    enabled: false

  issuer_groups:
    - name: "free"
      weight: 5
      match: ["Let's Encrypt", "ZeroSSL", "Google Trust Services", "Buypass"]
    - name: "ev_ov"
      weight: -15
      description: "OV/EV certificates point to an identity check"
      match_ev: true

# --------------- DOWNSTREAM (after the enrichment) -----------
# These rules only take effect in phase 2 and set off a rescoring.
post_enrichment:
  domain_age:
    - max_age_days: 1
      weight: 30
    - max_age_days: 7
      weight: 22
    - max_age_days: 30
      weight: 12
    - min_age_days: 365
      weight: -25              # an old domain: strongly exonerating

  privacy_registrar:
    description: "registrars with a high share of abuse, or whois privacy"
    weight: 10
    list_file: "data/registrar_risk.yaml"

  nameserver_patterns:
    weight: 12
    regex: ["(^|\\.)cloudns\\.", "(^|\\.)freenom", "(^|\\.)dnspod\\."]

  asn_risk:
    weight: 15
    list_file: "data/asn_risk.yaml"

  no_resolution:
    description: "a certificate exists but nothing resolves, often preparation"
    weight: 8

  parking_detected:
    weight: -20

# --------------------- CUSTOM REGEX RULES --------------------
custom:
  - id: "transfer-mandate-kombi"
    description: "a SEPA reference together with a call to action"
    regex: "(transfer|mandate).{0,15}(rueck|storno|mandat|release)"
    weight: 22
  - id: "otp-verfahren"
    regex: "(push|photo|sms|chip)?otp[-_.]?(release|verfahren|neu|update)"
    weight: 26

# ------------------------- EXCEPTIONS ------------------------
allowlist:
  # A hard suppress: produces no finding at all
  suppress:
    exact: ["paylio.com", "paylio.me", "kavano.com", "vantabank.com"]
    suffix: [".paylio.com", ".kavano.com", ".vantabank.com"]
    regex: ["^[a-z0-9-]+\\.cdn\\.cloudflare\\.net$"]
  # A soft suppress: points off only
  downweight:
    - match: { suffix: [".amazonaws.com", ".azurewebsites.net", ".herokuapp.com",
                        ".vercel.app", ".netlify.app", ".pages.dev", ".workers.dev"] }
      weight: -30
      note: "cloud hosters: their own abuse channels, a high noise rate"

# ------------------------- ALERTING --------------------------
notifications:
  - channel: webhook
    min_severity: warning
    target: "${WEBHOOK_FINANCE}"
  - channel: email
    min_severity: alert
    target: "soc@example.org"
    aggregate_window: 900        # collect for 15 min, then one mail
  - channel: syslog_cef
    min_severity: warning
    target: "siem.internal:514"
```

### 5.3 Reusable building blocks

So that rulesets do not get heavy with copy and paste, there are `includes`:

```yaml
includes:
  - common/lures_en.yaml
  - common/tlds_highrisk.yaml
  - common/allowlist_cloud.yaml
```

Resolution: recursive, lists get merged, and scalar values of the including document win. Cycles are detected and refused as a load error.

### 5.4 The "own identity" tenant

This case deserves a mention of its own because it works differently: the name space is small and very specific, fuzzy matching is especially valuable here, and the thresholds may sit lower because the absolute number of hits is low.

```yaml
tenant: { id: own-identity, name: "Your own identity and company" }
thresholds: { persist: 25, info: 30, warning: 45, alert: 60, enrich_from: 30 }
anchors:
  - terms: ["mycompany", "my-company", "miller", "productname"]
    weight: 45
    match:
      exact: true
      fuzzy: { enabled: true, max_distance: 2, min_term_length: 4 }
      homoglyph: true
      permutations: { enabled: true, kinds: [omission, insertion, transposition,
                      replacement, hyphenation, bitsquatting, tld_swap] }
  - terms: ["first.last", "firstlast"]
    weight: 40
tlds:
  overrides:
    - tld: [de, com, net, org, eu]
      weight: 5
      description: "here it is exactly the obvious TLDs that matter"
```

Also worth having: a `tld_swap` permutation that generates your own domains across *all* common TLDs (`mycompany.de` -> `mycompany.com`, `.net`, `.shop`, ...) and feeds those in as an anchor list. That is the classic defensive-registration blind spot.

---

## 6. The scoring engine

### 6.1 Requirements

- **Traceable.** For every finding the UI has to be able to say: "82 points, because the anchor `paylio` matched exactly (30), the lure `login` (14), the TLD `.top` (25), 4 labels (16), the domain is 2 days old (22), a cloud deduction (-25)."
- **Saturating.** Twenty weak hits must not reach the same weight as two strong ones.
- **Two-phase.** Phase 1 without external queries, phase 2 after the enrichment.

### 6.2 The formula

```
raw      = Σ (weight_i × strength_i)          over all firing rules
raw      = max(raw, 0)
score    = round( 100 × (1 − e^(−raw / k)) )  with k = scoring.saturation_k
score    = clamp(score, 0, 100)

if require_anchor and no anchor fired:
    score = min(score, anchor_missing_cap)
```

`strength_i ∈ [0, 1]` says how certain the rule's hit was:

| Rule type | strength |
|---|---|
| An exact term hit | `1.0` |
| A homoglyph hit in the skeleton | `0.95` |
| A fuzzy hit | `1 − (distance / (max_distance + 1))` - at `d=1, max=2`: `0.67` |
| A permutation hit | `0.9` |
| A threshold rule (labels, length, ...) | `1.0` when exceeded, otherwise `0` |
| A graduated rule | `min(1, (value − threshold) / span)` |

**The effect of the saturation** (at `k = 40`):

| raw | 10 | 20 | 40 | 60 | 80 | 120 | 200 |
|---|---|---|---|---|---|---|---|
| score | 22 | 39 | 63 | 78 | 86 | 95 | 99 |

The curve rewards *several independent* signals coming together and keeps single high weights from carrying the day. `k` is the central sensitivity dial per tenant.

### 6.3 Combination multipliers

Certain combinations are disproportionately telling. They act multiplicatively on `raw` before the saturation is applied:

```yaml
combos:
  - when: [anchor, lure]
    factor: 1.35
    description: "a brand plus a lure term in the same name"
  - when: [anchor, tld_group:high-risk]
    factor: 1.25
  - when: [brand_in_subdomain_only, lure]
    factor: 1.4
  - when: [anchor, domain_age:<7d]
    factor: 1.3
```

The overall factor is capped at `max_combo_factor` (2.0 by default).

### 6.4 The explanation object

Every finding carries a compact reason. It is stored as JSONB and served in the UI and through the API:

```json
{
  "raw": 104.0,
  "combo_factor": 1.35,
  "raw_effective": 140.4,
  "k": 40,
  "score": 97,
  "severity": "alert",
  "phase": 2,
  "contributions": [
    {"rule": "anchor:paylio",              "type": "homoglyph", "w": 30, "s": 0.95, "pts": 28.5},
    {"rule": "lure:login",                 "type": "exact",     "w": 14, "s": 1.0,  "pts": 14.0},
    {"rule": "structure:label_count",      "detail": "5 labels","w": 24, "s": 1.0,  "pts": 24.0},
    {"rule": "structure:brand_in_sub_only","w": 35, "s": 1.0,  "pts": 35.0},
    {"rule": "tld:high-risk:top",          "w": 25, "s": 1.0,  "pts": 25.0},
    {"rule": "post:domain_age",            "detail": "2 days", "w": 22, "s": 1.0,  "pts": 22.0},
    {"rule": "allow:downweight:cloud",     "w": -30,"s": 0.0,  "pts": 0.0}
  ],
  "combos_applied": ["anchor+lure", "brand_in_subdomain_only+lure"]
}
```

The list of contributions is cut to the `top_n` (12 by default) strongest entries, to keep the record size down.

### 6.5 Severities

| Severity | The default range | Behaviour |
|---|---|---|
| *(dropped)* | `< persist` | nothing is stored, only counters |
| `info` | `persist ... warning−1` | stored, visible in the UI, no notification |
| `warning` | `warning ... alert−1` | **a warning**: a notification over the configured channels |
| `alert` | `≥ alert` | **an alert**: escalating channels on top, inclusion in the feed, priority in the enrichment queue |

All the boundaries are configurable per tenant.

### 6.6 The states of a finding

```
    new ──► triaging ──► confirmed ──► reported ──► resolved
     │          │
     │          └──► false_positive ──► (a proposal for the allowlist)
     └──► suppressed   (suppressed afterwards by an allowlist rule)
```

State changes happen in the UI or through the API and are recorded with a timestamp and an optional note. `false_positive` marks feed into the rule statistics (see §15.3).

---

## 7. Enrichment

### 7.1 Basic principles

- The enrichment runs **asynchronously** and **only above `enrich_from`**. It must never block the ingest path.
- Every external source has a rate limiter of its own (a token bucket) and a cache of its own with a source-specific TTL.
- A failed enrichment is not an error state of the finding. The finding exists without the enrichment too, the field stays `null`, and a retry happens with backoff (3 attempts at most over 24 h).
- The cache key is always the **registrable domain**, not the full hostname. That saves enormously on subdomain-heavy campaigns.

### 7.2 RDAP (preferred over WHOIS)

RDAP serves structured JSON and is therefore considerably more robust than parsing WHOIS text.

- Bootstrap through the IANA RDAP bootstrap file (`dns.json`), cached locally, refreshed daily.
- What gets extracted: `registrar_name`, `registrar_iana_id`, `registration_date`, `expiration_date`, `last_changed`, `nameservers[]`, `status[]` (the EPP status, where `clientHold` for instance points to a suspension that already happened).
- **The cache TTL:** 7 days for domains older than 90 days, 24 h for younger ones (whose status can still change).
- **The rate limit:** 1 request a second per RDAP server by default, configurable. Some registries throttle harder - on a 429 the server is set aside for 10 min.
- **Data protection:** personal fields are **not stored**, see [§16.2](#162-handling-registration-data).

### 7.3 WHOIS (the fallback)

Only when RDAP is unavailable for the TLD (some ccTLDs, `.de` among them, offer RDAP in a limited way or not at all). A port 43 query with a 10 s timeout, a parser per registry, and the result mapped onto the same normalised structure. On a parse error the field stays `null` and nothing is aborted. The `.de` registry returns only minimal information over port 43 anyway - that is expected and not a bug.

### 7.4 DNS over DoH

Resolution over DNS-over-HTTPS, primarily Google (`https://dns.google/resolve?name={domain}&type={type}`), secondarily Cloudflare (`https://cloudflare-dns.com/dns-query`, header `accept: application/dns-json`) on an outage or a rate limit.

The types queried: `A`, `AAAA`, `NS`, `MX`, `CNAME`, `TXT`.

The evaluation:
- The response code `NXDOMAIN` -> the field `resolution: "nxdomain"`, and the rule `no_resolution` can fire.
- `A`/`AAAA` -> a list of IPs -> on to ASN and GeoIP.
- An `MX` present on an otherwise new phishing domain -> a clear extra signal (mail sending is prepared). A rule of its own with a weight of 15 is recommended.
- `TXT` with SPF/DMARC -> show it in the detail panel.
- Known parking IPs and parking nameservers (a list in `data/parking.yaml`) -> `parking_detected`.

**The cache TTL:** the TTL delivered by DNS, at least 300 s and at most 6 h.
**The rate limit:** conservatively 10 requests/s, configurable.

> Why DoH instead of classic DNS: a single, controllable HTTPS egress, no dependency on the container's resolver, no influence from local DNS filters, and the answers are machine-friendly as JSON.

### 7.5 ASN, geolocation, network

Through a **local MaxMind GeoLite2 database** (ASN plus country) - no external queries, no rate limit, no data leaving. The database is loaded by an init container (the license key as an optional environment variable) and refreshed weekly. If it is missing, the fields stay empty.

What gets served: `asn`, `as_org`, `country`, `network`.

### 7.6 Active modules (opt-in)

These modules make direct contact with the suspicious domain. They are **disabled by default** (`ENRICH_ACTIVE_ENABLED=false`) and clearly marked as active in the UI.

| Module | Description | Risk |
|---|---|---|
| `http_probe` | a `HEAD` or a limited `GET` on port 80/443, evaluating the status code, the `Server` header, `Location`, the page title and the content length | our own IP becomes known to the attacker |
| `favicon_hash` | MurmurHash3 of the favicon - very well suited to clustering campaigns, because phishing kits rarely change their favicon | as above |
| `tls_probe` | a TLS handshake, comparing the certificate found with the CT entry | as above |
| `screenshot` | a headless Chromium screenshot | the highest risk, the largest storage need |

When they are enabled: an egress path of their own (a proxy or VPN, configurable), a neutral user agent, short timeouts, `robots.txt` deliberately ignored (a security investigation), no following of redirects beyond 2 hops, and a hard size limit of 512 KB.

### 7.7 VirusTotal

**The default: no API call.** The detail panel has a button that leads to `https://www.virustotal.com/gui/domain/{domain}` in a new tab. That way there are no API costs, no rate limit problems and no unwanted data leaving.

**Optionally with an API key** (`VT_API_KEY`): fetching the domain report over the v3 API, cached for 24 h, with a strict token bucket matching the plan (the free plan allows very few requests a minute - the limiter has to model that and must not clog the queue). What gets shown is the detection ratio, the reputation value and the categories. A hit feeds into the scoring as the rule `vt_detections` with a configurable weight.

### 7.8 Further deeplink buttons

All of them as plain links, without a server-side call:

| Service | The URL pattern |
|---|---|
| crt.sh | `https://crt.sh/?q={domain}` |
| urlscan.io | `https://urlscan.io/domain/{domain}` |
| Shodan | `https://www.shodan.io/search?query=hostname%3A{domain}` |
| SecurityTrails | `https://securitytrails.com/domain/{domain}/dns` |
| AbuseIPDB | `https://www.abuseipdb.com/check/{ip}` |
| Google Safe Browsing | `https://transparencyreport.google.com/safe-browsing/search?url={domain}` |
| Wayback Machine | `https://web.archive.org/web/*/{domain}` |
| raw RDAP | `https://rdap.org/domain/{domain}` |
| DNS (dnsviz) | `https://dnsviz.net/d/{domain}/analyze/` |

The list lives in `config/deeplinks.yaml` and can be extended without a code change - which makes sense, because every team has its own preferred tools.

### 7.9 Rescoring after the enrichment

Once the enrichment has finished, phase 2 runs: the `post_enrichment` rules are evaluated, `raw` is recomputed, and the score and severity are updated.

- **The score rises above a threshold** -> a notification for the new severity is raised (it was `info` and after RDAP it is `alert`, say, because the domain is 6 hours old).
- **The score falls below `persist`** -> the finding is set to `suppressed`, not deleted (a learning effect for the rule statistics), and removed from the feed.
- Both phase scores are stored (`score_phase1`, `score`), so the effectiveness of the enrichment can be measured.

---

## 8. Alerting

### 8.1 Channels
| Channel | Description |
|---|---|
| `webhook` | a generic POST with a JSON payload, optionally an HMAC-SHA256 signature in the header `X-Watchtower-Signature` |
| `slack` / `mattermost` | an incoming webhook, Block Kit and attachment formatting respectively |
| `msteams` | an adaptive card over a workflow webhook |
| `matrix` | a message into a room |
| `email` | SMTP with STARTTLS, HTML plus plain text |
| `ntfy` | a push to mobile devices, a very low barrier |
| `telegram` | the bot API |
| `syslog_cef` | CEF-formatted to a SIEM (UDP/TCP/TLS) |
| `splunk_hec` | the HTTP event collector |
| `elastic` | a bulk index into a datastream |
| `misp` | creating an event over PyMISP |

All the channels implement the same interface (`send(batch: list[Finding]) -> None`), so new channels can be added as a small plugin file.

### 8.2 Aggregation and avoiding noise

Experience says this is the point at which systems like this fail: a phishing wave produces hundreds of findings in minutes, and the recipient switches the notifications off.

The mandatory mechanisms:

1. **An aggregation window.** `aggregate_window` per channel (300 s by default). The findings collected inside the window go out as **one** message, grouped by tenant and severity: "14 new warnings, 2 alerts in *financial products*" with a top-5 list and a link into the UI.
2. **Rate limiting.** `max_notifications_per_hour` per channel (12 by default). When it is exceeded the channel switches to summaries and says so once.
3. **Repeat suppression.** The same registrable domain sets off no further alert inside `renotify_after` (7 days by default) - unless the score rises by more than `rescore_delta`.
4. **Campaign bundling.** Findings assigned to the same campaign (see §17.1) are reported as one event.
5. **Quiet hours.** Optionally `quiet_hours` per channel; `alert` can be exempted from them.
6. **Delivery guarantee, light.** Failed deliveries go into a retry queue (3 attempts, exponential). A channel that keeps failing is disabled and marked in the UI.

### 8.3 The webhook payload

```json
{
  "version": 1,
  "tenant": "banking",
  "generated_at": "2026-09-15T10:24:02Z",
  "window_seconds": 300,
  "counts": { "info": 9, "warning": 14, "alert": 2 },
  "ui_url": "https://watchtower.internal/findings?tenant=banking&since=...",
  "findings": [
    {
      "id": "01J9X8...",
      "domain": "payli0-secure-login.top",
      "registrable": "payli0-secure-login.top",
      "score": 97,
      "severity": "alert",
      "first_seen": "2026-09-15T10:22:31Z",
      "matched": ["anchor:paylio(homoglyph)", "lure:login", "tld:top", "age:2d"],
      "issuer": "Let's Encrypt",
      "registrar": "Example Registrar Ltd.",
      "created": "2026-09-13",
      "a_records": ["203.0.113.44"],
      "asn": "AS64496",
      "country": "NL",
      "links": {
        "ui": "https://watchtower.internal/f/01J9X8...",
        "virustotal": "https://www.virustotal.com/gui/domain/payli0-secure-login.top",
        "crtsh": "https://crt.sh/?q=payli0-secure-login.top"
      }
    }
  ]
}
```

---

## 9. Data handling and being frugal with storage

### 9.1 The core decision

**Nothing is stored that does not reach at least `persist` points.** The CT stream comprises tens of millions of certificates a day. A system that archives them is a different product with different costs. CT-Watchtower is a filter.

On top of that:
- Raw certificates are **never** persisted, neither on the bus nor in the database. Anyone who needs the original gets a link to crt.sh and the `cert_index`, through which the entry can be fetched from the log again at any time.
- All the SANs of a certificate are scored, but only the **best-scoring** name is carried as the main record per finding; further brand-relevant names of the same certificate land compressed in the field `related_names` (20 entries at most).
- The explanation structure is cut down to the strongest contributions.

### 9.2 The database schema

```sql
-- ─────────────────────────── Tenants ─────────────────────────
CREATE TABLE tenants (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    tlp             TEXT NOT NULL DEFAULT 'clear',
    ruleset_hash    TEXT,                 -- the SHA-256 of the loaded YAML
    ruleset_loaded  TIMESTAMPTZ,
    config          JSONB NOT NULL DEFAULT '{}'
);

-- ───────────────────────── Log progress ──────────────────────
CREATE TABLE log_checkpoints (
    log_id          TEXT PRIMARY KEY,
    log_url         TEXT NOT NULL,
    api_type        TEXT NOT NULL,        -- 'rfc6962' | 'static-ct'
    last_index      BIGINT NOT NULL DEFAULT 0,
    tree_size       BIGINT NOT NULL DEFAULT 0,
    effective_batch INT NOT NULL DEFAULT 256,
    state           TEXT NOT NULL DEFAULT 'active',  -- active|degraded|suspended|retired
    last_error      TEXT,
    consecutive_err INT NOT NULL DEFAULT 0,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ──────────────────────────  Findings ────────────────────────
CREATE TABLE findings (
    id              UUID NOT NULL DEFAULT gen_random_uuid(),
    tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    domain          TEXT NOT NULL,        -- the complete hostname
    registrable     TEXT NOT NULL,        -- eTLD+1
    tld             TEXT NOT NULL,
    is_idn          BOOLEAN NOT NULL DEFAULT false,
    is_wildcard     BOOLEAN NOT NULL DEFAULT false,
    unicode_form    TEXT,                 -- only when is_idn

    score           SMALLINT NOT NULL,
    score_phase1    SMALLINT NOT NULL,
    severity        TEXT NOT NULL,        -- info|warning|alert
    explanation     JSONB NOT NULL,

    first_seen      TIMESTAMPTZ NOT NULL,
    last_seen       TIMESTAMPTZ NOT NULL,
    cert_count      INT NOT NULL DEFAULT 1,

    -- The certificate context (compact, no raw certificate)
    cert_sha256     BYTEA,
    cert_not_before TIMESTAMPTZ,
    cert_not_after  TIMESTAMPTZ,
    issuer_o        TEXT,
    san_count       SMALLINT,
    related_names   TEXT[],
    ct_log_id       TEXT,
    ct_index        BIGINT,

    -- The enrichment
    enrich_state    TEXT NOT NULL DEFAULT 'pending',  -- pending|done|failed|skipped
    enriched_at     TIMESTAMPTZ,
    registrar       TEXT,
    registrar_id    INT,
    domain_created  DATE,
    domain_expires  DATE,
    epp_status      TEXT[],
    nameservers     TEXT[],
    a_records       INET[],
    mx_present      BOOLEAN,
    asn             INT,
    as_org          TEXT,
    country         CHAR(2),
    vt_detections   SMALLINT,
    favicon_mmh3    BIGINT,

    -- Triage
    status          TEXT NOT NULL DEFAULT 'new',
    status_note     TEXT,
    status_at       TIMESTAMPTZ,
    campaign_id     UUID,

    PRIMARY KEY (id, first_seen)
) PARTITION BY RANGE (first_seen);

-- Daily or weekly partitions, created automatically by the scheduler
CREATE INDEX ON findings (tenant_id, first_seen DESC);
CREATE INDEX ON findings (tenant_id, severity, first_seen DESC);
CREATE UNIQUE INDEX ON findings (tenant_id, registrable, first_seen);
CREATE INDEX ON findings (registrable);
CREATE INDEX ON findings (campaign_id) WHERE campaign_id IS NOT NULL;
CREATE INDEX ON findings USING gin (explanation jsonb_path_ops);

-- ────────────────────── Daily aggregates ─────────────────────
-- These are kept permanently, even once findings have been deleted.
CREATE TABLE daily_stats (
    day             DATE NOT NULL,
    tenant_id       TEXT NOT NULL,
    certs_seen      BIGINT NOT NULL DEFAULT 0,
    prefilter_pass  BIGINT NOT NULL DEFAULT 0,
    findings_total  INT NOT NULL DEFAULT 0,
    findings_info   INT NOT NULL DEFAULT 0,
    findings_warn   INT NOT NULL DEFAULT 0,
    findings_alert  INT NOT NULL DEFAULT 0,
    false_positives INT NOT NULL DEFAULT 0,
    top_tlds        JSONB,
    top_registrars  JSONB,
    top_asns        JSONB,
    PRIMARY KEY (day, tenant_id)
);

-- ─────────────────── The effectiveness of rules ──────────────
CREATE TABLE rule_stats (
    day             DATE NOT NULL,
    tenant_id       TEXT NOT NULL,
    rule_id         TEXT NOT NULL,
    fired           INT NOT NULL DEFAULT 0,
    in_confirmed    INT NOT NULL DEFAULT 0,
    in_false_pos    INT NOT NULL DEFAULT 0,
    PRIMARY KEY (day, tenant_id, rule_id)
);
```

### 9.3 Retention

The `scheduler` runs daily:

| Tier | Age | The action |
|---|---|---|
| Hot | 0-30 days | everything present unchanged |
| Warm | 31-90 days | `explanation` cut to the top 3 contributions, `related_names` emptied |
| Cold | > 90 days (configurable) | the partition is removed with `DROP TABLE` |
| Permanent | unlimited | `daily_stats`, `rule_stats`, `log_checkpoints` |

**The exception:** findings with the status `confirmed` or `reported` are moved into the table `findings_archive` (not partitioned, a small volume) before the partition is dropped. Confirmed threats should not expire.

`DROP TABLE` on a partition is a matter of milliseconds with no vacuum pressure - which is why the partitioning is there. A `DELETE FROM findings WHERE first_seen < ...` would be the wrong approach at these volumes.

### 9.4 Using Redis, and memory discipline

| The key pattern | The purpose | TTL | Type |
|---|---|---|---|
| `s:cert.raw`, `s:cert.candidate`, `s:finding.enrich` | the bus | `MAXLEN ~` | a stream |
| `dd:cert:{sha256_prefix}` | certificate dedupe | 6 h | a string (empty) |
| `dd:find:{tenant}:{registrable}` | finding dedupe | 24 h | a string (the score) |
| `c:rdap:{registrable}` | the RDAP cache | 24 h - 7 d | a hash |
| `c:dns:{registrable}:{type}` | the DoH cache | the DNS TTL, 5 m - 6 h | a hash |
| `c:vt:{registrable}` | the VirusTotal cache | 24 h | a hash |
| `rl:{source}` | a token bucket | - | a string |
| `notif:{tenant}:{channel}` | the aggregation buffer | the window size | a list |

`maxmemory-policy volatile-lru` with `maxmemory` set (512 MB by default). The streams are exempt from eviction, because `MAXLEN` already bounds them - the application must not rely on Redis holding data, all the durable state lives in PostgreSQL.

**No RDB or AOF persistence needed.** Redis is a pure cache and transport buffer here. After a Redis restart the checkpoints carry on out of the database, and at most seconds of buffered certificates are lost. That saves disk I/O and startup time.

### 9.5 The expected magnitudes

As a planning basis, **to be verified by the developer in the first week of operation and documented in the README**:

| The quantity | The expectation |
|---|---|
| certificates/day across all the logs followed | tens of millions |
| names after the dedupe | roughly half |
| the prefilter pass rate | < 1 % |
| findings ≥ `persist` per tenant per day | an order of 10² - 10³ |
| the row size of a finding | about 1.5 KB including indexes |
| the database after 90 days, 5 tenants | a few GB |

The volumes are growing - short-lived certificates and the shortening of maximum certificate lifetimes lead to considerably more issuances per domain. The architecture is laid out so that this growth burdens only the prefilter, not the database.

---

## 10. The HTTP API

FastAPI, OpenAPI under `/openapi.json`, the Swagger UI under `/docs`. No auth (see §1.2), but optionally a static bearer token through `API_TOKEN` for deployments that have to be exposed.

### 10.1 The endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/healthz`, `/readyz` | liveness / readiness |
| `GET` | `/metrics` | Prometheus |
| `GET` | `/api/v1/status` | the log progress, the lag per log, the queue depths, the processing rate |
| `GET` | `/api/v1/tenants` | the tenant list with counters |
| `GET` | `/api/v1/tenants/{id}/rules` | the ruleset as JSON |
| `PUT` | `/api/v1/tenants/{id}/rules` | write the ruleset (validated, writes the YAML file) |
| `POST` | `/api/v1/tenants/{id}/rules/validate` | validate only, do not save |
| `POST` | `/api/v1/tenants/{id}/rules/simulate` | run the ruleset against test domains or against the last N days (§15.2) |
| `GET` | `/api/v1/findings` | the list with filters (see below), cursor pagination |
| `GET` | `/api/v1/findings/{id}` | the detail including the explanation and the enrichment |
| `PATCH` | `/api/v1/findings/{id}` | set the status and a note |
| `POST` | `/api/v1/findings/{id}/enrich` | set off the enrichment manually (again) |
| `POST` | `/api/v1/findings/{id}/false-positive` | mark as an FP, optionally generate a proposal for the allowlist |
| `GET` | `/api/v1/campaigns` | the campaign clusters |
| `GET` | `/api/v1/stats/daily` | time series for dashboards |
| `GET` | `/api/v1/stats/rules` | the effectiveness of the rules |
| `GET` | `/api/v1/stream` | **SSE** - a live stream of new findings, filterable by tenant and minimum score |
| `POST` | `/api/v1/lookup` | an ad-hoc assessment of any domain name against a ruleset |

The filter parameters for `/findings`: `tenant`, `min_score`, `max_score`, `severity`, `status`, `since`, `until`, `tld`, `registrar`, `asn`, `country`, `q` (a substring on the domain), `campaign`, `sort`, `limit`, `cursor`.

### 10.2 The feed endpoints

| Path | Format | A remark |
|---|---|---|
| `/feed/{tenant}/indicators.csv` | CSV | §11.1 |
| `/feed/{tenant}/indicators.json` | a JSON array | §11.2 |
| `/feed/{tenant}/indicators.jsonl` | JSON Lines | for streaming processing |
| `/feed/{tenant}/stix.json` | a STIX 2.1 bundle | §11.3 |
| `/feed/{tenant}/domains.txt` | a domain-only list | for DNS sinkholes, pihole, firewalls |
| `/feed/{tenant}/misp/manifest.json` | a MISP feed | §11.5 |
| `/taxii2/` | TAXII 2.1 discovery | §11.4 |

All the feeds support `?since=<ISO8601>` for a delta fetch, serve `ETag` and `Last-Modified` and answer `If-None-Match` with a `304`. They are pre-generated by the `scheduler` every 5 minutes and served from the file system - that way a feed fetch costs no database load, even when a hundred consumers pull it at once.

---

## 11. Exports: CSV, JSON, STIX, TAXII, MISP

What gets included: findings with `score >= feed_from` and a status not in (`false_positive`, `suppressed`).

### 11.1 CSV

UTF-8 with a BOM (so that Excel opens it correctly - that matters in practice), a comma as the separator, RFC 4180 conformant quoting, ISO 8601 timestamps in UTC. A fixed header line:

```csv
first_seen,last_seen,domain,registrable,tld,tenant,score,severity,status,matched_rules,
issuer,cert_not_before,cert_sha256,ct_log,ct_index,registrar,domain_created,epp_status,
nameservers,a_records,mx_present,asn,as_org,country,vt_detections,campaign_id,ui_url
```

List-valued fields (`matched_rules`, `nameservers`, `a_records`, `epp_status`) are carried in one field separated by `|` - not by a comma, which would collide with the separator.

### 11.2 JSON

```json
{
  "feed": {
    "name": "ct-watchtower/banking",
    "generated_at": "2026-09-15T10:30:00Z",
    "since": null,
    "count": 342,
    "tlp": "clear",
    "producer": "CT-Watchtower",
    "source": "https://github.com/<org>/ct-watchtower",
    "schema_version": 1
  },
  "indicators": [
    {
      "id": "01J9X8...",
      "type": "domain",
      "value": "payli0-secure-login.top",
      "registrable": "payli0-secure-login.top",
      "score": 97,
      "severity": "alert",
      "confidence": 97,
      "labels": ["phishing", "typosquatting", "financial-theme"],
      "first_seen": "2026-09-15T10:22:31Z",
      "last_seen": "2026-09-15T10:22:31Z",
      "valid_until": "2026-12-14T10:22:31Z",
      "matched_rules": ["anchor:paylio(homoglyph)", "lure:login",
                        "structure:label_count", "tld:high-risk:top",
                        "post:domain_age"],
      "certificate": {
        "sha256": "9f2c...",
        "issuer": "Let's Encrypt",
        "not_before": "2026-09-15T10:20:00Z",
        "not_after": "2026-09-21T10:20:00Z",
        "ct_log": "oak2026h1",
        "ct_index": 918273645
      },
      "enrichment": {
        "registrar": "Example Registrar Ltd.",
        "domain_created": "2026-09-13",
        "epp_status": ["clientTransferProhibited"],
        "nameservers": ["ns1.cloudns.net", "ns2.cloudns.net"],
        "a_records": ["203.0.113.44"],
        "mx_present": true,
        "asn": 64496,
        "as_org": "Example Hosting BV",
        "country": "NL"
      },
      "references": {
        "crtsh": "https://crt.sh/?q=payli0-secure-login.top",
        "virustotal": "https://www.virustotal.com/gui/domain/payli0-secure-login.top"
      }
    }
  ]
}
```

### 11.3 STIX 2.1

Generated with the `stix2` library. The structure of the bundle:

1. **`identity`** - the producer, once per bundle, a deterministic UUID out of the configured name.
2. **`marking-definition`** - the TLP marking according to the tenant setting.
3. **`indicator`** per finding.
4. Optionally **`grouping`** per campaign, referencing the indicators that belong to it.

```json
{
  "type": "bundle",
  "id": "bundle--8f6c2b1e-...",
  "objects": [
    {
      "type": "identity",
      "spec_version": "2.1",
      "id": "identity--3d1a...",
      "created": "2026-01-01T00:00:00.000Z",
      "modified": "2026-01-01T00:00:00.000Z",
      "name": "CT-Watchtower",
      "identity_class": "system",
      "sectors": ["technology"]
    },
    {
      "type": "marking-definition",
      "spec_version": "2.1",
      "id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
      "name": "TLP:CLEAR",
      "definition_type": "tlp",
      "definition": { "tlp": "clear" }
    },
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--a1b2c3d4-...",
      "created_by_ref": "identity--3d1a...",
      "created": "2026-09-15T10:22:31.000Z",
      "modified": "2026-09-15T10:31:00.000Z",
      "name": "A suspicious domain: payli0-secure-login.top",
      "description": "Score 97 (alert). Hits: the anchor 'paylio' (homoglyph), the lure 'login', 5 labels, the TLD .top, the domain 2 days old.",
      "indicator_types": ["malicious-activity"],
      "pattern": "[domain-name:value = 'payli0-secure-login.top']",
      "pattern_type": "stix",
      "pattern_version": "2.1",
      "valid_from": "2026-09-15T10:22:31.000Z",
      "valid_until": "2026-12-14T10:22:31.000Z",
      "confidence": 97,
      "labels": ["phishing", "typosquatting"],
      "object_marking_refs": ["marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"],
      "external_references": [
        { "source_name": "crt.sh", "url": "https://crt.sh/?q=payli0-secure-login.top" },
        { "source_name": "ct-watchtower", "external_id": "01J9X8...",
          "url": "https://watchtower.internal/f/01J9X8..." }
      ],
      "x_ctwatchtower_score": 97,
      "x_ctwatchtower_tenant": "banking",
      "x_ctwatchtower_rules": ["anchor:paylio(homoglyph)", "lure:login", "tld:top"],
      "x_ctwatchtower_registrar": "Example Registrar Ltd.",
      "x_ctwatchtower_domain_created": "2026-09-13"
    }
  ]
}
```

Notes on the implementation:

- **Keep the `id` stable.** The indicator UUID is derived deterministically out of `(tenant, registrable)` with UUIDv5. That is the only way a consumer recognises the same object on a repeated fetch and does not create a duplicate. `modified` is bumped on every change.
- **`confidence`** = the score (both scaled to 0-100, so it fits directly).
- **`valid_until`** = `first_seen + indicator_ttl_days` (90 by default). An IOC without an expiry date is data garbage at the consumer.
- **Revocation.** Once a finding is marked `false_positive`, the next bundle carries an object with `"revoked": true` and the same `id`. It stays in the bundle for 30 days, so consumers notice the retraction.
- **`x_` properties** are permitted custom properties. They should be named consistently (lower case, underscores) - OpenCTI and MISP then take them over cleanly.
- **The bundle size.** Above `stix_max_objects` (5000 by default) it is paginated by date: `/feed/{tenant}/stix.json?page=2`, with a `Link` header per RFC 8288.

### 11.4 TAXII 2.1 (optional, recommended)

Since the STIX objects are there anyway, a minimal TAXII server is little extra effort and makes the system directly connectable for OpenCTI, MISP and commercial TIPs.

| Endpoint | Description |
|---|---|
| `GET /taxii2/` | discovery, lists the API root |
| `GET /taxii2/api/` | the API root information |
| `GET /taxii2/api/collections/` | one collection per tenant |
| `GET /taxii2/api/collections/{id}/objects/` | the objects, with `added_after`, `limit`, `next` |
| `GET /taxii2/api/collections/{id}/manifest/` | the manifest for a delta fetch |

The content type is `application/taxii+json;version=2.1` throughout. Read access only, no `POST /objects/`.

### 11.5 The MISP feed

The MISP feed format is deliberately simple and needs no MISP server:

```
/feed/{tenant}/misp/manifest.json
/feed/{tenant}/misp/{event-uuid}.json
/feed/{tenant}/misp/hashes.csv
```

One event per day and tenant, attributes of the type `domain` with `to_ids: true` from the severity `alert` upwards and `to_ids: false` below it. The tags: `tlp:clear`, `type:OSINT`, `ctwatchtower:score=<bucket>`. In MISP it is wired up over *Feeds → Add Feed → Network* with the manifest URL.

---

## 12. The user interface

No login, deliberately lean, works on a tablet too.

### 12.1 The views

**Live** - a header with the tenant switch and the global status (certificates/s, queue depth, log lag). Below it a live ticker over SSE: newly arriving findings appear at the top, coloured by severity, with a minimum-score slider. A pause button, because a scrolling ticker gets in the way of analysis.

**Findings** - a table with all the filters from §10.1, sorting, a column chooser, multiple selection for bulk actions (setting a status, exporting). Exporting the current filter selection as CSV or JSON straight out of the table.

**The detail (a side panel)** - the most important screen:
- the domain large, and for an IDN **both forms** (Unicode and punycode) - that matters for security, because the rendered Unicode name can deceive.
- the score with the contribution list unfolded as bars: every rule with its point contribution, negative contributions in another colour. That is the core function for trust in the system.
- the certificate data, the enrichment data, the DNS resolution.
- a button bar with the deeplinks from §7.8, the **VirusTotal** button prominent among them.
- the actions: set a status, a note, "mark as a false positive" with an automatically proposed allowlist entry, "enrich again", "generate an abuse report".
- related hits: other findings of the same campaign, the same nameservers, the same IP, the same registrar.

**Rules** - a YAML editor (CodeMirror) with schema validation, live error display and a diff against the saved version. Next to it a **test field**: enter a domain name -> an immediate assessment against the ruleset currently in the editor (not yet saved), with the complete contribution list. That function decides whether the whole system is usable day to day.

**Campaigns** - a cluster view with the shared traits and the course over time.

**Statistics** - time series (findings per day and severity), the top TLDs, the top registrars, the top ASNs, the effectiveness of the rules (§15.3), the prefilter pass rate.

**System** - a table of all the CT logs with the API type, the progress, the lag, the error state; the queue depths; the cache hit rates; the state of the notification channels.

### 12.2 Notes on the design

- Dark mode as the default (an SOC context), switchable, the setting in `localStorage`.
- Domain names **always** in monospace, so that `l` and `1`, and `rn` and `m`, stay distinguishable.
- Highlight homoglyphs and non-ASCII characters in the domain name in colour and show the Unicode code point on hover.
- **Never** render suspicious domains as a clickable `<a href>` onto the domain itself. They are shown as text with a copy button, and the deeplinks go exclusively to analysis services. Optionally a presentation with `hxxps://` and `[.]` defanging, switchable.
- Keyboard shortcuts: `j`/`k` for the next and previous finding, `c` for confirmed, `f` for false positive, `/` for the search. Analysts work faster with the keyboard.

---
## 13. Operation, containers, configuration

### 13.1 The images

A single application image for all the Python services, with the behaviour steered through the command (`python -m ctwatchtower.ingest` and so on). That cuts build time, registry volume and version drift.

```dockerfile
# Multi-stage, the goal: a lean, non-root runtime image
FROM python:3.12-slim AS builder
RUN pip install --no-cache-dir uv
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv export --frozen --no-dev -o requirements.txt \
 && pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim
RUN useradd -r -u 10001 -s /usr/sbin/nologin watchtower
COPY --from=builder /install /usr/local
WORKDIR /app
COPY --chown=watchtower:watchtower src/ ./src/
COPY --chown=watchtower:watchtower data/ ./data/
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PATH="/app/.venv/bin:$PATH"
USER watchtower
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -m ctwatchtower.healthcheck || exit 1
ENTRYPOINT ["python", "-m"]
CMD ["ctwatchtower.api"]
```

The requirements: a multi-arch build for `linux/amd64` and `linux/arm64`, non-root, a `read_only: true` file system with a `tmpfs` for `/tmp`, `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, and no secrets in the image.

### 13.2 docker-compose.yml

```yaml
name: ct-watchtower

x-app: &app
  image: ghcr.io/${GH_ORG:-example}/ct-watchtower:${TAG:-latest}
  restart: unless-stopped
  env_file: [.env]
  depends_on:
    postgres: { condition: service_healthy }
    redis:    { condition: service_healthy }
  volumes:
    - ./rules:/app/rules:ro
    - ./config:/app/config:ro
    - feeds:/app/feeds
  read_only: true
  tmpfs: [/tmp]
  cap_drop: [ALL]
  security_opt: [no-new-privileges:true]
  logging:
    driver: json-file
    options: { max-size: "10m", max-file: "3" }

services:
  postgres:
    image: postgres:16-alpine
    restart: unless-stopped
    environment:
      POSTGRES_DB: watchtower
      POSTGRES_USER: watchtower
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?please set this in .env}
    volumes: [pgdata:/var/lib/postgresql/data]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U watchtower -d watchtower"]
      interval: 10s
      timeout: 5s
      retries: 5
    command: >
      postgres -c shared_buffers=512MB -c work_mem=32MB
               -c maintenance_work_mem=256MB -c max_connections=80
               -c random_page_cost=1.1

  redis:
    image: redis:7-alpine
    restart: unless-stopped
    command: >
      redis-server --maxmemory 512mb --maxmemory-policy volatile-lru
                   --save "" --appendonly no
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 3s
      retries: 5

  ingest:
    <<: *app
    command: ["ctwatchtower.ingest"]
    deploy: { replicas: 2 }

  normalizer:
    <<: *app
    command: ["ctwatchtower.normalizer"]
    deploy: { replicas: 2 }

  scorer:
    <<: *app
    command: ["ctwatchtower.scorer"]
    deploy: { replicas: 3 }

  enricher:
    <<: *app
    command: ["ctwatchtower.enricher"]
    deploy: { replicas: 2 }

  notifier:
    <<: *app
    command: ["ctwatchtower.notifier"]

  scheduler:
    <<: *app
    command: ["ctwatchtower.scheduler"]

  api:
    <<: *app
    command: ["ctwatchtower.api"]
    ports: ["127.0.0.1:8080:8080"]

  # Optional: a CertStream server of our own, for mode A
  certstream:
    image: 0rickyy0/certstream-server-go:latest
    profiles: [certstream]
    restart: unless-stopped
    ports: ["127.0.0.1:8081:8080"]

  # Optional: the monitoring stack
  prometheus:
    image: prom/prometheus:latest
    profiles: [monitoring]
    volumes: [./config/prometheus.yml:/etc/prometheus/prometheus.yml:ro, promdata:/prometheus]
  grafana:
    image: grafana/grafana:latest
    profiles: [monitoring]
    ports: ["127.0.0.1:3000:3000"]
    volumes: [grafanadata:/var/lib/grafana, ./config/grafana:/etc/grafana/provisioning:ro]

volumes:
  pgdata:
  feeds:
  promdata:
  grafanadata:
```

The API's port is deliberately bound to `127.0.0.1`. Anyone who wants the interface reachable over the network puts a reverse proxy with authentication of its own in front of it - and that is to be documented in the README.

### 13.3 Configuration

Two levels, clearly separated:

- **Environment variables** for everything environment-dependent: connection strings, secrets, resource limits, feature flags.
- **YAML files** for everything domain-related: rulesets, deeplinks, risk lists. Those belong in the repository.

An extract of the environment variables (the complete reference in [§18.1](#181-the-environment-variable-reference)):

```bash
DATABASE_URL=postgresql+asyncpg://watchtower:***@postgres/watchtower
REDIS_URL=redis://redis:6379/0
CT_SOURCE=logs                     # logs | certstream
CT_LOG_LIST_URL=https://www.gstatic.com/ct/log_list/v3/all_logs_list.json
CT_POLL_INTERVAL=30
CT_MAX_CONCURRENCY_PER_LOG=2
CT_USER_AGENT=ct-watchtower/1.0 (+https://github.com/example/ct-watchtower)
CT_BACKLOG_POLICY=catch_up
ENRICH_RDAP_ENABLED=true
ENRICH_RDAP_RPS=1
ENRICH_DOH_PRIMARY=https://dns.google/resolve
ENRICH_DOH_FALLBACK=https://cloudflare-dns.com/dns-query
ENRICH_ACTIVE_ENABLED=false
VT_API_KEY=
RETENTION_DAYS=90
FEED_REFRESH_SECONDS=300
INDICATOR_TTL_DAYS=90
LOG_LEVEL=INFO
LOG_FORMAT=json
```

### 13.4 Observability

**The metrics** (Prometheus, per service under `/metrics`):

```
ctw_certs_ingested_total{log_id}
ctw_ingest_lag_entries{log_id}
ctw_ingest_errors_total{log_id,code}
ctw_log_state{log_id,state}
ctw_names_processed_total
ctw_prefilter_pass_total
ctw_prefilter_pass_ratio
ctw_findings_total{tenant,severity}
ctw_findings_suppressed_total{tenant,reason}
ctw_score_histogram{tenant}
ctw_scoring_duration_seconds{phase}
ctw_enrichment_duration_seconds{source}
ctw_enrichment_errors_total{source,reason}
ctw_cache_hits_total{cache} / ctw_cache_misses_total{cache}
ctw_ratelimit_waits_seconds{source}
ctw_queue_depth{stream}
ctw_notifications_sent_total{channel,severity}
ctw_notifications_failed_total{channel}
ctw_db_rows{table}
ctw_feed_generation_duration_seconds{format}
```

A ready-made Grafana dashboard ships as JSON in the repository (`config/grafana/dashboards/`).

**The logs:** structured as JSON, with a field `correlation_id` generated by the ingest and passed through all the stages, so that a certificate's path through the pipeline can be followed.

**Alerts on the system itself** (examples for `alerting_rules.yml`):
- `ctw_ingest_lag_entries > 100000` for 15 min
- `ctw_prefilter_pass_ratio > 0.02` for 1 h -> the ruleset is too unspecific
- `rate(ctw_findings_total[1h]) == 0` for 2 h -> the pipeline has stalled
- `ctw_queue_depth{stream="cert.raw"} > 150000`
- `rate(ctw_notifications_failed_total[15m]) > 0`
---

## 14. The repository and publishing on GitHub

### 14.1 The directory structure

```
ct-watchtower/
├── README.md
├── LICENSE                        # Apache-2.0
├── SECURITY.md                    # how to report a vulnerability
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── CHANGELOG.md                   # Keep a Changelog
├── pyproject.toml
├── uv.lock
├── Dockerfile
├── docker-compose.yml
├── docker-compose.dev.yml
├── .env.example                   # fully commented, no real values
├── .dockerignore
├── .gitignore
├── .pre-commit-config.yaml
│
├── src/ctwatchtower/
│   ├── __init__.py
│   ├── config.py                  # pydantic-settings
│   ├── models.py                  # SQLAlchemy
│   ├── schemas.py                 # the pydantic API models
│   ├── bus.py                     # the Redis streams abstraction
│   ├── ingest/
│   │   ├── __main__.py
│   │   ├── loglist.py
│   │   ├── rfc6962.py
│   │   ├── static_ct.py
│   │   ├── certstream.py
│   │   └── checkpoint.py
│   ├── normalize/
│   │   ├── __main__.py
│   │   ├── names.py               # IDN, wildcards, the PSL
│   │   ├── homoglyph.py
│   │   └── prefilter.py           # Aho-Corasick
│   ├── rules/
│   │   ├── schema.py              # the pydantic schema of the RuleSet
│   │   ├── loader.py              # YAML, includes, the hot reload
│   │   ├── permutations.py        # dnstwist-like generation
│   │   └── detectors/             # one module per detector type
│   ├── scoring/
│   │   ├── __main__.py
│   │   ├── engine.py
│   │   └── explain.py
│   ├── enrich/
│   │   ├── __main__.py
│   │   ├── rdap.py
│   │   ├── whois.py
│   │   ├── doh.py
│   │   ├── geoip.py
│   │   ├── virustotal.py
│   │   └── active/                # the opt-in modules
│   ├── notify/
│   │   ├── __main__.py
│   │   ├── aggregator.py
│   │   └── channels/              # one module per channel
│   ├── export/
│   │   ├── csv.py
│   │   ├── json.py
│   │   ├── stix.py
│   │   ├── taxii.py
│   │   └── misp.py
│   ├── api/
│   │   ├── __main__.py
│   │   ├── routes/
│   │   └── sse.py
│   ├── scheduler/__main__.py
│   └── web/                       # templates plus static files
│
├── rules/
│   ├── banking.yaml
│   ├── online-retail.yaml
│   ├── own-identity.yaml
│   ├── wallets.yaml
│   ├── logistics.yaml
│   └── common/
│       ├── lures_en.yaml
│       ├── lures_en.yaml
│       ├── tlds_highrisk.yaml
│       └── allowlist_cloud.yaml
│
├── data/
│   ├── public_suffix_list.dat
│   ├── confusables.txt
│   ├── registrar_risk.yaml
│   ├── asn_risk.yaml
│   └── parking.yaml
│
├── migrations/                    # Alembic
├── config/
│   ├── deeplinks.yaml
│   ├── prometheus.yml
│   └── grafana/
├── tests/
│   ├── unit/
│   ├── integration/
│   └── fixtures/
│       ├── golden_malicious.yaml  # has to reach a score ≥ X
│       └── golden_benign.yaml     # has to stay at a score ≤ Y
├── docs/
│   ├── architecture.md
│   ├── rules.md                   # the rule language documented in full
│   ├── deployment.md
│   ├── feeds.md
│   ├── tuning.md
│   └── images/
└── .github/
    ├── workflows/
    │   ├── ci.yml
    │   ├── release.yml
    │   ├── codeql.yml
    │   └── update-data.yml        # the PSL and confusables, weekly
    ├── ISSUE_TEMPLATE/
    ├── PULL_REQUEST_TEMPLATE.md
    └── dependabot.yml
```

### 14.2 The CI pipeline (`ci.yml`)

On every push and pull request:

1. `ruff check` plus `ruff format --check`
2. `mypy --strict src/`
3. `pytest` with a coverage threshold (the proposal: 70 % of lines, 100 % in the scoring module)
4. **The golden set test** (see §15.1) - it breaks the build when known phishing domains slip below the threshold or known benign domains climb above it
5. Schema validation of all the YAML files in `rules/`
6. `docker build` for both architectures
7. A Trivy scan of the image, and the build breaks on HIGH or CRITICAL
8. SBOM generation (CycloneDX), attached as a build artefact
9. `hadolint` on the Dockerfile
10. `docker compose config` as a syntax check

### 14.3 The release (`release.yml`)

On a git tag `v*`:
- a multi-arch build and a push to `ghcr.io`
- the tags `vX.Y.Z`, `vX.Y`, `latest`
- an image signature with `cosign` (keyless over OIDC)
- the SBOM as an attestation
- a GitHub release with a generated changelog

### 14.4 How the README is built

The README decides whether anyone uses the project. The order:

1. a one-sentence description and a screenshot of the detail view
2. badges (CI, the licence, the last release, the container size)
3. **a quickstart in five lines** - `git clone`, `cp .env.example .env`, set a password, `docker compose up -d`, open a browser. Anyone who has no running system after five minutes is gone.
4. what a ruleset looks like (one short, complete example)
5. screenshots of the main views
6. the feed URLs and how to wire them into MISP or OpenCTI
7. an architecture diagram
8. the resource need and measured throughput figures
9. the boundaries: what the project is not
10. notes on data protection and operating it responsibly
11. thanks to the CT log operators - that is only proper

### 14.5 What does not belong in the repository

- Real API keys, `.env`, access credentials of any kind (`gitleaks` as a pre-commit hook)
- Database dumps, findings, productive rulesets with customer names
- The GeoLite2 database (the licence terms)
- Brand word lists that would read as a customer list - the example rulesets use exclusively brands that are generally known

---

## 15. Quality assurance and rule tuning

### 15.1 The golden set

Two YAML files with test cases, checked on every CI run:

```yaml
# tests/fixtures/golden_malicious.yaml
- domain: "payli0-secure-login.top"
  tenant: banking
  min_score: 75
  must_match: ["anchor:paylio", "tld:high-risk:top"]
- domain: "vantabank.com.clientportal-release.cfd"
  tenant: banking
  min_score: 80
  must_match: ["structure:brand_in_subdomain_only"]
- domain: "xn--pypal-4ve.com"          # pаypal.com with a Cyrillic a
  tenant: banking
  min_score: 70
  must_match: ["punycode", "anchor:paylio"]

# tests/fixtures/golden_benign.yaml
- domain: "www.paylio.com"
  tenant: banking
  max_score: 0
  reason: "the allowlist"
- domain: "paylio-community.com"
  tenant: banking
  max_score: 45
  reason: "an official secondary domain, must not set off an alert"
- domain: "d1a2b3c4.cloudfront.net"
  tenant: banking
  max_score: 20
```

The golden set grows with every real false positive and every missed hit. It is the project's memory against regressions.

### 15.2 Shadow mode and the backtest

Two operating modes for rule changes:

**Shadow mode.** A ruleset can be marked `shadow: true`. It runs along in full and produces findings, but **no notifications and no feed entries**. In the UI shadow findings are filterable separately. After a few days the change's noise behaviour can be judged. Only then is it armed.

**The backtest.** `POST /api/v1/tenants/{id}/rules/simulate` with `{"days": 14}` rescores all the findings **stored** in the last 14 days (including other tenants' and the suppressed ones) with the new ruleset and delivers a comparison: how many findings would be added, how many would fall away, how the score distribution would shift, which confirmed hits would now be missed.

A limitation that has to be documented: the backtest sees only what passed the prefilter and reached `persist`. Rules that open up an entirely new name space cannot be checked retroactively with it - that is what shadow mode is for. Optionally a ring buffer of the last 24 hours of *all* the names (hostnames only, a few GB or so) can be enabled as `--sample-buffer`, to make that possible too.

### 15.3 The effectiveness of the rules

The table `rule_stats` makes this possible for every rule:

```
precision(rule)    = in_confirmed / (in_confirmed + in_false_pos)
contribution(rule) = fired / findings_total
```

The statistics view shows a sorted table and highlights:
- rules with a high firing rate and low precision -> lower the weight or tighten the condition
- rules that never fire -> dead rules, remove them
- rules that fire exclusively in confirmed hits -> the weight may rise

That is the basis for a ruleset that is still in use after six months instead of having been muted.

### 15.4 The false-positive feedback loop

On marking something a false positive, the system proposes a concrete allowlist entry - the most fitting one out of the exact hostname, the registrable domain, and a suffix rule for the whole subdomain level. One click takes the entry over into the YAML file (with a comment, the date and a reference to the finding id). All the existing findings that the new entry would suppress are set to `suppressed` and removed from the feeds.

### 15.5 Test coverage

| The kind of test | The scope |
|---|---|
| Unit | the normalisation (IDN edge cases, PSL special cases such as `co.uk`, `s3.amazonaws.com`), the homoglyph skeleton, every detector on its own, the scoring formula, the saturation curve |
| Property-based (`hypothesis`) | the score always stays in [0,100]; the order of the rules does not change the result; adding a rule with weight 0 changes nothing |
| Integration | the pipeline with a fake CT log (a static HTTP server with prepared `get-entries` answers) end to end as far as the finding in the database |
| Contract | validate the STIX bundle against the official schema; the CSV against RFC 4180; the TAXII answers against the specification |
| Load | 50,000 synthetic names through the prefilter and the scoring, with the throughput as a regression threshold in CI |

---

## 16. Law, data protection, ethics

This section belongs both in the repository (`docs/legal.md`) and, shortened, in the README. It is not an accessory - a tool that collects domain names and registration data touches data protection law.

*A note: what follows is a collection of recommendations for the implementation, not legal advice. For concrete use in a company, the data protection officer or the legal department should be involved.*

### 16.1 Dealing with the CT infrastructure

CT logs are public and intended to be read, but they are provided by operators at their own cost. The polling discipline from §3.2 is therefore not an optimisation but an obligation towards the operators. A meaningful user agent with a way to make contact is part of that.

### 16.2 Handling registration data

RDAP and WHOIS answers can contain personal data (the registrant's name, address, email), even though most registries have redacted these since the GDPR came into force.

The mandatory implementation:

- What gets stored is **exclusively**: the registrar name and id, the registration, change and expiry dates, the EPP status, the nameservers.
- The registrant's name, organisation, address, email and telephone number are **discarded while parsing and never persisted**. That is to be implemented in the code as an explicit allowlist filter over the field names, not as a denylist - otherwise a new field slips through at the next registry.
- The raw answer is not stored, not even in the cache beyond the TTL.
- The retention period from §9.3 applies to these fields too.
- The purpose of the processing: detecting and fending off attacks on one's own organisation or its customers - as a rule a legitimate interest in the sense of Art. 6 (1) (f) GDPR. That should be documented in the record of processing activities.

### 16.3 A score is not a verdict

The UI and the feed descriptions have to make it clear: a high score means "worth checking", not "malicious". There are legitimate reasons for brand-like domains (partners, resellers, fan pages, a coincidence of names, and criticism and opinion sites, which in many jurisdictions are protected as a fundamental right). An automatically generated indicator must not travel unchecked into a blocklist or a takedown request.

That is why the STIX indicators carry the confidence and the rule reasoning with them - the consumer should be able to decide for themselves.

### 16.4 The active modules

The modules from §7.6 make contact with other people's systems. A `HEAD` request to a publicly reachable website is unproblematic; automated fetching at a high frequency, or reading out deep paths, may be judged differently. Hence: off by default, a hard rate limit, and a documented warning on enabling them.

### 16.5 Publishing feeds

Anyone who makes the generated feeds publicly accessible publishes a list of domains with the label "suspicious". That can hit third parties unfairly. The recommendations: take the TLP marking seriously, public feeds only from the severity `alert` upwards and after human confirmation (`status = confirmed`), and name a way to object in the feed description.

---

## 17. Later stages and further ideas

These functions are not part of the first version, but the architecture should not block them. Sorted by benefit per effort.

### 17.1 Campaign clustering *(a high benefit, a medium effort)*

Phishing rarely comes alone. Findings are bundled into campaigns on the basis of shared traits:

| The trait | How telling it is |
|---|---|
| identical nameserver sets | high |
| an identical A-record IP | high |
| the same registrar plus the same registration date ± 1 day | medium |
| an identical favicon hash (with the active modules) | very high |
| the same name pattern (the same kind of permutation, the same lure words) | medium |
| certificates with overlapping SAN sets | high |

The implementation: a simple union-find over weighted trait agreement, run hourly by the `scheduler`. The benefit is considerable: 200 single reports become three campaigns, and the alerting becomes manageable.

### 17.2 An abuse report generator *(a high benefit, a low effort)*

A button in the detail panel generates a ready-to-send text to `abuse@<registrar>` or the hoster, carrying the domain name, the certificate details including the CT log index as evidence, the registration date, the resolved IP, the reasoning, the brand affected by name, and a request to look into it. The templates are multilingual (DE/EN) and adjustable in `config/abuse_templates/`. The abuse address comes out of the RDAP answer.

### 17.3 Volume anomalies *(a medium benefit, a low effort)*

On the basis of `daily_stats`, keep a moving average per TLD, registrar and ASN. On a deviation above 3σ, generate a report of its own: "Registrar X has twelve times the usual volume of brand-like domains today." That finds waves before the single hit stands out.

### 17.4 A defensive-registration check *(a medium benefit, a low effort)*

For the "own identity" tenant: generate all the permutations of your own domains and check over DoH which of them are registered and do not belong to your own organisation. The result as a prioritised list. It runs weekly and has no relation to the CT stream.

### 17.5 Extended indicator types *(a medium benefit, a medium effort)*

Besides `domain-name`, also emit `x509-certificate` (the SHA-256 and the issuer) and `ipv4-addr` as STIX objects, linked over `relationship` SDOs (`indicator --resolves-to--> ipv4-addr`). That makes the feed directly usable for network blocklists.

### 17.6 Word list proposals out of operation *(a medium benefit, a medium effort)*

Extract the most frequent tokens out of confirmed findings that are not yet in any lure list, and offer them as proposals. The phishing vocabulary shifts (`otp` -> `pushotp` -> `release`), and otherwise the lists age imperceptibly.

### 17.7 An optional classification as a second opinion *(a low benefit at first, interesting later)*

A small, locally running model (character n-grams plus gradient boosting, a few MB) as an **additional** signal, trained on your own confirmed hits and false positives. Important: only as a further contribution with a weight of its own in the scoring, never as a replacement for the rules. Explainability is this system's distinguishing feature and must not be replaced by a black box. It makes sense only from a few thousand labelled examples upwards.

### 17.8 Several feeds as an input *(a low benefit, a low effort)*

Besides CT, also read zone file deltas (`.com`/`.net` over CZDS, free after an application) or newly-registered-domain lists. The same assessment path, a different source. It catches domains that have no certificate (yet).

### 17.9 Further small ideas

- **A watchlist import** out of a CSV with your own domains, which creates a tenant automatically
- **A domain similarity search** in the UI: "show me everything that resembles `vantabank`", independent of the ruleset
- **A diff view** between two ruleset versions with a preview of the effect
- **An export as STIX for a time range**, not only as a live feed
- **A read-only mode** for demonstrations (status changes disabled)
- **A `--dry-run` command** that scores a file of domain names against a ruleset and writes a CSV - useful for tuning without a running system
- **The distribution of issuances over the hours of the day** per campaign - attacker time zones are a nice by-product
- **A health badge** as an SVG under `/badge.svg` for internal dashboards

---

## 18. Appendices

### 18.1 The environment variable reference

| Variable | The default | Description |
|---|---|---|
| `DATABASE_URL` | - | the PostgreSQL connection (asyncpg) |
| `REDIS_URL` | `redis://redis:6379/0` | the Redis connection |
| `CT_SOURCE` | `logs` | `logs` or `certstream` |
| `CT_LOG_LIST_URL` | the Chrome log list path | the source of the log list |
| `CT_LOG_LIST_REFRESH` | `3600` | the seconds between log list fetches |
| `CT_LOG_STATES` | `usable` | a comma list of the states to follow |
| `CT_LOG_INCLUDE` / `CT_LOG_EXCLUDE` | empty | a filter on log ids |
| `CT_POLL_INTERVAL` | `30` | the base poll interval in seconds |
| `CT_MAX_CONCURRENCY_PER_LOG` | `2` | simultaneous connections per log |
| `CT_MAX_CONCURRENCY_TOTAL` | `16` | the global ceiling |
| `CT_BACKLOG_POLICY` | `catch_up` | `catch_up` or `skip_to_head` |
| `CT_MAX_BACKLOG` | `2000000` | the threshold for the backlog policy |
| `CT_USER_AGENT` | see §13.3 | has to contain a way to make contact |
| `CERTSTREAM_URL` | - | the websocket URL for mode A |
| `STREAM_MAXLEN_RAW` | `200000` | the bus limit |
| `DEDUPE_CERT_TTL` | `21600` | seconds, the certificate dedupe |
| `DEDUPE_FINDING_TTL` | `86400` | seconds, the finding dedupe |
| `RESCORE_DELTA` | `15` | the score rise that sets off a new report |
| `ENRICH_RDAP_ENABLED` | `true` | |
| `ENRICH_RDAP_RPS` | `1` | requests/s per RDAP server |
| `ENRICH_WHOIS_FALLBACK` | `true` | |
| `ENRICH_DOH_PRIMARY` | Google | |
| `ENRICH_DOH_FALLBACK` | Cloudflare | |
| `ENRICH_DOH_RPS` | `10` | |
| `ENRICH_GEOIP_PATH` | `/app/data/GeoLite2-ASN.mmdb` | empty = disabled |
| `ENRICH_ACTIVE_ENABLED` | `false` | the switch for all the active modules |
| `ENRICH_ACTIVE_PROXY` | empty | the egress proxy for the active modules |
| `VT_API_KEY` | empty | empty = the deeplink button only |
| `VT_RPM` | `4` | requests/min, adjust to the plan |
| `RETENTION_DAYS` | `90` | the partition retention |
| `RETENTION_WARM_DAYS` | `30` | from when things are cut down |
| `INDICATOR_TTL_DAYS` | `90` | `valid_until` in STIX |
| `FEED_REFRESH_SECONDS` | `300` | the pre-generation of the feeds |
| `STIX_MAX_OBJECTS` | `5000` | the pagination limit |
| `PRODUCER_NAME` | `CT-Watchtower` | the identity name in STIX |
| `API_BIND` | `0.0.0.0:8080` | |
| `API_TOKEN` | empty | an optional bearer token |
| `UI_DEFANG_DEFAULT` | `true` | show domains defanged |
| `LOG_LEVEL` / `LOG_FORMAT` | `INFO` / `json` | |

### 18.2 Further example rulesets (in short)

**Online shopping**
```yaml
tenant: { id: online-retail, name: "Online shopping and marketplaces" }
anchors:
  - terms: [vendora, oria, zelo, oria, zelo, payro, vexa,
            payro, payro, vexa, zelo, oria, payro]
    weight: 28
    match: { exact: true, fuzzy: { enabled: true, max_distance: 2 },
             homoglyph: true, permutations: { enabled: true } }
lures:
  - terms: [shop, store, sale, outlet, discount, offer, voucher, shipping,
            delivery, tracking, parcel, parcel, order, prize]
    weight: 12
tlds:
  groups:
    - name: "retail_themed"
      weight: 20
      list: [shop, store, sale, deals, best, top, xyz, online, site]
```

**Crypto and wallets**
```yaml
tenant: { id: wallets, name: "Crypto and wallets" }
anchors:
  - terms: [paylio, korvex, korvex, stellax, kavano, northvault, northvault,
            korvex, korvex, korvex, orbex]
    weight: 35
    match: { exact: true, fuzzy: { enabled: true, max_distance: 2 },
             homoglyph: true, permutations: { enabled: true } }
lures:
  - terms: [wallet, seed, phrase, recovery, restore, airdrop, claim, mint,
            connect, sync, validate, migration, staking, bridge]
    weight: 20      # especially telling in this area
scoring: { saturation_k: 35 }   # more sensitive, because the damage is irreversible
```

**Logistics and delivery services**
```yaml
tenant: { id: logistics, name: "Logistics and delivery services" }
anchors:
  - terms: [zelo, korvex, zelo, zelo, oria, cardex, northvault,
            stellax, northvault, customs, vehicle, penalty, tollpoint]
    weight: 30
lures:
  - terms: [parcel, delivery, surcharge, fee, customs, clearance,
            tracking, appointment, notice, reminder, fine]
    weight: 18
```

> Every brand in these examples is invented. Put the names you actually watch in their place; the rule language stays the same. For a language other than English, replace the lure terms with the vocabulary that phishing is written in there - that is what the detection runs on.

### 18.3 The recommended order of implementation

| Stage | The content | The result |
|---|---|---|
| **1** | ingest (mode A, CertStream) → the normalizer → simple scoring → SQLite → CLI output | the concept works, the first findings are visible |
| **2** | PostgreSQL, the Redis bus, the rule YAML schema, the complete scoring with explanation, the dedupe, retention | a load-bearing core |
| **3** | the API, SSE, the UI (live, findings, detail) | the system becomes usable |
| **4** | the enrichment (RDAP, DoH, GeoIP), phase-2 scoring, the deeplinks | findings become assessable |
| **5** | alerting with aggregation, the CSV/JSON/STIX exports | the system becomes connectable |
| **6** | the rule editor with the test field, the golden set, the backtest, shadow mode | the system stays usable in the long run |
| **7** | ingest mode B (direct log polling, both API types) | independence from other people's infrastructure |
| **8** | TAXII, MISP, campaign clustering, abuse reports | the build-out |

Stages 1 to 3 already make a useful tool. What matters is cutting the interface contracts (the bus messages, the database schema, the rule schema) from the start the way they will be needed in the end - changing them afterwards is expensive.

### 18.4 Open decisions for the team

These points should be settled before the implementation starts and added to the document:

1. **The language and the runtime** - Python throughout, or Go for the ingest?
2. **The frontend** - server-rendered (HTMX) or an SPA? That has a considerable influence on the build chain and the image size.
3. **The number of logs followed** - all the `usable` logs or a selection? It influences the resource need directly.
4. **The default retention** - 90 days is a proposal; to be adjusted where compliance requires it.
5. **How public the feeds are** - internal or public? It influences §16.5 and the pre-generation strategy.
6. **The registry name and the repository visibility** - GHCR public or private, and from when is the repository public?
7. **Handling customer names in rulesets** - should the project become public, productive rulesets need a separate, private repository that is mounted as a volume.

---

*The end of the document.*
