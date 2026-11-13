# Building a filter that people actually keep using

A monitoring system for the Certificate Transparency stream fails in one of two ways.
It reports too little and nobody notices it is blind. Or it reports too much and
somebody mutes it. The second failure is the common one, and it is quiet: nothing
breaks, the service keeps running, and the alerts go to a folder nobody opens.

This guide is about avoiding the second failure without walking into the first. The
numbers in it come from measurements against 1.74 million real certificates, ten
minutes of the live stream. Every brand name is invented and matches the example
ruleset in `rules/examples/banking.yaml`.

---

## The one number that decides everything

Before any rule, understand the scale. Ten minutes of the stream carry **1.74 million
certificates** and 2.95 million names, of which 646,000 are unique. Extrapolated,
that is tens of millions of certificates a day.

A ruleset that reports **0.001 %** of them produces around 500 findings a day. That
is already more than a person can triage.

So the question is never "what could be suspicious?" It is always: **what is so
suspicious that it is worth a human minute?**

### What a bad ruleset looks like

The first version of the shipped defaults, measured:

| | measured | what it should be |
|---|---:|---:|
| Through the prefilter | 18.77 % | under 2 % |
| Findings in 10 minutes | 3,545 | — |
| of those alerts | 2,809 (79 %) | — |
| Extrapolated per day | **~510,000** | tens |

79 % of everything was an alert. At that point the severity levels carry no
information at all.

---

## Step 1: Write down what you are protecting

Before any YAML, make a list. For each item, answer one question: **would a
convincing imitation of this name get credentials, money or data?**

| Category | Examples | Usually worth it? |
|---|---|---|
| The company name and its spellings | `velton`, `velton-group`, `veltondesk` | yes |
| Product and portal names | the thing employees log into | yes |
| Payment and banking brands you operate | `paylio`, `vantabank` | yes |
| Names of executives | for spear phishing | sometimes |
| Internal project names | rarely public, rarely attacked | usually not |
| Generic service words | `portal`, `intranet`, `webmail` | **never as an anchor** |

The last row is the important one. A word that describes a function is not an
anchor. It belongs in the lures, where it only counts beside a brand.

---

## Step 2: Choose anchors, and test them before you commit

An anchor is the term that makes the tenant care at all. Everything else only
modifies. Get this wrong and nothing downstream can save you.

### Check the length first

| Length | What happens | What to do |
|---|---|---|
| 1-3 characters | matches everything | **do not use** |
| 4 characters | no fuzzy matching, whole token only | fine, but exact only |
| 5-7 characters | fuzzy allows 1 edit; is often a prefix of longer words | check for collisions |
| 8+ characters | fuzzy allows 2 edits; usually distinctive | the comfortable case |

Fuzzy matching is capped at **a quarter of the term's length**. That is not a knob
to turn up. Measured: two deviations on a 5 to 7 letter term hit everyday words in
7 out of 9 cases.

### Hunt for collisions before the rule goes live

This is the step everybody skips, and it is the one that produces the 510,000
findings a day. For every anchor, ask three questions:

**1. Is it a prefix of a longer word?**

A five or six letter brand almost always is.

```
payro   sits in  payroll        -> a finding a day, all wrong
cardex  sits in  cardexpress    -> a logistics company, every certificate a finding
zelo    sits in  zelophobia     -> and in surnames
```

**2. Is it one edit away from a common word?**

```
stellax  ->  stellar   (one replacement, an everyday word)
```

**3. Does a generated typo variant spell something real?**

The permutation generator produces omissions, insertions, transpositions,
replacements, hyphenations and bit flips. One of them will be a word.

```
stellax  --omission-->  stella    (a name, a brand, a word)
```

The quickest way to find all three: run the anchor against a recording of the stream
before you arm it.

```bash
python scripts/record_stream.py --seconds 600 --out sample.tsv
python scripts/analyse_stream.py sample.tsv --rules rules/ --out hits.tsv
python scripts/stream_missed.py sample.tsv --rules rules/   # the other direction
```

### Write the exception, not a weaker rule

When you find a collision, the instinct is to shorten the anchor or switch fuzzy
off. Both make you blind. Use `exclude` instead: it cuts the word out of the name
*before* matching, so the brand stays findable everywhere else.

```yaml
anchors:
- terms: [payro, zelo]
  weight: 26
  exclude: [payroll]      # the brand still matches in `payro-login.top`
```

#### The trap that costs you an afternoon

**An exclusion must not be a prefix of the brand.** It is cut out first, and it takes
the brand with it:

```yaml
# WRONG: `stella` is cut out of `stellax` too. The anchor never matches again,
# and nothing tells you - the rule simply goes quiet.
exclude: [stella]

# RIGHT: `stellar` is a different word, the brand survives.
exclude: [stellar]
```

After every `exclude` you add, check that the brand itself still matches. One line
in the test field is enough.

### Exempt your own infrastructure

```yaml
  owned_domains: [paylio.com, paylio.net]
```

Without this your first finding is your own website, and your second is your own
staging environment. `owned_domains` applies to the whole hostname, so
`terminal.device.paylio.net` is covered as well.

---

## Step 3: Lures - useful, and the single biggest source of noise

A lure is the action word beside the brand: `login`, `verify`, `refund`. On its own
it says nothing. That is the point, and it is also the danger.

### Always set `whole_word` on generic terms

Measured yield of single lure terms over ten minutes:

| Term | names let through | of those a finding |
|---|---:|---:|
| `app` | 21,790 | **30** |
| `shop` | 6,067 | **12** |
| `portal` | 5,885 | **7** |
| `online` | 4,896 | **4** |

`app` pulled 21,790 names through the automaton to produce 30 findings. It matched
in `appointment`, `apple`, `happy`. One term, and it alone explains most of the
18.77 % pass rate.

```yaml
lures:
- terms: [app, my, web, portal]
  weight: 7
  whole_word: true       # `app` no longer matches inside `appointment`
```

### Write lures in the language the phishing is written in

This is the one place where translation hurts you. If the attacks against your
organisation are written in German, the lure list has to be German -
`freigabe`, `konto`, `sicherheit`. The brand names stay as they are, the action
words follow the victims.

### Keep two groups, not one

```yaml
lures:
- terms: [iban, transfer, mandate, statement, overdraft]   # specific to the trade
  weight: 14
- terms: [branch, advisor, inbox]                          # weak but common
  weight: 7
```

A weight of 14 for a word that says "money is moving", 7 for one that just sounds
official. The difference decides whether two weak signals can reach an alert on
their own. They should not.

---

## Step 4: Turn the structure detectors down

This is the correction nobody expects, and it is the one that fixes the inversion.

The structure detectors count labels, hyphens, digits and length. The default
weights were built for the names of 2015. Measured against today's stream:

| Band | Findings | came from `label_count` | from `hyphen_count` |
|---|---:|---:|---:|
| Alert ≥ 64 | 2,809 | **98 %** | **93 %** |
| Warning 37-63 | 508 | 88 % | 50 % |
| Info < 37 | 228 | 19 % | 3 % |

In the alert band the score came almost entirely from **the shape of the name**.
But many labels with many hyphens is not a phishing trait - it is how modern cloud
infrastructure is named.

The result in its purest form:

| Name | scored |
|---|---:|
| `rc-agent-pycr-nonprod-001.redis.cache.windows.net` | 100 · alert |
| `*.eu-central-1.search.localhost.localstack.cloud` | 100 · alert |
| | |
| `paylio-signon.net.ph` *(real phishing)* | 38 · warning |
| `cardex-vantabank-northvault.com.ph` *(real)* | 48 · warning |

Infrastructure in the alert band, real phishing in the warning band.

### The correction

```yaml
structure:
  # From 2 labels and 8 points each, to 3 and 4. Three labels are normal today.
  label_count: {baseline: 3, weight_per_extra_label: 4, max_weight: 12}
  # From a threshold of 2 to 3. Administrative and product names carry hyphens.
  hyphen_count: {threshold: 3, weight_per_hyphen: 4, max_weight: 12}
```

Structure should be a tiebreaker between two brand hits, never a reason on its own.

### `brand_in_subdomain_only` deserves its own warning

The rule says: the brand sits to the left, the registrable domain belongs to
somebody else. `paylio.com.attacker.top` - a strong signal, worth 35 points.

It is also exactly what every managed service produces: `customer-x.zendesk.com`,
`mycompany.atlassian.net`. Measured in one tenant, **it supplied seven of the ten
highest-scoring findings, all of them wrong**.

Two ways out, and you need to pick deliberately:

1. **Leave it out** and catch the real case with a deduction on the known platforms.
2. **Keep it at a much lower weight** (18 instead of 35) *and* fix how the
   registrable domain is determined - see the next section.

---

## Step 5: The root cause most people never find

The engine splits a name into "what somebody registered" and "what is to the left of
it", using the public suffix list. The PSL has two sections: the ICANN section
(`.com`, `.co.uk`) and a private section, where platforms register their own
suffixes (`pages.dev`, `workers.dev`, `github.io`).

**If you only use the ICANN section, these two cases become indistinguishable:**

| Name | registrable without the private section | with it |
|---|---|---|
| `auth-korvex-wallet-en-us.pages.dev` | `pages.dev` | `auth-korvex-wallet-en-us.pages.dev` |
| `agent-001.redis.cache.windows.net` | `windows.net` | `windows.net` |

The first is an attacker who registered that name themselves. The second is a tenant
of a provider's subdomain. Without the private section both look like "the brand is
only in the subdomain", and you cannot write a rule that separates them.

Measured consequence: a proposal that deducted points on `pages.dev` lost three real
phishing domains, because the deduction hit the attackers renting space there as
well. With the private section in place, the same deduction lost none.

If your tooling lets you choose, switch the private section on. Plan it: the
registrable domain also sits in the dedupe keys and in the feeds, so existing
findings get new keys.

---

## Step 6: The allowlist is your largest single lever

One change, measured: **−62 % findings.**

Cloud and SaaS providers hand their customers a subdomain, so their namespace
inevitably carries other people's brands. These are not attacks.

```yaml
allowlist:
  downweight:
  - match:
      suffix: [.amazonaws.com, .amazonaws.com.cn, .azurewebsites.net,
               .cache.windows.net, .herokuapp.com, .vercel.app, .netlify.app,
               .pages.dev, .workers.dev, .localstack.cloud, .ts.net, .sslip.io,
               .zendesk.com, .salesforce.com, .atlassian.net, .okta.com]
    weight: -30
    note: "cloud hosters: their own abuse channels, a high noise rate"
```

Three details that matter:

- **Deduct, do not suppress.** A real attack rented on Cloudflare Pages still carries
  a lure and a cheap ending, and still gets over the threshold. A hard suppression
  would blind you.
- **Watch the regional variants.** `.amazonaws.com` was covered, `.amazonaws.com.cn`
  was not - and it alone produced 1,841 findings.
- **Your own domains belong in `suppress`, not here.** They are never an attack.

---

## Step 7: Set thresholds so that an anchor alone does not alert

The most common mistake in the threshold block: a single anchor hit reaches `alert`.
Then every mention of your brand anywhere wakes somebody.

```yaml
thresholds:
  persist: 20      # below this nothing is even stored
  info: 28
  warning: 40
  alert: 58        # an anchor at weight 45 stays below this on its own
  enrich_from: 50
  feed_from: 58

scoring:
  require_anchor: true
  anchor_missing_cap: 6     # no brand, no case. 6 points means: invisible.
```

The arithmetic to do by hand, once: take your heaviest anchor weight, and make sure
it is **below** `alert`. Reporting should start when a second signal arrives - a
lure, a cheap TLD, a young domain. That is the difference between "the name occurs"
and "somebody is building a login page".

`require_anchor` with a low cap is what keeps a name without any brand out of the
list entirely, however suspicious its shape.

### Combination bonuses, not multipliers

If your system offers multipliers, prefer flat bonuses. A factor of 1.35 adds 13
points at a score of 37 and 28 points at 80 - it rewards what is already high. A
bonus of 22 adds 22 everywhere, which is what you actually meant.

```yaml
combos:
- when: [anchor, lure]
  bonus: 22
- when: [anchor, "tld_group:high-risk"]
  bonus: 16
- when: [anchor, "domain_age:<7d"]
  bonus: 19
```

---

## Step 8: Authorities, municipalities and anything without a brand name

Some organisations have no brand. A public authority is recognised not by a name but
by a *combination*: a place and an administrative term.

Taking the place name as an anchor is the single worst rule you can write. Measured:
it reported driving schools, hotels, clubs and estate agents, and produced by far the
largest share of all false alarms.

Use a multi-part rule instead. Neither word counts on its own:

```yaml
rules:
- name: "An administrative procedure relating to the city"
  weight: 38
  counts_as_anchor: true
  exclude: [similarplace, otherplace]
  all_of:
  - description: "the place"
    any_of: [lakeside, hillside]
  - description: "the procedure"
    any_of: [customercare, customerdesk, registry, permit, taxoffice]
```

`drivingschool-lakeside.de` sets nothing off. `customercare-lakeside.top` does.

The same shape works for any organisation whose name is a common word: pair it with
a second term that only your context produces.

---

## Step 9: Measure, then decide

Every claim about false alarms is a guess until you have run the ruleset against real
data. The cycle:

```bash
# 1. Record a slice of the live stream (no extra load on the CT logs:
#    this attaches to the certstream service you already run)
python scripts/record_stream.py --seconds 600 --out sample.tsv

# 2. Score it, with the per-term yield
python scripts/analyse_stream.py sample.tsv --rules rules/ --out hits.tsv

# 3. The other direction: brand-like names that scored below every threshold
python scripts/stream_missed.py sample.tsv --rules rules/ --out missed.tsv

# 4. Build a list to judge by hand
python scripts/rating_list.py --hits hits.tsv --missed missed.tsv --out rating.tsv
```

Then read three numbers:

| Number | Where it should be | What it means if it is not |
|---|---|---|
| Prefilter pass rate | **under 2 %** | a lure or anchor is too generic |
| Findings per day | what your team can triage | thresholds or anchors too broad |
| Share of alerts | well under half | the severity levels carry no information |

### Judge the edge, not the obvious cases

When you have somebody rate names by hand, do not give them the 100-point findings.
Those are easy and tell you nothing. Give them the band **within ±6 points of your
warning threshold**. That is where the decision actually sits, and those judgements
are what move the threshold to the right place.

---

## Step 10: Write every lesson into the golden set

A ruleset that nobody can change without fear decays. The golden set is what makes
changing it safe: two lists that run on every build.

```yaml
# tests/fixtures/golden_malicious.yaml - these must fire
- domain: "payli0-secure-login.top"
  tenant: banking
  min_score: 70
  must_match: ["anchor:paylio", "structure:numeric_lookalike"]

# tests/fixtures/golden_benign.yaml - these must stay quiet
- domain: "payroll-xyz.io"
  tenant: banking
  max_score: 0
  reason: "payro. `payroll` is an everyday word that contains the brand"
```

Two rules for keeping it useful:

- **Every real false positive becomes a benign case. Every missed finding becomes a
  malicious one.** That is how the set becomes the project's memory instead of a
  snapshot.
- **Include cases near the line.** A set made only of 100-point findings will not
  notice a halved weight. Add cases that carry exactly two signals and pin them with
  both `min_score` and `max_score`.

---

## Step 11: Arm it carefully

Do not switch a new ruleset to live alerting. Run it alongside first:

```yaml
shadow: true     # produces findings, but no notifications and no feed entries
```

After a few days you can judge the noise. Only then arm it.

And when you do arm it, make sure the alerting cannot flood anyone - that is the
other way these systems die:

```yaml
NOTIFY_WINDOW=300           # collect for 5 minutes, send one message
NOTIFY_MAX_PER_HOUR=12      # then switch to summaries
NOTIFY_RENOTIFY_DAYS=7      # the same domain at most weekly
```

A wave produces hundreds of findings in minutes. Without bundling, the recipient
mutes the channel after the first one, and everything you built goes with it.

---

## The anti-patterns, collected

| Do not | Because | Instead |
|---|---|---|
| Anchor on a word under 4 characters | matches everything | drop it, or use a pattern |
| Raise `max_distance` to catch more | two edits on a short term hit everyday words | fix the anchor list |
| Switch fuzzy off because of a false hit | you lose every real typosquat | `exclude` the colliding word |
| Use an `exclude` that is a prefix of the brand | it cuts the brand out too, silently | choose a different word |
| Anchor on a generic service word | `portal` is in a million names | make it a lure |
| Let structure alone reach `alert` | infrastructure outscores phishing | cap the structure weights |
| Suppress a whole cloud provider | attackers rent there too | deduct instead |
| Publish `registrable` in a block list | you block the provider, not the tenant | publish the watched name |
| Arm a new ruleset directly | you will not know what it costs | shadow mode first |
| Tune by reading rules | every claim is a guess | measure against a recording |

---

## A first-week checklist

- [ ] List of what you protect, with the "would an imitation get credentials?" test
- [ ] Every anchor checked for prefix collisions, near words and typo variants
- [ ] `exclude` set where needed - and the brand verified to still match afterwards
- [ ] `owned_domains` filled, so your own sites are not your first findings
- [ ] `whole_word` on every generic lure
- [ ] Structure weights turned down; `brand_in_subdomain_only` decided deliberately
- [ ] Cloud allowlist filled, including the regional variants
- [ ] Thresholds arithmetic done: heaviest anchor stays below `alert`
- [ ] `require_anchor: true` with a low cap
- [ ] Ruleset measured against a real recording; pass rate under 2 %
- [ ] Edge cases rated by hand, threshold moved accordingly
- [ ] Golden set seeded with the false positives you already found
- [ ] Shadow mode for a few days before arming
- [ ] Alert bundling and rate limits configured

---

## One last thing

A high score means **worth checking**, not malicious. There are legitimate reasons
for brand-like domains: partners, resellers, fan pages, a coincidence of names,
criticism sites. Whatever the number says, a person decides - and the tool's job is
to make that decision cheap by showing exactly which rules fired and what each one
contributed.

A filter that cannot explain itself will be ignored, however good its arithmetic.
