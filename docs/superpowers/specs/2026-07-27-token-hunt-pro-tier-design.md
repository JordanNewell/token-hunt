# token-hunt Pro Tier — Open-Core Design

**Status:** Sketch (informs v0.2+ roadmap)
**Date:** 2026-07-27
**Author:** Jordan Newell

---

## Goal

Define the free/Pro line, pricing, and build order for token-hunt's open-core monetization. Target: $20-50K Year-1 ARR. Same pattern as `curtis-compliance` (MIT core + paid Pro peer package).

## The line: free vs Pro

| Feature | Free (MIT) | Pro (Commercial) |
|---|---|---|
| Regex detection (12 providers) | ✓ | ✓ |
| Bash escape-hatch detection | ✓ | ✓ |
| Entropy candidates | ✓ | ✓ |
| 6 Claude Code hooks | ✓ | ✓ |
| CLI (`scan`/`list`/`close`/`watch`) | ✓ | ✓ |
| `rotations.log` JSONL store | ✓ | ✓ |
| Allowlist (path + fingerprint) | ✓ | ✓ |
| `TOKEN_HUNT_DISABLE` / `TOKEN_HUNT_ALLOW` | ✓ | ✓ |
| **Silent redaction** via `updatedToolOutput` | ✗ | ✓ |
| **Active verification** (provider API "is key live?") | ✗ | ✓ |
| **Auto-rotation API** (one-click rotate at Anthropic/GitHub/Linear) | ✗ | ✓ |
| **Fleet sync** (push patterns to OpenClaw/Cursor agents) | ✗ | ✓ |
| **Dashboard** (web UI for rotations.log) | ✗ | ✓ |
| **Audit log export** (SIEM/CSV) | ✗ | ✓ |
| **SSO/SAML** | ✗ | ✓ (Enterprise) |
| **Support SLA** | community | ✓ (Enterprise) |

**Rule:** Free catches leaks. Pro automates the response.

The unique IP (escape-hatch detection) stays free forever. It's the wedge. Monetizing it would gut adoption.

## Pro v0.2 features (build order)

Prioritized by user value × ease of build:

1. **Silent redaction via `updatedToolOutput`** (~2 days)
   - Already researched (see `docs/superpowers/research/hook-rewrite-capability.md`)
   - Add `token-hunt redact --stdin` CLI subcommand
   - Update PostToolUse hooks to emit JSON with redacted output
   - **Highest-value Pro feature** — fixes the #1 leak vector (agent reads settings.json)

2. **Active verification** (~3 days)
   - TruffleHog-style "call provider API to check if key is live"
   - For providers with check endpoints: GitHub (`/user`), Stripe (`/v1/account`), Slack (`auth.test`)
   - Cuts FPs dramatically, justifies the upsell

3. **Auto-rotation API** (~5 days)
   - For providers with rotation endpoints: Anthropic, GitHub, Linear, OpenAI
   - `token-hunt rotate <id>` → opens browser to rotation page (free tier) vs. calls API to rotate without browser (Pro)
   - One-click rotate after detection is the killer workflow

4. **Fleet sync** (~5 days)
   - Push patterns + allowlists to multiple machines via simple HTTP API or git-based sync
   - Targets multi-agent fleet operators (Jordan's own use case — 15 OpenClaw agents)
   - Optional central rotations.log aggregator

5. **Dashboard** (~7 days)
   - Web UI (FastAPI + htmx, no JS framework)
   - Lists open leaks with rotate links
   - Filters by kind/source/date
   - Local-only by default (binds 127.0.0.1)

6. **Audit log export** (~2 days)
   - SIEM-friendly JSON Lines export
   - CSV export for compliance
   - Signed export (HMAC) for evidentiary chain-of-custody

**Ship Pro v0.2.0 once features 1-3 land.** 4-6 ship as v0.2.1+ rolling updates.

## License + distribution

**Dual license:**
- `token-hunt` core: MIT (existing)
- `token-hunt-pro`: Commercial (custom license — see `LICENSE-PRO`)

**Distribution:** Two PyPI packages, same pattern as curtis-compliance:
- `pip install token-hunt` (free)
- `pip install token-hunt-pro` (paid, requires license key)

**License validation:** Offline-first. License key signed with ed25519 public key embedded in package. No phone-home. User installs once, works forever offline. Renewal check on `token-hunt-pro --update` (manual, never blocks).

**Repo strategy:**
- `JordanNewell/token-hunt` (public, MIT, this repo)
- `JordanNewell/token-hunt-pro` (private, source-available to paying customers)

Source-available not open-source — paying customers get read access to the Pro repo. Reduces piracy risk while preserving auditability.

## Pricing

| Tier | Price | Target | Includes |
|---|---|---|---|
| **Free** | $0 | individuals, hobby projects, OSS maintainers | Everything in current v0.1, forever |
| **Solo Pro** | $8/mo ($80/yr) | professional devs, indie hackers | Silent redact + active verify + auto-rotate APIs |
| **Team Pro** | $5/user/mo (min 5 users) | small engineering teams | Solo Pro + dashboard + fleet sync (up to 25 agents) |
| **Enterprise** | $15/user/mo (min 25 users) | mid-market + enterprise | Team Pro + SSO/SAML + audit log + SLA + unlimited agents |

**Year-1 conservative targets:**
- 100 Solo Pro @ $80 = $8,000
- 10 Team Pro (5 users each) @ $300/yr = $15,000
- 2 Enterprise (avg 50 users) @ $9,000/yr = $18,000
- **Total: ~$41K Year-1 ARR**

**Year-1 stretch targets:**
- 300 Solo Pro = $24K
- 25 Team Pro = $37K
- 5 Enterprise = $45K
- **Total: ~$106K Year-1 ARR**

## Why this displaces existing tools

| Competitor | Pricing | Their gap | Our Pro wedge |
|---|---|---|---|
| Nightfall AI | $20+/user/mo, cloud-only | Cloud-only, no offline | Local-first + same DLP quality + ¼ price |
| Lasso Security | $19-24/user/mo | Cloud gateway required | Plugin-only, no proxy setup |
| Prompt Security | Acquired by SentinelOne, bundled | Enterprise-only, no self-serve | Self-serve Pro tier, no sales call |
| GitGuardian (ggshield) | $9/user/mo + cloud API | Cloud API + fail-open | Local + fail-closed + active verification |
| sensitive-canary | Free OSS | No PostToolUse, no fleet | All five Pro features |

**The pitch:** "Nightfall-class detection at ¼ price, runs on your laptop, no proxy required, no API keys to leak."

## Migration path (free → Pro)

**Frictionless upgrade:**
1. User installs Pro: `pip install token-hunt-pro`
2. Runs `token-hunt-pro activate <license-key>` (one-time)
3. Pro package patches the hooks via `plugin/hooks.json` overlay (Pro takes over PostToolUse + adds redact subcommand)
4. Existing `rotations.log`, allowlist, patterns — all preserved
5. Token-hunt free is left installed (becomes "fallback if Pro ever fails")

**Downgrade path:** `pip uninstall token-hunt-pro` reverts to free. No data loss.

**Trial:** 14-day license on signup (no credit card). Email-verified.

## Open questions

1. **Payment processor?** Stripe + License Spring vs. Stripe + self-rolled license API. Self-rolled is ~3 days work and avoids 5%+ revenue share. Lean self-rolled.

2. **Where's the license server hosted?** Cheapest: Vercel + Supabase. ~$0 at low volume. Migrate to self-hosted on `production` (Hetzner) once monthly revenue >$500.

3. **Refund policy?** 30-day no-questions. Stripe handles. Reduces support burden.

4. **Pricing page URL?** `jordannewell.com/products/token-hunt-pro/` — matches curtis-compliance pattern. Or dedicated landing page (e.g. `token-hunt.dev`)? Domain decision deferred to v0.2 launch.

5. **Should free tier ever be feature-limited by usage (e.g. "max 50 leaks/day")?** No. Free is free. Anything else creates anti-evangelism. Volume limits belong in Pro (max agents, max users).

6. **What about a hosted/SaaS tier?** Not in Year-1. Adds compliance scope (SOC2 for handling customer data, multi-tenant infra, etc.). Stick to self-hosted Pro until $50K ARR proves demand.

## Risks

- **Pricing pressure from free OSS clones.** sensitive-canary or another OSS tool could add silent redaction. Mitigation: ship Pro fast (Pro v0.2 within 30 days of v0.1 launch) and compete on workflow (active verify + auto-rotate), not just features.

- **Enterprise sales cycle is 6-12 months.** Don't bet Year-1 revenue on landing enterprise. Bet on Solo + Team, treat Enterprise as upside.

- **License server downtime blocks new installs.** License keys validate offline post-install, so existing users keep working. New signups fail gracefully with "try again later" + email capture.

- **"Open-core" reputation risk.** Some users will call it "crippleware." Mitigation: be explicit in README about what's free vs Pro, and keep the escape-hatch detection free forever (it's the unique IP — don't ever move it to Pro).

- **Jordan's bandwidth.** Solo maintainer with day-job + 15-agent fleet + curtis-ai-chat + curtis-compliance + bug bounty hybrid. Pro tier adds support burden. Mitigation: 72h ack SLA is already documented, stick to it. Hire part-time support contractor at $30K ARR.

## Next actions (after v0.1 ships)

1. v0.1 launch (Show HN, r/claudecode, r/netsec, dev.to) — collect first 100 GH stars + 500 PyPI downloads
2. Wire Stripe + license server (3 days)
3. Build Pro features 1-3 (silent redact + active verify + auto-rotate APIs) — 10 days
4. Landing page on jordannewell.com + Product Hunt launch
5. v0.2.0 launch with Pro tier — ~30 days after v0.1

**Kill criteria:** If v0.1 doesn't reach 100 stars / 500 PyPI downloads within 60 days, pause Pro development and reconsider positioning. Don't build Pro on top of crickets.
