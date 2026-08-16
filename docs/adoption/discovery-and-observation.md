# Discovery and observation runbook

The structured files in this directory separate repository preparation from owner-authorized external
actions:

- `listings.json` records each directory's rules at a fixed upstream commit and the project's current
  eligibility. Re-read the live policy immediately before any submission; the snapshot is evidence of
  a review, not permission to submit later.
- `publication-schedule.json` keeps Show HN, V2EX and Zenn 48-72 hours apart. Every post requires a
  fresh owner decision and manual publication. Reorder the source before the first live action if the
  owner chooses a different channel order.
- `observation.schema.json` defines the pre-publication, 24-hour, 72-hour and 7-day records.
  `observations/pre-publication.json` is the actual baseline captured before any channel post.

## Directory review rule

Do not use star count as a proxy for current maintainer attention. For every directory, record the
latest external merge, open pull-request backlog, default-branch activity, live submission policy,
audience fit and any cost of maintaining a second copy of the Skill. A submitted or merged listing is
discovery evidence only; it is not product adoption, maintainer endorsement or security validation.

The 2026-08-17 review produced this order:

| Directory | Current decision | Reason |
|---|---|---|
| Awesome Claude Code | Submit after the 14-day gate on 2026-08-26 | Strong audience and active review; human web issue form only |
| hahwul/DevSecOps | High priority after v0.5.4 release | Smaller reach, active maintainer, one open PR and direct security-audit fit |
| Awesome Agent Skills | Wait for independent usage | Active list explicitly rejects brand-new skills without community use |
| Awesome Web Security | Wait for independent usage | Active, selective and low-backlog; maintainer precedent requires a new tool track record |
| BehiSecc Claude Skills | Supplemental | Direct security category, moderate backlog and lower editorial signal |
| Awesome Codex Skills | Supplemental | Real Codex fit, but high backlog and no dedicated security category |
| Agentic Awesome Skills | Defer | Requires a second source copy plus repository-specific security metadata |
| Composio Claude Skills | Low priority | Requires a second source copy and has a severe PR backlog |
| Awesome Vibe Coding | Low priority | High backlog, weak recent merge throughput and positioning mismatch |
| Static Analysis | Long-term only | Numeric maturity gates remain unmet and detector positioning needs recheck |

The existing `devsecops/awesome-devsecops` PR remains open, but upstream had not merged an external
PR since 2021-10-20 at review time. Its 5,455 historical stars do not make it an effective current
channel. The zero-star `parousia8888/awesome-devsecops` repository is the normal source fork used to
open that upstream PR.

Use `null` with a concrete `missingData` entry when a metric is unavailable. Do not convert missing
downloads, Marketplace installs or independent references to zero. GitHub traffic is a rolling 14-day
counter and can include CI, release verification, the author, crawlers and other automation.

After a live post, create a schema-conforming record for each planned window. Record the exact channel,
published time, live URL and source draft. A metric change can be described as occurring after a post;
the record must keep `causalAttribution: false` because channel, timing, author network, GitHub
discovery and unrelated demand remain confounded.

MCP registry submission stays out of scope while this project has no MCP server.
