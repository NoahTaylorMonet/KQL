# KQL Office Hours — Session 2 Demo Plan

**Audience:** Jacobs SOC team (Troy, Shawn, Jeff, Max) — beginner→intermediate, working in Defender Advanced Hunting
**Duration target:** 45 min
**Theme:** *"From single-table queries to investigation-grade pivots"* — every concept tied to a real SOC scenario, not abstract syntax.

---

## Pre-Session Prep

1. **Save a `.kql` scratchpad** with all demo queries pre-written (paste-ready) so a browser crash doesn't kill the flow — lesson learned from last week.
2. **Pick one IOC to thread through the demo** so it feels like an investigation, not a tutorial:
   - A domain in the test tenant
   - A SHA256 of a common binary so hash pivots actually return rows
   - A user principal name from the DibSecurity tenant
3. **Open two browser tabs** to Advanced Hunting in case one crashes.
4. **Have Task Manager visible** for the "browsers eat memory" callback joke from last session.

---

## Session Flow (45 min)

### 0. Recap & framing — 3 min
- Quick verbal recap: *"Last week = `where`, `project`, `extend`, `summarize`, `let`. Today = stitching tables together, which is where real investigations live."*
- State the scenario up front: *"We got a tip that domain X is malicious and hash Y was seen on an endpoint. Let's pivot."*

---

### 1. Field discovery workflow (Shawn's question) — 4 min

**Why this opens the session:** Shawn asked last time, *"how do I know which table even has the field I need?"* That question went unanswered. Open with the win.

**Three ways to answer it:**

```kql
// 1. getschema on a single table — what columns does this table expose?
DeviceNetworkEvents
| getschema
| where ColumnName contains "Url"
```

```kql
// 2. union withsource — scan many tables at once for a field's presence
union withsource=Table DeviceNetworkEvents, DeviceFileEvents, DeviceProcessEvents, EmailUrlInfo, UrlClickEvents
| getschema
| where ColumnName has "Domain" or ColumnName has "Url"
| distinct Table, ColumnName
```

3. **Schema sidebar + filter box** in the portal (point at the UI).

**Takeaway to call out:** "The same logical thing (a domain) lives under different column names across tables — `RemoteUrl`, `Url`, `UrlDomain`, `SenderFromDomain`. That's *exactly* why we join."

---

### 2. Joins — the main event — 18 min

**Framing blurb (say this out loud first):**
> A join takes two tables and merges them into one result set, side-by-side, by matching rows on a shared key (the `on` clause). Think of it like SQL joins or Excel `VLOOKUP` — you're using a value that exists in both tables (a device ID, a user, a hash) as the bridge. The **kind** of join controls *which* rows survive: only matches, all of one side, only the misses, etc. Pick the kind based on the question you're asking, not the data you have.

#### 2a. `inner` join — "show me only rows that exist in both"

**What it does:** Returns rows where the join key is present in **both** tables. If a `DeviceId` only shows up on the left, it gets dropped. If it only shows up on the right, it gets dropped. You're left with the **intersection**.

**When to use it:** When the question is *"X happened AND Y happened on the same thing"* — both events must exist for the row to be interesting. This is your default 80%-of-the-time join.

**Scenario:** *Which devices had a failed logon AND ran a suspicious process within 30 minutes of that failure?*

```kql
let lookback = 24h;
let suspiciousProcs = dynamic(["net.exe","whoami.exe","nltest.exe","quser.exe"]);
DeviceLogonEvents
| where Timestamp > ago(lookback) and ActionType == "LogonFailed"
| project Timestamp, DeviceId, DeviceName, AccountName, FailureReason
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where FileName in~ (suspiciousProcs)
    | project ProcTime=Timestamp, DeviceId, FileName, ProcessCommandLine, InitiatingProcessAccountName
  ) on DeviceId
| where abs(datetime_diff('minute', Timestamp, ProcTime)) <= 30
| project Timestamp, DeviceName, AccountName, FailureReason, ProcTime, FileName, ProcessCommandLine
```

**Teach moments:**
- The `on` clause = the shared key. Both sides must have a `DeviceId` column.
- **Alias collision columns BEFORE joining** (`ProcTime=Timestamp`). Otherwise KQL auto-renames the right-side `Timestamp` to `Timestamp1` and your query gets ugly fast.
- **Filter and `project` on each side BEFORE the join.** The smaller you make each side, the faster (and cheaper) the join runs.
- **Time-bound the correlation AFTER the join** with `datetime_diff` — that's how you say "around the same time" instead of just "same device, any time."

---

#### 2b. `leftouter` join — "keep everything from the left, enrich from the right"

**What it does:** Returns **every row from the left table**, and attaches the matching right-side columns when they exist. If there's no match on the right, the right-side columns come back as empty/null. Nothing on the left ever gets dropped.

**When to use it:** When the left table is your **primary source of truth** and the right table is **enrichment**. You want all your sign-ins, and *if* you happen to have device info, attach it. Missing enrichment shouldn't make a row disappear.

**Scenario:** *Show me every failed sign-in, and if we have device telemetry for that user, attach it.*

```kql
SigninLogs
| where TimeGenerated > ago(1d) and ResultType != 0
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ResultType
| join kind=leftouter (
    DeviceInfo
    | summarize arg_max(Timestamp, DeviceName, OSPlatform) by AccountUpn=tolower(LoggedOnUsers)
  ) on $left.UserPrincipalName == $right.AccountUpn
```

**Teach moments:**
- `$left.X == $right.Y` is the syntax for joining on **differently-named columns** — huge once you start joining across Defender + Entra tables where naming conventions differ.
- `arg_max(Timestamp, ...)` collapses the right table to **the most recent row per user** before joining. Without this you'd duplicate every sign-in row by however many DeviceInfo records the user has — a common surprise.
- If you see lots of empty right-side columns in the output, that's not a bug — that's `leftouter` telling you "no match found, but I kept your row anyway."

---

#### 2c. `leftanti` join — "show me what's missing"

**What it does:** Returns rows from the left table that have **NO match** on the right. The right-side columns aren't returned at all — `leftanti` is purely a filter. It's the opposite of `inner`: where `inner` keeps matches, `leftanti` keeps misses.

**When to use it:** Anytime you find yourself describing the question with the word *"NOT"* — *"users who failed sign-in but did NOT succeed,"* *"devices that got an alert but did NOT run a follow-up scan,"* *"hashes seen in email but NOT yet on any endpoint."* This is the **gap-finder** join.

**Scenario:** *Users who failed sign-in in the last 24h but have NO successful sign-in in that same window — possible compromise/lockout candidates.*

```kql
let failed =
    SigninLogs
    | where TimeGenerated > ago(1d) and ResultType != 0
    | distinct UserPrincipalName;
let succeeded =
    SigninLogs
    | where TimeGenerated > ago(1d) and ResultType == 0
    | distinct UserPrincipalName;
failed
| join kind=leftanti succeeded on UserPrincipalName
```

**Teach moment:** Mental model — **`leftanti` = subtraction**. `failed` minus `succeeded`. If you can phrase the question as "A minus B," reach for `leftanti`.

---

#### 2d. `leftsemi` join — "filter the left using the right, but don't bring the right's columns"

**What it does:** Returns rows from the left table that **DO have a match** on the right — but unlike `inner`, it does *not* pull in any of the right-side columns. It's a pure filter: *"keep my left rows that exist in this other set."*

**When to use it:** When you have a list of "interesting things" (a watchlist of bad IPs, a set of compromised users, a hash list) and you want to filter another table down to just those — without polluting your output with extra columns from the watchlist.

**Quick example:**
```kql
let watchedUsers = SigninLogs | where RiskLevelDuringSignIn == "high" | distinct UserPrincipalName;
DeviceLogonEvents
| where Timestamp > ago(1d)
| join kind=leftsemi watchedUsers on $left.AccountName == $right.UserPrincipalName
```

**Teach moment:** `leftsemi` ≈ *"where exists in"*. Use it instead of `inner` when you don't want the right-side columns cluttering your output.

---

#### 2e. Join kinds quick reference (put on screen)

| Kind | Mental model | Use when |
|---|---|---|
| `inner` | Intersection | Both sides must match. Default for "X AND Y happened." |
| `leftouter` | Enrich the left | Keep all left rows, attach right when available. Use for enrichment. |
| `leftanti` | Subtract | Rows in left with NO match on right. The "NOT" join. |
| `leftsemi` | Filter | Rows in left WITH a match — without pulling right's columns. |
| `rightouter` / `rightanti` / `rightsemi` | Mirrors of the above | Rare — usually cleaner to just swap which table is on the left. |
| `fullouter` | Everything from both | Rare in security; useful for reconciliation. |

**Universal rule:** **Always put the smaller / more-filtered table on the LEFT.** Advanced Hunting (and Sentinel) builds the join from the left side, so a smaller left = faster, cheaper queries.

---

### 3. Union vs join — when to pick which — 5 min

**Framing blurb:**
> Joins put tables **side by side** (more columns). Unions stack tables **on top of each other** (more rows). If you want to ask *"what other facts can I attach to this row?"* you want a join. If you want to ask *"where else does this thing show up?"* you want a union.

**Scenario:** *Search for a domain across every table that could contain a URL.*

```kql
let badDomain = "example-bad.com";
union isfuzzy=true
    (DeviceNetworkEvents | where RemoteUrl has badDomain | project Timestamp, Source="DeviceNetworkEvents", DeviceName, Detail=RemoteUrl),
    (DeviceEvents       | where RemoteUrl has badDomain | project Timestamp, Source="DeviceEvents",       DeviceName, Detail=RemoteUrl),
    (EmailUrlInfo       | where Url has badDomain       | project Timestamp, Source="EmailUrlInfo",       DeviceName="", Detail=Url),
    (UrlClickEvents     | where Url has badDomain       | project Timestamp, Source="UrlClickEvents",     DeviceName="", Detail=Url)
| order by Timestamp desc
```

**Teach moments:**
- `isfuzzy=true` keeps the query alive even if one of the tables doesn't exist in this tenant — defensive habit.
- **Project to a common shape inside each union leg.** This is the trick that turns the "messy union with empty columns" complaint from last week into a clean, readable result set.
- Add a `Source="…"` literal column so you can tell which table each row came from — invaluable when the same domain hit four different telemetry sources.

---

### 4. Arrays — `make_list`, `make_set`, `mv-expand` — 7 min

**Framing blurb:**
> Sometimes you want one row per user with a *list* of things they did, instead of one row per event. That's what `make_set` and `make_list` are for — they collapse many rows into one and bundle the values into an array. `mv-expand` is the reverse — it explodes an array back into one row per element. The collapse-then-expand pattern is half of advanced hunting.

**Scenario:** *For each user with 10+ failed sign-ins today, give me the distinct source IPs and apps they hit.*

```kql
SigninLogs
| where TimeGenerated > ago(1d) and ResultType != 0
| summarize
    FailureCount = count(),
    SourceIPs    = make_set(IPAddress, 100),
    Apps         = make_set(AppDisplayName, 50),
    FirstSeen    = min(TimeGenerated),
    LastSeen     = max(TimeGenerated)
    by UserPrincipalName
| where FailureCount >= 10
| order by FailureCount desc
```

Then reverse it:

```kql
// Explode the set back into rows for further pivoting
SigninLogs
| where TimeGenerated > ago(1d) and ResultType != 0
| summarize SourceIPs = make_set(IPAddress, 100) by UserPrincipalName
| mv-expand SourceIPs
| project UserPrincipalName, SourceIP = tostring(SourceIPs)
```

**Teach moments:**
- `make_set` = distinct values. `make_list` = preserves duplicates (use when count/order matters).
- **Bound the array size** — `make_set(IPAddress, 100)`. Unbounded arrays can blow up your query.
- `mv-expand` undoes the collapse — useful when you want to join an exploded array back to another table.

---

### 5. Finish the `render` demo (the one the browser killed last time) — 4 min

Easy win, light material to end on.

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| summarize
    Failures  = countif(ResultType != 0),
    Successes = countif(ResultType == 0)
    by bin(TimeGenerated, 1h)
| render timechart
```

Swap `timechart` → `columnchart` → `piechart` to show how cheap visual pivots are. Mention this is exactly what you paste into a management report.

---

### 6. Wrap — 4 min
- **Cheat sheet handout** — share this file after the call.
- Ask: *"What scenario do you want walked through next time?"* — this is where you'll learn what they're actually stuck on day-to-day.
- Possible next topics: parsing (`parse` / `extract` / regex), `externaldata` for IOC lists, **building a custom detection rule from a hunting query**, watchlists.

---

## Common Gotchas (call these out as they come up)

- Always filter `Timestamp` / `TimeGenerated` **first** — before any joins, projects, or summarizes.
- `project` early to shrink the data flowing into a join.
- Alias colliding columns **before** joining (`ProcTime=Timestamp`).
- `has` is faster than `contains`. `endswith` is faster than `has` when you know the anchor (e.g., a domain suffix on a UPN).
- Bound `make_set` / `make_list` sizes.
- Use `isfuzzy=true` on unions across tables that may not exist in every tenant.
- Put the smaller table on the **left** of a join.

---

## Risk / Contingency

- **Browser crash again:** queries are pre-written and saved — reload and paste, don't retype.
- **Running long:** Section 4 (arrays) is the most cuttable. Section 5 (render) is fast and a great ender — keep it.
- **Running short:** Add a 7th section — **build a custom detection rule from a hunting query** (Advanced Hunting → Create detection rule). They'll love seeing the operationalization path.
