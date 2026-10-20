# Progress

Where hib stands and what to do next. Agents working here: read this first, and update it when you finish a piece of work.
hib itself sends this file with the first message of every fresh workspace session.

_Last updated: 2026-10-20_

## Where it stands

hib is usable day to day: a local daemon, a terminal agent (`hib`), a web workspace (`hib serve`), a multi-model chat, and an
OpenAI-compatible router, all over the Claude Code and Codex subscription CLIs. CI runs typecheck and `bun test` (323 tests,
2 of them Linux-only) on Ubuntu and macOS.

A full security audit ran on 2026-10-09 (daemon surface, agent permissions, guard/egress, analyze/plugins/web). All of
its high and medium findings are fixed (below), except one part noted under Known issues. The low ones are open, under
Known issues and in order under Next.

### Done
- **Router.** OpenAI-compatible `/v1`. Classification uses rules first, then Haiku for anything ambiguous. Routes come from config with learned scores (Thompson sampling), and failover is driven by usage and rate limits. Also: advisor review on routes, arena, and work/personal accounts via `CLAUDE_CONFIG_DIR` / `CODEX_HOME`.
- **Guard.**
  - Detection: regex detectors ported from sib, plus local NER (optional).
  - Placeholders: secrets and identifiers become per-conversation `[HIB…]` placeholders, and the answer is restored as it streams.
  - Policy: ask-first, with an AES-GCM sealed vault.
  - Egress log of everything sent.
- **Workspaces.**
  - Agent sessions: long-lived native CLI sessions with permission prompts in the web UI and terminal, resume, and handoff across CLIs. The handoff transcript is guarded.
  - Shared daemon: CLI and web follow the same live session.
  - Browser panels: file tree, git panel, and a browser terminal.
- **Sensitive workspaces.**
  - Pinned to one Claude account (Codex accounts are refused: it runs cat/grep without asking, so reads couldn't be gated or pseudonymised; a policy set earlier refuses new turns). No handoff, failover, advisor, arena, browser terminal or background tasks.
  - Secrets are blocked, and every read asks. Data files reach the agent only through Read, as a pseudonymised copy (a symlink is judged by its target). Commands keep placeholders unrestored.
  - **Commands vs data files: OS-enforced** (`denyData()` in `sessions.ts`).
    - macOS: the sandbox denies data files by pattern (`<root>/**/*.csv`, tsv, jsonl, ndjson, xls(x), parquet, sqlite, and every `*.json` except build config via `allowRead`).
    - Checked live, through hib and with `claude -p`: any depth, upper-case names, symlinks, hard links, renames, copies, files created after start, and a Python glob loop are all refused, while `package.json` stays readable.
    - Linux: the data files found at session start, with no depth cap. A folder that can't be listed completely (unreadable directory, over 50,000 entries) refuses the session. Glob support in Claude's Linux sandbox is unverified.
    - Obvious tries are refused up front by `datarules.ts` (UX, not the boundary).
    - No working OS sandbox (`sandboxProblem()`, e.g. Ubuntu's `kernel.apparmor_restrict_unprivileged_userns=1`): the session refuses to start, with the reason.
    - Re-run `bun test/manual/sandbox-probe.ts` after a Claude Code upgrade.
  - **Read/Grep vs data files: CLI-enforced, not OS-enforced.** Claude's file tools run outside the sandbox. The pseudonymised copy depends on Claude routing every Read/Grep through hib's permission prompt (`--permission-mode manual`, `ask` rules), and on hib's path checks (symlinks by target, case-insensitive). Not host-level containment.
  - Text you edit in a guard approval gets the secret block and name detection again.
  - Checked live: with a data file in the Claude sandbox's `denyRead`, Read still reaches hib and the redirect to the pseudonymised copy works (the sandbox doesn't apply to Claude's file tools).
  - When a policy is inherited (a parent of a sensitive folder, or a subfolder), the terminal banner and the web pill name the folder it comes from (`/ws/tree` returns `policyFrom`).
  - The policy covers the whole tree (`Workspaces.effectivePolicy`): every folder inside a sensitive one, and any folder that contains one. A folder spanning two sensitive folders pinned to different accounts is refused. Used by sessions, the terminal, `/ws/tree`, tasks.
  - It can only be tightened over HTTP; lifting it takes `hib workspace normal`, and the API won't forget a sensitive folder.
- **Analyze** (`hib analyze`, web panel). The model sees only the schema and writes `analyze(rows)`, which runs locally. Interpretation is optional. Includes column pseudonymisation and an offline GeoNames gazetteer for travel analysis.
  - macOS: Seatbelt with no network, no writes, no `process-exec` except bun, no Apple Events, and no reads of `/Users`, `/Volumes`, `/private/tmp`, `/private/var/folders` or keychains (metadata reads allowed, for path resolution). Written in a sandboxed session where nested Seatbelt can't run: CI's macOS job and a local `bun test` are what check it.
  - Without an OS sandbox (Windows, Linux without bwrap) model code doesn't run at all.
  - Identifying values are tokenized wherever they appear in a result or error (numbers too, case-insensitively, and an email's local part) before anything is cut to size; the fix step sends at most 1500 characters of error. With several files, any sensitive one pins the analysis, and two different pins are refused.
  - Linux with bwrap: bubblewrap from an empty root, only `/usr`, `/lib*`, `/bin`, `/sbin`, bun and `src/analyze` mounted read-only, all namespaces unshared, empty `/tmp`. CI installs bwrap so the Linux tests run.
- **Agent sandbox** (`src/workspace/sandbox.ts`). On in every session.
  - Claude: its Bash sandbox with `failIfUnavailable`, `allowUnsandboxedCommands: false`, and `autoAllowBashIfSandboxed: false` so prompts still reach hib.
  - Codex: a `default_permissions` profile extending `:workspace` with `filesystem = { path = "deny" }`. Codex runs its own binary from `~/.codex/packages`, so only `auth.json` is denied there.
  - Commands can't read `~/.hib`, CLI logins or credential stores (`secretPaths().commands`: also `.cargo` credentials, `.pypirc`, `.docker/config.json`, `.kube`, gcloud, azure), can't write outside the folder, and can't reach localhost or the network. A new host is a `SandboxNetworkAccess` prompt in Claude; Codex has no network.
  - Claude's own Read tool (outside the sandbox) is denied the same paths plus `~/.npmrc`, `~/.yarnrc.yml`, gem credentials and whole CLI homes (`secretPaths().tools`, as `Read(//path)` rules).
  - Nested Seatbelt isn't allowed (`sandbox_apply: Operation not permitted`), so hib can't wrap a whole CLI itself.
  - Checked live with real Claude and Codex sessions; the advisor MCP still reaches the daemon.
  - Git: Claude's sandbox lets the agent commit (worktrees too) but blocks the main repo's `.git/config` and `.git/hooks`. Codex keeps `.git` read-only, so Codex agents can't commit; hib's end-of-turn commit covers tasks.
  - Codex marks a request to run outside its sandbox only with a `reason` field; hib treats it as "beyond the sandbox", which auto mode and "always" never approve.
  - Test sandbox probes with repos outside `/tmp`: Codex's workspace profile can write anywhere under `/tmp`.
- **Daemon auth.**
  - The token is compared in constant time.
  - The registry refuses relative paths, and the CLI resolves `[dir]` itself: `hib workspace sensitive .` used to be resolved against the daemon's working directory, so it could protect (or `normal .` unprotect) the wrong folder.
  - Browser login: `POST /hib/login` (needs the token) mints a one-time code (15 min) for the link `hib serve` / `/web` prints. `POST /hib/session` trades it for a browser session id, stored as a sha256 in `browser_sessions`. It ends after 12 idle hours and after 7 days at most. `DELETE /hib/session` signs one browser out (the home page's Sign out), and with the token signs out all of them (`hib logout`). The page keeps it in `localStorage` (per origin, port included) and sends it as a bearer header. The terminal WebSocket opens with a one-time ticket (`POST /ws/terminal/ticket`: 30 s, one folder), never the session id in a URL. No cookie: one on 127.0.0.1 would reach every other local server.
  - The page's CSP (`img-src 'self' data:`, no frames, objects, media or forms) and the markdown renderer never load images, so restored values in model output can't leave through an image URL.
- **Protected files** (`src/workspace/protect.ts`). Defense in depth, not prevention: a file changed and used within one turn has already been used. The `Edit(./.git/**)` deny rules and the sandbox's write limits are the preventive layer. Each turn snapshots git hooks and config (a worktree's common dir too), `.claude/`, `.codex/`, `.hib/` and `.mcp.json` by content. Changes you didn't approve are put back, and a `protected_reverted` event says what. Nothing an agent creates can stop the check: fifos, sockets and unreadable entries are recorded without being opened, too many files is itself a finding, and a failed check is reported, never silent. Claude also has an `Edit(./.git/**)` deny rule; only `Edit(...)` rules are honoured, and they cover Write too.
- **Protected paths.** Judged on the resolved path, case-insensitively, following dangling symlinks too (a write through one creates its target) — `realTarget()` in `fs.ts`.
- **Auto mode** (`/auto`, off by default; needs the sandbox). Edits in the folder and sandboxed commands run without asking. Reads and searches outside the folder ask. New network hosts ask, except package registries. WebFetch/WebSearch always ask. Risky commands (push, publishing in any spelling like `npm --tag x publish` or `twine upload`, sudo, rm -r, anything naming hib's daemon or credentials) still ask. "Always" for interpreters and wrappers covers only the exact command line.
- **Web approvals.** Carry `outbound` (host, full URL, prompt or query, guard findings, placeholder count), shown in both UIs. Web calls get placeholders, not restored values. "Always" for WebFetch covers one host. Claude always asks hib for web tools via an `ask` rule; without it, user settings or Claude's pre-approved sites let WebFetch run unasked.
- **Background tasks** (`hib task "…"`, `/bg` in the terminal and web).
  - Each task is one agent session in its own git worktree, on branch `hib/task-<id>`, in auto mode. Worktrees live in `~/.local/share/hib/worktrees` (override with `HIB_WORKTREES`), a path without `.hib`/`.claude`.
  - The worktree is registered as a workspace so sessions, the guard and the web UI work there, but it's hidden from workspace listings.
  - The model is chosen for the original folder, so `accounts.dirs` pins still apply.
  - The agent is told nobody is watching and to leave PROGRESS.md alone (parallel tasks would conflict); update PROGRESS.md after merging. hib commits what the agent leaves at the end of each turn.
  - hib's own git calls run no repo code: task commits, merges and worktree setup run without hooks (`core.hooksPath=/dev/null`, `--no-verify`), since hook files can be ones the agent edited (husky, lefthook). Every git call hib makes on its own disables fsmonitor, and diffs disable external diff and textconv. Commits from the web git panel still run your hooks.
  - Status: running, waiting, done, failed, interrupted. A macOS notification fires on done, failed and needs-approval.
  - `hib tasks` lists them; `review`, `merge` (`--no-ff`; a conflicting merge is aborted) and `discard` act on one, and `open` opens its session. `/tasks` and `/task <id>` do the same on the web.
  - Refused in sensitive workspaces and without an OS sandbox.
- **Advisor tool** (`/advisor`, off by default). hib's MCP server gives the agent an `advisor` tool backed by the other provider, through the guard, logged.
- **SecOps readability.** Free-text columns flagged only because cells contain emails (`full_log`, `rule.description`) keep their words; only the identifiers inside are replaced (`identifyingBy` → "text"). `hib workspace keep col,col` stores a per-folder keep-list in the policy (CLI only, it loosens; re-applying the policy over the API clears it): Read copies leave those columns untokenized, still guarded.
- **Sensitive folders: every non-config .json is data, and auto-memory is off.** A JSON object used to count as "not data" and reached Claude's Read raw (after approval), as did any JSON over 50 MB. Now every `.json` but build config is data: an object loads as the largest list of records inside it or an object of records keyed by id, JSON with no records gets a regex-guarded copy, and over 50 MB is refused. Sensitive sessions also start with auto-memory off (setting and env, checked live against Claude Code 2.1.304), since memory notes held names and case details and went out unguarded.
- **SIEM and log data.** Nested JSON is flattened into dotted columns (`user.name`, `source.ip`; `x.name` is judged by its parent, so `process.name` stays readable). Elasticsearch exports (`hits.hits[]._source`) and JSON-lines `.log` files load as tables. In sensitive folders `.log` is a data file (OS-denied to commands, Read gets a copy); a plain-text log's copy gets the regex guard alone. Hidden values are matched inside `CORP\jdoe`, `C:\Users\jdoe`, `jdoe@host`. New detectors: passwords on command lines (`net use /user:`, `net user`, `--password`, `-pass pass:`, `/pass:`, `sshpass`/`psexec -p`, `mysql -p…`, `sqlcmd -P`) and Windows home folders. The guard on a pseudonymised copy now runs per cell: over the whole CSV a password detector swallowed the next cell. Benchmark: `test/manual/bench.ts`, numbers in the README.
- **Hidden values are tokenized in every column.** A name, email or other value from a hidden column that also appears in a free-text column ("follow up with josip müller") gets the same token there, in any case or spacing. The copy a sensitive folder hands Claude's Read tool also goes through the regex guard, so an address typed into a notes column doesn't go out. On a 10k-row file this took the readable names from 7,950 rows to 0, for about 50 ms. A name that appears in no identifying column still needs NER (about 24 ms a row).
- **SIEM guard gaps (2026-10-20, from an end-to-end test of a 113-event Wazuh export through `hib ask -f`).**
  - Encoded payloads (`src/guard/encoded.ts`). Base64 (also base64url and line-wrapped), hex and percent-encoded runs that decode to mostly printable UTF-8 are guarded as text. This happens in `detect()` (every regex path, Read copies included), in name detection (the decoded text plus its string literals), and against hidden column values in `pseudonymize`. A blob with any finding inside becomes one `[…-BASE64|HEX|URL-ENCODED-n]` token covering all of it; secrets inside keep ask-first via `absorbed`. Any address counts inside a payload, `example.org` too. Two encodings deep at most. Before, sudo's `python3 -c <base64>` went out and the model decoded and quoted the names.
  - Name detection has no size limit; it has a budget instead (`nerScan`). It runs line by line, in ≤1000-char pieces, within `guard.nerBudgetSec` (120 s) and 1 GB of RSS growth. The "once found, tokenised everywhere" pass still covers the whole text, as one regex. Past the budget, free-text cells (4+ words, spans from `pseudonymizeWithSpans`) and free-text lines outside tables become `[…-TEXT-n]`, and the approval reason says how far detection got. Before, over 200,000 characters it failed, and approving sent every name in free text.
  - `hib ask -f` sends `attachment-N.csv` as the table name and in the history note (`jdoe_ssh_logs.csv` went out as is).
  - Identifying-column rule refined (`identifyingName` in `table.ts`). `<thing>Name`/`<thing>_name` (method, service, log, event, program, process, app, resource…) and descriptors (`*_type`, `*Count`, `*_status`, `client_id`/`client_type`/`clientOs…`) aren't identifying. Number and date columns are identifying by name only as ids (`*id`) or hard identifiers (phone, OIB, IBAN, card, birth/dob, account…: deliberately wider than "ids only", so an 11-digit OIB or a birth date stays hidden). `callerIp`/`sourceIP`/`source_ip` are now caught by name.
  - JSON stored in a string cell (Wazuh `full_log`) is flattened into dotted columns like nested JSON (`full_log.protoPayload.requestMetadata.callerIp`), in JSON and CSV loads, three levels deep at most. The original column goes away; plain-text cells keep it.
  - Design (not built): `docs/design-sensitive-mcp-and-commands.md`. It covers an allow-listed MCP proxy run by the daemon with the session vault, and guarding Bash output. The recommendation is a FIFO relay to a filter outside the sandbox, so nothing in the sandbox reaches the daemon or vault.
- **Overlapping findings merge.** When findings overlap (a term, your username or a plugin pattern inside an email address; a username inside a path; NER inside an email), they become one placeholder covering all of them, so no part of any match goes out in the clear. The label is the secret's if one is involved, otherwise the widest match's (EMAIL, PATH); the other categories are kept in `absorbed`, and ask-first rules still see them. Before, the first detector won and the rest of the address leaked (`dana.horvat@[TERM-1]-logistics.io`).
- **Guard order and coverage.**
  - Text is guarded whole, then cut (handoff transcript, PROGRESS.md, the advisor's transcript and diff, the classifier excerpt), so a cut can't strip a key's BEGIN line. The classifier gets plugin patterns and machine identities too.
  - The router's advisor gets the primary answer through the guard (in agent mode it can quote files).
  - History keeps the text you approved, edits included, so later turns, titles, handoffs and the advisor never resend what you removed.
  - `accounts.dirs` pins hold for an over-quota explicit pick and for the advisor (`Router.advisorFor(primary, cwd)`).
- **Approvals cover one model.** An approved turn goes only to the model the approval named: no failover, advisor or arena. If that model fails, the turn fails.
- **Claude settings.** Every session runs with `--permission-mode manual` and `--setting-sources user`: your own settings apply, a repo's `.claude/` settings and hooks don't. "Always" for an MCP or unknown tool is keyed on that exact call.
- **Codex permissions.** The whole command is judged (Codex's `/bin/zsh -lc '…'` unwrapped), not the first parsed segment; a move's destination is among the paths checked; a request with a `reason` (asking to leave the sandbox) is never auto-approved.
- **Web UI, terminal.** Dark-first web UI with slash commands; Ink terminal agent and router chat with slash autocomplete and `**bold**`.
- **Plugins.** Markdown plugins (skill, agent, route, guard, advisor) and code plugins.
  - Trust is a fingerprint of every file in the plugin (helpers, node_modules, route files; symlinks by target, never followed), recorded by `hib plugin trust` and checked before anything trusted loads. An edit on disk, or an update that changes anything but plain markdown docs, needs trust again. Trust from before fingerprints must be given again.
  - Route plugins choose which account sees your prompts, so they apply only once trusted, and never below the standard guard level. Agent plugins can only raise the level, and can't turn the advisor back on in sensitive or attachment runs.
- **Ready to publish.** MIT LICENSE; the README says hib drives the official CLIs on your own subscriptions and never extracts their logins.
- **PROGRESS.md.** Workspaces with this file at their root start every fresh session from it. In sensitive folders hib only points to it.

## Known issues
Open findings from the 2026-10-09 audit (all low), and older ones.

- **Guard and egress**
  - [medium] Name detection has no measured precision/recall. The lowercase-name miss from the `clients.csv` experiment has fixes but no benchmark proving it closed, so there are no guarantees about catching every person's name in free text.
  - [low] Egress log gaps: handoff transcript and PROGRESS.md content are logged only as flags and counts; agent tool output isn't logged as egress.
  - [low] Plaintext at rest: `messages`, `ws_events` and arena text keep originals; WAL/SHM files use the default umask.
  - [low] Detectors slow down quadratically on long input (100k chars ≈ 2.6 s at paranoid).
  - [low] Encoded payloads: a base64 run glued to a path (`/tmp/aGVs…`) is decoded from the wrong offset and missed; gzip+base64 and other compressed payloads aren't opened; a blob that decodes to text with nothing the guard knows (a name without NER, a bare username not in a hidden column) still goes out encoded.
  - [low] Name detection skips code-looking lines, so in a CSV row heavy with `{}`/`[]` (raw JSON in a cell that isn't an object) names aren't scanned. Decoded payloads have their string literals scanned to cover the script case.
  - [low] Wazuh `agent.name` (the monitored host) isn't hidden by name; `agent` isn't in the identifying words because `agent.version` etc. would follow.
  - [low] Detector gaps: unprefixed tokens (`hvs.`, `hf_`, `shpat_`, Datadog, Okta), `scheme://user:pass@`, compressed IPv6, 100.64/8 and 169.254/16 as internal, IBANs, cards, phone numbers, names without NER.
- **Agent permissions**
  - [low] Your own Claude allow rules and PreToolUse hooks (user settings) can still decide a call before hib sees it; that's your choice, and the README says so.
  - [low] Codex `webSearch` isn't gated, only logged. Turning it off needs the right Codex config key (likely `web_search = "disabled"`, an enum with disabled/cached/indexed/live in 0.160); verify with `codex sandbox -c 'web_search="bogus"' -- true` outside a sandboxed session (it should reject the value) before setting it in `codex-driver.ts`, since a wrong key could break every Codex session.
  - [low] "Always" on a WebFetch host allows any URL/query to that host. An approved protected-file edit lets any content into that path for the rest of the turn.
  - [low] A background command can swap a directory for a symlink between an Edit's approval and its write; the end-of-turn check catches it for protected files only.
  - [low] Grep on a folder (not a single data file) in a sensitive workspace can return raw rows; it asks first and says so.
- **Daemon**
  - [medium] A browser session still carries the daemon's whole authority (workspaces, approvals, terminal tickets) for up to 7 days. Separating the terminal and approvals from ordinary UI calls would need scoped sessions.
  - [low] The advisor key and system prompt are on CLI command lines (visible in `ps`).
  - [low] No `frame-ancestors` (a meta CSP can't set it; the HTML route can't set headers yet).
  - [low] Git pathspec magic (`:(top)x`) gets past `safePath` in `/ws/git/diff` when the workspace is a subfolder of a bigger repo.
- **Analyze and plugins**
  - [medium] Plugin fingerprints prove the files are the ones you trusted; they don't isolate trusted code, and a process outside the agent sandbox could swap a file between the check and the import.
  - [low] Headerless CSVs send the first data row as column names; async model code runs past the vm timeout (bounded by the kill timer); plugin guard regexes aren't checked for catastrophic backtracking.
- **Other**
  - [low] The sandbox check is per host, not per CLI: a kernel that blocks Claude Code's sandbox also turns off auto mode and tasks for Codex, whose sandbox may work there. `sandboxFor` could become provider-aware.
  - [low] Credential paths are denied to commands only if they exist when the session starts; a CLI you log into mid-session is covered from the next session.
  - [low] Linux sensitive sessions walk the whole folder at start, `node_modules` included (skipping it would leave data files there readable), and check every JSON file's content. A large dependency tree is slow, or over 50,000 entries refuses the session.
  - [low] The macOS keychain is reachable from inside the agent sandbox (`security find-generic-password`); with the network closed it can only go back to the model's vendor or an approved host. `~/.npmrc` stays readable to commands (npm needs it), so a registry token could be used by a script if a publish slips past the command check.
  - The token is still all-powerful for anything outside an agent sandbox.
  - `ls` came back empty in one auto-mode test although the file existed; not investigated.
  - The advisor needs a logged-in account of the other provider; without one `/advisor` switches itself off.

## Next
0. **Sensitive SecOps gaps** (from a real investigation; in priority order). The design for the first two is in `docs/design-sensitive-mcp-and-commands.md`:
   - **Command output.** The biggest remaining source: hib asks before each command but sends what it prints (ssh queries, script summaries, gh). Recommended: rewrite each approved command to write into a FIFO that the daemon guards with the session vault, and read the guarded output back from a second FIFO. Probe the sandbox's per-session write allow-list first.
   - **MCP proxy.** A sensitive session can't use MCP servers (`--strict-mcp-config`), and outside one their results aren't guarded. The daemon would run an allow-list of servers behind a `hib-mcp` shim with a per-session key (like the advisor). It would restore tokens in arguments and pseudonymise results like a Read copy.
   - Names that appear only in free text in a Read copy need name detection, which the copy doesn't run (`allowDecision` is synchronous; `nerScan` with the cell spans from `pseudonymizeWithSpans` would slot in once it isn't).
1. **Measure name detection.** A labeled fixture set: synthetic names in lowercase, mixed case and other scripts, the `clients.csv` shape, and names inside free text. A test that reports precision and recall for regex + NER and fails below a threshold. Then decide on **query-aware column minimization** for `hib ask -f` / analyze: send only the columns the question needs.
2. **Push and check CI.** Several things can't run in a sandboxed Claude session and are checked only by CI (or `bun test` on your machine): the server tests (browser sessions, forget refused), the Linux bubblewrap tests, and the macOS analysis Seatbelt profile (the "sandboxed run" tests). Confirm both jobs pass. If the macOS "sandboxed run" tests fail with EPERM on `tsconfig.json` or `package.json`, bun walked up to the repo root (now under the `/Users` deny): add literal allows for those two files in `seatbelt()`, don't re-allow the repo.
3. **Low-severity items** above, roughly in order: gate Codex `webSearch` (verify the key first); egress log of handoff/PROGRESS content; detector gaps and speed; `frame-ancestors` via a header; pathspec literals; command-line secrets via env; plaintext at rest.
4. **Older items**: the empty `ls` output; background-task polish (a tasks panel with review/merge/discard in the web UI; worktrees start without `node_modules`; tasks don't include uncommitted changes, hib warns).
5. **Review feedback, P2**: whether the router's learned scores get enough real feedback; prompt injection from repo content and tool results beyond what the sandbox and approvals cover.

## How to check it works
- `bun test` and `bunx tsc --noEmit -p .`. Inside a sandboxed Claude session, the analyze tests (nested Seatbelt) and the server tests (local port binding) fail for environmental reasons; CI runs them.
- With a scratch home: `HIB_HOME=/tmp/hibhome hib daemon start`, then open the printed URL in a test folder. Change `port` in its config.toml first if your own daemon is running.
- After changing web or daemon code, run `hib daemon stop`. The running daemon serves the old code. Browsers need a fresh link (`/web` or `hib serve`) after 12 idle hours or 7 days.
