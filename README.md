# hib — harness in a box

[![ci](https://github.com/matijazezelj/hib/actions/workflows/ci.yml/badge.svg)](https://github.com/matijazezelj/hib/actions/workflows/ci.yml)

A local, security-first harness over your **subscription** coding CLIs (Claude Code, Codex). It gives you a coding agent in the terminal and the browser and a local OpenAI-compatible router. It picks a model per task, switches accounts as quota runs low, lets one provider review another, learns what works where, and redacts sensitive data before anything leaves your machine.

hib drives the official CLIs you're already logged into. It never extracts OAuth tokens or calls private endpoints.

## Requirements

- [Bun](https://bun.sh) ≥ 1.4 (`brew install oven-sh/bun/bun`)
- At least one of these, installed and logged in:
  - [Claude Code](https://docs.claude.com/en/docs/claude-code) (`claude`)
  - [Codex CLI](https://github.com/openai/codex) (`codex`)
- `git`
- macOS or Linux

## Install

```sh
git clone git@github.com:matijazezelj/hib.git ~/work/personal/hib
cd ~/work/personal/hib && bun install
ln -s ~/work/personal/hib/src/cli.ts ~/.local/bin/hib   # any dir on your PATH; the file has a bun shebang
```

## Quick start

```sh
cd ~/code/myproject
hib                  # terminal coding agent for this folder
hib serve            # the same folder in the browser: http://127.0.0.1:4141/?ws=…
hib --resume         # pick up a session in this folder, whether it started here or in the browser
hib chat             # multi-model router chat in the terminal
hib ask "…"          # one-shot answer on stdout
hib daemon status    # or: stop
```

There is one background daemon, which logs to `~/.hib/daemon.log`. `hib` and `hib serve` start it if needed and register the folder you're in. Turns run inside the daemon, so the terminal and any browser tabs are views of the same live session. Start a task in the terminal and approve its edits in the browser, or the other way round. Closing a view doesn't stop the agent; Esc, `/stop` or the Stop button does.

Any OpenAI client can use the router: set `OPENAI_BASE_URL=http://127.0.0.1:4141/v1` and `OPENAI_API_KEY=$(cat ~/.hib/token)`, and use the model `hib/auto`.

## Workspace (terminal and browser)

- **Agent timeline.** Reads, edits and commands stream in as they happen. Edits show a diff and wait for **Allow / Always / Deny**. In the terminal those are **y / a / n**.
  - "Always" lasts for the session and is scoped to the program and subcommand, so `git status` doesn't cover `git push`.
  - Compound commands like `a; rm b` only ever match themselves.
  - "Always allow edits" only covers files inside the folder.
- **Native sessions.** Claude runs as a long-lived `claude -p --input-format stream-json --permission-prompt-tool stdio` process, and Codex as `codex app-server`. Sessions resume natively. Switching to a model on another CLI mid-session hands the transcript over.
- **Files, changes, terminal** (browser only):
  - a file tree and viewer, jailed to the folder and gitignore-aware;
  - a git panel with diff, discard and commit;
  - a real shell on a pty, using xterm.js.
- **Terminal commands:** `/model`, `/models`, `/new`, `/resume`, `/web` (prints the browser link for this session), `/egress`, `/usage`, `/quit`. Type `/` for an autocomplete menu: Tab completes, ↑/↓ select, Enter runs, Esc clears (or stops a running turn). `/model` and `/resume` also complete their arguments. A message that starts with a path, like `/etc/hosts is broken`, is sent as text.

The browser home page `/` lists your workspaces, and `/?router` is the multi-model chat. hib refuses `~` and `/` as workspaces, and `hib workspace forget` removes a folder.

## Sensitive workspaces

```sh
cd ~/code/client-project
hib workspace sensitive --account claude@work   # pin this folder to one vendor account
hib workspace egress                            # what left the machine in the latest session, and to whom
hib workspace normal                            # lift it
```

A sensitive folder is seen by exactly one vendor account. The policy is stored in hib's database, not in the repo, so an agent working in the folder can't edit it. While it's on:
- **One account only.** Models on other accounts or vendors are refused, in the workspace and in router requests whose working directory is inside the folder.
- **Nothing that copies data elsewhere:** no handoff, failover, advisor, arena, or classifier call.
- **Reads need approval.** Every file read, search, Bash command and subagent asks first, so you see each file before its contents go out. "Always" for a read covers only that directory.
- **Secrets are blocked** in prompts outright, not just tokenized.
- **Repo config is ignored.** Claude sessions load only your user settings, never the repo's `.claude/` settings or hooks, and no MCP servers. A cloned repo can't add allow rules or run hooks.
- **No browser terminal** (the server refuses it).
- **Egress log.** Each turn records the redacted prompt and the account it went to, plus every tool call. View it in the *Egress* tab, with `/egress` in the terminal, or with `hib workspace egress`.

Limits:
- Codex runs read-only commands like `cat` and `grep` without asking, so reads can't be gated on a Codex account. Prefer a Claude account for sensitive folders.
- Router chat that isn't tied to a folder isn't covered, so don't paste sensitive content into `hib chat`.
- Check each subscription's own data settings (training opt-out, retention) and your employer's rules. hib can't change those.

## Analysing data without sending it

```sh
hib analyze users.csv "average salary per department, and inactive users per department"
hib ask -f users.csv "which 3 people in Engineering earn the most?"
```

**`hib analyze`: send code, not data.** The model gets only a profile of the table: column names and types, row, null and distinct counts, and three made-up rows showing the shape.
- Columns that look identifying are marked so; their values are never shown. That means anything with a name like user, email, phone, IP or address, or values that look like emails, IPs or phone numbers.
- `--share department` adds the real distinct values of a non-identifying column, so the model can filter on them.
- The model writes an `analyze(rows)` function. You see it and approve it, and it runs **on your machine**:
  - in a separate process, with no `eval` or imports;
  - on macOS, inside a sandbox with no network, no file writes and no reads of your home folder.
- The result stays local. Sending the question, code and result for interpretation is a separate step, and you see exactly what would be sent first.
- If the code fails, only the error message is sent back for a fix.
- In the browser, open a CSV, TSV or JSON file in a workspace and press **Analyze**.

**`hib ask -f`: pseudonymise by column**, for questions that need the model to see rows.
- Identifying columns become stable tokens (`[…-USERNAME-7]`). An email becomes two tokens, one for the name and one for the domain, so grouping by domain still works without revealing it.
- Numbers and categories stay readable.
- The answer comes back with real values restored.
- `--hide col` and `--keep col` adjust which columns are tokenized.

In a **sensitive workspace**, when you approve Claude reading a `.csv` or `.tsv`, it gets a pseudonymised copy instead of the real file. The egress log records which columns were tokenized.

Limits:
- The profile still reveals column names and row counts.
- Detecting identifying columns is heuristic, so check the "identifying" list and use `--hide` for anything it missed.
- Only Claude reads can be redirected, not Bash `cat`. In sensitive mode Bash asks, so deny it.

## How a router request flows

1. **Classify** the request as chat, code, review or long. Heuristics come first; Haiku is asked only when they're unsure. Plugin routes can add classes.
2. **Route** to the candidates for that class.
   - A candidate is skipped if it isn't logged in, is at or above 90% of any quota window, or is cooling down after a rate limit.
   - The rest are ranked by learned scores (Thompson sampling).
3. **Guard** replaces secrets, IPs, emails, usernames, home paths and your configured terms with per-conversation tokens such as `[HIB3fa2-IP-INTERNAL-NET1-2]`.
   - The same value always gets the same token, and IPs that share a `NETn` share a /24, so models can still reason about relationships.
   - Private keys, DB URIs, AWS keys and your configured terms trigger **ask-first**: you approve or edit the exact text before it is sent.
4. **Run** the CLI in chat mode, in an empty scratch dir with every tool disabled.
5. **Restore** the real values in the streamed answer.
6. **Advisor** (set per route): a different provider critiques the answer, and the primary model revises it if problems are found.
7. **Learn** from thumbs up/down, arena picks, retries, advisor findings and errors.

## Security model

- **Network:** the daemon listens on `127.0.0.1` only.
  - Host header checks stop DNS rebinding.
  - Origin checks and a `SameSite=Strict` cookie stop other websites.
  - API clients use the token in `~/.hib/token`.
  - Local processes are trusted.
- **Files:** everything in `~/.hib` is `0600`.
  - `hib.db` holds conversations as originals, plus the audit log, which records counts, never values.
  - `vault.key` seals each conversation's token map with AES-256-GCM.
- **Agent mode:** in agent mode the CLI reads your files itself, so the guard covers only your prompt. The real protections are:
  - the folder boundary;
  - a one-time pre-scan for `.env` and key files;
  - per-action permission prompts.
- **Credentials are off-limits.** Every workspace session, sensitive or not, is denied reads of `~/.hib`, `~/.claude*`, `~/.codex`, `~/.ssh`, `~/.aws`, `~/.gnupg` and `~/.config/gh`.
- **Tool config needs approval every time.** "Always allow edits" never covers `.claude/`, `.codex/`, `.git/` or `.mcp.json` inside the folder, so an agent can't quietly widen its own permissions or plant a git hook.
- **Policies can only be tightened over the API.** Lifting one takes `hib workspace normal` at the terminal, so the API token alone can't switch it off.
- **Local processes are trusted.** Anything already running as your user can read `~/.hib`. hib raises the bar but doesn't sandbox your own account.
- **Your own CLI config still applies:** your `settings.json` allow rules, MCP servers and `CLAUDE.md` / `AGENTS.md` load into agent sessions. Broad allow rules there bypass hib's prompts.
- **Rendering:** model output is rendered as markdown without raw HTML.

## Accounts

Each `CLAUDE_CONFIG_DIR` or `CODEX_HOME` is a separate login and quota. You address one as `claude@work/sonnet`. Each CLI gets a minimal environment plus its account's variables, so accounts never leak into each other.

Quota numbers come from the CLIs themselves: Claude's `rate_limit_event` and Codex's `rate_limits`.

Router sessions are one-shot and deleted from Codex history afterwards. Workspace sessions are kept so they can be resumed:
- Claude's appear under `claude --resume` for that folder.
- Codex's are stored in `~/.codex/sessions`.

## Config: `~/.hib/config.toml`

The file is created on first run. It holds:
- routes and their candidates
- accounts
- advisor models
- model tiers
- guard terms, `askOn` and `agentDirs`

## Plugins

```sh
hib plugin install git://host/repo.git | https://…/x.md | ./path
hib plugin list | trust <name> | update <name> | remove <name>
```

Markdown files with `kind:` in their frontmatter add capabilities:

| kind | what it adds |
|---|---|
| `skill` | a `/name args` command; the body is a template with `{{args}}` |
| `agent` | a persona, used as the model `hib/agent/<name>` |
| `route` | a new task class with its candidates, keywords and level |
| `guard` | extra terms, regex patterns and `askOn` entries; these can only tighten the guard |
| `advisor` | a review checklist for the given classes |

Code plugins are `*.provider.ts` files that default-export a `Provider`. They load only after `hib plugin trust`. Trust is tied to the pinned commit, so an update that changes code drops trust and shows you the diff. See `examples/plugins/starter`.

## Development

```sh
bun test            # unit + end-to-end tests with fake providers; no CLI login needed
bunx tsc --noEmit   # typecheck
```

The tests cover:
- the guard: cases derived from sib, false positives on code, round trips, streaming restore and sealing
- the CLI stream parsers, against captured fixtures
- the router engine end to end: what reaches the wire, failover, advisor, resume, learning and arena
- workspace sessions: permission scoping, restoring tokens in tool input, live fan-out and the busy lock
- the file jail, the git panel, and plugin trust

CI runs the typecheck and tests on Ubuntu and macOS.

Layout: `src/` is the daemon, router, guard, providers and the workspace drivers and sessions; `src/tui/` is the terminal UIs; `web/` is the browser UI; `test/` is the tests.
