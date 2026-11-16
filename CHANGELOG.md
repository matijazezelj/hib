# Changelog

All notable changes to hib. Versions follow [semantic versioning](https://semver.org); before 1.0, a minor version can change behaviour.

## [0.2.0] - 2026-11-16

Mostly the security event log and what a SIEM (such as [SIB](https://github.com/matijazezelj/sib)) needs to use it safely.

### Added
- **Event log profiles.** `[events] profile = "local"` (default: every field whole) or `"siem"` (for logs that leave the machine). `siem` hashes `workspace` and `account` with a keyed HMAC, cuts `net_host` and `url` to the registrable domain, logs only a program label instead of the command, and leaves out the peer address. Each setting (`workspace`, `account`, `net_host`, `command`, `remote`) can also be set on its own. (#11, #12)
- **`events.key_refused`.** If `~/.hib/events.key` is refused (a symlink, not a regular file, wrong owner, readable by others, wrong format), hib writes one warning per run giving only the reason. The key is also checked at daemon start. (#13)
- **`home.changed`.** Each agent turn checks shell startup files, Claude and Codex settings, instructions, hooks, agents, commands and skills (in `~/.claude`, `~/.codex` and every account's config folder), `~/.gitconfig`, ssh config, `authorized_keys` and `rc`, autostart entries and systemd user units. A change is reported in the timeline and as `home.changed`: critical, or a warning when every change was an edit you approved. These files are reported, never put back. (#14)
- **`HIB_SESSION`.** Agent CLIs start with `HIB_SESSION=<session_id>`, so every process an agent starts can be tied to its session by process telemetry such as Falco's `proc.env`. (#16)
- **A scripted agent for acceptance tests,** turned on only by `[testing] script_dir`. It replays tool calls through hib's real permission, data-rule, protected-file and home-watch checks, so an end-to-end test can trigger security events without a CLI login. A daemon running it says so in `daemon.start` (`script_driver: true`). (#15, #17)

### Changed
- **Domains** come from the Public Suffix List (`tldts`), ICANN suffixes only, so customer names under shared hosting suffixes don't leave the machine: `acme.s3.amazonaws.com` becomes `amazonaws.com`, and `you.github.io` becomes `github.io`. Hosts are read the way `new URL` reads them, so tricks like `https://evil.com\@good.com/` give the real host. IDN comes out as punycode. Link-local (`169.254.169.254`), CGNAT, unspecified, ULA and mapped IPv6 addresses are classed as internal. `.arpa`, `.corp` and `.local` names become `[INTERNAL]`, and input that can't be parsed becomes `[HOST]` or `[URL]`. (#12)
- **The program label** (`command = "program"`) splits the command the way the shell quotes it, so a word inside a quoted secret can't become the label. It knows more `sudo` and `env` options, and falls back to `[COMMAND]` when it can't tell safely. (#12)
- **`data.block`** carries only a fixed reason when commands are coarsened, never the file name or script path. (#12)

### Security
- The hash key is opened without following symlinks or blocking on a named pipe, and its size is capped. (#12)
- Redaction placeholders in a host field keep only their category; other bracketed text is treated as a name. (#12)

## 0.1.0 - 2026-11-15 (untagged)

First versioned release: the harness as built from 8 October to 15 November 2026.

- **The harness:** a local daemon over Claude Code and Codex subscriptions, with a router, failover, advisor and arena. It has terminal and browser UIs, workspace sessions with permission prompts, auto mode in an OS sandbox, background tasks in git worktrees, and an egress log.
- **Guard:** secrets, identifiers and configured terms are replaced with placeholders before anything leaves the machine, and restored in what comes back. Local name detection is optional.
- **Sensitive workspaces:** pinned to one account, every read asks, data files are read as pseudonymised copies, and there is no raw JSON or auto-memory.
- **Data analysis** without sending the data.
- **Protected files:** git hooks and config and agent config inside the workspace are checked after every turn, and unapproved changes are put back.
- **`hib pipe`** redacts log streams before they reach an LLM. (#7)
- **Security event log** (`~/.hib/events/events.jsonl`) for a SIEM, with a `daemon.alive` heartbeat and redaction hardened by fuzzing. (#8, #9)

[0.2.0]: https://github.com/matijazezelj/hib/releases/tag/v0.2.0
