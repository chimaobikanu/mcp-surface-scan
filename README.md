# mcp-surface-scan

**Read-only reconnaissance of publicly advertised MCP tool manifests.**

An MCP server tells any caller what tools it offers. `mcp-surface-scan` reads those
manifests and classifies every advertised tool by the capability its *name* implies —
read, write, destructive, execute, credential, financial — so you can see the shape of an
agent surface before you point an agent at it.

It never invokes a tool. It never sends a payload. It never attempts authentication.

```
$ mcp-surface-scan --url https://example.com/mcp

reachable       1
leads           4
strong leads    4 across 1 endpoint(s)
                (capability matched the tool NAME, not prose)

STRONG LEADS — review these first, then read the actual tool:
  [destructive] example.com/mcp        delete_project     (6 tools)
  [execute    ] example.com/mcp        run_shell_command  (6 tools)
  [financial  ] example.com/mcp        create_wallet      (6 tools)
  [credential ] example.com/mcp        rotate_api_key     (6 tools)
```

## Why this exists

When you connect an agent to an MCP server, you hand it every tool that server advertises.
The manifest is the contract. Most teams read the tool list once, at integration time, and
never again — even as the server adds tools.

This tool answers one question cheaply: **how much authority does this surface actually
carry, and how much of it is destructive?**

## Install

```bash
# from the release wheel (no PyPI account needed)
pip install https://github.com/chimaobikanu/mcp-surface-scan/releases/download/v0.1.0/mcp_surface_scan-0.1.0-py3-none-any.whl

# or straight from the repo
pip install "git+https://github.com/chimaobikanu/mcp-surface-scan"

# then, either way
mcp-surface-scan --url https://example.com/mcp
```

`fastmcp` is the only runtime dependency and it is imported only when a scan actually
runs, so `mcp-surface-scan --help` and `--version` work before it is installed.

## Usage

```bash
# one endpoint, human-readable report
python mcp_surface_scan.py --url https://example.com/mcp

# batch, from a CSV with an `endpoint`, `url`, `host` or `hosted_endpoint` column
python mcp_surface_scan.py --csv targets.csv --out results.json

# machine-readable only
python mcp_surface_scan.py --url https://example.com/mcp --json-only
```

## How classification works, and why names come first

The tool is deliberately biased toward the **tool name** over the description, because in
real testing the description produced false positives that the name never did — the word
"card" inside "encyclopaedia card" flagged a documentation site as a financial surface.

Names are also harder to get right than they look. Underscore is a *word character* in
regex, so `\bdelete\b` does **not** match `betterpost_delete_content` or `delete_list` —
which are exactly the names that matter. This scanner tokenises on non-alphanumerics
instead. That single bug, caught in testing, was the difference between finding 13 leads
and 22.

Where the class matched, the report tells you: `matched_in: "name"` is a strong signal,
`"description"` is a weak one.

## A capability flag is a lead, not a conclusion

This is the most important thing to understand about the output.

A tool named `delete_list` may be perfectly safe — it may delete a saved *search*. A tool
named `get_status` may be an unauthenticated data-exfiltration path. **The scanner tells
you where to look. It does not tell you what is wrong.** Every lead requires a human to
open the manifest, read the actual tool description, and reason about it.

In practice, manual review eliminated most of the leads this scanner produced: they turned
out to be price quotes, loyalty lookups, public-key retrieval, or an agent revoking its own
session — all of which are correct behaviour, not risk.

## Not a scanner for vulnerabilities

This does not fuzz, probe, exploit, or test for injection, authentication flaws, or
injection sinks. It classifies advertised capability. Those are different tools.

## Authorised use only

Use this on servers you own, or whose owner has authorised you in writing, or that are
in scope for a bug-bounty program you are enrolled in.

Reading a manifest is low-impact, but low-impact is not consent. Do not point this at
third-party production systems on the theory that the manifest was public anyway.

## Design constraints

- **Read-only by construction.** The only call made is `tools/list`.
- **No credentials.** It does not attempt auth, and reports `auth-required` and stops.
- **Bounded.** Per-endpoint timeout, bounded concurrency.
- **Cite your source.** If you publish findings, name the tool and version.

## Licence

MIT — see `LICENSE`.
