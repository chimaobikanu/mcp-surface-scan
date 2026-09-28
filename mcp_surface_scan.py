#!/usr/bin/env python3
"""mcp_surface_scan — read-only reconnaissance of publicly advertised MCP tool manifests.

WHAT THIS DOES
    Connects to an MCP server endpoint, calls `tools/list`, and classifies every
    advertised tool by the capability its NAME and description imply: read, write,
    destructive, execute, credential, financial.

WHAT THIS DOES NOT DO — BY DESIGN
    It never invokes a tool. It never sends a payload. It never submits a tool call.
    It never attempts authentication, never brute-forces, never probes for
    vulnerabilities. It reads a manifest that the server publishes to anyone who asks,
    which is equivalent to reading a public web page.

    A capability flag is a LEAD, NOT A CONCLUSION. A tool named `delete_list` may well
    be safe; a tool named `get_status` may well not be. This tool tells you where to
    look. It does not tell you what is wrong.

AUTHORISED USE ONLY
    Use this on servers you own, or whose owner has authorised you in writing, or in a
    bug-bounty program whose scope explicitly covers the asset. Reading a manifest is
    low-impact but it is not consent.

Usage:
    python mcp_surface_scan.py --url https://example.com/mcp
    python mcp_surface_scan.py --csv targets.csv --out results.json
    python mcp_surface_scan.py --csv targets.csv --json-only

CSV input needs a column named `endpoint`, `url`, `hosted_endpoint`, or `host`.
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import json
import pathlib
import re
import sys

try:
    from fastmcp import Client
except ImportError:  # pragma: no cover
    sys.exit("fastmcp is required:  pip install fastmcp")

# Priority order matters — the FIRST class that matches wins, so destructive outranks
# read. A tool that both lists and deletes is reported as destructive.
CLASS_ORDER = ["destructive", "execute", "credential", "financial", "write", "read"]

# Token sets, not regex word boundaries.
#
# WHY: underscore is a word character in regex, so \bdelete\b does NOT match
# `betterpost_delete_content` or `delete_list`. Tokenising on non-alphanumerics is the
# only way to see through namespaced tool names, which are the norm in MCP.
# Do not "simplify" this back to \b patterns.
CLASS_TOKENS: dict[str, set[str]] = {
    "destructive": {
        "delete", "destroy", "purge", "wipe", "remove", "drop", "terminate", "revoke",
        "reset", "cancel", "uninstall", "clear", "truncate", "kill",
    },
    "execute": {
        "run", "exec", "execute", "shell", "cmd", "command", "script", "eval", "deploy",
        "invoke", "spawn", "launch", "apply", "eval", "ssh", "sudo",
    },
    "credential": {
        "key", "apikey", "token", "secret", "credential", "credentials", "password",
        "keypair", "mint", "rotate", "auth", "login", "session", "impersonate",
    },
    "financial": {
        "pay", "payment", "transfer", "bank", "wallet", "charge", "invoice", "refund",
        "withdraw", "checkout", "fund", "funds", "balance", "order", "price", "quote",
        "billing", "purchase", "subscribe",
    },
    "write": {
        "create", "update", "set", "add", "publish", "post", "signup", "register",
        "upload", "insert", "modify", "patch", "write", "send", "submit", "edit", "put",
    },
    "read": {
        "get", "list", "search", "fetch", "read", "query", "find", "check", "view",
        "describe", "status", "lookup", "browse", "download", "export", "show",
    },
}

# Names are the strong signal; descriptions are the weak one. Kept separate so the
# caller can tell which fired — description-only matches are noisy (the word "card"
# inside "encyclopaedia card" produced a false financial flag in real testing).
DESC_PATTERNS: dict[str, str] = {
    cls: r"\b(" + "|".join(sorted(toks)) + r")\b" for cls, toks in CLASS_TOKENS.items()
}

TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")

TOOL_TIMEOUT = 22.0


def classify(name: str, description: str) -> tuple[str, str]:
    """Return (class, where_matched). where is 'name', 'description', or 'none'."""
    name = name or ""
    description = description or ""

    tokens = {t for t in TOKEN_SPLIT.split(name.lower()) if t}
    for cls in CLASS_ORDER:
        if tokens & CLASS_TOKENS[cls]:
            return cls, "name"

    for cls in CLASS_ORDER:
        if re.search(DESC_PATTERNS[cls], description, re.IGNORECASE):
            return cls, "description"

    return "other", "none"


async def scan_endpoint(sem: asyncio.Semaphore, url: str) -> dict:
    async with sem:
        result: dict = {
            "endpoint": url,
            "status": "unreachable",
            "tool_count": 0,
            "by_class": {},
            "tools": [],
            "leads": [],
        }
        try:
            async with Client(url, timeout=TOOL_TIMEOUT) as client:
                tools = await client.list_tools()
        except Exception as exc:  # noqa: BLE001 — any transport error is just 'unreachable'
            msg = str(exc)[:120].replace("\n", " ")
            result["status"] = (
                "auth-required" if ("401" in msg or "403" in msg) else f"error: {msg}"
            )
            return result

        result["status"] = "ok"
        result["tool_count"] = len(tools)

        counts: dict[str, int] = {}
        for tool in tools:
            cls, where = classify(tool.name, tool.description)
            counts[cls] = counts.get(cls, 0) + 1
            entry = {
                "name": tool.name,
                "class": cls,
                "matched_in": where,
                "description": (tool.description or "")[:300],
            }
            result["tools"].append(entry)
            if cls in ("destructive", "execute", "credential", "financial"):
                result["leads"].append(entry)

        result["by_class"] = counts
        # strongest leads first: name-matched before description-matched
        result["leads"].sort(key=lambda e: (e["matched_in"] != "name",))
        return result


def load_endpoints(path: str) -> list[str]:
    urls: list[str] = []
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            for col in ("endpoint", "url", "hosted_endpoint", "host", "mcp"):
                value = (row.get(col) or "").strip()
                if value.startswith(("http://", "https://")):
                    urls.append(value)
                    break
    return sorted(set(urls))


def print_report(results: list[dict]) -> None:
    ok = [r for r in results if r["status"] == "ok"]
    auth = [r for r in results if r["status"] == "auth-required"]
    strong_eps = [r for r in ok if any(l["matched_in"] == "name" for l in r["leads"])]
    strong_leads = sum(
        1 for r in ok for l in r["leads"] if l["matched_in"] == "name"
    )

    print(f"\nprobed          {len(results)} endpoint(s)")
    print(f"reachable       {len(ok)}")
    print(f"auth-gated      {len(auth)}")
    print(f"leads           {sum(len(r['leads']) for r in ok)}")
    print(f"strong leads    {strong_leads} across {len(strong_eps)} endpoint(s)")
    print("                (capability matched the tool NAME, not prose)\n")

    if strong_eps:
        print("STRONG LEADS — review these first, then read the actual tool:")
        for r in sorted(strong_eps, key=lambda x: -x["tool_count"]):
            for lead in r["leads"]:
                if lead["matched_in"] == "name":
                    print(
                        f"  [{lead['class']:11s}] {r['endpoint'][:56]:58s} "
                        f"{lead['name'][:38]}  ({r['tool_count']} tools)"
                    )
        print()

    total = sum(sum(r["by_class"].values()) for r in ok)
    if total:
        agg: dict[str, int] = {}
        for r in ok:
            for cls, n in r["by_class"].items():
                agg[cls] = agg.get(cls, 0) + n
        print("capability distribution across all advertised tools:")
        for cls in CLASS_ORDER + ["other"]:
            if agg.get(cls):
                pct = 100 * agg[cls] / total
                print(f"  {cls:12s} {agg[cls]:5d}  {pct:5.1f}%")
        print()


async def main_async(args: argparse.Namespace) -> int:
    if args.url:
        endpoints = [args.url]
    elif args.csv:
        endpoints = load_endpoints(args.csv)
        if not endpoints:
            print(f"no http(s) endpoints found in {args.csv}", file=sys.stderr)
            return 2
    else:
        print("pass --url or --csv", file=sys.stderr)
        return 2

    sem = asyncio.Semaphore(args.concurrency)
    results = await asyncio.gather(*(scan_endpoint(sem, u) for u in endpoints))

    payload = json.dumps(results, indent=2)
    if args.out:
        pathlib.Path(args.out).write_text(payload, encoding="utf-8")
    if not args.json_only:
        print_report(results)
        if args.out:
            print(f"wrote {args.out}")
    if args.json_only:
        print(payload)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only reconnaissance of public MCP tool manifests.",
    )
    parser.add_argument("--url", help="single MCP endpoint")
    parser.add_argument("--csv", help="CSV of endpoints (column: endpoint/url/host)")
    parser.add_argument("--out", help="write full JSON results here")
    parser.add_argument("--json-only", action="store_true", help="print JSON, no report")
    parser.add_argument("--concurrency", type=int, default=6)
    args = parser.parse_args()
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    raise SystemExit(main())
