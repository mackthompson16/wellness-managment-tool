#!/usr/bin/env python3
"""
Wellness manifest split/merge tool implementing the README rules.

Prompts (interactive defaults):
- AIO? y/n           -> process all manifest entries
- Standalone? y/n    -> process only the first manifest entry
- External? y/n      -> exit (reserved)
- appID: <string>    -> required for merge (replaces all appID fields)
- merge or split? m/s

CLI flags may skip prompts:
  --input <file>      (default: input.json)
  --master <file>     (default: master_manifest.json)
  --select aio|standalone|external
  --action merge|split
  --app-id <value>
"""
import argparse
import copy
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

IGNORED_KEYS = {"url", "imageURL", "analyticsName", "appID", "backgroundImageURL"}
OCCV_APPS_RE = re.compile(r"/ocvapps/[^/]+/", re.IGNORECASE)


# ---------- I/O ----------
def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: str, data: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# ---------- Diff helpers (split) ----------
def sanitize_string(value: str) -> str:
    # Treat any /ocvapps/<id>/ segment as equivalent regardless of app id or casing.
    return OCCV_APPS_RE.sub("/ocvapps/<APP>/", value)


def meaningfully_contained(current: Any, master: Any, path: List[str]) -> bool:
    """
    Containment-based comparison:
    - Dict: every non-ignored key in current must exist in master and be contained.
    - List: every item in current must be contained in some item in master (order irrelevant).
    - Scalar: must match after string sanitization.
    """
    if master is None:
        return False

    if isinstance(current, dict) and isinstance(master, dict):
        for k, v in current.items():
            if k in IGNORED_KEYS:
                continue
            if k not in master:
                return False
            if not meaningfully_contained(v, master[k], path + [k]):
                return False
        return True

    if isinstance(current, list) and isinstance(master, list):
        for item in current:
            if not any(meaningfully_contained(item, m_item, path) for m_item in master):
                return False
        return True

    if isinstance(current, str) and isinstance(master, str):
        return sanitize_string(current) == sanitize_string(master)

    return current == master


def diff(current: Any, master: Any, path: List[str]) -> Optional[Any]:
    """
    Traverse top-down; if a leaf differs, include the full parent chain.
    Ignored keys are skipped for comparison.
    """
    if master is None:
        return copy.deepcopy(current)

    if isinstance(current, dict) and isinstance(master, dict):
        filtered = {k: v for k, v in current.items() if k not in IGNORED_KEYS}
        result: Dict[str, Any] = {}
        changed = False
        for k, v in filtered.items():
            m_val = master.get(k)
            child = diff(v, m_val, path + [k])
            if child is not None:
                changed = True
                result[k] = child
        return result if changed else None

    if isinstance(current, list) and isinstance(master, list):
        uniques = [
            copy.deepcopy(item)
            for item in current
            if not any(meaningfully_contained(item, m_item, path) for m_item in master)
        ]
        return uniques or None

    return None if meaningfully_contained(current, master, path) and meaningfully_contained(master, current, path) else copy.deepcopy(current)


def count_nodes(node: Any) -> int:
    """Count total nodes (dict entries, list items, scalars) in an overlay subtree."""
    if isinstance(node, dict):
        return sum(count_nodes(v) for v in node.values()) + len(node)
    if isinstance(node, list):
        return sum(count_nodes(i) for i in node) + len(node)
    return 1


# ---------- Analytics prefix ----------
def extract_prefix(manifest: Dict[str, Any]) -> Optional[str]:
    features = manifest.get("features", {})
    for f_key in sorted(features):
        if f_key == "openSettings":
            continue
        val = features[f_key]
        if isinstance(val, dict):
            analytics = val.get("analyticsName")
            if isinstance(analytics, str) and analytics and not analytics.endswith("|openSettings"):
                parts = analytics.split("|")
                return "|".join(parts[:2]) if len(parts) >= 2 else analytics

    prefix: Optional[str] = None

    def dfs(node: Any) -> None:
        nonlocal prefix
        if prefix is not None:
            return
        if isinstance(node, dict):
            analytics = node.get("analyticsName")
            if isinstance(analytics, str) and analytics and not analytics.endswith("|openSettings"):
                parts = analytics.split("|")
                prefix = "|".join(parts[:2]) if len(parts) >= 2 else analytics
                return
            for k in sorted(node):
                dfs(node[k])
        elif isinstance(node, list):
            for item in node:
                dfs(item)

    dfs(manifest)
    return prefix


# ---------- Merge helpers ----------
def merge_overlay_into_master(master: Any, overlay: Any, path: List[str]) -> Any:
    """
    Overlay is assumed to contain only data absent/different from master.
    """
    if overlay is None:
        return copy.deepcopy(master)

    if isinstance(master, dict) and isinstance(overlay, dict):
        result = copy.deepcopy(master)
        for k, o_val in overlay.items():
            if k in result:
                result[k] = merge_overlay_into_master(result[k], o_val, path + [k])
            else:
                result[k] = copy.deepcopy(o_val)
        return result

    if isinstance(master, list) and isinstance(overlay, list):
        result = copy.deepcopy(master)
        for o in overlay:
            if not any(meaningfully_contained(o, m, path) and meaningfully_contained(m, o, path) for m in result):
                result.append(copy.deepcopy(o))
        return result

    return copy.deepcopy(overlay)


def rewrite_identity(node: Any, app_id: str, prefix: Optional[str], feature_key: Optional[str] = None) -> Any:
    if isinstance(node, dict):
        new = {}
        for k, v in node.items():
            if k == "features" and isinstance(v, dict):
                new[k] = {
                    f_key: rewrite_identity(f_val, app_id, prefix, feature_key=f_key)
                    for f_key, f_val in v.items()
                }
                continue
            new_val = rewrite_identity(v, app_id, prefix, feature_key=feature_key)
            if k == "appID":
                new_val = app_id
            elif k == "analyticsName" and isinstance(v, str) and prefix:
                tail = v.split("|")[-1] if "|" in v and v.split("|")[-1] else (feature_key or v)
                new_val = f"{prefix}|{tail}"
            new[k] = new_val
        return new
    if isinstance(node, list):
        return [rewrite_identity(i, app_id, prefix, feature_key=feature_key) for i in node]
    if isinstance(node, str):
        return OCCV_APPS_RE.sub(f"/ocvapps/{app_id}/", node) if app_id else node
    return node


def write_log(path: str, overlays: Dict[str, Any], diff_counts: Dict[str, int]) -> None:
    keys = sorted(overlays.keys(), key=lambda k: diff_counts.get(k, 0))
    total_diffs = sum(diff_counts.get(k, 0) for k in keys)
    lines = [
        f"Overlays: {len(keys)}",
        f"Total diffs (nodes): {total_diffs}",
        "",
        "Apps with overlays (differences found):",
    ]
    for k in keys:
        lines.append(f"- {k} (nodes: {diff_counts.get(k, 0)})")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


# ---------- Prompts ----------
def prompt_yes_no(label: str) -> bool:
    while True:
        resp = input(f"{label} (y/n): ").strip().lower()
        if resp in {"y", "yes"}:
            return True
        if resp in {"n", "no"}:
            return False


def prompt_choice(label: str, choices: List[str]) -> str:
    mapped = {c.lower(): c for c in choices}
    while True:
        resp = input(f"{label} [{'/'.join(choices)}]: ").strip().lower()
        if resp in mapped:
            return mapped[resp]


def prompt_path(label: str, default: str) -> str:
    resp = input(f"{label} [{default}]: ").strip()
    return resp or default


# ---------- Pipeline ----------
def select_app_headers(manifest: Dict[str, Any], select_mode: str) -> List[str]:
    excluded_prefixes = ("_", "OLD", "demo", "main", "tier", "30", "trial")
    keys = [
        k
        for k in manifest.keys()
        if not any(k.startswith(prefix) for prefix in excluded_prefixes)
    ]
    if select_mode == "standalone":
        return keys[:1]
    if select_mode == "external":
        return []
    return keys


def build_overlays_and_prefixes(
    manifest_data: Dict[str, Any],
    master: Dict[str, Any],
    app_headers: List[str],
) -> Tuple[Dict[str, Any], Dict[str, str], Dict[str, int]]:
    overlays: Dict[str, Any] = {}
    prefixes: Dict[str, str] = {}
    diff_counts: Dict[str, int] = {}
    for app_header in app_headers:
        manifest = manifest_data[app_header]
        overlay = diff(manifest, master, [])
        if overlay:
            overlays[app_header] = overlay
            diff_counts[app_header] = count_nodes(overlay)
        prefix = extract_prefix(manifest)
        if prefix:
            prefixes[app_header] = prefix
    return overlays, prefixes, diff_counts


def merge_outputs(
    master: Dict[str, Any],
    overlays: Dict[str, Any],
    prefixes: Dict[str, str],
    manifest_data: Dict[str, Any],
    app_headers: List[str],
    app_id: str,
) -> Dict[str, Any]:
    merged = {"manifest": {}}
    for app_header in app_headers:
        overlay = overlays.get(app_header)
        compiled = merge_overlay_into_master(master, overlay, [])
        prefix = prefixes.get(app_header) or extract_prefix(manifest_data[app_header])
        merged["manifest"][app_header] = rewrite_identity(compiled, app_id, prefix)
    return merged


def process(
    manifest_path: str,
    master_path: str,
    select_mode: str,
    action: str,
    app_id: Optional[str],
    log_enabled: bool,
) -> None:
    master = load_json(master_path)
    aio = load_json(manifest_path)
    manifest_data = aio.get("manifest", {})
    app_headers = select_app_headers(manifest_data, select_mode)

    if select_mode == "external":
        print("External mode selected; nothing to do.")
        return

    overlays, prefixes, diff_counts = build_overlays_and_prefixes(manifest_data, master, app_headers)

    # Update analytics_prefix_lookup.json while preserving other entries.
    existing_prefixes: Dict[str, str] = {}
    if os.path.exists("analytics_prefix_lookup.json"):
        try:
            existing_prefixes = load_json("analytics_prefix_lookup.json")
        except Exception:
            existing_prefixes = {}
    merged_prefixes = {**existing_prefixes, **prefixes}

    if action == "split":
        save_json("split_overlays.json", {"manifest": overlays})
        save_json("analytics_prefix_lookup.json", merged_prefixes)
        if log_enabled:
            write_log("split_log.txt", overlays, diff_counts)
        print(f"Split complete. Overlays: {len(overlays)}. Analytics prefixes: {len(merged_prefixes)}.")
        return

    # Merge
    if not app_id:
        raise ValueError("appID is required for merge.")

    merged_output = merge_outputs(master, overlays, merged_prefixes, manifest_data, app_headers, app_id)
    save_json("split_overlays.json", {"manifest": overlays})
    save_json("analytics_prefix_lookup.json", merged_prefixes)
    save_json("merged_output.json", merged_output)
    if log_enabled:
        write_log("merge_log.txt", overlays, diff_counts)
    print(
        f"Merge complete. Apps: {len(app_headers)}. "
        f"Overlays: {len(overlays)}. Analytics prefixes: {len(merged_prefixes)}."
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Wellness manifest split/merge tool")
    parser.add_argument("--input", default=None, help="Path to input manifest file (default: input.json)")
    parser.add_argument("--master", default=None, help="Path to master manifest file (default: master_manifest.json)")
    parser.add_argument("--select", choices=["aio", "standalone", "external"], help="App selection mode")
    parser.add_argument("--action", choices=["merge", "split"], help="Operation to perform")
    parser.add_argument("--app-id", dest="app_id", help="appID to inject during merge")
    parser.add_argument("--log", dest="log_enabled", action="store_true", help="Write log with overlays and diff counts")
    parser.add_argument("--no-log", dest="log_enabled", action="store_false", help="Do not write log")
    parser.set_defaults(log_enabled=None)
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    input_path = args.input
    master_path = args.master
    select_mode = args.select
    action = args.action
    app_id = args.app_id
    log_enabled = args.log_enabled

    # Interactive prompts when flags are absent.
    if select_mode is None:
        if prompt_yes_no("AIO?"):
            select_mode = "aio"
        elif prompt_yes_no("Standalone?"):
            select_mode = "standalone"
        elif prompt_yes_no("External?"):
            select_mode = "external"
        else:
            select_mode = "aio"

    if action is None:
        action = prompt_choice("merge or split?", ["m", "s"])
        action = "merge" if action.lower().startswith("m") else "split"

    if input_path is None:
        input_path = prompt_path("Input manifest path", "input.json")
    if master_path is None:
        master_path = prompt_path("Master manifest path", "master_manifest.json")

    if log_enabled is None:
        log_enabled = prompt_yes_no("Include log?")

    if action == "merge" and not app_id:
        app_id = input("appID: ").strip()
        if not app_id:
            print("appID is required for merge.", file=sys.stderr)
            sys.exit(1)

    process(input_path, master_path, select_mode, action, app_id, log_enabled)


if __name__ == "__main__":
    main()
