# Wellness Master Manifest Tool — Implementation Summary

---

## Purpose

This tool manages Wellness app manifests by separating:

- **Shared master content** (single source of truth)
- **App-specific overlays** (only meaningful differences)

It operates purely on JSON manifests and does **not** require platform, runtime, or app code changes.

---

## How to Use (script-driven)

- Split (produce overlays + analytics lookup):  
  `python manifest_tool.py --select aio --action split --input OCVWellness_a71936801.json --master master_manifest.json --log`  
  Uses master as the baseline; outputs only data unique to the input manifests.

- Merge (pull in latest master, apply overlays, rewrite appIDs/analytics/URLs):  
  `python manifest_tool.py --select aio --action merge --input OCVWellness_a71936801.json --master master_manifest.json --app-id <APPID> --log`  
  The `--app-id` value is injected for all appID fields and URL rewrites; analyticsName fields are rebuilt from the prefix lookup.

Interactive mode (no flags) will prompt for AIO/Standalone/External, merge/split, appID, and optional logging. Defaults: input `OCVWellness_a71936801.json`, master `master_manifest.json`.

---

## Files

### Input Files

- `master_manifest.json`  
  Canonical shared Wellness manifest.

- `AIO.json` (or similar)  
  Contains:
  ```json
  {
    "manifest": {
      "<appHeader>": { ... },
      ...
    }
  }

Output Files

split_overlays.json
Per-app overlays containing only differences from master.

analytics_prefix_lookup.json
Mapping:

{
  "<appHeader>": "<prefixA>|<prefixB>"
}


merged_output.json
Fully compiled manifests (master + overlay), ready for rebuild.

CLI Interface

The script prompts:

AIO? y/n (if y skip next 2)
Standalone? y/n (if y skip next)
External? y/n (if y, print not implemented exception)
merge or split? m/s

retrieve the AppID by inputfile.split("_")[1]; the item after the underscore

App Selection Rules

AIO
Process every child under input.manifest.

Standalone
Process only the first item under input.manifest.

External
Exit (reserved for future handling).

### Analytics Prefix Lookup
For each app:

get the features.resilienceReps.analyticsName

Extract prefix: A|B|C → A|B
Store:

{
  "<appHeader>": "A|B"
}

## Comparison Semantics
Key Principles

To find diff, start at the root nodes of the app. For each node, if it exists in master open it up.
If it doesn't exist, add the node and all of the elements to the output.

For each child Node, if there is a value that does not exist in master, add the full tree into output.

continue this process until we reach the leaf.

For example, you will be iterating through features: if features.oCVWellnessResources is not in master, add it to the output. 


When traversing, you can skip the ignore fields:

url, imageURL, analyticsName, appID

split_overlays.json contains:

{
  "manifest": {
    "<appHeader>": {
      "<section>": { ...all diffs, stored with the same path as originally found... }
    }
  }
}


analytics_prefix_lookup.json updated automatically.

## Merge Logic (Compilation)
Objective

Generate full app manifests by combining:

compiled = master + overlay

Assume the overlay does not contain anything that is already in master. 

For every item in the overlay, check if master has the node.

If it does, to find the first node that does not exist in master (may be a leaf). Add the data here/

When complete, 


Replace every occurence of "changeMe" with the appID found in the begging.
(can be as simple as ctrl+f replace)

Replace every "analyticsName" field the lookup by using the header.

Single output file:

{
  "manifest": {
    "<appHeader>": { ...compiled manifest... }
  }
}

