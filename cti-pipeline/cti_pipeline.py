#!/usr/bin/env python3
"""PIR-driven Cyber Threat Intelligence pipeline.

Walks the intelligence cycle end to end, interactively:

  1. Planning & Direction  -> write down a Priority Intelligence Requirement
  2. Collection            -> MITRE ATT&CK over TAXII (GitHub fallback) + a STIX indicator feed
  3. Processing            -> age out, score confidence, de-duplicate (false-positive reduction)
  4. Analysis              -> map adversaries + indicators onto ATT&CK behaviors
  5. Dissemination         -> Markdown report, CSV, ATT&CK Navigator layer
  6. Sharing               -> TLP-marked STIX 2.1 bundle, optionally pushed over TAXII

Run:   python cti_pipeline.py            (interactive)
       python cti_pipeline.py --demo     (accept every default, no typing)
"""

import argparse
import os
import shutil
import sys
from datetime import datetime, timezone

from ctilib import analysis, indicators, navigator, report, requirements, sharing
from ctilib.attack_data import AttackKnowledgeBase, download_attack

OUTPUT_DIR = "output"
SAMPLE_FEED = os.path.join("samples", "sample_indicator_feed.json")

DEMO = False   # set by --demo; makes ask() return defaults without prompting


# ---- tiny UI helpers -------------------------------------------------------------


def banner(step, title):
    width = shutil.get_terminal_size((80, 20)).columns
    print()
    print("=" * width)
    print(f" STEP {step}: {title}")
    print("=" * width)


def ask(prompt, default=None):
    """Prompt for input; Enter (or --demo) returns the default."""
    suffix = f" [{default}]" if default not in (None, "") else ""
    if DEMO:
        print(f"{prompt}{suffix}: {default if default is not None else ''}")
        return default
    answer = input(f"{prompt}{suffix}: ").strip()
    return answer or default


def ask_int(prompt, default):
    while True:
        value = ask(prompt, str(default))
        try:
            return int(value)
        except (TypeError, ValueError):
            print("  Please enter a whole number.")


def ask_yes(prompt, default=False):
    value = ask(prompt + " (y/n)", "y" if default else "n")
    return str(value).lower().startswith("y")


def choose(prompt, options, default_key):
    """options: {key: label}. Returns the chosen key."""
    for key, label in options.items():
        print(f"  {key}) {label}")
    while True:
        key = ask(prompt, default_key)
        if key in options:
            return key
        print("  Not an option, try again.")


# ---- the six steps ---------------------------------------------------------------


def step_requirements():
    banner(1, "PLANNING & DIRECTION - who is this intelligence for?")
    print("A requirement is written before anything is collected. If it is not written")
    print("down, nobody can later judge whether the intelligence met the consumer's needs.\n")

    stakeholder_key = choose("Who is the consumer?", {k: f"{v[0]} ({v[1]})" for k, v in requirements.STAKEHOLDERS.items()}, "1")
    stakeholder = requirements.STAKEHOLDERS[stakeholder_key][0]

    question = ask("Intelligence question", "Which adversary behaviors should our detections prioritize this quarter?")
    decision = ask("Decision this supports", "Which ATT&CK techniques get new analytics and which mitigations get budget")

    print()
    presets = {str(i + 1): f"{name}: {info['description']}" for i, (name, info) in enumerate(requirements.SECTOR_PRESETS.items())}
    presets[str(len(presets) + 1)] = "custom: type your own list of ATT&CK group names or aliases"
    preset_key = choose("Which adversary set?", presets, "1")

    if preset_key == str(len(presets)):
        sector = ask("Name for this scenario", "custom")
        raw = ask("Group names or aliases, comma separated", "APT29, APT28")
        groups = [g.strip() for g in raw.split(",") if g.strip()]
    else:
        sector = list(requirements.SECTOR_PRESETS)[int(preset_key) - 1]
        entries = requirements.SECTOR_PRESETS[sector]["groups"]
        print()
        for name, origin in entries:
            print(f"    - {name:<16} {origin}")
        groups = [name for name, _ in entries]
        extra = ask("Add more groups (comma separated) or press Enter", "")
        if extra:
            groups += [g.strip() for g in extra.split(",") if g.strip()]

    req = requirements.IntelRequirement(stakeholder=stakeholder, question=question, decision=decision, sector=sector, groups=groups)
    path = os.path.join(OUTPUT_DIR, "requirement.json")
    req.save(path)
    print(f"\nRequirement recorded -> {path}")
    print(req.summary())
    return req


def step_collection(attack_file):
    banner(2, "COLLECTION - gather the knowledge base and a raw indicator feed")

    print("ATT&CK knowledge base (MITRE TAXII 2.1 server, GitHub mirror as fallback):")
    path, source = download_attack(attack_file, log=print)
    kb = AttackKnowledgeBase(path)
    print(f"  Loaded ATT&CK v{kb.version()} from {source} ({path})")

    print("\nIndicator feed: a STIX 2.1 bundle from a file or a TAXII collection.")
    mode = choose("Where is the feed?", {"1": f"local file (default: {SAMPLE_FEED})", "2": "pull from a TAXII 2.1 server"}, "1")
    if mode == "2":
        server_url = ask("TAXII discovery URL", "http://127.0.0.1:5555/taxii2/")
        user = ask("Username (blank for none)", "student")
        password = ask("Password", "password")
        server = sharing.connect(server_url, user or None, password or None)
        print(f"  Connected to '{server.title}'. Collections:")
        found = sharing.list_collections(server)
        for i, (coll, root) in enumerate(found, start=1):
            access = "read/write" if coll.can_write else "read-only"
            print(f"    {i}) {coll.title}  [{access}]  {root}")
        pick = ask_int("Pull which collection?", 1)
        collection, _ = found[pick - 1]
        objects = sharing.pull_collection(collection, log=print)
        feed = indicators.indicators_from_objects(objects)
        feed_source = f"TAXII: {server_url} / {collection.title}"
    else:
        feed_path = ask("Path to STIX bundle", SAMPLE_FEED)
        feed = indicators.load_feed(feed_path)
        feed_source = feed_path
    print(f"  {len(feed)} indicators received from {feed_source}")
    return kb, source, feed


def step_processing(feed):
    banner(3, "PROCESSING - reduce false positives before anything becomes an alert")
    print("Stale IPs and over-broad hashes teach analysts to ignore the SIEM. Four rules:\n")
    print("  1. expired:        valid_until has passed")
    print("  2. stale:          created longer ago than the max age")
    print(f"  3. low confidence: score below the threshold (unknown = {indicators.UNKNOWN_CONFIDENCE}, "
          f"no ATT&CK context = -{indicators.NO_CONTEXT_PENALTY})")
    print("  4. duplicate:      same pattern already kept\n")
    max_age = ask_int("Maximum indicator age in days", 90)
    min_conf = ask_int("Minimum confidence (0-100)", 50)

    result = indicators.process_feed(feed, max_age_days=max_age, min_confidence=min_conf)
    print()
    print(f"  Received: {result.total}")
    for reason, items in result.dropped.items():
        print(f"  Dropped ({reason}): {len(items)}")
        for ind in items:
            print(f"      - {indicators.indicator_kind(ind):<11} {ind.pattern[:60]}")
    print(f"  Kept:     {len(result.kept)}")
    print(f"\n  Alerts avoided: {result.dropped_count} of {result.total} ({result.reduction_percent()}%)")
    return result


def step_analysis(kb, req, processing):
    banner(4, "ANALYSIS - map adversaries and indicators onto ATT&CK behaviors")
    print("Infrastructure changes daily; behavior changes slowly. Everything is mapped to techniques.\n")
    result = analysis.analyze(kb, req.groups, processing.kept, log=print)

    print(f"\n  Unique techniques across tracked adversaries: {len(result.hits)}")
    shared = result.shared_by_all()
    if shared:
        print(f"  Used by every tracked adversary: {', '.join(sorted(h.attack_id for h in shared))}")

    print("\n  Top 10 behaviors (score = adversaries using it + live indicators):")
    print(f"  {'Rank':<5}{'ID':<11}{'Name':<45}{'Groups':>7}{'IOCs':>6}{'Score':>7}")
    for rank, hit in enumerate(result.ranked(10), start=1):
        print(f"  {rank:<5}{hit.attack_id:<11}{hit.name[:44]:<45}{len(hit.groups):>7}{hit.indicator_count:>6}{hit.score:>7}")

    print("\n  Mitigations covering the most prioritized behavior:")
    for (mid, name), score in result.mitigations.most_common(5):
        print(f"    {mid:<7} {name:<40} coverage {score}")

    gaps = result.detection_gaps(5)
    if gaps:
        print("\n  Prioritized techniques with NO documented detection strategy:")
        for hit in gaps:
            print(f"    {hit.attack_id:<11} {hit.name}")
    return result


def step_dissemination(req, processing, result, kb, attack_source):
    banner(5, "DISSEMINATION - products for the human consumer")
    md = report.write_markdown(os.path.join(OUTPUT_DIR, "report.md"), req, processing, result, kb.version(), attack_source)
    csv_path = report.write_csv(os.path.join(OUTPUT_DIR, "techniques.csv"), result)
    layer_name = f"{req.sector} - prioritized behaviors"
    layer = navigator.write_layer(
        result, os.path.join(OUTPUT_DIR, "navigator_layer.json"), layer_name, kb.version(),
        description=f"{req.stakeholder}: {req.question}",
    )
    print(f"  Markdown report      -> {md}")
    print(f"  Technique CSV        -> {csv_path}")
    print(f"  Navigator heat map   -> {layer}")
    print("     open https://mitre-attack.github.io/attack-navigator/ and upload the layer file")


def step_sharing(req, processing, result):
    banner(6, "SHARING - standards-based, with handling designations applied first")
    print("STIX is the language, TAXII is the transport. TLP is applied before anything leaves.\n")
    tlp = choose("TLP marking for this package?", {
        "clear": "TLP:CLEAR - no restriction",
        "green": "TLP:GREEN - community wide",
        "amber": "TLP:AMBER - limited disclosure, recipients' organizations only",
        "red":   "TLP:RED - named recipients only",
    }, "amber")
    bundle = sharing.build_share_bundle(req, processing.kept, result, tlp=tlp)
    path = sharing.write_bundle(bundle, os.path.join(OUTPUT_DIR, f"share_bundle_tlp_{tlp}.json"))
    print(f"\n  STIX 2.1 bundle ({len(bundle['objects'])} objects, TLP:{tlp.upper()}) -> {path}")

    if ask_yes("Push it to a TAXII 2.1 collection now?", default=False):
        server_url = ask("TAXII discovery URL", "http://127.0.0.1:5555/taxii2/")
        user = ask("Username (blank for none)", "student")
        password = ask("Password", "password")
        try:
            server = sharing.connect(server_url, user or None, password or None)
            writable = [(c, r) for c, r in sharing.list_collections(server) if c.can_write]
            if not writable:
                print("  No writable collections on that server.")
                return
            for i, (coll, root) in enumerate(writable, start=1):
                print(f"    {i}) {coll.title}  {root}")
            pick = ask_int("Push to which collection?", 1)
            status = sharing.push_bundle(writable[pick - 1][0], bundle)
            print(f"  TAXII status: {status.get('status')} - {status.get('success_count', 0)} accepted, "
                  f"{status.get('failure_count', 0)} failed, {status.get('pending_count', 0)} pending")
        except Exception as exc:  # noqa: BLE001 - show the student what went wrong, keep outputs
            print(f"  Push failed: {exc.__class__.__name__}: {exc}")
            print(f"  The bundle is still saved at {path}.")


# ---- main --------------------------------------------------------------------------------


def main(argv=None):
    global DEMO
    parser = argparse.ArgumentParser(description="PIR-driven CTI pipeline on MITRE ATT&CK, STIX and TAXII")
    parser.add_argument("--demo", action="store_true", help="accept every default without prompting")
    parser.add_argument("--attack-file", default=os.path.join("data", "enterprise-attack.json"),
                        help="where to cache the ATT&CK STIX bundle")
    args = parser.parse_args(argv)
    DEMO = args.demo

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    started = datetime.now(timezone.utc)

    print("PIR-driven Cyber Threat Intelligence pipeline")
    print("MITRE ATT&CK + STIX 2.1 + TAXII 2.1   (press Enter to accept a default)")

    req = step_requirements()
    kb, attack_source, feed = step_collection(args.attack_file)
    processing = step_processing(feed)
    result = step_analysis(kb, req, processing)
    step_dissemination(req, processing, result, kb, attack_source)
    step_sharing(req, processing, result)

    banner("DONE", "summary")
    print(f"  Requirement for:      {req.stakeholder}")
    print(f"  Adversaries tracked:  {len(result.groups)} ({len(result.hits)} unique techniques)")
    print(f"  Indicators:           {processing.total} received, {len(processing.kept)} kept, "
          f"{processing.reduction_percent()}% alerts avoided")
    top = result.ranked(1)
    if top:
        print(f"  #1 behavior:          {top[0].attack_id} {top[0].name} (score {top[0].score})")
    best = result.mitigations.most_common(1)
    if best:
        print(f"  #1 mitigation:        {best[0][0][0]} {best[0][0][1]}")
    print(f"  Outputs in:           {os.path.abspath(OUTPUT_DIR)}/")
    print(f"  Elapsed:              {(datetime.now(timezone.utc) - started).seconds}s")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nCancelled.")
        sys.exit(130)
