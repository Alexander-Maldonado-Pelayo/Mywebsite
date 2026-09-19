"""Dissemination: human-readable Markdown report and a CSV for spreadsheets."""

import csv

from .indicators import indicator_kind


def write_markdown(path, requirement, processing, result, attack_version, attack_source, top=25):
    lines = []
    add = lines.append

    add("# Cyber Threat Intelligence Report")
    add("")
    add(f"*Generated {requirement.created} from MITRE ATT&CK v{attack_version} ({attack_source}).*")
    add("")

    add("## 1. Planning & Direction: the requirement this answers")
    add("")
    add(f"- **Stakeholder:** {requirement.stakeholder}")
    add(f"- **Intelligence question:** {requirement.question}")
    add(f"- **Decision it supports:** {requirement.decision}")
    add(f"- **Scenario:** {requirement.sector}")
    add(f"- **Adversaries tracked:** {', '.join(requirement.groups)}")
    add("")

    add("## 2. Processing: false-positive reduction on the indicator feed")
    add("")
    add(f"Rules applied: drop expired, drop older than {processing.max_age_days} days, "
        f"drop effective confidence below {processing.min_confidence}, drop duplicates.")
    add("")
    add("| Outcome | Count |")
    add("|---|---:|")
    add(f"| Indicators received | {processing.total} |")
    for reason, items in processing.dropped.items():
        add(f"| Dropped: {reason} | {len(items)} |")
    add(f"| **Kept for detection** | **{len(processing.kept)}** |")
    add(f"| **Alerts avoided** | **{processing.dropped_count} ({processing.reduction_percent()}%)** |")
    add("")
    if processing.kept:
        add("Indicators that survived, with the behavior they point at:")
        add("")
        add("| Type | Pattern | Confidence | ATT&CK context |")
        add("|---|---|---:|---|")
        for ind in processing.kept:
            ctx = ", ".join(sorted(ind.techniques | ind.groups)) or "none"
            add(f"| {indicator_kind(ind)} | `{ind.pattern}` | {ind.effective_confidence()} | {ctx} |")
        add("")

    add("## 3. Analysis: adversary behaviors mapped to ATT&CK")
    add("")
    add("| Adversary | ATT&CK ID | Techniques | Known software (sample) |")
    add("|---|---|---:|---|")
    for name, attack_id, count, software in result.groups:
        add(f"| {name} | {attack_id} | {count} | {', '.join(software[:5]) or '-'} |")
    if result.unresolved_groups:
        add("")
        add(f"Not found in ATT&CK: {', '.join(result.unresolved_groups)}")
    add("")
    add(f"Unique techniques across all tracked adversaries: **{len(result.hits)}**")
    shared = result.shared_by_all()
    if shared:
        add(f"Techniques every tracked adversary uses: **{len(shared)}** "
            f"({', '.join(sorted(h.attack_id for h in shared))})")
    add("")
    add("### Techniques by tactic")
    add("")
    add("| Tactic | Techniques |")
    add("|---|---:|")
    for tactic, count in result.tactic_counts.most_common():
        add(f"| {tactic} | {count} |")
    add("")
    add(f"### Top {top} behaviors to prioritize")
    add("")
    add("Score = number of tracked adversaries using the technique + live indicators pointing at it.")
    add("")
    add("| Rank | Technique | Name | Tactic(s) | Adversaries | Indicators | Score |")
    add("|---:|---|---|---|---:|---:|---:|")
    for rank, hit in enumerate(result.ranked(top), start=1):
        add(f"| {rank} | {hit.attack_id} | {hit.name} | {', '.join(hit.tactics)} | "
            f"{len(hit.groups)} | {hit.indicator_count} | {hit.score} |")
    add("")

    add("## 4. Recommendations for the stakeholder")
    add("")
    add("### Mitigations that cover the most prioritized behavior")
    add("")
    add("| Mitigation | Name | Coverage score |")
    add("|---|---|---:|")
    for (mid, name), score in result.mitigations.most_common(10):
        add(f"| {mid} | {name} | {score} |")
    add("")
    add("### Detection strategies for the top behaviors")
    add("")
    for hit in result.ranked(10):
        strategies = result.detections.get(hit.attack_id) or ["(no detection strategy documented)"]
        add(f"- **{hit.attack_id} {hit.name}**: {'; '.join(strategies)}")
    gaps = result.detection_gaps(10)
    add("")
    if gaps:
        add("### Coverage gaps: prioritized techniques with no documented detection")
        add("")
        for hit in gaps:
            add(f"- {hit.attack_id} {hit.name} (score {hit.score})")
        add("")

    add("## 5. Sharing")
    add("")
    add("The surviving indicators and this technique list are packaged as a STIX 2.1 bundle "
        "with a TLP marking so partners can ingest them over TAXII (see the sharing step output).")
    add("")

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return path


def write_csv(path, result):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["technique_id", "name", "tactics", "adversaries", "adversary_count", "indicators", "score", "detections"])
        for hit in result.ranked():
            writer.writerow([
                hit.attack_id,
                hit.name,
                "; ".join(hit.tactics),
                "; ".join(sorted(hit.groups)),
                len(hit.groups),
                hit.indicator_count,
                hit.score,
                "; ".join(result.detections.get(hit.attack_id, [])),
            ])
    return path
