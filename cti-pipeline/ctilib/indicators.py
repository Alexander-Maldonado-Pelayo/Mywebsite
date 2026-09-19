"""Processing: turn a raw STIX indicator feed into something worth alerting on.

This is where recommendation two of the paper lives. Raw feeds flood a SIEM
with stale IPs and over-broad hashes. Before anything reaches a detection we:

  1. drop indicators whose `valid_until` has passed          (expired)
  2. drop indicators older than a maximum age                  (stale)
  3. score confidence, penalizing indicators with no context   (low confidence)
  4. drop repeated patterns                                     (duplicate)

Every drop is recorded with its reason so the report can show the analyst
exactly how many alerts were avoided and why.
"""

import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta

UNKNOWN_CONFIDENCE = 50      # STIX has no confidence -> treat as "unknown", not "good"
NO_CONTEXT_PENALTY = 20      # an indicator tied to no adversary or technique is worth less


@dataclass
class Indicator:
    id: str
    pattern: str
    pattern_type: str
    created: datetime
    valid_from: datetime | None
    valid_until: datetime | None
    confidence: int | None
    labels: list = field(default_factory=list)
    techniques: set = field(default_factory=set)   # ATT&CK technique IDs, e.g. {"T1566.001"}
    groups: set = field(default_factory=set)       # adversary names, e.g. {"APT29"}
    raw: dict = field(default_factory=dict)        # original STIX object, kept for sharing

    @property
    def has_context(self):
        return bool(self.techniques or self.groups)

    def effective_confidence(self):
        score = self.confidence if self.confidence is not None else UNKNOWN_CONFIDENCE
        if not self.has_context:
            score -= NO_CONTEXT_PENALTY
        return max(score, 0)


@dataclass
class ProcessingResult:
    kept: list
    dropped: dict            # reason -> [Indicator, ...]
    max_age_days: int
    min_confidence: int

    @property
    def total(self):
        return len(self.kept) + sum(len(v) for v in self.dropped.values())

    @property
    def dropped_count(self):
        return self.total - len(self.kept)

    def reduction_percent(self):
        return round(100 * self.dropped_count / self.total, 1) if self.total else 0.0


# ---- loading ------------------------------------------------------------------------


def parse_time(value):
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def load_feed(path):
    """Read a STIX 2.x bundle and return a list of Indicator objects."""
    with open(path, encoding="utf-8") as fh:
        bundle = json.load(fh)
    return indicators_from_objects(bundle.get("objects", []))


def indicators_from_objects(objects):
    """Build Indicator objects, resolving `indicates` relationships to ATT&CK context."""
    by_id = {obj["id"]: obj for obj in objects}

    # What does each STIX id mean in ATT&CK terms?
    technique_ids = {}
    group_names = {}
    for obj in objects:
        if obj["type"] == "attack-pattern":
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                    technique_ids[obj["id"]] = ref["external_id"]
        elif obj["type"] == "intrusion-set":
            group_names[obj["id"]] = obj["name"]

    # Which indicator points at which context?
    context = {}
    for obj in objects:
        if obj["type"] != "relationship" or obj.get("relationship_type") != "indicates":
            continue
        source, target = obj["source_ref"], obj["target_ref"]
        techniques, groups = context.setdefault(source, (set(), set()))
        if target in technique_ids:
            techniques.add(technique_ids[target])
        elif target in group_names:
            groups.add(group_names[target])
        elif target in by_id and by_id[target]["type"] == "malware":
            groups.add(by_id[target]["name"])

    indicators = []
    for obj in objects:
        if obj["type"] != "indicator":
            continue
        techniques, groups = context.get(obj["id"], (set(), set()))
        indicators.append(
            Indicator(
                id=obj["id"],
                pattern=obj.get("pattern", ""),
                pattern_type=obj.get("pattern_type", "stix"),
                created=parse_time(obj["created"]),
                valid_from=parse_time(obj.get("valid_from")),
                valid_until=parse_time(obj.get("valid_until")),
                confidence=obj.get("confidence"),
                labels=list(obj.get("labels", [])),
                techniques=techniques,
                groups=groups,
                raw=obj,
            )
        )
    return indicators


# ---- processing ------------------------------------------------------------------------


def process_feed(indicators, max_age_days=90, min_confidence=50, now=None):
    """Apply the four false-positive rules in order. Returns a ProcessingResult."""
    now = now or datetime.now(timezone.utc)
    oldest_allowed = now - timedelta(days=max_age_days)
    dropped = {"expired": [], "stale": [], "low confidence": [], "duplicate": []}
    kept = []
    seen_patterns = set()

    for ind in indicators:
        if ind.valid_until and ind.valid_until < now:
            dropped["expired"].append(ind)
        elif ind.created < oldest_allowed:
            dropped["stale"].append(ind)
        elif ind.effective_confidence() < min_confidence:
            dropped["low confidence"].append(ind)
        elif ind.pattern in seen_patterns:
            dropped["duplicate"].append(ind)
        else:
            seen_patterns.add(ind.pattern)
            kept.append(ind)

    return ProcessingResult(kept=kept, dropped=dropped, max_age_days=max_age_days, min_confidence=min_confidence)


def technique_counts(indicators):
    """How many kept indicators point at each ATT&CK technique."""
    counts = Counter()
    for ind in indicators:
        counts.update(ind.techniques)
    return counts


def indicator_kind(indicator):
    """Human label for the pattern: 'ipv4-addr', 'domain-name', 'file hash', ..."""
    pattern = indicator.pattern
    if "file:hashes" in pattern:
        return "file hash"
    for kind in ("ipv4-addr", "ipv6-addr", "domain-name", "url", "email-addr"):
        if pattern.startswith(f"[{kind}"):
            return kind
    return indicator.pattern_type
