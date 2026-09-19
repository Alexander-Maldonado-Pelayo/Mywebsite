"""Analysis: fuse adversary profiles and processed indicators onto ATT&CK behaviors.

Adversary infrastructure changes daily; adversary behavior changes slowly.
So the unit of analysis here is the ATT&CK technique, not the IP address.
"""

from collections import Counter
from dataclasses import dataclass, field


@dataclass
class TechniqueHit:
    attack_id: str
    name: str
    tactics: list
    groups: set = field(default_factory=set)
    indicator_count: int = 0

    @property
    def score(self):
        """Higher = more of the tracked adversaries use it, plus live indicator evidence."""
        return len(self.groups) + self.indicator_count

    @property
    def is_subtechnique(self):
        return "." in self.attack_id


@dataclass
class AnalysisResult:
    groups: list                       # [(name, attack_id, technique_count, [software])]
    unresolved_groups: list
    hits: dict                         # attack_id -> TechniqueHit
    mitigations: Counter               # (M-id, name) -> weighted score
    detections: dict                   # attack_id -> [detection strategy names]
    tactic_counts: Counter

    def ranked(self, limit=None):
        ordered = sorted(
            self.hits.values(),
            key=lambda hit: (-hit.score, -len(hit.groups), hit.attack_id),
        )
        return ordered[:limit] if limit else ordered

    def shared_by_all(self):
        total = len(self.groups)
        return [hit for hit in self.hits.values() if total and len(hit.groups) == total]

    def detection_gaps(self, limit=None):
        """Top techniques with no documented detection strategy at all."""
        gaps = [hit for hit in self.ranked() if not self.detections.get(hit.attack_id)]
        return gaps[:limit] if limit else gaps


def analyze(kb, group_names, kept_indicators, top_n_for_mitigations=25, log=print):
    """Build the fused picture of what the tracked adversaries do."""
    hits = {}
    groups_out = []
    unresolved = []

    for name in group_names:
        group = kb.find_group(name)
        if group is None:
            unresolved.append(name)
            log(f"  ! '{name}' not found in ATT&CK, skipping")
            continue
        techniques = kb.techniques_for_group(group)
        groups_out.append((group["name"], kb.attack_id(group), len(techniques), kb.software_for_group(group)))
        log(f"  {group['name']:<16} {kb.attack_id(group):<6} {len(techniques):>4} techniques")
        for attack_id, technique in techniques.items():
            hit = hits.get(attack_id)
            if hit is None:
                hit = hits[attack_id] = TechniqueHit(attack_id, technique["name"], kb.tactics_of(technique))
            hit.groups.add(group["name"])

    # Fold in behavior evidence from the processed indicator feed.
    for ind in kept_indicators:
        for attack_id in ind.techniques:
            hit = hits.get(attack_id)
            if hit is None:
                technique = kb.technique_by_id(attack_id)
                if technique is None:
                    continue
                hit = hits[attack_id] = TechniqueHit(attack_id, technique["name"], kb.tactics_of(technique))
            hit.indicator_count += 1

    tactic_counts = Counter()
    for hit in hits.values():
        tactic_counts.update(hit.tactics)

    # Rank mitigations by how much of the top-N behavior they cover.
    mitigations = Counter()
    detections = {}
    ranked = sorted(hits.values(), key=lambda h: -h.score)[:top_n_for_mitigations]
    for hit in ranked:
        technique = kb.technique_by_id(hit.attack_id)
        if technique is None:
            continue
        for mitigation in kb.mitigations_for(technique):
            mitigations[mitigation] += hit.score
        detections[hit.attack_id] = kb.detections_for(technique)

    return AnalysisResult(
        groups=groups_out,
        unresolved_groups=unresolved,
        hits=hits,
        mitigations=mitigations,
        detections=detections,
        tactic_counts=tactic_counts,
    )
