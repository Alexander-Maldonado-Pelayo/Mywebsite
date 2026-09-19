"""Planning & Direction: capture Priority Intelligence Requirements (PIRs).

A CTI program that cannot say who its intelligence serves, and which decision
it supports, cannot later judge whether it met their needs. So the pipeline
refuses to run until a requirement is written down.
"""

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone


# Adversary presets a student can pick from. Names match ATT&CK group names.
SECTOR_PRESETS = {
    "nation-states": {
        "description": "State-sponsored groups tracked by ATT&CK, one or two per major state actor.",
        "groups": [
            ("APT29", "Russia (SVR)"),
            ("APT28", "Russia (GRU)"),
            ("Sandworm Team", "Russia (GRU)"),
            ("APT41", "China"),
            ("Mustang Panda", "China"),
            ("Volt Typhoon", "China"),
            ("Lazarus Group", "North Korea"),
            ("Kimsuky", "North Korea"),
            ("APT33", "Iran"),
            ("MuddyWater", "Iran"),
        ],
    },
    "ransomware": {
        "description": "Financially motivated intrusion and ransomware operators.",
        "groups": [
            ("FIN7", "Criminal"),
            ("Wizard Spider", "Criminal"),
            ("Scattered Spider", "Criminal"),
            ("Indrik Spider", "Criminal"),
        ],
    },
    "financial": {
        "description": "Groups that target banks and payment systems.",
        "groups": [
            ("Lazarus Group", "North Korea"),
            ("FIN7", "Criminal"),
            ("Carbanak", "Criminal"),
            ("APT38", "North Korea"),
        ],
    },
}

STAKEHOLDERS = {
    "1": ("SOC analyst", "tuning detections and triaging alerts"),
    "2": ("Detection engineer", "deciding which behaviors to build analytics for"),
    "3": ("CISO", "prioritizing budget and briefing leadership"),
    "4": ("Incident responder", "knowing what to hunt for during an intrusion"),
}


@dataclass
class IntelRequirement:
    """One Priority Intelligence Requirement negotiated with a consumer."""

    stakeholder: str
    question: str
    decision: str
    sector: str
    groups: list = field(default_factory=list)
    created: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, data):
        return cls(**data)

    def save(self, path):
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2)

    @classmethod
    def load(cls, path):
        with open(path, encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))

    def summary(self):
        return (
            f"Stakeholder: {self.stakeholder}\n"
            f"Question:    {self.question}\n"
            f"Decision:    {self.decision}\n"
            f"Sector:      {self.sector}\n"
            f"Adversaries: {', '.join(self.groups)}"
        )
