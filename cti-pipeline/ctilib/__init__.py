"""ctilib - building blocks for the PIR-driven CTI pipeline.

Each module maps to one phase of the intelligence cycle:

    requirements.py  -> Planning & Direction (Priority Intelligence Requirements)
    attack_data.py   -> Collection (MITRE ATT&CK knowledge base over TAXII / GitHub)
    indicators.py    -> Processing (age-out, confidence scoring, de-duplication)
    analysis.py      -> Analysis (map adversaries and indicators to ATT&CK behaviors)
    report.py        -> Dissemination (Markdown report + CSV)
    navigator.py     -> Dissemination (ATT&CK Navigator heat map layer)
    sharing.py       -> Sharing (STIX 2.1 bundle with TLP markings, TAXII push/pull)
"""
