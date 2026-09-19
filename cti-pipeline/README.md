# PIR-driven Cyber Threat Intelligence Pipeline

A Python project built on [mitreattack-python](https://github.com/mitre-attack/mitreattack-python),
[stix2](https://github.com/oasis-open/cti-python-stix2) and
[taxii2-client](https://github.com/oasis-open/cti-taxii-client) that walks the intelligence
cycle end to end. It puts the three recommendations from my CNG 4010 paper into working code:

| Paper recommendation | Where it lives |
|---|---|
| 1. Start with requirements, not feeds | Step 1 refuses to run until a Priority Intelligence Requirement (stakeholder, question, decision) is written down |
| 2. Measure effectiveness, attack false positives | Step 3 ages out expired/stale indicators, scores confidence, drops duplicates, and reports the % of alerts avoided. Step 4 maps everything to ATT&CK *behaviors* instead of atomic indicators |
| 3. Share on standards, with guardrails | Step 6 builds a STIX 2.1 bundle, applies a TLP marking *before* anything leaves, and pushes it over TAXII 2.1 |

## Quick start

```bash
pip install -r requirements.txt
python cti_pipeline.py            # interactive: press Enter to accept each default
python cti_pipeline.py --demo     # same run with every default, no typing
```

The first run downloads the ATT&CK knowledge base (about 50 MB) from MITRE's TAXII 2.1 server,
falling back to the GitHub mirror if the TAXII server is blocked. It is cached in `data/`.

Outputs land in `output/`:

- `requirement.json` - the PIR that directed the run
- `report.md` - the full report (requirement, false-positive metrics, top behaviors, mitigations, detection gaps)
- `techniques.csv` - every technique with the adversaries that use it
- `navigator_layer.json` - heat map: upload it at https://mitre-attack.github.io/attack-navigator/
- `share_bundle_tlp_<level>.json` - TLP-marked STIX 2.1 bundle ready to share

## The six steps

1. **Planning & Direction** - pick a stakeholder (SOC analyst, detection engineer, CISO, IR),
   state the question and the decision it supports, choose an adversary set
   (`nation-states` by default: APT29, APT28, Sandworm, APT41, Mustang Panda, Volt Typhoon,
   Lazarus, Kimsuky, APT33, MuddyWater) or type your own group names or aliases.
2. **Collection** - load ATT&CK, then load a STIX indicator feed from a file or pull it from any
   TAXII 2.1 collection.
3. **Processing** - four false-positive rules, each drop recorded with its reason.
4. **Analysis** - techniques per adversary, overlap scoring (score = adversaries using it + live
   indicators pointing at it), mitigations ranked by coverage, detection strategies, and gaps.
5. **Dissemination** - Markdown, CSV, Navigator layer.
6. **Sharing** - STIX 2.1 bundle with TLP marking; optional push to a writable TAXII collection.

## Demo the TAXII sharing with a local server

`medallion` is the OASIS reference TAXII 2.1 server. A config and a data file are included:

```bash
pip install medallion
medallion --port 5555 samples/medallion_config.json
```

Then in the pipeline choose "pull from a TAXII 2.1 server" in step 2 and answer "y" to the
push in step 6. Defaults point at `http://127.0.0.1:5555/taxii2/` with user `student` /
password `password`. The server has a read-only "Indicator feed" collection (the sample feed)
and a writable "Member submissions" collection the pipeline pushes into.

## Sample feed

`samples/sample_indicator_feed.json` is a STIX 2.1 bundle of 14 indicators built to be
messy on purpose: 6 good ones with ATT&CK context, 2 expired, 2 stale, 3 low confidence or
context-free, and 1 duplicate. Dates are relative to the day it was generated, so regenerate
it if the good indicators start aging out:

```bash
python scripts/make_sample_feed.py
python scripts/build_taxii_demo_data.py    # refresh the local TAXII server data too
```

## Project layout

```
cti_pipeline.py          the interactive script (start here)
ctilib/requirements.py   PIRs and adversary presets
ctilib/attack_data.py    ATT&CK download (TAXII -> GitHub fallback) and lookups
ctilib/indicators.py     feed loading and the false-positive rules
ctilib/analysis.py       technique overlap, mitigations, detections
ctilib/report.py         Markdown + CSV
ctilib/navigator.py      Navigator layer
ctilib/sharing.py        STIX bundle with TLP, TAXII pull/push
samples/                 sample feed, local TAXII server config and data
scripts/                 generators for the sample data
tests/                   pytest suite (python -m pytest tests)
```

## Sources

- MITRE ATT&CK: https://attack.mitre.org/
- NIST SP 800-150, Guide to Cyber Threat Information Sharing
- OASIS STIX 2.1 and TAXII 2.1 specifications
