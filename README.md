# VotingOntoSec — A Security Ontology for Risk Modeling in Electronic Voting Systems

Reproducibility package for the paper *"VotingOntoSec: A Security Ontology for
Risk Modeling in Electronic Voting Systems"* (Scientific Journal of Astana IT University).

**Version:** v1.0
**License:** CC BY 4.0 (see `LICENSE`)
**Authors:** T. Aidynov, D. Satybaldina, W. Dimitrov
**Contact:** tolegen.ch@gmail.com

## Contents
| File | Description |
|------|-------------|
| `VotingOntoSec.owl` | The ontology in OWL 2 DL (RDF/XML). Open in Protégé 5.6.1. |
| `01_build_ontology.py` | Reconstructs the ontology programmatically (owlready2). |
| `02_run_hermit_reasoner.py` | Runs the HermiT reasoner and prints consistency / satisfiability results. |
| `03_generate_heatmap.py` | Reproduces the risk heat map (Fig. 5) from P, C and R = (P+C)/2. |
| `04_generate_usecase_figure.py` | Reproduces the multi-asset scenario figure (Fig. 6). |
| `requirements.txt` | Python dependencies. |

## Ontology structure
- Top classes: `Asset`, `Threat`, `Vulnerability`, `Countermeasure`, `Risk`, `SecurityCriteria`.
- 16 object properties with declared domains/ranges: `affects`, `isHarmedBy`,
  `exploits`/`exploitedBy`, `mitigates`/`mitigatedBy`, `reduces`, `protects`,
  `hasRisk`, `givesRiseTo`, `threatens`, `supports`, `ownedBy`, `hasSource`,
  `requires`, `dependsOn`.
- 9 data properties (impact level, likelihood, asset criticality, risk score, ...).
- Individuals for the extended multi-asset use case (voter data, smart contract,
  consensus node, communication channel, voting device).

## How to reproduce
```bash
pip install -r requirements.txt      # needs Java (JRE) for HermiT
python 01_build_ontology.py          # writes VotingOntoSec.owl
python 02_run_hermit_reasoner.py     # -> Consistent; 0 unsatisfiable classes
python 03_generate_heatmap.py        # -> fig5_heatmap_new.png
python 04_generate_usecase_figure.py # -> fig6_usecase_new.png
```
Or open `VotingOntoSec.owl` in Protégé 5.6.1 and run *Reasoner → HermiT → Start reasoner*.

## Competency questions (examples)
- Which threats affect a given asset? (`Threat affects Asset`)
- Which vulnerabilities does a threat exploit? (`Threat exploitedBy Vulnerability`)
- Which countermeasures mitigate a threat / reduce a vulnerability? (`mitigatedBy`, `reduces`)

## Citation
> T. Aidynov, D. Satybaldina, W. Dimitrov. "VotingOntoSec: A Security Ontology for
> Risk Modeling in Electronic Voting Systems." Scientific Journal of Astana IT University, 2026.
