import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
import numpy as np

plt.rcParams.update({"font.family": "DejaVu Sans"})

# 5 asset -> vulnerability -> threat -> countermeasure chains (multi-asset scenario)
rows = [
    # asset, vulnerability, threat, countermeasure
    ("Voter Data",           "Lack of\nAnonymization",        "Deanonymization\nAttack",   "Homomorphic Encryption +\nAnonymity Overlay Network"),
    ("Smart Contract\n(Ledger)", "Error-Prone\nSmart Contract",   "Smart-Contract\nExploit",   "Formal Verification +\nContract Auditing"),
    ("Consensus /\nNetwork Node", "Fake Identities\nin Consensus", "Sybil Attack",              "Proof-of-Authority +\nIdentity Verification"),
    ("Communication\nChannel",   "Insecure\nCommunication",       "Man-in-the-\nMiddle",       "TLS / End-to-End\nEncryption"),
    ("Voting Device",        "Weak Authentication /\nControls", "Tampering /\nEndpoint Threat", "Tamper-Resistant Device +\nMulti-Factor Auth."),
]

col_titles = ["ASSET", "VULNERABILITY", "THREAT", "COUNTERMEASURE"]
col_colors = ["#1f3a5f", "#8a5a1b", "#7a1f2b", "#1f5f3a"]  # asset, vuln, threat, countermeasure
edge_labels = ["isHarmedBy", "exploitedBy", "mitigatedBy"]

n = len(rows)
col_x = [0.10, 1.55, 3.00, 4.55]
col_w = [1.15, 1.15, 1.15, 1.55]
row_h = 0.92
row_gap = 0.30
top = n * (row_h + row_gap)

fig, ax = plt.subplots(figsize=(13.5, 7.6), dpi=300)
ax.set_xlim(-0.15, col_x[3] + col_w[3] + 0.2)
ax.set_ylim(-0.35, top + 0.9)
ax.axis("off")

# column headers
for c in range(4):
    cx = col_x[c] + col_w[c] / 2
    ax.text(cx, top + 0.55, col_titles[c], ha="center", va="center",
            fontsize=14, fontweight="bold", color=col_colors[c])

def box(x, y, w, h, text, color):
    p = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.06",
                       linewidth=1.4, edgecolor=color, facecolor=color, alpha=0.92)
    ax.add_patch(p)
    ax.text(x + w/2, y + h/2, text, ha="center", va="center",
            fontsize=11, color="white", fontweight="bold", linespacing=1.15)

def arrow(x0, x1, y, label):
    a = FancyArrowPatch((x0, y), (x1, y), arrowstyle="-|>", mutation_scale=16,
                        linewidth=1.6, color="#333333")
    ax.add_patch(a)
    ax.text((x0+x1)/2, y + 0.11, label, ha="center", va="bottom",
            fontsize=8.6, style="italic", color="#333333")

for i, (asset, vuln, threat, cm) in enumerate(rows):
    y = top - (i + 1) * (row_h + row_gap) + row_gap/2
    cells = [asset, vuln, threat, cm]
    for c in range(4):
        box(col_x[c], y, col_w[c], row_h, cells[c], col_colors[c])
    # arrows between columns
    for c in range(3):
        arrow(col_x[c] + col_w[c], col_x[c+1], y + row_h/2, edge_labels[c])

ax.set_title("Multi-asset risk-modeling scenario in VotingOntoSec\n(Smart City blockchain e-voting)",
             fontsize=15.5, fontweight="bold", pad=18)

plt.tight_layout()
plt.savefig("fig6_usecase_new.png", dpi=300, bbox_inches="tight", facecolor="white")
print("saved fig6_usecase_new.png")
