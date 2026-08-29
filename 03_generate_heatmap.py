import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.colors import LinearSegmentedColormap

plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "font.size": 13,
})

# Vulnerabilities and their assigned scores (ISO/IEC 27005 qualitative -> [0,1])
vulns = [
    "Insecure Communication\nControl",
    "Fake Identity Creation",
    "Weak Authentication",
    "Ineffective Cryptographic\nControl",
    "Lack of Anonymization\nof Voter",
]
# P = threat likelihood, C = asset criticality, R = (P + C)/2 risk level
P = np.array([0.80, 0.75, 0.70, 0.65, 0.60])
C = np.array([1.00, 0.95, 0.90, 0.85, 0.80])
R = (P + C) / 2.0   # -> 0.90, 0.85, 0.80, 0.75, 0.70

data = np.column_stack([P, C, R])
cols = ["Threat\nLikelihood (P)", "Asset\nCriticality (C)", "Risk Level\nR = (P+C)/2"]

reds = LinearSegmentedColormap.from_list("reds2", ["#fff5f0", "#fb6a4a", "#67000d"])

fig, ax = plt.subplots(figsize=(9.2, 5.4), dpi=300)
im = ax.imshow(data, cmap=reds, vmin=0.5, vmax=1.0, aspect="auto")

ax.set_xticks(np.arange(len(cols)))
ax.set_xticklabels(cols, fontsize=12.5)
ax.set_yticks(np.arange(len(vulns)))
ax.set_yticklabels(vulns, fontsize=12.5)
ax.tick_params(top=True, bottom=False, labeltop=True, labelbottom=False, length=0)

# gridlines
ax.set_xticks(np.arange(-.5, len(cols), 1), minor=True)
ax.set_yticks(np.arange(-.5, len(vulns), 1), minor=True)
ax.grid(which="minor", color="white", linestyle="-", linewidth=2.5)
ax.tick_params(which="minor", length=0)
for spine in ax.spines.values():
    spine.set_visible(False)

for i in range(len(vulns)):
    for j in range(len(cols)):
        val = data[i, j]
        txt = f"{val:.2f}"
        color = "white" if val >= 0.82 else "black"
        weight = "bold" if j == 2 else "normal"
        ax.text(j, i, txt, ha="center", va="center", color=color,
                fontsize=13.5, fontweight=weight)

cbar = fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
cbar.set_label("Score (0-1)", fontsize=12)
cbar.ax.tick_params(labelsize=11)

ax.set_title("Risk level of identified vulnerabilities\n(threat likelihood x asset criticality)",
             fontsize=15, pad=34, fontweight="bold")

plt.tight_layout()
plt.savefig("fig5_heatmap_new.png", dpi=300, bbox_inches="tight", facecolor="white")
print("saved fig5_heatmap_new.png")
