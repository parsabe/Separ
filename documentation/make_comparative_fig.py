"""Generate publication-grade comparative analysis chart for Separ vs. Related Work."""

from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np

OUT = Path(__file__).resolve().parent / "figures" / "fig_comparative.pdf"


def main() -> None:
    plt.rcParams.update(
        {
            "font.family": "sans-serif",
            "font.size": 8.5,
            "axes.titlesize": 9.5,
            "axes.labelsize": 8.5,
            "xtick.labelsize": 7.5,
            "ytick.labelsize": 7.5,
            "legend.fontsize": 7.5,
            "axes.spines.top": False,
            "axes.spines.right": False,
        }
    )

    systems = [
        "SELinux /\nAppArmor",
        "Falco /\nAuditd",
        "HOLMES /\nSLEUTH",
        "UNICORN\n(GNN)",
        "GhostBuster\n(1-Pass)",
        "Separ\n(This Work)",
    ]

    # Capability & benchmark coverage (%) grounded in Table 1 & Table 2
    # Categories: ClickFix/Prompt-Inj Pre-Exec (%), Zero-Leak Privacy (%), Benign Non-Block (%)
    clickfix_pre = [0, 0, 25, 15, 0, 100]
    privacy_zero_leak = [0, 0, 20, 60, 0, 100]
    benign_pass = [96, 88, 95, 94, 82, 100]

    x = np.arange(len(systems))
    w = 0.25

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10.5, 3.4), dpi=300)

    # Panel (a): Comparative Capabilities & Pre-Execution Defense
    b1 = ax1.bar(x - w, clickfix_pre, width=w, label="ClickFix / Prompt-Inj. Pre-Exec (%)", color="#2563eb")
    b2 = ax1.bar(x, privacy_zero_leak, width=w, label="Zero-Raw Privacy Boundary (%)", color="#0d9488")
    b3 = ax1.bar(x + w, benign_pass, width=w, label="Neutral Benign Non-Block (%)", color="#64748b")

    ax1.set_xticks(x)
    ax1.set_xticklabels(systems)
    ax1.set_ylim(0, 118)
    ax1.set_ylabel("Score / Coverage (%)")
    ax1.set_title("(a) Comparative Security & Privacy Coverage")
    ax1.grid(axis="y", linestyle="--", alpha=0.35)
    ax1.legend(loc="upper left", frameon=False)

    for bars in (b1, b2, b3):
        for bar in bars:
            h = bar.get_height()
            if h == 100 or bar == bars[-1]:
                ax1.text(
                    bar.get_x() + bar.get_width() / 2,
                    h + 1.5,
                    f"{int(h)}",
                    ha="center",
                    va="bottom",
                    fontsize=6.5,
                    fontweight="bold",
                )

    # Panel (b): Separ Version Progression (v1.0 -> v2.0) on Containment vs Neutral False Blocks
    versions = ["v1.0", "v1.1", "v1.2", "v1.3", "v1.7", "v2.0"]
    malicious_contained = [86.3, 98.7, 98.7, 98.7, 98.4, 98.4]
    neutral_false_blocks = [2.0, 2.0, 2.0, 2.0, 1.3, 0.0]

    vx = np.arange(len(versions))
    ax2.plot(vx, malicious_contained, marker="o", linewidth=2.0, color="#16a34a", label="Malicious Contained (%)")
    ax2.set_xticks(vx)
    ax2.set_xticklabels(versions)
    ax2.set_ylim(80, 102)
    ax2.set_ylabel("Malicious Containment (%)", color="#16a34a")
    ax2.tick_params(axis="y", labelcolor="#16a34a")
    ax2.set_title("(b) Separ Evolution: Containment vs. False Blocks")
    ax2.grid(axis="y", linestyle="--", alpha=0.35)

    ax2_r = ax2.twinx()
    ax2_r.spines["top"].set_visible(False)
    ax2_r.plot(vx, neutral_false_blocks, marker="s", linestyle="--", linewidth=1.8, color="#dc2626", label="Neutral False Blocks (%)")
    ax2_r.set_ylim(-0.3, 3.5)
    ax2_r.set_ylabel("Neutral False Blocks (%)", color="#dc2626")
    ax2_r.tick_params(axis="y", labelcolor="#dc2626")

    lines1, labels1 = ax2.get_legend_handles_labels()
    lines2, labels2 = ax2_r.get_legend_handles_labels()
    ax2.legend(lines1 + lines2, labels1 + labels2, loc="center right", frameon=False)

    plt.tight_layout()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT, bbox_inches="tight")
    print(f"Generated {OUT}")


if __name__ == "__main__":
    main()
