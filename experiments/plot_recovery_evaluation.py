"""Optional standalone research figure from recorded paired benchmark results."""
import argparse
import json
from pathlib import Path


def main():
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("summary", type=Path)
    args = parser.parse_args()
    report = json.loads(args.summary.read_text())
    colors = {"fixed": "#667085", "unguided": "#2274a5", "guided": "#e17c05", "boundary": "#16866d",
        "ttl": "#9c4db1", "context_repair": "#a34a39"}
    labels = {mode: ("context+repair" if mode == "context_repair" else mode) for mode in colors}
    groups = report["aggregate"]["groups"]
    modes = [mode for mode in colors if mode in groups]
    fig, axes = plt.subplots(1, 3, figsize=(12, 4.2), constrained_layout=True)
    for mode in modes:
        if mode == "fixed":
            continue
        runs = sorted((r for r in report["runs"] if r["mode"] == mode), key=lambda r: r["seed"])
        if not runs:
            continue
        axes[0].plot([r["seed"] for r in runs], [r["coverage"]["transitions"] for r in runs],
            marker="o", label=labels[mode], color=colors[mode])
    axes[0].set(xlabel="Paired seed", ylabel="Unique normalized transitions", title="Recovery trace coverage")
    axes[0].legend(fontsize=8)
    axes[1].bar([labels[m] for m in modes], [groups[m]["defect_detection"]["no_proof_ttl"]["detected_runs"] for m in modes],
        color=[colors[m] for m in modes])
    axes[1].set(ylabel="Runs detecting seeded TTL defect", ylim=(0, len(report["seeds"]) + 1),
        title="Permit expiry sensitivity")
    axes[2].bar([labels[m] for m in modes], [groups[m]["elapsed_sec"]["median"] for m in modes], color=[colors[m] for m in modes])
    axes[2].set(ylabel="Median wall time (seconds)", title=f"{report['budget']} executions per run")
    if len(modes) > 3:
        for ax in axes[1:]:
            plt.setp(ax.get_xticklabels(), rotation=35, ha="right", fontsize=8)
    for ax in axes:
        ax.spines[["top", "right"]].set_visible(False)
        ax.grid(axis="y", alpha=.2)
        ax.set_axisbelow(True)
    fig.suptitle(f"Offline recovery evaluation: {len(report['seeds'])} seeds; injected defects, not production findings", fontsize=11)
    for suffix in ("png", "svg"):
        fig.savefig(args.summary.with_name(f"evaluation.{suffix}"), dpi=180)
    plt.close(fig)


if __name__ == "__main__":
    main()
