from typing import Any, Literal
from .globals import Counters
import numpy as np
import matplotlib.pyplot as plt


def plot(lat: Counters, tp: Counters, path: str, mode: Literal["TP", "LAT", "BOTH"]):
    categories = [
        "one match\nsame value",
        "multiple matches\nall same value",
        "multiple matches\ndifferent values",
        "one match\ndifferent value",
        # "no match",
    ]

    def no_zero_autopct(pct):
        return f"{pct:.1f}%" if pct > 0 else ""

    inner_colors = ["#008000", "#ff0000", "grey"]
    outer_colors = [
        "#6fbe59",
        "#bfffa7",
        "#ffd8b3",
        "#ff914d",
        "grey",
        "grey",
    ]

    # reference values are Zen4
    # [[one match sameval, mulmatch sameval], [mulmatch diffval, one match diff val], [no match, 0]]
    if lat is None:
        lat = np.array([[6964, 3995], [206, 546], [546, 0]])
    else:
        lat = np.array(
            [
                [lat.uniqueMatchSameValueC, lat.multiMatchSameValueC],
                [lat.multiMatchDiffValueC, lat.uniqueMatchDiffValueC],
                [lat.noMatchC + lat.noUopsDataC, 0],
            ]
        )
    if tp is None:
        tp = np.array([[3642, 1779], [77, 309], [288, 0]])
    else:
        tp = np.array(
            [
                [tp.uniqueMatchSameValueC, tp.multiMatchSameValueC],
                [tp.multiMatchDiffValueC, tp.uniqueMatchDiffValueC],
                [tp.noMatchC + tp.noUopsDataC, 0],
            ]
        )

    size = 0.3

    def plot_wedges(vals, ax, radius, colors, pctdistance) -> Any:
        wedges, _, _ = ax.pie(
            vals,
            radius=radius,
            colors=colors,
            wedgeprops=dict(width=size, edgecolor="w"),
            autopct=no_zero_autopct,
            pctdistance=pctdistance,
        )
        return wedges

    if mode == "TP" or mode == "LAT":
        fig, ax1 = plt.subplots(figsize=(6, 4))
        ax1.set_position([0.65, 0.1, 0.6, 0.8])  # Move chart left, width=0.6
        ax1.set(aspect="equal")
        ax1.set(title="Throughput") if mode == "TP" else ax1.set(title="Latency")
    if mode == "BOTH":
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 5))
        ax1.set(aspect="equal")  # keep the pie circular
        ax2.set(aspect="equal")  # keep the pie circular
        ax1.set(title="Latency")
        ax2.set(title="Throughput")

    if mode == "BOTH":
        # plot LAT
        acc_wedges = plot_wedges(lat.sum(axis=1), ax1, 1 - size, inner_colors, 0.77)
        wedges = plot_wedges(lat.flatten(), ax1, 1, outer_colors, 0.85)

        # plot TP
        acc_wedges = plot_wedges(tp.sum(axis=1), ax2, 1 - size, inner_colors, 0.77)
        wedges = plot_wedges(tp.flatten(), ax2, 1, outer_colors, 0.85)

    if mode == "TP":
        acc_wedges = plot_wedges(tp.sum(axis=1), ax1, 1 - size, inner_colors, 0.77)
        wedges = plot_wedges(tp.flatten(), ax1, 1, outer_colors, 0.85)
    if mode == "LAT":
        acc_wedges = plot_wedges(lat.sum(axis=1), ax1, 1 - size, inner_colors, 0.77)
        wedges = plot_wedges(lat.flatten(), ax1, 1, outer_colors, 0.85)

    inner_legend = ax1.legend(acc_wedges, ["same value", "different value    ", "no match"], bbox_to_anchor=(0.93, 0.9))
    outer_legend = ax1.legend(wedges, categories, bbox_to_anchor=(0.93, 0.7))
    ax1.add_artist(outer_legend)
    ax1.add_artist(inner_legend)
    if mode == "BOTH":
        plt.suptitle("Comparison between WINIC and uops.info")
    plt.tight_layout()
    plt.savefig(path)
    print(f"combined plot saved to {path}")
