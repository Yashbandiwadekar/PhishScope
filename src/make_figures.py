"""Draw the architecture and investigation-flow figures used in the report (matplotlib only, no external tools)."""
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "outputs"
COL = {"src": "#e8f0fc", "col": "#e7f5ec", "core": "#fdf0d5", "ui": "#f3e8fb", "edge": "#44546a"}


def box(ax, x, y, w, h, title, sub="", fc="#fff", fs=9):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.12", fc=fc, ec=COL["edge"], lw=1.1))
    ax.text(x + w / 2, y + h * (0.64 if sub else 0.5), title, ha="center", va="center", fontsize=fs, fontweight="bold", color="#17202b")
    if sub:
        ax.text(x + w / 2, y + h * 0.28, sub, ha="center", va="center", fontsize=fs - 2, color="#44546a")


def arrow(ax, p, q, rad=0.0):
    ax.add_patch(FancyArrowPatch(p, q, arrowstyle="-|>", mutation_scale=11, lw=1.2, color=COL["edge"], connectionstyle=f"arc3,rad={rad}"))


def architecture():
    """Banded component diagram. Same geometry and edges as the 'How it works' tab of the web interface (webapp/app.js),
    in the same units (1000 x 620, y downwards). Every edge is routed by hand through the gaps, so no line crosses a box or a label."""
    PW, PH, PC, PT = 200, 66, [50, 285, 520, 755], [52, 198, 344, 490]
    fig = plt.figure(figsize=(11, 6.82))
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 1000)
    ax.set_ylim(620, 0)
    ax.axis("off")
    bands = ["1  PUBLIC DATA (read only)", "2  PASSIVE COLLECTION", "3  ANALYSIS", "4  OUTPUTS"]
    fills = [COL["src"], COL["col"], COL["core"], COL["ui"]]
    for k, name in enumerate(bands):
        ax.add_patch(FancyBboxPatch((38, PT[k] - 22), 929, PH + 30, boxstyle="round,pad=0,rounding_size=10", fc="none", ec="#c9d2dd", lw=1, ls="--"))
        ax.text(46, PT[k] - 10, name, fontsize=7.5, fontweight="bold", color="#5d6b7c", va="center")
    nodes = {"F1": (0, 0, "Phishing feeds", "Phishing.Database - OpenPhish\nPhishStats - URLhaus"), "F2": (0, 1, "Tranco ranking", "benign reference names (deep ranks)"),
             "F3": (0, 2, "Registries and DNS", "RDAP - DNS - Team Cymru ASN\nShodan InternetDB - crt.sh - Wayback"),
             "B": (1, 0, "Dataset builder", "registered-name unit, bias controls"), "D": (1, 1, "Batch enrichment", "thread pool, resumable"),
             "C": (1, 2, "Passive collectors", "one function per source"), "K": (1, 3, "Evidence cache", "SQLite, every lookup kept"),
             "E": (2, 0, "Feature extraction", "name + DNS + hosting + registry"), "G": (2, 1, "Campaign matcher", "shared IP / name servers, Louvain"),
             "F": (2, 2, "Rule engine (core)", "21 weighted rules, score 0-100"), "H": (2, 3, "Investigation engine", "evidence -> rules -> report"),
             "ML": (3, 0, "ML comparison", "baseline only, not the verdict"), "J": (3, 1, "Evaluation", "frozen test sets, Wilson CIs"),
             "M": (3, 2, "Live monitor", "polls feeds, verdict in seconds"), "I": (3, 3, "Interfaces", "CLI - web - JSON / streaming API")}
    for b, c, t, sub in nodes.values():
        x, y = PC[c], PT[b]
        ax.add_patch(FancyBboxPatch((x, y), PW, PH, boxstyle="round,pad=0,rounding_size=9", fc=fills[b], ec=COL["edge"], lw=1.1))
        two = "\n" in sub
        ax.text(x + PW / 2, y + (19 if two else 24), t, ha="center", va="center", fontsize=9, fontweight="bold", color="#17202b")
        ax.text(x + PW / 2, y + (45 if two else 46), sub, ha="center", va="center", fontsize=7, color="#44546a", linespacing=1.25)
    X = lambda c, f: PC[c] + f * PW
    top, bot, mid = (lambda b: PT[b]), (lambda b: PT[b] + PH), (lambda b: PT[b] + PH / 2)
    edges = [[(X(0, .7), bot(0)), (X(0, .7), top(1))],                                                      # feeds -> dataset builder
             [(X(1, .5), bot(0)), (X(1, .5), 150), (X(0, .85), 150), (X(0, .85), top(1))],                    # Tranco -> dataset builder
             [(X(2, .5), bot(0)), (X(2, .5), top(1))],                                                      # registries -> collectors
             [(X(0, 1), mid(1)), (X(1, 0), mid(1))], [(X(1, 1), mid(1)), (X(2, 0), mid(1))], [(X(2, 1), mid(1)), (X(3, 0), mid(1))],
             [(X(3, .5), bot(1)), (X(3, .5), top(2))],                                                      # cache -> engine
             [(X(3, .5), bot(1)), (X(3, .5), 292), (X(1, .5), 292), (X(1, .5), top(2))],                      # cache -> campaign matcher
             [(X(3, .5), bot(1)), (X(3, .5), 292), (X(0, .75), 292), (X(0, .75), top(2))],                    # cache -> features
             [(X(1, 1), mid(2)), (X(2, 0), mid(2))], [(X(2, 1), mid(2)), (X(3, 0), mid(2))],
             [(X(0, .85), bot(2)), (X(0, .85), 432), (X(2, .3), 432), (X(2, .3), bot(2))],                    # features -> rules
             [(X(0, .6), bot(2)), (X(0, .6), top(3))],                                                      # features -> ML
             [(X(2, .65), bot(2)), (X(2, .65), 450), (X(1, .6), 450), (X(1, .6), top(3))],                    # rules -> evaluation
             [(X(0, 1), mid(3)), (X(1, 0), mid(3))],                                                        # ML -> evaluation
             [(X(3, .6), bot(2)), (X(3, .6), top(3))],                                                      # engine -> interfaces
             [(X(2, .8), top(3)), (X(2, .8), 440), (X(3, .3), 440), (X(3, .3), bot(2))],                      # monitor -> engine
             [(X(0, 0), mid(0)), (16, mid(0)), (16, 584), (X(2, .5), 584), (X(2, .5), bot(3))],                # live feeds -> monitor
             [(X(0, 0), mid(1) + 10), (28, mid(1) + 10), (28, 574), (X(1, .4), 574), (X(1, .4), bot(3))]]      # frozen test sets -> evaluation
    for pts in edges:
        if len(pts) > 2:
            ax.plot([p[0] for p in pts[:-1]], [p[1] for p in pts[:-1]], color=COL["edge"], lw=1.1, solid_joinstyle="round", solid_capstyle="butt")
        ax.annotate("", xy=pts[-1], xytext=pts[-2], arrowprops=dict(arrowstyle="-|>", color=COL["edge"], lw=1.1, mutation_scale=10, shrinkA=0, shrinkB=0))
    ax.text(500, 13, "PhishScope - component architecture", ha="center", va="center", fontsize=11.5, fontweight="bold", color="#17202b")
    ax.text(500, 604, "Passive only: no component ever opens a listed page. Phishing names are defanged in every interface.", ha="center", va="center", fontsize=8, color="#c0392b")
    fig.savefig(OUT / "fig_architecture.png", dpi=180)
    plt.close(fig)


def flow():
    fig, ax = plt.subplots(figsize=(11, 3.4))
    ax.set_xlim(0, 11)
    ax.set_ylim(0, 3.4)
    ax.axis("off")
    steps = [("Input", "URL or domain\n(defanged ok)", COL["src"]), ("Parse", "host, registered name,\nsubdomain, path", COL["col"]), ("Collect", "DNS - ASN - RDAP\nInternetDB (CT, Wayback)", COL["col"]),
             ("Features", "name + network\nvalues", COL["core"]), ("Rules", "21 rules fire or not\npoints add up", COL["core"]), ("Verdict", "score, level,\nreasons, evidence", COL["ui"])]
    w, gap = 1.55, 0.28
    for i, (t, s, c) in enumerate(steps):
        x = 0.2 + i * (w + gap)
        box(ax, x, 1.35, w, 1.3, t, s, c, fs=10)
        if i:
            arrow(ax, (x - gap, 2.0), (x, 2.0))
    ax.text(5.5, 0.85, "campaign match: known phishing on the same IP / name-server set  ->  rules G1, G2", ha="center", fontsize=9, color="#44546a")
    ax.text(5.5, 0.4, "streamed to the web page step by step (Server-Sent Events); the same code runs in the CLI and the monitor", ha="center", fontsize=9, color="#44546a")
    fig.tight_layout()
    fig.savefig(OUT / "fig_flow.png", dpi=180)
    plt.close(fig)


if __name__ == "__main__":
    architecture()
    flow()
    print("figures written")
