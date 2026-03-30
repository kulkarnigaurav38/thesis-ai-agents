"""
generate_graphs.py - DSR Academic Visualization Generator

Reads evaluation_results.csv and generates publication-ready PNGs:
1. Confusion matrices per vector (1x3 heatmap grid) with custom colors + Recall badges
2. Latency boxplot by vector with jitter overlay + cold-start annotation
3. Consent fatigue stacked bar chart with auto-resolution subtitle
4. Summary metrics CSV table (thesis-ready, paste into Word/LaTeX)
"""

import os
import sys
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import matplotlib.patches as mpatches
import seaborn as sns
from sklearn.metrics import confusion_matrix

# =============================================================================
# Configuration
# =============================================================================

RESULTS_PATH = os.path.join(os.path.dirname(__file__), "evaluation_results.csv")
GRAPHS_DIR = os.path.join(os.path.dirname(__file__), "graphs")

# Academic styling
plt.rcParams.update({
    'font.family': 'serif',
    'font.size': 11,
    'axes.titlesize': 13,
    'axes.labelsize': 11,
    'xtick.labelsize': 10,
    'ytick.labelsize': 10,
    'figure.dpi': 300,
    'savefig.dpi': 300,
    'savefig.bbox': 'tight',
    'axes.spines.top': False,
    'axes.spines.right': False,
})

VECTOR_LABELS = {"MCP": "MCP\n(Local Tools)", "A2A": "A2A\n(Agent Delegation)", "WEB": "Web\n(Browser DOM)"}
VECTOR_COLORS = {"MCP": "#2196F3", "A2A": "#FF9800", "WEB": "#4CAF50"}

# Custom confusion matrix cell colors
CM_COLORS = {
    (0, 0): "#BBDEFB",   # TN = light blue
    (0, 1): "#FFF9C4",   # FP = yellow
    (1, 0): "#FFCDD2",   # FN = red
    (1, 1): "#C8E6C9",   # TP = green
}


def load_data():
    """Load and validate results CSV."""
    if not os.path.exists(RESULTS_PATH):
        print("[Error] Results file not found: " + RESULTS_PATH)
        print("  Run evaluate_shim.py first.")
        sys.exit(1)

    df = pd.read_csv(RESULTS_PATH)
    df.columns = df.columns.str.strip()
    for col in ['vector', 'classification', 'actual', 'correct']:
        if col in df.columns:
            df[col] = df[col].str.strip()
    if 'is_malicious' in df.columns:
        df['is_malicious'] = df['is_malicious'].astype(str).str.strip().map(
            {'True': True, 'False': False}
        ).fillna(False)
    print("[Graphs] Loaded " + str(len(df)) + " results from " + RESULTS_PATH)
    return df


def ensure_output_dir():
    """Create graphs output directory."""
    os.makedirs(GRAPHS_DIR, exist_ok=True)


# =============================================================================
# Graph 1: Confusion Matrices (1x3 grid) with custom colors + Recall badge
# =============================================================================

def plot_confusion_matrices(df):
    """
    Generate a 1x3 subplot grid showing confusion matrices per vector.
    Custom cell colors: TN=light blue, FP=yellow, FN=red, TP=green.
    Shows count and percentage in each cell. Recall badge below each matrix.
    """
    fig, axes = plt.subplots(1, 3, figsize=(14, 5))
    fig.suptitle("Security Efficacy: Confusion Matrices by Attack Vector",
                 fontsize=14, fontweight='bold', y=1.02)

    for idx, vector in enumerate(["MCP", "A2A", "WEB"]):
        ax = axes[idx]
        vec_df = df[df["vector"] == vector]

        if len(vec_df) == 0:
            ax.text(0.5, 0.5, "No data", ha='center', va='center')
            ax.set_title(VECTOR_LABELS.get(vector, vector))
            continue

        y_true = vec_df["is_malicious"].astype(int).values
        y_pred = (vec_df["actual"] != "allow").astype(int).values

        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        total = cm.sum()

        for i in range(2):
            for j in range(2):
                color = CM_COLORS[(i, j)]
                ax.add_patch(plt.Rectangle((j, 1-i), 1, 1, fill=True,
                                           facecolor=color, edgecolor='white', linewidth=2))
                count = cm[i, j]
                pct = count / total * 100 if total > 0 else 0
                ax.text(j + 0.5, 1.5 - i, f"{count}\n({pct:.0f}%)",
                        ha='center', va='center', fontsize=13, fontweight='bold')

        ax.set_xlim(0, 2)
        ax.set_ylim(0, 2)
        ax.set_xticks([0.5, 1.5])
        ax.set_xticklabels(["Predicted\nBenign", "Predicted\nMalicious"], fontsize=9)
        ax.set_yticks([0.5, 1.5])
        ax.set_yticklabels(["Actual\nMalicious", "Actual\nBenign"], fontsize=9)
        ax.set_title(VECTOR_LABELS.get(vector, vector), fontsize=12, fontweight='bold')
        ax.set_aspect('equal')

        tp = cm[1, 1]
        fn = cm[1, 0]
        recall = tp / (tp + fn) * 100 if (tp + fn) > 0 else 0
        ax.text(1.0, -0.15, f"Recall: {recall:.1f}%", ha='center', va='top',
                fontsize=11, fontweight='bold', color='#1B5E20',
                transform=ax.transAxes,
                bbox=dict(boxstyle='round,pad=0.3', facecolor='#C8E6C9', edgecolor='#2E7D32'))

    plt.tight_layout()
    path = os.path.join(GRAPHS_DIR, "confusion_matrices.png")
    fig.savefig(path, bbox_inches='tight')
    plt.close()
    print("  [1/4] Confusion matrices -> " + path)


# =============================================================================
# Graph 2: Latency Boxplot with jitter + mean diamonds + cold-start annotation
# =============================================================================

def plot_latency_boxplot(df):
    """
    Box-and-whisker plot with individual points overlaid (jitter),
    diamond markers for mean, and cold-start outlier annotation.
    """
    fig, ax = plt.subplots(figsize=(8, 5))

    vectors = ["MCP", "A2A", "WEB"]
    data = [df[df["vector"] == v]["latency_ms"].values for v in vectors]
    labels = [VECTOR_LABELS.get(v, v) for v in vectors]
    colors = [VECTOR_COLORS[v] for v in vectors]

    bp = ax.boxplot(data, labels=labels, patch_artist=True, widths=0.5,
                    medianprops=dict(color='black', linewidth=2),
                    whiskerprops=dict(linewidth=1.2),
                    capprops=dict(linewidth=1.2),
                    flierprops=dict(marker='o', markersize=4, alpha=0.5),
                    showmeans=True,
                    meanprops=dict(marker='D', markerfacecolor='white',
                                   markeredgecolor='black', markersize=7))

    for patch, color in zip(bp['boxes'], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)

    for i, (d, color) in enumerate(zip(data, colors)):
        jitter = np.random.normal(0, 0.08, size=len(d))
        ax.scatter(np.full_like(d, i + 1) + jitter, d,
                   alpha=0.4, s=15, color=color, edgecolor='none', zorder=3)

    ax.set_title("Policy Evaluation Latency Overhead by Vector", fontweight='bold')
    ax.set_ylabel("Processing Latency (ms)")
    ax.yaxis.set_major_formatter(mticker.FormatStrFormatter('%.2f'))

    for i, v in enumerate(vectors):
        vec_data = df[df["vector"] == v]["latency_ms"]
        median_val = vec_data.median()
        mean_val = vec_data.mean()
        ax.annotate(f'med={median_val:.3f}ms\nmean={mean_val:.3f}ms',
                    xy=(i+1, median_val),
                    xytext=(0, 15), textcoords='offset points',
                    ha='center', fontsize=8, fontweight='bold', color=colors[i])

    all_latencies = df["latency_ms"].values
    p95 = np.percentile(all_latencies, 95)
    cold_starts = df[df["latency_ms"] > 3 * p95]
    if len(cold_starts) > 0:
        for _, row in cold_starts.iterrows():
            vec_idx = vectors.index(row["vector"]) + 1 if row["vector"] in vectors else 1
            ax.annotate(f'Cold start\n({row["latency_ms"]:.1f}ms)',
                        xy=(vec_idx, row["latency_ms"]),
                        xytext=(30, 5), textcoords='offset points',
                        fontsize=8, fontstyle='italic',
                        arrowprops=dict(arrowstyle='->', color='grey'))

    ax.grid(axis='y', alpha=0.3, linestyle='--')

    path = os.path.join(GRAPHS_DIR, "latency_boxplot.png")
    fig.savefig(path, bbox_inches='tight')
    plt.close()
    print("  [2/4] Latency boxplot -> " + path)


# =============================================================================
# Graph 3: Consent Fatigue Mitigation (Stacked Bar) - clean layout
# =============================================================================

def plot_consent_fatigue(df):
    """
    100% stacked bar chart: auto-allowed / auto-blocked / HITL-escalated per vector.

    Layout strategy to avoid all overlaps:
      - Title is placed via fig.suptitle() at the very top of the figure
      - Subtitle (overall auto-resolution rate) is placed via ax.set_title()
        directly above the axes -- completely separate from suptitle
      - Legend is placed BELOW the x-axis using bbox_to_anchor
      - 'X% auto' annotations float just above the 100% line inside the plot
    """
    fig, ax = plt.subplots(figsize=(9, 7))
    # top=0.82 leaves room for suptitle; bottom=0.28 leaves room for legend
    fig.subplots_adjust(top=0.82, bottom=0.28, left=0.10, right=0.97)

    vectors = ["MCP", "A2A", "WEB", "Overall"]
    allow_pcts, block_pcts, hitl_pcts = [], [], []

    for vec in vectors:
        subset = df if vec == "Overall" else df[df["vector"] == vec]
        total = len(subset)
        if total == 0:
            allow_pcts.append(0)
            block_pcts.append(0)
            hitl_pcts.append(0)
            continue

        n_allow = len(subset[subset["actual"] == "allow"])
        n_block = len(subset[subset["actual"] == "block"])
        n_hitl  = len(subset[subset["actual"] == "hitl"])

        allow_pcts.append(n_allow / total * 100)
        block_pcts.append(n_block / total * 100)
        hitl_pcts.append(n_hitl  / total * 100)

    x = np.arange(len(vectors))
    width = 0.55

    labels_display = [VECTOR_LABELS.get(v, v) for v in vectors]
    labels_display[-1] = "Overall"

    bars_allow = ax.bar(x, allow_pcts, width, label='Auto-Allowed (PERMIT)',
                        color='#4CAF50', alpha=0.85)
    bars_block = ax.bar(x, block_pcts, width, bottom=allow_pcts,
                        label='Auto-Blocked (PROHIBITION)', color='#F44336', alpha=0.85)
    bars_hitl  = ax.bar(x, hitl_pcts, width,
                        bottom=[a + b for a, b in zip(allow_pcts, block_pcts)],
                        label='HITL-Escalated (CONSENT_NEEDED)', color='#FFC107', alpha=0.85)

    # Percentage labels inside each bar segment
    for i in range(len(vectors)):
        cumulative = 0
        for pct, bars in [(allow_pcts[i], bars_allow),
                          (block_pcts[i], bars_block),
                          (hitl_pcts[i],  bars_hitl)]:
            if pct > 5:
                ax.text(i, cumulative + pct / 2, f'{pct:.0f}%',
                        ha='center', va='center', fontsize=9, fontweight='bold', color='white')
            cumulative += pct

        # "X% auto" label just above the bar (y=103 is safely inside ylim=115)
        auto_pct = allow_pcts[i] + block_pcts[i]
        ax.text(i, 103, f'{auto_pct:.0f}% auto',
                ha='center', va='bottom', fontsize=8, fontweight='bold', color='#333333')

    overall_auto = allow_pcts[-1] + block_pcts[-1]

    # Main title at the top of the figure (separate from axes)
    fig.suptitle("Consent Fatigue Mitigation:\nAutomated Resolution vs. Human Escalation",
                 fontsize=13, fontweight='bold', y=0.97)

    # Subtitle just above the axes (ax.set_title is relative to the axes, not figure)
    ax.set_title(f"Overall Auto-Resolution Rate: {overall_auto:.0f}%",
                 fontsize=10, fontstyle='italic', color='#555555', pad=8)

    ax.set_ylabel("Percentage of Requests (%)")
    ax.set_xticks(x)
    ax.set_xticklabels(labels_display)
    ax.set_ylim(0, 115)

    # Legend below the x-axis ticks -- cannot overlap anything above
    ax.legend(
        loc='upper center',
        bbox_to_anchor=(0.5, -0.20),
        ncol=1,
        fontsize=9,
        framealpha=0.9
    )

    ax.grid(axis='y', alpha=0.2, linestyle='--')

    path = os.path.join(GRAPHS_DIR, "consent_fatigue.png")
    fig.savefig(path, bbox_inches='tight')
    plt.close()
    print("  [3/4] Consent fatigue chart -> " + path)


# =============================================================================
# Table 4: Summary Metrics - exported as CSV for thesis paste-in
# =============================================================================

def export_summary_table(df):
    """
    Computes TP, TN, FP, FN, Accuracy, Recall, Precision, F1,
    Mean Latency, P50, P95, P99 per vector and exports a clean CSV
    that can be copied directly into a thesis (Word / LaTeX).
    """
    vectors = ["MCP", "A2A", "WEB", "Overall"]
    headers = [
        "Vector", "TP", "TN", "FP", "FN",
        "Accuracy (%)", "Recall (%)", "Precision (%)", "F1 (%)",
        "Mean Lat (ms)", "P50 (ms)", "P95 (ms)", "P99 (ms)"
    ]
    rows = []

    for vec in vectors:
        subset = df if vec == "Overall" else df[df["vector"] == vec]

        tp = len(subset[subset["classification"] == "TP"])
        tn = len(subset[subset["classification"] == "TN"])
        fp = len(subset[subset["classification"] == "FP"])
        fn = len(subset[subset["classification"] == "FN"])

        binary_total = tp + tn + fp + fn
        accuracy  = (tp + tn) / binary_total * 100 if binary_total > 0 else 0
        precision = tp / (tp + fp) * 100            if (tp + fp) > 0 else 0
        recall    = tp / (tp + fn) * 100            if (tp + fn) > 0 else 0
        f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        lats    = sorted(subset["latency_ms"].values)
        n       = len(lats)
        avg_lat = np.mean(lats)       if n > 0 else 0
        p50     = lats[n // 2]        if n > 0 else 0
        p95     = lats[int(n * 0.95)] if n > 0 else 0
        p99     = lats[int(n * 0.99)] if n > 0 else 0

        label = VECTOR_LABELS.get(vec, vec).replace('\n', ' ')
        rows.append([
            label,
            tp, tn, fp, fn,
            round(accuracy,  1), round(recall,    1),
            round(precision, 1), round(f1,        1),
            round(avg_lat, 3),   round(p50, 3),
            round(p95, 3),       round(p99, 3)
        ])

    result_df = pd.DataFrame(rows, columns=headers)

    csv_path = os.path.join(GRAPHS_DIR, "summary_metrics.csv")
    result_df.to_csv(csv_path, index=False)
    print("  [4/4] Summary metrics table -> " + csv_path)
    print()
    print(result_df.to_string(index=False))
    print()
    return result_df


# =============================================================================
# Main
# =============================================================================

if __name__ == "__main__":
    ensure_output_dir()
    df = load_data()

    print("[Graphs] Generating publication-ready visualizations...\n")

    plot_confusion_matrices(df)
    plot_latency_boxplot(df)
    plot_consent_fatigue(df)
    export_summary_table(df)

    print("\n[Graphs] All outputs saved to: " + GRAPHS_DIR + "/")
