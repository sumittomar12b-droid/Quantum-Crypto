"""
Plot Generation Module for Security Analysis and Performance Evaluation.
Produces publication-quality figures for reports and SOC dashboard.
"""

from __future__ import annotations
import os
from typing import Dict, List, Optional
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend
import matplotlib.pyplot as plt
import numpy as np

from detection.statistical_engine import BinomialThreatEngine


class PlotGenerator:
    """Generates analytical plots and saves them as PNG/SVG images."""

    @classmethod
    def plot_p_forge_vs_L(
        cls,
        output_path: str,
        L_values: Optional[List[int]] = None,
        q_adv_values: Optional[List[float]] = None
    ) -> str:
        """Plots P_forge vs Signature Length L for various adversary capabilities."""
        if L_values is None:
            L_values = [50, 100, 150, 200, 300, 400, 500, 750, 1000]
        if q_adv_values is None:
            q_adv_values = [0.25, 0.30, 0.35, 0.50]

        plt.figure(figsize=(9, 5.5), dpi=300)
        plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")

        colors = ["#e74c3c", "#e67e22", "#f39c12", "#2ecc71"]

        for idx, q_adv in enumerate(q_adv_values):
            p_values = []
            for L in L_values:
                t = int(0.15 * L)
                p_f = BinomialThreatEngine.compute_p_forge(L, t, q_adv)
                p_values.append(max(p_f, 1e-18))  # Clamp for log scale

            plt.plot(
                L_values,
                p_values,
                marker="o",
                linewidth=2.2,
                color=colors[idx % len(colors)],
                label=f"Adversary $q_{{adv}} = {q_adv}$"
            )

        # Target security threshold line at 10^-6
        plt.axhline(1e-6, color="#2c3e50", linestyle="--", linewidth=1.5, label="Target Bound ($10^{-6}$)")

        plt.yscale("log")
        plt.xlabel("Signature Length ($L$ qubits)", fontsize=12, fontweight="bold")
        plt.ylabel("Forgery Success Probability $P_{forge}$", fontsize=12, fontweight="bold")
        plt.title("QDS Forgery Probability Scaling vs Signature Length $L$", fontsize=13, fontweight="bold", pad=12)
        plt.grid(True, which="both", linestyle=":", alpha=0.6)
        plt.legend(frameon=True, fontsize=10, loc="upper right")
        plt.tight_layout()

        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        plt.savefig(output_path)
        plt.close()
        return output_path

    @classmethod
    def plot_attack_detection_rates(
        cls,
        output_path: str,
        attack_results: List[Dict[str, Any]]
    ) -> str:
        """Plots bar chart of detection rates across all 10 attack scenarios."""
        plt.figure(figsize=(11, 6), dpi=300)
        plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")

        names = [r["attack_name"] for r in attack_results]
        rates = [r["detection_rate"] * 100 for r in attack_results]

        colors = ["#27ae60" if r >= 95.0 else "#e74c3c" for r in rates]
        y_pos = np.arange(len(names))

        bars = plt.barh(y_pos, rates, color=colors, height=0.65, edgecolor="#2c3e50", linewidth=1.0)
        plt.axvline(95.0, color="#c0392b", linestyle="--", linewidth=2.0, label="Success Target (95%)")

        for bar in bars:
            width = bar.get_width()
            plt.text(
                width + 1.0,
                bar.get_y() + bar.get_height() / 2.0,
                f"{width:.1f}%",
                va="center",
                ha="left",
                fontsize=9,
                fontweight="bold"
            )

        plt.yticks(y_pos, names, fontsize=10)
        plt.xlabel("Empirical Detection Rate (%)", fontsize=12, fontweight="bold")
        plt.xlim(0, 115)
        plt.title("Deterministic Threat Detection Rates (10 Attack Scenarios)", fontsize=13, fontweight="bold", pad=12)
        plt.legend(frameon=True, fontsize=10, loc="lower right")
        plt.tight_layout()

        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        plt.savefig(output_path)
        plt.close()
        return output_path

    @classmethod
    def plot_qber_histogram(
        cls,
        output_path: str,
        honest_qbers: List[float],
        attacked_qbers: List[float],
        epsilon_max: float = 0.11
    ) -> str:
        """Plots QBER distribution comparing honest channel vs channel disturbance."""
        plt.figure(figsize=(9, 5.5), dpi=300)
        plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")

        plt.hist(honest_qbers, bins=25, alpha=0.75, color="#2980b9", label="Honest Environmental Noise", density=True)
        plt.hist(attacked_qbers, bins=25, alpha=0.75, color="#e74c3c", label="Active Channel Disturbance", density=True)

        plt.axvline(epsilon_max, color="#8e44ad", linestyle="--", linewidth=2.0, label=f"Quarantine Threshold $\\varepsilon_{{max}} = {epsilon_max}$")

        plt.xlabel("Quantum Bit Error Rate (QBER)", fontsize=12, fontweight="bold")
        plt.ylabel("Probability Density", fontsize=12, fontweight="bold")
        plt.title("QBER Separability: Honest Channel vs Adversarial Attack", fontsize=13, fontweight="bold", pad=12)
        plt.legend(frameon=True, fontsize=10)
        plt.tight_layout()

        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        plt.savefig(output_path)
        plt.close()
        return output_path

    @classmethod
    def plot_runtime_scaling(
        cls,
        output_path: str,
        L_values: List[int],
        runtimes_ms: List[float]
    ) -> str:
        """Plots verification runtime vs L showing O(L) linearity."""
        plt.figure(figsize=(9, 5.5), dpi=300)
        plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")

        plt.plot(L_values, runtimes_ms, marker="s", markersize=7, color="#16a085", linewidth=2.2, label="Empirical Runtime")

        # Linear fit line
        fit = np.polyfit(L_values, runtimes_ms, 1)
        fit_fn = np.poly1d(fit)
        plt.plot(L_values, fit_fn(L_values), color="#7f8c8d", linestyle="--", label=f"Linear Fit $\\mathcal{{O}}(L)$")

        plt.xlabel("Signature Length ($L$ qubits)", fontsize=12, fontweight="bold")
        plt.ylabel("Verification Execution Time (ms)", fontsize=12, fontweight="bold")
        plt.title("Computational Complexity: Signature Verification vs Length $L$", fontsize=13, fontweight="bold", pad=12)
        plt.legend(frameon=True, fontsize=10)
        plt.tight_layout()

        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        plt.savefig(output_path)
        plt.close()
        return output_path
