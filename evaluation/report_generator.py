"""
Automated PDF Report Generator (Deliverables D8 & D9).
Uses ReportLab to generate Security Analysis and Performance Benchmark documents.
"""

from __future__ import annotations
import json
import os
from typing import Any, Dict, Optional

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
except ImportError:
    # Fallback handled if reportlab is not imported
    letter = None
    SimpleDocTemplate = None


class PDFReportGenerator:
    """Generates official security and performance evaluation PDF reports."""

    @classmethod
    def generate_security_analysis_pdf(
        cls,
        output_pdf_path: str,
        benchmark_json_path: str,
        plots_dir: str = "evaluation/reports"
    ) -> str:
        """Generates Deliverable D8: security_analysis.pdf."""
        if SimpleDocTemplate is None:
            return ""

        os.makedirs(os.path.dirname(os.path.abspath(output_pdf_path)), exist_ok=True)
        doc = SimpleDocTemplate(output_pdf_path, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Heading1"],
            fontSize=20,
            leading=24,
            textColor=colors.HexColor("#1a252f"),
            spaceAfter=10
        )
        subtitle_style = ParagraphStyle(
            "DocSubTitle",
            parent=styles["Normal"],
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#7f8c8d"),
            spaceAfter=15
        )
        h2_style = ParagraphStyle(
            "H2Style",
            parent=styles["Heading2"],
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#2980b9"),
            spaceBefore=12,
            spaceAfter=8
        )
        body_style = ParagraphStyle(
            "BodyStyle",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#2c3e50")
        )

        elements = []

        elements.append(Paragraph("Security Analysis Report (D8)", title_style))
        elements.append(Paragraph("Quantum-Inspired Cyber Threat Detection for Teleportation-Based QDS | SIH 2026", subtitle_style))
        elements.append(Spacer(1, 10))

        elements.append(Paragraph("1. Executive Security Summary", h2_style))
        summary_text = (
            "This report details the statistical security bounds and threat mitigation efficacy of the "
            "3-party teleportation-based Quantum Digital Signature (QDS) architecture secured with ML-KEM-768. "
            "All threat evaluation mechanisms are completely deterministic and non-AI based, leveraging exact "
            "quantum mechanics, Binomial cumulative distribution bounds, and Wilson score upper confidence bounds."
        )
        elements.append(Paragraph(summary_text, body_style))
        elements.append(Spacer(1, 12))

        # Include P_forge Scaling Plot
        p_forge_plot = os.path.join(plots_dir, "p_forge_scaling.png")
        if os.path.exists(p_forge_plot):
            elements.append(Paragraph("2. Forgery Probability Bounds ($P_{forge}$ vs $L$)", h2_style))
            elements.append(Image(p_forge_plot, width=500, height=270))
            elements.append(Spacer(1, 10))

        # Include QBER Plot
        qber_plot = os.path.join(plots_dir, "qber_distribution.png")
        if os.path.exists(qber_plot):
            elements.append(Paragraph("3. QBER Separability & Channel Quarantine Confidence", h2_style))
            elements.append(Image(qber_plot, width=500, height=270))
            elements.append(Spacer(1, 10))

        doc.build(elements)
        return output_pdf_path

    @classmethod
    def generate_performance_benchmarks_pdf(
        cls,
        output_pdf_path: str,
        benchmark_json_path: str,
        plots_dir: str = "evaluation/reports"
    ) -> str:
        """Generates Deliverable D9: performance_benchmarks.pdf."""
        if SimpleDocTemplate is None:
            return ""

        os.makedirs(os.path.dirname(os.path.abspath(output_pdf_path)), exist_ok=True)
        doc = SimpleDocTemplate(output_pdf_path, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Heading1"],
            fontSize=20,
            leading=24,
            textColor=colors.HexColor("#1a252f"),
            spaceAfter=10
        )
        subtitle_style = ParagraphStyle(
            "DocSubTitle",
            parent=styles["Normal"],
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#7f8c8d"),
            spaceAfter=15
        )
        h2_style = ParagraphStyle(
            "H2Style",
            parent=styles["Heading2"],
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#27ae60"),
            spaceBefore=12,
            spaceAfter=8
        )
        body_style = ParagraphStyle(
            "BodyStyle",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#2c3e50")
        )

        elements = []

        elements.append(Paragraph("Performance Benchmarks Report (D9)", title_style))
        elements.append(Paragraph("Computational Latency, Attack Detection Rates & Complexity | SIH 2026", subtitle_style))
        elements.append(Spacer(1, 10))

        # Attack Detection Bar Chart
        attack_plot = os.path.join(plots_dir, "attack_detection_rates.png")
        if os.path.exists(attack_plot):
            elements.append(Paragraph("1. Attack Mitigation Efficacy (10 Adversary Scenarios)", h2_style))
            elements.append(Image(attack_plot, width=500, height=270))
            elements.append(Spacer(1, 10))

        # Runtime scaling plot
        runtime_plot = os.path.join(plots_dir, "runtime_scaling.png")
        if os.path.exists(runtime_plot):
            elements.append(Paragraph("2. Verification Time Scaling ($O(L)$ Linearity)", h2_style))
            elements.append(Image(runtime_plot, width=500, height=270))
            elements.append(Spacer(1, 10))

        # Attack Summary Table
        if os.path.exists(benchmark_json_path):
            with open(benchmark_json_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            table_data = [["Attack ID", "Scenario Name", "Detection %", "False Positive %", "Status"]]
            for r in data.get("attack_benchmarks", []):
                table_data.append([
                    r["attack_id"],
                    r["attack_name"][:25],
                    f"{r['detection_rate']*100:.1f}%",
                    f"{r['false_positive_rate']*100:.1f}%",
                    "PASS" if r["passed_success_criterion"] else "FAIL"
                ])

            t = Table(table_data, colWidths=[65, 180, 80, 100, 65])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#bdc3c7")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8f9fa"), colors.white]),
            ]))
            elements.append(Paragraph("3. Detailed Detection Metrics Table", h2_style))
            elements.append(t)

        doc.build(elements)
        return output_pdf_path
