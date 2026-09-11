// Cyber-Quantum SOC Dashboard Controller
document.addEventListener("DOMContentLoaded", () => {
  const btnExecute = document.getElementById("btn-execute");
  const btnBenchmark = document.getElementById("btn-benchmark");
  const selectMode = document.getElementById("scenario-mode");
  const inputLength = document.getElementById("sig-length");
  const inputThreshold = document.getElementById("threshold-t");
  const inputMessage = document.getElementById("payload-message");

  const threatBanner = document.getElementById("threat-banner");
  const bannerTitle = document.getElementById("banner-title");
  const bannerDesc = document.getElementById("banner-desc");
  const bannerBadge = document.getElementById("banner-badge");

  const valMismatches = document.getElementById("val-mismatches");
  const valMismatchRate = document.getElementById("val-mismatch-rate");
  const valQber = document.getElementById("val-qber");
  const valQberStatus = document.getElementById("val-qber-status");
  const valPforge = document.getElementById("val-pforge");
  const valFidelity = document.getElementById("val-fidelity");

  const bobCorrection = document.getElementById("bob-correction");
  const bobDecision = document.getElementById("bob-decision");
  const auditFeed = document.getElementById("audit-feed");

  // Chart setup
  const ctx = document.getElementById("threatChart").getContext("2d");
  const threatChart = new Chart(ctx, {
    type: "line",
    data: {
      labels: ["T-4", "T-3", "T-2", "T-1", "Current"],
      datasets: [
        {
          label: "Mismatch Rate %",
          data: [2.5, 3.0, 2.0, 3.5, 3.0],
          borderColor: "#00f0ff",
          backgroundColor: "rgba(0, 240, 255, 0.1)",
          tension: 0.3,
          fill: true
        },
        {
          label: "QBER 99% UCB %",
          data: [4.0, 4.5, 3.8, 5.0, 4.2],
          borderColor: "#ff9900",
          borderDash: [5, 5],
          tension: 0.3
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: {
          beginAtZero: true,
          grid: { color: "#1e293b" },
          ticks: { color: "#94a3b8" }
        },
        x: {
          grid: { color: "#1e293b" },
          ticks: { color: "#94a3b8" }
        }
      },
      plugins: {
        legend: { labels: { color: "#e2e8f0" } }
      }
    }
  });

  // Fetch initial audit logs
  fetchAuditLogs();

  btnExecute.addEventListener("click", async () => {
    btnExecute.disabled = true;
    btnExecute.textContent = "⏳ Simulating Quantum Teleportation...";

    const payload = {
      mode: selectMode.value,
      signer_id: "ALICE",
      verifier_id: "BOB",
      message: inputMessage.value,
      signature_length_L: parseInt(inputLength.value),
      threshold_t: parseInt(inputThreshold.value)
    };

    try {
      const resp = await fetch("/api/protocol/execute", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      const data = await resp.json();
      updateDashboard(data);
      fetchAuditLogs();
    } catch (err) {
      console.error(err);
    } finally {
      btnExecute.disabled = false;
      btnExecute.textContent = "▶ Execute Protocol Run";
    }
  });

  btnBenchmark.addEventListener("click", async () => {
    btnBenchmark.disabled = true;
    btnBenchmark.textContent = "⚡ Running 10 Attacks (n=100)...";

    try {
      const resp = await fetch("/api/benchmarks/run", { method: "POST" });
      const data = await resp.json();
      alert(`Benchmark Complete! All 10 attacks evaluated. Status: ${data.status}. Reports generated!`);
      fetchAuditLogs();
    } catch (err) {
      console.error(err);
    } finally {
      btnBenchmark.disabled = false;
      btnBenchmark.textContent = "⚡ Run 10-Attack Benchmark";
    }
  });

  function updateDashboard(data) {
    if (data.threat_detected) {
      threatBanner.className = "threat-banner banner-threat";
      bannerTitle.textContent = `🚨 THREAT DETECTED: ${data.primary_threat ? data.primary_threat.threat_name : "Security Violation"}`;
      bannerDesc.textContent = `${data.primary_threat ? data.primary_threat.explanation : data.explanation} [Rule: ${data.primary_threat ? data.primary_threat.rule_id : data.rule_id}]`;
      bannerBadge.textContent = "DEFENSE TRIGGERED";
      bobDecision.textContent = "Status: REJECTED";
      bobDecision.style.background = "#ff3366";
    } else {
      threatBanner.className = "threat-banner banner-safe";
      bannerTitle.textContent = "🟢 Quantum Signature Verified & Accepted";
      bannerDesc.textContent = `Mismatch count within threshold (${data.mismatch_count} <= ${data.threshold_t}). Mathematical P_forge <= 10^-6 bound verified.`;
      bannerBadge.textContent = "SIGNATURE VALID";
      bobDecision.textContent = "Status: ACCEPTED";
      bobDecision.style.background = "#00ff88";
      bobDecision.style.color = "#000000";
    }

    if (data.mismatch_count !== undefined) {
      valMismatches.textContent = `${data.mismatch_count} / ${inputLength.value}`;
      valMismatchRate.textContent = `Rate: ${(data.mismatch_rate * 100).toFixed(1)}% (Limit: 15%)`;
    }

    if (data.qber_assessment) {
      valQber.textContent = `${(data.qber_assessment.wilson_upper_bound * 100).toFixed(2)}%`;
      valQberStatus.textContent = data.qber_assessment.quarantine_alert ? "QUARANTINE ALERT ACTIVE" : "Healthy (< 11.0%)";
      valQberStatus.style.color = data.qber_assessment.quarantine_alert ? "#ff3366" : "#00ff88";
    }

    if (data.p_forge_bound !== undefined) {
      valPforge.textContent = data.p_forge_bound < 1e-6 ? "≤ 10⁻⁶" : data.p_forge_bound.toExponential(2);
    }

    if (data.entanglement_fidelity !== undefined) {
      valFidelity.textContent = data.entanglement_fidelity.toFixed(3);
    }

    // Update chart
    const currentRate = (data.mismatch_rate || 0.03) * 100;
    const currentQber = (data.qber_assessment ? data.qber_assessment.wilson_upper_bound : 0.04) * 100;

    threatChart.data.datasets[0].data.shift();
    threatChart.data.datasets[0].data.push(currentRate);
    threatChart.data.datasets[1].data.shift();
    threatChart.data.datasets[1].data.push(currentQber);
    threatChart.update();
  }

  async function fetchAuditLogs() {
    try {
      const resp = await fetch("/api/audit/logs?limit=15");
      const data = await resp.json();
      auditFeed.innerHTML = "";

      data.events.forEach(e => {
        const item = document.createElement("div");
        item.className = "audit-item";
        item.innerHTML = `
          <span class="audit-time">[${e.timestamp.split("T")[1].slice(0, 8)} UTC]</span>
          <span class="audit-type">${e.event_type}</span>
          <span class="audit-actor">${e.actor}</span>
          <span class="audit-hash">#${e.event_hash}</span>
          <span class="audit-desc">${JSON.stringify(e.details).slice(0, 60)}...</span>
        `;
        auditFeed.appendChild(item);
      });
    } catch (err) {
      console.error(err);
    }
  }
});
