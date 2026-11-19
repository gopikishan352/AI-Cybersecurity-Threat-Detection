// =====================================================================
// AI Cyber Threat Detection System - Main Controller
// Fully Integrated with Flask, Random Forest, NSL-KDD & Groq Backend
// =====================================================================

let pieChart = null;
let presetsCache = {};
let latestReportData = null;

// Threat category color mapping
const THREAT_COLORS = {
    "Normal": "#22c55e",
    "DoS": "#f97316",
    "Probe": "#3b82f6",
    "R2L": "#a855f7",
    "U2R": "#ef4444"
};

// =====================================================================
// Initialization
// =====================================================================
document.addEventListener("DOMContentLoaded", () => {
    initClock();
    loadMetrics();
    loadPresets();
    checkHealth();
    loadStoredHistory();
});

// =====================================================================
// 1. Live Clock
// =====================================================================
function initClock() {
    updateClock();
    setInterval(updateClock, 1000);
}

function updateClock() {
    const clockEl = document.getElementById("clock");
    if (clockEl) {
        const now = new Date();
        clockEl.textContent = now.toLocaleTimeString();
    }
}

// =====================================================================
// 2. Load Model Metrics Dynamically
// =====================================================================
function loadMetrics() {
    fetch("/metrics")
        .then(res => {
            if (!res.ok) throw new Error("Metrics response not OK");
            return res.json();
        })
        .then(data => {
            if (data.accuracy) document.getElementById("accuracy").textContent = formatMetric(data.accuracy);
            if (data.precision) document.getElementById("precision").textContent = formatMetric(data.precision);
            if (data.recall) document.getElementById("recall").textContent = formatMetric(data.recall);
            if (data.f1_score || data.f1) document.getElementById("f1").textContent = formatMetric(data.f1_score || data.f1);
        })
        .catch(err => {
            console.log("Using default model metrics fallback:", err);
        });
}

function formatMetric(val) {
    if (typeof val === "string" && val.includes("%")) return val;
    const num = Number(val);
    if (isNaN(num)) return val;
    if (num <= 1 && num > 0) return (num * 100).toFixed(1) + "%";
    return num.toFixed(1) + "%";
}

// =====================================================================
// 3. System & Groq Health Check
// =====================================================================
function checkHealth() {
    fetch("/api/health")
        .then(res => res.json())
        .then(data => {
            const badge = document.getElementById("aiBadge");
            if (badge) {
                if (data.groq_configured) {
                    badge.className = "badge bg-success";
                    badge.innerHTML = "🟢 Groq AI Active";
                } else {
                    badge.className = "badge bg-secondary";
                    badge.innerHTML = "⚡ SOC Intel Mode";
                }
            }
        })
        .catch(e => console.log("Health check skipped:", e));
}

// =====================================================================
// 4. Quick Feature Presets (Normal, DoS, Probe, R2L)
// =====================================================================
function loadPresets() {
    fetch("/api/presets")
        .then(res => res.json())
        .then(data => {
            presetsCache = data;
        })
        .catch(e => {
            // Fallback presets if endpoint is offline
            presetsCache = {
                "normal": { "features": [0,"tcp","http","SF",181,5450,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,8,8,0.0,0.0,0.0,0.0,1.0,0.0,0.0,9,9,1.0,0.0,0.11,0.0,0.0,0.0,0.0,0.0] },
                "dos": { "features": [0,"tcp","private","S0",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,123,6,1.0,1.0,0.0,0.0,0.05,0.07,0.0,255,26,0.1,0.05,0.0,0.0,1.0,1.0,0.0,0.0] },
                "probe": { "features": [0,"tcp","private","REJ",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,237,7,0.0,0.0,1.0,1.0,0.03,0.06,0.0,255,7,0.03,0.06,0.0,0.0,0.0,0.0,1.0,1.0] },
                "r2l": { "features": [0,"tcp","telnet","SF",126,179,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0.0,0.0,0.0,0.0,1.0,0.0,0.0,1,1,1.0,0.0,1.0,0.0,0.0,0.0,0.0,0.0] }
            };
        });
}

function loadPreset(type) {
    if (presetsCache && presetsCache[type] && presetsCache[type].features) {
        document.getElementById("features").value = presetsCache[type].features.join(", ");
    }
}

// =====================================================================
// 5. Predict Single Network Traffic Record
// =====================================================================
function predict() {
    const textarea = document.getElementById("features");
    const resultDiv = document.getElementById("result");
    const predictBtn = document.getElementById("predictBtn");

    const text = (textarea ? textarea.value : "").trim();
    if (!text) {
        resultDiv.innerHTML = `
            <div class="alert alert-warning py-2">
                <i class="bi bi-exclamation-triangle me-2"></i>
                Please enter 41 feature values or click a quick scenario preset above.
            </div>`;
        return;
    }

    const arr = text.split(",").map(s => s.trim());
    if (arr.length !== 41) {
        resultDiv.innerHTML = `
            <div class="alert alert-danger py-2">
                <i class="bi bi-x-circle me-2"></i>
                Expected exactly 41 features, but received ${arr.length}. Please check your inputs.
            </div>`;
        return;
    }

    // Set loading state
    predictBtn.disabled = true;
    predictBtn.innerHTML = `<span class="spinner-border spinner-border-sm me-2"></span> Predicting...`;
    resultDiv.innerHTML = `
        <div class="text-warning text-center py-2">
            <span class="spinner-border spinner-border-sm me-2"></span>
            Evaluating traffic flow with Random Forest model...
        </div>`;

    fetch("/predict", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ features: arr })
    })
    .then(res => res.json())
    .then(data => {
        if (data.error) {
            resultDiv.innerHTML = `<div class="alert alert-danger py-2"><i class="bi bi-exclamation-triangle me-2"></i>${escapeHTML(data.error)}</div>`;
            return;
        }

        const isThreat = data.threat_type !== "Normal";
        const badgeColor = isThreat ? "#ef4444" : "#22c55e";
        const cardBorderClass = isThreat ? "border-threat" : "border-safe";
        const icon = isThreat ? "🚨" : "🛡️";
        const threatBadge = getThreatBadge(data.threat_type);
        const riskBadge = getRiskBadge(data.risk_level);
        const ai = data.ai_analysis || {};

        resultDiv.innerHTML = `
            <div class="dark-result-card ${cardBorderClass} mt-3">
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <h5 class="m-0 fw-bold" style="color: ${badgeColor};">
                        ${icon} ${data.prediction} (${data.confidence}%)
                    </h5>
                    <div>
                        ${threatBadge} ${riskBadge}
                    </div>
                </div>

                <div class="row g-2 mb-3 small text-secondary">
                    <div class="col-sm-6"><b>Source:</b> <code class="text-light">${data.source || '192.168.1.105:54321'}</code></div>
                    <div class="col-sm-6"><b>Destination:</b> <code class="text-light">${data.destination || '10.0.0.1:80'}</code></div>
                    <div class="col-sm-6"><b>Protocol:</b> <span class="badge bg-dark border border-secondary">${data.protocol || 'TCP'}</span> &nbsp;|&nbsp; <b>Service:</b> ${data.service || 'http'}</div>
                    <div class="col-sm-6"><b>Category:</b> <span style="color: ${THREAT_COLORS[data.threat_type] || '#fff'}; font-weight: bold;">${data.threat_type}</span></div>
                </div>

                <!-- AI Explanation -->
                <div class="p-3 rounded bg-dark border border-secondary border-opacity-50">
                    <h6 class="text-info mb-1"><i class="bi bi-robot me-1"></i>${ai.source || 'AI Threat Intelligence'}:</h6>
                    <p class="mb-2 text-white" style="font-size: 0.9rem;">${ai.explanation || 'Network anomaly inspection complete.'}</p>
                    <small class="text-secondary d-block mb-1"><b>Recommended Actions:</b></small>
                    <ul class="mb-0 text-secondary ps-3" style="font-size: 0.85rem;">
                        ${(ai.recommended_actions || []).map(r => `<li>${escapeHTML(r)}</li>`).join('') || '<li>Monitor traffic flow and verify access rules.</li>'}
                    </ul>
                </div>
            </div>
        `;

        // Update AI panel with report
        const aiPanel = document.getElementById("aiReport");
        if (aiPanel) {
            aiPanel.innerHTML = `
                <div class="ai-report-content">
                    <pre>Threat Category: ${data.threat_type}
Risk Level: ${data.risk_level}
Confidence: ${data.confidence}%
Source: ${data.source} -> ${data.destination}

Assessment:
${ai.explanation || 'Traffic inspected.'}

Recommended Actions:
${(ai.recommended_actions || []).map(r => `• ${r}`).join('\n') || '• Continue continuous monitoring.'}</pre>
                </div>
            `;
        }

        // Add to detection history table
        addHistoryRow({
            time: new Date().toLocaleTimeString(),
            total: 1,
            safe: isThreat ? 0 : 1,
            threat: isThreat ? 1 : 0,
            status: isThreat ? "THREATS DETECTED" : "SAFE"
        });
    })
    .catch(error => {
        resultDiv.innerHTML = `<div class="alert alert-danger py-2">❌ Prediction failed: ${escapeHTML(error.message || error)}</div>`;
        console.error("Prediction error:", error);
    })
    .finally(() => {
        predictBtn.disabled = false;
        predictBtn.innerHTML = `<i class="bi bi-bullseye me-2"></i> Predict`;
    });
}

// =====================================================================
// 6. Upload & Batch Predict NSL-KDD Dataset
// =====================================================================
function uploadCSV() {
    const fileInput = document.getElementById("csvFile");
    const resultDiv = document.getElementById("uploadResult");
    const uploadBtn = document.getElementById("uploadBtn");

    if (!fileInput || !fileInput.files || fileInput.files.length === 0) {
        resultDiv.innerHTML = `
            <div class="alert alert-danger py-2">
                <i class="bi bi-exclamation-triangle me-2"></i>
                Please choose a .csv or .txt dataset file first.
            </div>`;
        return;
    }

    const file = fileInput.files[0];
    const formData = new FormData();
    formData.append("file", file);

    // Set loading state
    uploadBtn.disabled = true;
    uploadBtn.innerHTML = `<span class="spinner-border spinner-border-sm me-2"></span> Analyzing Dataset...`;
    resultDiv.innerHTML = `
        <div class="text-warning py-2">
            <span class="spinner-border spinner-border-sm me-2"></span>
            Processing and classifying dataset with Random Forest...
        </div>`;

    fetch("/upload", {
        method: "POST",
        body: formData
    })
    .then(res => res.json())
    .then(data => {
        if (data.error) {
            resultDiv.innerHTML = `<div class="alert alert-danger py-2">❌ Error: ${escapeHTML(data.error)}</div>`;
            return;
        }

        const total = Number(data.total) || 0;
        const safe = Number(data.safe) || 0;
        const threat = Number(data.threat) || 0;
        const threatRate = data.threat_rate !== undefined ? data.threat_rate : (total > 0 ? ((threat / total) * 100).toFixed(1) : 0);
        const safePercent = total > 0 ? ((safe / total) * 100).toFixed(1) : 0;
        const threatPercent = total > 0 ? ((threat / total) * 100).toFixed(1) : 0;

        // 1. Update Live Analytics Cards
        document.getElementById("liveTotal").textContent = total.toLocaleString();
        document.getElementById("liveSafe").textContent = safe.toLocaleString();
        document.getElementById("liveThreat").textContent = threat.toLocaleString();
        document.getElementById("liveRate").textContent = threatRate + "%";

        // 2. Render Chart.js Threat Distribution Doughnut
        renderThreatChart(safe, threat, data.threat_counts);

        // 3. Render Upload Success Summary
        resultDiv.innerHTML = `
            <div class="dark-result-card border-safe mt-3">
                <h5 class="text-success fw-bold m-0 mb-2">
                    <i class="bi bi-check-circle me-2"></i> Dataset Analyzed Successfully!
                </h5>
                <p class="text-secondary small mb-2">Processed <b>${total.toLocaleString()}</b> records using trained Random Forest model.</p>
                <div class="d-flex justify-content-between small mb-2">
                    <span>Safe Traffic: <b class="text-success">${safe.toLocaleString()} (${safePercent}%)</b></span>
                    <span>Threat Traffic: <b class="text-danger">${threat.toLocaleString()} (${threatPercent}%)</b></span>
                </div>
                <div class="progress" style="height: 12px; background-color: #21262d;">
                    <div class="progress-bar bg-success" style="width: ${safePercent}%;"></div>
                    <div class="progress-bar bg-danger" style="width: ${threatPercent}%;"></div>
                </div>
            </div>
        `;

        // 4. Update AI Threat Analysis Panel
        const aiPanel = document.getElementById("aiReport");
        if (aiPanel) {
            aiPanel.innerHTML = `
                <div class="ai-report-content">
                    <pre>${escapeHTML(data.ai_report || "Comprehensive dataset analysis complete. No anomalous incidents identified.")}</pre>
                </div>
            `;
        }

        // 5. Store for CSV/PDF downloads
        latestReportData = {
            date: new Date().toLocaleString(),
            total: total,
            safe: safe,
            threat: threat,
            threatRate: threatRate + "%",
            aiReport: data.ai_report || ""
        };

        // 6. Append Row to Detection History
        addHistoryRow({
            time: new Date().toLocaleTimeString(),
            total: total,
            safe: safe,
            threat: threat,
            status: threat > 0 ? "THREATS DETECTED" : "SAFE"
        });
    })
    .catch(error => {
        resultDiv.innerHTML = `<div class="alert alert-danger py-2">❌ Upload failed: ${escapeHTML(error.message || error)}</div>`;
        console.error("Upload error:", error);
    })
    .finally(() => {
        uploadBtn.disabled = false;
        uploadBtn.innerHTML = `<i class="bi bi-cloud-arrow-up me-2"></i> Upload & Predict`;
    });
}

// =====================================================================
// 7. Threat Distribution Chart (Chart.js Doughnut)
// =====================================================================
function renderThreatChart(safe, threat, threatCounts = {}) {
    const canvas = document.getElementById("pieChart");
    const placeholder = document.getElementById("chartPlaceholder");

    if (!canvas) return;

    // Hide empty placeholder
    if (placeholder) placeholder.style.display = "none";
    canvas.style.display = "block";

    if (pieChart) {
        pieChart.destroy();
    }

    const labels = ["Safe Traffic", "Threat Traffic"];
    const chartData = [safe, threat];
    const backgroundColors = ["#22c55e", "#ef4444"];

    pieChart = new Chart(canvas, {
        type: "doughnut",
        data: {
            labels: labels,
            datasets: [{
                data: chartData,
                backgroundColor: backgroundColors,
                borderColor: "#161b22",
                borderWidth: 3
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: "65%",
            plugins: {
                legend: {
                    position: "bottom",
                    labels: {
                        color: "#ffffff",
                        padding: 16,
                        font: { size: 13, weight: "bold" }
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function (context) {
                            const val = context.raw || 0;
                            const total = safe + threat;
                            const pct = total > 0 ? ((val / total) * 100).toFixed(1) : 0;
                            return ` ${context.label}: ${val.toLocaleString()} (${pct}%)`;
                        }
                    }
                }
            }
        }
    });
}

// =====================================================================
// 8. Detection History Table & Local Persistence
// =====================================================================
function loadStoredHistory() {
    try {
        const stored = localStorage.getItem("cyber_detection_history");
        if (stored) {
            const list = JSON.parse(stored);
            if (Array.isArray(list) && list.length > 0) {
                renderHistoryTable(list);
            }
        }
    } catch (e) {
        console.log("Could not load stored history:", e);
    }
}

function addHistoryRow(record) {
    try {
        let history = [];
        const stored = localStorage.getItem("cyber_detection_history");
        if (stored) {
            history = JSON.parse(stored) || [];
        }
        // Insert at the beginning (most recent first)
        history.unshift(record);
        // Keep up to 25 records in local session
        if (history.length > 25) history = history.slice(0, 25);
        localStorage.setItem("cyber_detection_history", JSON.stringify(history));
        renderHistoryTable(history);
    } catch (e) {
        console.log("Error saving history:", e);
    }
}

function renderHistoryTable(records) {
    const tbody = document.getElementById("historyTable");
    if (!tbody) return;

    if (!records || records.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="text-center py-4 text-secondary">No analysis performed yet.</td></tr>`;
        return;
    }

    tbody.innerHTML = records.map(item => {
        const isThreat = item.threat > 0 || item.status === "THREATS DETECTED";
        const badge = isThreat
            ? `<span class="badge bg-danger fw-bold">THREATS DETECTED</span>`
            : `<span class="badge bg-success fw-bold">SAFE</span>`;

        return `
            <tr>
                <td class="font-monospace text-secondary">${escapeHTML(item.time)}</td>
                <td class="fw-bold">${Number(item.total).toLocaleString()}</td>
                <td class="text-success fw-bold">${Number(item.safe).toLocaleString()}</td>
                <td class="${isThreat ? 'text-danger' : 'text-secondary'} fw-bold">${Number(item.threat).toLocaleString()}</td>
                <td>${badge}</td>
            </tr>
        `;
    }).join("");
}

// =====================================================================
// 9. Report Downloads (CSV & PDF)
// =====================================================================
function downloadReport() {
    // Direct backend CSV export endpoint
    window.location.href = "/api/export/csv";
}

function downloadPDFReport() {
    // Direct backend ReportLab PDF generation endpoint
    window.location.href = "/api/export/pdf";
}

// =====================================================================
// Helper Utilities & Badges
// =====================================================================
function getThreatBadge(threat) {
    switch (threat) {
        case "Normal":
            return `<span class="badge badge-normal">Normal</span>`;
        case "DoS":
            return `<span class="badge badge-dos">DoS</span>`;
        case "Probe":
            return `<span class="badge badge-probe">Probe</span>`;
        case "R2L":
            return `<span class="badge badge-r2l">R2L</span>`;
        case "U2R":
            return `<span class="badge badge-u2r">U2R</span>`;
        default:
            return `<span class="badge bg-secondary">${escapeHTML(threat || 'Unknown')}</span>`;
    }
}

function getRiskBadge(risk) {
    switch (risk) {
        case "LOW":
            return `<span class="badge bg-success">LOW</span>`;
        case "MEDIUM":
            return `<span class="badge bg-warning text-dark">MEDIUM</span>`;
        case "HIGH":
            return `<span class="badge bg-warning text-dark fw-bold">HIGH</span>`;
        case "CRITICAL":
            return `<span class="badge bg-danger fw-bold">CRITICAL</span>`;
        default:
            return `<span class="badge bg-secondary">${escapeHTML(risk || 'LOW')}</span>`;
    }
}

function escapeHTML(str) {
    if (!str) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}