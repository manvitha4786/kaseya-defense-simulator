
const API_BASE = "/api";

const stages = [
  "Initial Access",
  "Server Compromise",
  "Suspicious Command",
  "Remote Deployment",
  "Multiple Endpoints",
  "Ransomware-like Activity"
];

// ==========================================
// GLOBAL STATE
// ==========================================

let current = 0;
let score = 0;
let running = false;
let timer = null;
let riskHistory = [0];
let requestInProgress = false;

let simulationGeneration = 0;
let historyRequestId = 0;
let detailsRequestId = 0;
let alertsRequestId = 0;
let logsRequestId = 0;

let savedSecurityLogs = [];

// ==========================================
// DOM ELEMENTS
// ==========================================

const stageList = document.getElementById("stageList");
const eventTable = document.getElementById("eventTable");
const startBtn = document.getElementById("startBtn");
const resetBtn = document.getElementById("resetBtn");
const eventCount = document.getElementById("eventCount");

const dashboardPage = document.getElementById("dashboardPage");
const historyPage = document.getElementById("historyPage");
const alertsPage = document.getElementById("alertsPage");
const logsPage = document.getElementById("logsPage");

const historyTableBody =
  document.getElementById("historyTableBody");

const historyDetails =
  document.getElementById("historyDetails");

const historyEventsBody =
  document.getElementById("historyEventsBody");

const alertsTableBody =
  document.getElementById("alertsTableBody");

const logsTableBody =
  document.getElementById("logsTableBody");

const logsSearch =
  document.getElementById("logsSearch");

const logsSeverityFilter =
  document.getElementById("logsSeverityFilter");

const logsSimulationFilter =
  document.getElementById("logsSimulationFilter");

// ==========================================
// UTILITY FUNCTIONS
// ==========================================

function refreshIcons() {
  if (window.lucide) {
    lucide.createIcons();
  }
}

function escapeHTML(value) {
  return String(value ?? "").replace(/[&<>"']/g, char => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[char]);
}

function formatDate(value) {
  if (!value) return "N/A";

  const date = new Date(value);

  return Number.isNaN(date.getTime())
    ? "N/A"
    : date.toLocaleString();
}

function threatInfo(value) {
  if (value < 30) return ["LOW", "green"];
  if (value < 60) return ["MEDIUM", "orange"];
  if (value < 80) return ["HIGH", "orange"];
  return ["CRITICAL", "red"];
}

function severityClass(value) {
  const severity = String(value || "LOW").toUpperCase();

  return ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    .includes(severity)
      ? severity.toLowerCase()
      : "low";
}

function historyRiskClass(value) {
  const threat = String(value || "LOW").toUpperCase();

  if (threat === "CRITICAL") {
    return "history-risk-critical";
  }

  if (threat === "HIGH" || threat === "MEDIUM") {
    return "history-risk-high";
  }

  return "history-risk-low";
}

function historyStatusClass(value) {
  const status = String(value || "").toLowerCase();

  return ["completed", "running", "reset", "interrupted"]
    .includes(status)
      ? status
      : "unknown";
}

function alertStatusClass(value) {
  const status = String(value || "NEW").toUpperCase();

  return ["NEW", "ACKNOWLEDGED", "RESOLVED"]
    .includes(status)
      ? status.toLowerCase()
      : "new";
}

function setStartButton(label, iconName) {
  startBtn.innerHTML =
    `<i data-lucide="${iconName}"></i>${escapeHTML(label)}`;

  refreshIcons();
}

async function apiRequest(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, options);

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));

    throw new Error(
      error.error || `HTTP ${response.status}`
    );
  }

  return response.json();
}

// ==========================================
// ATTACK STAGES
// ==========================================

function renderStages() {
  stageList.innerHTML = stages.map((stage, i) => {
    let cls = "";
    let status = "→ Pending";

    if (i < current) {
      cls = "done";
      status = "✓ Completed";
    } else if (i === current && running) {
      cls = "active";
      status = "→ In Progress";
    }

    return `
      <div class="stage ${cls}">
        <div class="stage-number">${i + 1}</div>

        <div class="stage-text">
          <strong>${escapeHTML(stage)}</strong>
        </div>

        <div class="stage-status">${status}</div>
      </div>
    `;
  }).join("");
}

// ==========================================
// ATTACK PROPAGATION MAP
// ==========================================

function updatePropagationMap(progress) {
  const server =
    document.querySelector(".server-node.central");

  const clientA =
    document.querySelector(".client-a");

  const clientB =
    document.querySelector(".client-b");

  const clientC =
    document.querySelector(".client-c");

  if (!server || !clientA || !clientB || !clientC) {
    return;
  }

  [server, clientA, clientB, clientC].forEach(node => {
    node.classList.remove("compromised", "at-risk");
  });

  if (progress >= 1) {
    server.classList.add("at-risk");
  }

  if (progress >= 2) {
    server.classList.remove("at-risk");
    server.classList.add("compromised");
  }

  if (progress >= 3) {
    clientA.classList.add("at-risk");
  }

  if (progress >= 4) {
    clientB.classList.add("at-risk");
  }

  if (progress >= 5) {
    clientA.classList.remove("at-risk");
    clientB.classList.remove("at-risk");

    clientA.classList.add("compromised");
    clientB.classList.add("compromised");
    clientC.classList.add("at-risk");
  }

  if (progress >= 6) {
    clientC.classList.remove("at-risk");
    clientC.classList.add("compromised");
  }
}

// ==========================================
// RISK SCORE AND AI PANEL
// ==========================================

function updateRiskUI() {
  const [level, tone] = threatInfo(score);

  document.getElementById("smallRisk").textContent =
    score;

  document.getElementById("smallRiskBar").style.width =
    `${score}%`;

  document.getElementById("threatLevel").textContent =
    level;

  document.getElementById("threatLevel").className =
    tone === "green"
      ? "green-text"
      : `risk-text-${tone}`;

  document.getElementById("threatBar").style.width =
    `${score}%`;

  document.getElementById("gaugeValue").innerHTML =
    `${score}<small>/ 100</small>`;

  document.getElementById("gaugeThreat").textContent =
    level;

  document.getElementById("aiBadge").textContent =
    `${level.charAt(0) + level.slice(1).toLowerCase()} Risk`;

  const reasons = [];

  if (score >= 10) {
    reasons.push("Unusual administrative activity");
  }

  if (score >= 25) {
    reasons.push("Management server anomaly detected");
  }

  if (score >= 40) {
    reasons.push("Suspicious command execution");
  }

  if (score >= 60) {
    reasons.push("Unexpected software deployment");
  }

  if (score >= 75) {
    reasons.push("Multiple endpoints contacted");
  }

  if (score >= 100) {
    reasons.push("Mass file modifications detected");
  }

  document.getElementById("reasonList").innerHTML =
    reasons.length
      ? reasons.map(reason =>
          `<li>${escapeHTML(reason)}</li>`
        ).join("")
      : "<li>Waiting for simulation events</li>";
}

// ==========================================
// LIVE SECURITY EVENT TABLE
// ==========================================

function addEvent(event) {
  const now = new Date().toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit"
  });

  if (current === 1) {
    eventTable.innerHTML = "";
  }

  const severity =
    String(event.severity || "LOW").toUpperCase();

  const cls = severityClass(severity);

  const row = document.createElement("tr");

  row.innerHTML = `
    <td>
      <span class="event-dot ${cls}"></span>
      ${escapeHTML(now)}
    </td>

    <td>${escapeHTML(event.name)}</td>

    <td>${escapeHTML(event.source)}</td>

    <td>
      <span class="severity ${cls}">
        ${escapeHTML(severity)}
      </span>
    </td>
  `;

  eventTable.prepend(row);
}

// ==========================================
// ATTACK TIMELINE CHART
// ==========================================

const chart = new Chart(
  document.getElementById("riskChart"),
  {
    type: "line",

    data: {
      labels: ["Start"],

      datasets: [{
        data: [0],
        borderColor: "#ff3b65",
        backgroundColor: "rgba(255,59,101,.22)",
        fill: true,
        tension: 0.35,
        pointRadius: 3,
        pointBackgroundColor: "#ff3b65"
      }]
    },

    options: {
      responsive: true,
      maintainAspectRatio: false,

      plugins: {
        legend: {
          display: false
        }
      },

      scales: {
        x: {
          grid: {
            color: "rgba(38,91,130,.25)"
          },

          ticks: {
            color: "#7fa8ce",
            font: { size: 9 }
          }
        },

        y: {
          min: 0,
          max: 100,

          grid: {
            color: "rgba(38,91,130,.25)"
          },

          ticks: {
            color: "#7fa8ce",
            font: { size: 9 }
          }
        }
      }
    }
  }
);

function updateChart() {
  chart.data.labels = riskHistory.map((_, i) =>
    i === 0 ? "Start" : `Event ${i}`
  );

  chart.data.datasets[0].data = riskHistory;

  chart.update();
}

// ==========================================
// START SIMULATION
// ==========================================

async function startSimulation() {
  const generation = ++simulationGeneration;

  clearInterval(timer);

  timer = null;
  running = true;
  requestInProgress = false;

  startBtn.disabled = true;

  setStartButton("Starting...", "loader-circle");

  try {
    await apiRequest("/simulation/start", {
      method: "POST"
    });

    if (generation !== simulationGeneration) {
      return;
    }

    current = 0;
    score = 0;
    riskHistory = [0];

    eventCount.textContent = "0";

    eventTable.innerHTML = `
      <tr>
        <td colspan="4" class="empty">
          Waiting for security events...
        </td>
      </tr>
    `;

    updatePropagationMap(0);
    updateChart();
    updateRiskUI();
    renderStages();

    setStartButton("Running...", "loader-circle");

    await processNext(generation);

    if (running && generation === simulationGeneration) {
      timer = setInterval(() => {
        if (running && !requestInProgress) {
          processNext(generation);
        }
      }, 1500);
    }

  } catch (error) {
    if (generation !== simulationGeneration) {
      return;
    }

    console.error("Simulation start error:", error);

    running = false;

    clearInterval(timer);
    timer = null;

    setStartButton("Connection Error", "alert-circle");

    alert(
      "Unable to start simulation: " + error.message
    );

  } finally {
    if (generation === simulationGeneration) {
      startBtn.disabled = false;
    }
  }
}

// ==========================================
// PROCESS NEXT SIMULATION EVENT
// ==========================================

async function processNext(
  generation = simulationGeneration
) {
  if (!running || requestInProgress) {
    return;
  }

  requestInProgress = true;

  try {
    const data = await apiRequest(
      "/simulation/next",
      { method: "POST" }
    );

    if (generation !== simulationGeneration) {
      return;
    }

    if (data.completed) {
      running = false;

      clearInterval(timer);
      timer = null;

      setStartButton(
        "Simulation Complete",
        "check-circle"
      );

      renderStages();
      return;
    }

    current = Number(data.progress) || 0;
    score = Number(data.risk_score) || 0;

    eventCount.textContent = current;

    addEvent(data.event);

    riskHistory.push(score);

    updatePropagationMap(current);
    updateChart();
    updateRiskUI();
    renderStages();

    if (current >= stages.length) {
      running = false;

      clearInterval(timer);
      timer = null;

      setStartButton(
        "Simulation Complete",
        "check-circle"
      );

      renderStages();
    }

  } catch (error) {
    if (generation !== simulationGeneration) {
      return;
    }

    console.error("Simulation event error:", error);

    running = false;

    clearInterval(timer);
    timer = null;

    setStartButton(
      "Connection Error",
      "alert-circle"
    );

  } finally {
    if (generation === simulationGeneration) {
      requestInProgress = false;
    }
  }
}

// ==========================================
// RESET SIMULATION
// ==========================================

async function resetSimulation() {
  const generation = ++simulationGeneration;

  clearInterval(timer);

  timer = null;
  running = false;
  requestInProgress = false;

  resetBtn.disabled = true;

  try {
    await apiRequest("/simulation/reset", {
      method: "POST"
    });

    if (generation !== simulationGeneration) {
      return;
    }

    current = 0;
    score = 0;
    riskHistory = [0];

    eventCount.textContent = "0";

    eventTable.innerHTML = `
      <tr>
        <td colspan="4" class="empty">
          No events detected yet.
        </td>
      </tr>
    `;

    updatePropagationMap(0);
    updateChart();
    renderStages();
    updateRiskUI();

    setStartButton(
      "Start Simulation",
      "play"
    );

  } catch (error) {
    console.error("Reset error:", error);

    alert("Reset failed: " + error.message);

    setStartButton(
      "Start Simulation",
      "play"
    );

  } finally {
    resetBtn.disabled = false;
  }
}

startBtn.addEventListener("click", async () => {
  if (running) return;

  if (current >= stages.length) {
    await resetSimulation();
  }

  if (!running) {
    await startSimulation();
  }
});

resetBtn.addEventListener(
  "click",
  resetSimulation
);

// ==========================================
// SIMULATION HISTORY
// ==========================================

async function loadSimulationHistory() {
  const requestId = ++historyRequestId;

  historyTableBody.innerHTML = `
    <tr>
      <td colspan="7" class="empty">
        Loading history...
      </td>
    </tr>
  `;

  try {
    const data = await apiRequest("/simulations", {
      cache: "no-store"
    });

    if (requestId !== historyRequestId) {
      return;
    }

    const simulations =
      Array.isArray(data.simulations)
        ? data.simulations
        : [];

    document.getElementById(
      "totalSimulations"
    ).textContent = simulations.length;

    document.getElementById(
      "completedSimulations"
    ).textContent = simulations.filter(
      s => s.status === "COMPLETED"
    ).length;

    document.getElementById(
      "totalSavedEvents"
    ).textContent = simulations.reduce(
      (total, s) =>
        total + (Number(s.event_count) || 0),
      0
    );

    if (!simulations.length) {
      historyTableBody.innerHTML = `
        <tr>
          <td colspan="7" class="empty">
            No simulation history available.
          </td>
        </tr>
      `;
      return;
    }

    historyTableBody.innerHTML =
      simulations.map(sim => {
        const id = Number(sim.id);

        const threat =
          String(sim.final_threat_level || "LOW");

        return `
          <tr>
            <td>#${escapeHTML(sim.id)}</td>

            <td>
              ${escapeHTML(
                formatDate(sim.started_at)
              )}
            </td>

            <td>
              <span class="history-status ${
                historyStatusClass(sim.status)
              }">
                ${escapeHTML(sim.status)}
              </span>
            </td>

            <td class="${historyRiskClass(threat)}">
              ${escapeHTML(
                sim.final_risk_score
              )} / 100
            </td>

            <td class="${historyRiskClass(threat)}">
              ${escapeHTML(threat)}
            </td>

            <td>
              ${escapeHTML(sim.event_count)}
            </td>

            <td>
              <button
                class="history-view-btn"
                data-simulation-id="${
                  Number.isSafeInteger(id) ? id : 0
                }">
                View Details
              </button>
            </td>
          </tr>
        `;
      }).join("");

  } catch (error) {
    if (requestId !== historyRequestId) {
      return;
    }

    console.error(
      "History loading error:",
      error
    );

    historyTableBody.innerHTML = `
      <tr>
        <td colspan="7" class="empty">
          Unable to load simulation history.
        </td>
      </tr>
    `;
  }
}

// ==========================================
// SIMULATION DETAILS
// ==========================================

async function viewSimulationDetails(id) {
  const requestId = ++detailsRequestId;

  historyDetails.hidden = false;

  document.getElementById(
    "historyDetailsTitle"
  ).textContent = `Simulation #${id} Details`;

  document.getElementById(
    "historyDetailInfo"
  ).innerHTML = "";

  historyEventsBody.innerHTML = `
    <tr>
      <td colspan="6" class="empty">
        Loading events...
      </td>
    </tr>
  `;

  try {
    const simulation = await apiRequest(
      `/simulations/${id}`,
      { cache: "no-store" }
    );

    if (
      requestId !== detailsRequestId ||
      historyDetails.hidden
    ) {
      return;
    }

    const events = Array.isArray(simulation.events)
      ? simulation.events
      : [];

    document.getElementById(
      "historyDetailInfo"
    ).innerHTML = `
      <span>
        Status:
        <strong>${escapeHTML(simulation.status)}</strong>
      </span>

      <span>
        Started:
        <strong>${escapeHTML(
          formatDate(simulation.started_at)
        )}</strong>
      </span>

      <span>
        Ended:
        <strong>${escapeHTML(
          formatDate(simulation.ended_at)
        )}</strong>
      </span>

      <span>
        Final Risk:
        <strong>${escapeHTML(
          simulation.final_risk_score
        )} / 100</strong>
      </span>

      <span>
        Threat:
        <strong>${escapeHTML(
          simulation.final_threat_level
        )}</strong>
      </span>

      <span>
        Events:
        <strong>${events.length}</strong>
      </span>
    `;

    if (!events.length) {
      historyEventsBody.innerHTML = `
        <tr>
          <td colspan="6" class="empty">
            No security events saved for this simulation.
          </td>
        </tr>
      `;
      return;
    }

    historyEventsBody.innerHTML =
      events.map(item => `
        <tr>
          <td>${escapeHTML(
            formatDate(item.timestamp)
          )}</td>

          <td>${escapeHTML(item.event_name)}</td>

          <td>${escapeHTML(item.source)}</td>

          <td>
            <span class="severity ${
              severityClass(item.severity)
            }">
              ${escapeHTML(item.severity)}
            </span>
          </td>

          <td>
            ${escapeHTML(item.risk_score)} / 100
          </td>

          <td class="${
            historyRiskClass(item.threat_level)
          }">
            ${escapeHTML(item.threat_level)}
          </td>
        </tr>
      `).join("");

  } catch (error) {
    if (requestId !== detailsRequestId) {
      return;
    }

    console.error(
      "Simulation details error:",
      error
    );

    historyEventsBody.innerHTML = `
      <tr>
        <td colspan="6" class="empty">
          Unable to load saved events.
        </td>
      </tr>
    `;
  }
}

historyTableBody.addEventListener(
  "click",
  event => {
    const button = event.target.closest(
      "[data-simulation-id]"
    );

    if (!button) return;

    const id = Number(
      button.dataset.simulationId
    );

    if (!Number.isSafeInteger(id) || id <= 0) {
      return;
    }

    viewSimulationDetails(id);

    historyDetails.scrollIntoView({
      behavior: "smooth",
      block: "start"
    });
  }
);

document.getElementById(
  "refreshHistoryBtn"
).addEventListener(
  "click",
  loadSimulationHistory
);

document.getElementById(
  "closeHistoryDetails"
).addEventListener("click", () => {
  detailsRequestId++;
  historyDetails.hidden = true;
});

// ==========================================
// SECURITY ALERTS
// ==========================================

async function loadSecurityAlerts() {
  const requestId = ++alertsRequestId;

  alertsTableBody.innerHTML = `
    <tr>
      <td colspan="9" class="empty">
        Loading security alerts...
      </td>
    </tr>
  `;

  try {
    const data = await apiRequest("/alerts", {
      cache: "no-store"
    });

    if (requestId !== alertsRequestId) {
      return;
    }

    const alerts = Array.isArray(data.alerts)
      ? data.alerts
      : [];

    document.getElementById(
      "alertsTotal"
    ).textContent = alerts.length;

    document.getElementById(
      "alertsHigh"
    ).textContent = alerts.filter(
      a => a.severity === "HIGH"
    ).length;

    document.getElementById(
      "alertsMedium"
    ).textContent = alerts.filter(
      a => a.severity === "MEDIUM"
    ).length;

    const alertBadge =
      document.getElementById("alertBadge");

    if (alertBadge) {
      alertBadge.textContent = alerts.filter(
        a => a.status !== "RESOLVED"
      ).length;
    }

    if (!alerts.length) {
      alertsTableBody.innerHTML = `
        <tr>
          <td colspan="9" class="empty">
            No security alerts detected.
          </td>
        </tr>
      `;
      return;
    }

    alertsTableBody.innerHTML =
      alerts.map(item => {
        const status =
          String(item.status || "NEW").toUpperCase();

        const severity =
          String(item.severity || "LOW").toUpperCase();

        const id = Number(item.id);

        const safeId =
          Number.isSafeInteger(id) && id > 0
            ? id
            : 0;

        let action = "";

        if (status === "NEW") {
          action = `
            <button
              class="alert-action-btn"
              data-alert-id="${safeId}"
              data-new-status="ACKNOWLEDGED">
              Acknowledge
            </button>
          `;

        } else if (status === "ACKNOWLEDGED") {
          action = `
            <button
              class="alert-action-btn resolve"
              data-alert-id="${safeId}"
              data-new-status="RESOLVED">
              Resolve
            </button>
          `;

        } else {
          action = `
            <span class="alert-complete">
              ✓ Resolved
            </span>
          `;
        }

        return `
          <tr>
            <td>#${escapeHTML(item.id)}</td>

            <td>${escapeHTML(
              formatDate(item.timestamp)
            )}</td>

            <td>${escapeHTML(item.title)}</td>

            <td>${escapeHTML(item.source)}</td>

            <td>
              <span class="severity ${
                severityClass(severity)
              }">
                ${escapeHTML(severity)}
              </span>
            </td>

            <td class="${
              historyRiskClass(item.threat_level)
            }">
              ${escapeHTML(item.threat_level)}
            </td>

            <td>
              #${escapeHTML(item.simulation_id)}
            </td>

            <td>
              <span class="alert-status ${
                alertStatusClass(status)
              }">
                ${escapeHTML(status)}
              </span>
            </td>

            <td>${action}</td>
          </tr>
        `;
      }).join("");

  } catch (error) {
    if (requestId !== alertsRequestId) {
      return;
    }

    console.error(
      "Alerts loading error:",
      error
    );

    alertsTableBody.innerHTML = `
      <tr>
        <td colspan="9" class="empty">
          Unable to load security alerts.
        </td>
      </tr>
    `;
  }
}

// ==========================================
// ACKNOWLEDGE AND RESOLVE ALERTS
// ==========================================

async function changeAlertStatus(
  id,
  newStatus,
  button
) {
  if (button.disabled) {
    return;
  }

  button.disabled = true;
  button.textContent = "Updating...";

  try {
    await apiRequest(
      `/alerts/${id}/status`,
      {
        method: "PATCH",

        headers: {
          "Content-Type": "application/json"
        },

        body: JSON.stringify({
          status: newStatus
        })
      }
    );

    await loadSecurityAlerts();

  } catch (error) {
    console.error(
      "Alert update error:",
      error
    );

    alert(
      "Unable to update alert: " + error.message
    );

    button.disabled = false;

    button.textContent =
      newStatus === "ACKNOWLEDGED"
        ? "Acknowledge"
        : "Resolve";
  }
}

alertsTableBody.addEventListener(
  "click",
  event => {
    const button = event.target.closest(
      "[data-alert-id][data-new-status]"
    );

    if (!button) return;

    const id = Number(
      button.dataset.alertId
    );

    const status =
      button.dataset.newStatus;

    if (!Number.isSafeInteger(id) || id <= 0) {
      return;
    }

    if (
      !["ACKNOWLEDGED", "RESOLVED"]
        .includes(status)
    ) {
      return;
    }

    changeAlertStatus(
      id,
      status,
      button
    );
  }
);

document.getElementById(
  "refreshAlertsBtn"
).addEventListener(
  "click",
  loadSecurityAlerts
);

// ==========================================
// SECURITY LOGS PAGE
// ==========================================

async function loadSecurityLogs() {
  const requestId = ++logsRequestId;

  logsTableBody.innerHTML = `
    <tr>
      <td colspan="8" class="empty">
        Loading security logs...
      </td>
    </tr>
  `;

  try {
    const data = await apiRequest("/events", {
      cache: "no-store"
    });

    if (requestId !== logsRequestId) {
      return;
    }

    savedSecurityLogs =
      Array.isArray(data.events)
        ? data.events
        : [];

    // Total events
    document.getElementById(
      "logsTotal"
    ).textContent = savedSecurityLogs.length;

    // High severity events
    document.getElementById(
      "logsHigh"
    ).textContent =
      savedSecurityLogs.filter(event =>
        ["HIGH", "CRITICAL"].includes(
          String(event.severity || "")
            .toUpperCase()
        )
      ).length;

    // Unique simulations
    const simulationIds = [
      ...new Set(
        savedSecurityLogs.map(event =>
          String(event.simulation_id)
        )
      )
    ];

    document.getElementById(
      "logsSimulations"
    ).textContent = simulationIds.length;

    const previousSelection =
      logsSimulationFilter.value;

    logsSimulationFilter.innerHTML = `
      <option value="ALL">
        All Simulations
      </option>

      ${simulationIds.map(id => `
        <option value="${escapeHTML(id)}">
          Simulation #${escapeHTML(id)}
        </option>
      `).join("")}
    `;

    if (simulationIds.includes(previousSelection)) {
      logsSimulationFilter.value =
        previousSelection;
    }

    renderSecurityLogs();

  } catch (error) {
    if (requestId !== logsRequestId) {
      return;
    }

    console.error(
      "Logs loading error:",
      error
    );

    logsTableBody.innerHTML = `
      <tr>
        <td colspan="8" class="empty">
          Unable to load security logs.
        </td>
      </tr>
    `;
  }
}

// ==========================================
// SEARCH AND FILTER SECURITY LOGS
// ==========================================

function renderSecurityLogs() {
  const query =
    logsSearch.value.trim().toLowerCase();

  const severity =
    logsSeverityFilter.value;

  const simulation =
    logsSimulationFilter.value;

  const filtered =
    savedSecurityLogs.filter(event => {
      const eventSeverity =
        String(event.severity || "LOW")
          .toUpperCase();

      const matchesSearch =
        String(event.event_name || "")
          .toLowerCase()
          .includes(query) ||

        String(event.source || "")
          .toLowerCase()
          .includes(query);

      const matchesSeverity =
        severity === "ALL" ||
        eventSeverity === severity;

      const matchesSimulation =
        simulation === "ALL" ||
        String(event.simulation_id) === simulation;

      return (
        matchesSearch &&
        matchesSeverity &&
        matchesSimulation
      );
    });

  document.getElementById(
    "logsResultCount"
  ).textContent = `${filtered.length} results`;

  if (!filtered.length) {
    logsTableBody.innerHTML = `
      <tr>
        <td colspan="8" class="empty">
          No matching security logs found.
        </td>
      </tr>
    `;
    return;
  }

  logsTableBody.innerHTML =
    filtered.map(event => `
      <tr>
        <td>
          #${escapeHTML(event.id)}
        </td>

        <td>
          ${escapeHTML(
            formatDate(event.timestamp)
          )}
        </td>

        <td>
          ${escapeHTML(event.event_name)}
        </td>

        <td>
          ${escapeHTML(event.source)}
        </td>

        <td>
          <span class="severity ${
            severityClass(event.severity)
          }">
            ${escapeHTML(event.severity)}
          </span>
        </td>

        <td>
          ${escapeHTML(event.risk_score)} / 100
        </td>

        <td class="${
          historyRiskClass(event.threat_level)
        }">
          ${escapeHTML(event.threat_level)}
        </td>

        <td>
          #${escapeHTML(event.simulation_id)}
        </td>
      </tr>
    `).join("");
}

logsSearch.addEventListener(
  "input",
  renderSecurityLogs
);

logsSeverityFilter.addEventListener(
  "change",
  renderSecurityLogs
);

logsSimulationFilter.addEventListener(
  "change",
  renderSecurityLogs
);

document.getElementById(
  "refreshLogsBtn"
).addEventListener(
  "click",
  loadSecurityLogs
);

// ==========================================
// PAGE NAVIGATION - CORRECTED
// ==========================================

function navigateToPage() {
  const hash =
    window.location.hash || "#dashboard";

  const showHistory =
    hash === "#history";

  const showAlerts =
    hash === "#alerts";

  const showLogs =
    hash === "#logs";

  // Hide dashboard when another page is open
  dashboardPage.hidden =
    showHistory || showAlerts || showLogs;

  // Show selected page
  historyPage.hidden = !showHistory;
  alertsPage.hidden = !showAlerts;
  logsPage.hidden = !showLogs;

  // Highlight selected sidebar item
  document.querySelectorAll(
    ".side-nav .nav-item"
  ).forEach(link => {
    link.classList.toggle(
      "active",
      link.getAttribute("href") === hash
    );
  });

  // Load page data
  if (showHistory) {
    loadSimulationHistory();
    window.scrollTo(0, 0);

  } else if (showAlerts) {
    loadSecurityAlerts();
    window.scrollTo(0, 0);

  } else if (showLogs) {
    loadSecurityLogs();
    window.scrollTo(0, 0);

  } else {
    requestAnimationFrame(() => {
      chart.resize();
    });

    if (hash !== "#dashboard") {
      const target =
        document.getElementById(
          hash.slice(1)
        );

      if (target) {
        requestAnimationFrame(() => {
          target.scrollIntoView({
            behavior: "smooth"
          });
        });
      }
    }
  }
}

window.addEventListener(
  "hashchange",
  navigateToPage
);

// ==========================================
// LIVE CLOCK
// ==========================================

function updateClock() {
  const now = new Date();

  document.getElementById(
    "clock"
  ).textContent = now.toLocaleTimeString();

  const clockDate =
    document.getElementById("clockDate");

  if (clockDate) {
    clockDate.textContent =
      now.toLocaleDateString([], {
        year: "numeric",
        month: "short",
        day: "numeric"
      });
  }
}

setInterval(updateClock, 1000);

// ==========================================
// INITIALIZATION
// ==========================================

renderStages();
updateRiskUI();
updatePropagationMap(0);
updateClock();
refreshIcons();
navigateToPage();


/* ==========================================
   AI THREAT ANALYSIS MODULE
   Explainable rule-based security assessment
========================================== */

let analysisRequestId = 0;
let analysisSimulations = [];

const analysisPage =
  document.getElementById("analysisPage");

const analysisSimulationSelect =
  document.getElementById("analysisSimulationSelect");

const analysisEventsBody =
  document.getElementById("analysisEventsBody");

const analysisIndicators =
  document.getElementById("analysisIndicators");

const analysisRecommendations =
  document.getElementById("analysisRecommendations");

// Explainable detection rules
const threatRules = [
  {
    match: /administrator login/i,
    title: "Unusual Administrative Login",
    explanation:
      "An unexpected administrator login may indicate compromised credentials or unauthorized privileged access.",
    recommendation:
      "Verify the login source, review authentication logs, and reset credentials if unauthorized."
  },
  {
    match: /server activity anomaly/i,
    title: "Management Server Anomaly",
    explanation:
      "Abnormal activity on the management server may indicate suspicious access or unauthorized operations.",
    recommendation:
      "Investigate server logs, validate active sessions, and inspect recent configuration changes."
  },
  {
    match: /command execution/i,
    title: "Suspicious Command Execution",
    explanation:
      "Unexpected commands may indicate an attacker attempting to execute unauthorized operations.",
    recommendation:
      "Review command execution records, investigate affected accounts, and restrict unnecessary privileges."
  },
  {
    match: /software deployment/i,
    title: "Unexpected Software Deployment",
    explanation:
      "Unapproved software deployment through a management platform can distribute malicious files across managed systems.",
    recommendation:
      "Suspend suspicious deployments, verify software packages, and isolate affected endpoints."
  },
  {
    match: /multiple endpoints contacted/i,
    title: "Potential Lateral Propagation",
    explanation:
      "Communication with multiple endpoints may indicate an attempt to spread malicious activity across the network.",
    recommendation:
      "Inspect endpoint connections, segment affected systems, and investigate suspicious network traffic."
  },
  {
    match: /mass file modification/i,
    title: "Possible Ransomware Activity",
    explanation:
      "Rapid modification of many files is consistent with a potential ransomware-like attack pattern.",
    recommendation:
      "Isolate affected endpoints, preserve forensic evidence, and verify clean offline backups."
  }
];

function getThreatRule(eventName) {
  return threatRules.find(rule =>
    rule.match.test(String(eventName || ""))
  );
}

function analysisThreatClass(level) {
  const value = String(level || "LOW").toUpperCase();

  if (value === "CRITICAL") return "critical";
  if (value === "HIGH") return "high";
  if (value === "MEDIUM") return "medium";

  return "low";
}

function updateAnalysisRisk(score, level) {
  const safeScore = Math.max(
    0,
    Math.min(100, Number(score) || 0)
  );

  const safeLevel = String(level || "LOW").toUpperCase();

  document.getElementById("analysisRiskScore").textContent =
    `${safeScore} / 100`;

  document.getElementById("analysisThreatLevel").textContent =
    safeLevel;

  const badge = document.getElementById("analysisRiskBadge");

  badge.textContent = safeLevel;
  badge.className =
    `analysis-risk-badge ${analysisThreatClass(safeLevel)}`;

  const bar = document.getElementById("analysisRiskBar");

  bar.style.width = `${safeScore}%`;
  bar.className = analysisThreatClass(safeLevel);
}

function resetAnalysisDisplay(message) {
  updateAnalysisRisk(0, "LOW");

  document.getElementById("analysisIndicatorCount").textContent =
    "0";

  document.getElementById("analysisSummary").textContent =
    message;

  analysisIndicators.innerHTML =
    `<p class="analysis-empty">${escapeHTML(message)}</p>`;

  analysisRecommendations.innerHTML =
    `<p class="analysis-empty">No recommendations available.</p>`;

  analysisEventsBody.innerHTML = `
    <tr>
      <td colspan="5" class="empty">
        ${escapeHTML(message)}
      </td>
    </tr>
  `;
}

async function loadAIAnalysis() {
  const requestId = ++analysisRequestId;

  resetAnalysisDisplay("Loading saved simulations...");

  try {
    const data = await apiRequest("/simulations", {
      cache: "no-store"
    });

    if (requestId !== analysisRequestId) return;

    analysisSimulations = Array.isArray(data.simulations)
      ? data.simulations
      : [];

    const previousSelection =
      analysisSimulationSelect.value;

    analysisSimulationSelect.innerHTML = "";

    if (!analysisSimulations.length) {
      analysisSimulationSelect.innerHTML =
        `<option value="">No simulations available</option>`;

      resetAnalysisDisplay(
        "Run a simulation first to generate a threat assessment."
      );
      return;
    }

    analysisSimulations.forEach(simulation => {
      const option = document.createElement("option");

      option.value = String(simulation.id);
      option.textContent =
        `Simulation #${simulation.id} — ${simulation.status}`;

      analysisSimulationSelect.appendChild(option);
    });

    const selectionExists = analysisSimulations.some(
      sim => String(sim.id) === previousSelection
    );

    if (selectionExists) {
      analysisSimulationSelect.value = previousSelection;
    } else {
      const preferred =
        analysisSimulations.find(sim =>
          sim.status === "COMPLETED"
        ) || analysisSimulations[0];

      analysisSimulationSelect.value =
        String(preferred.id);
    }

    await analyzeSelectedSimulation();

  } catch (error) {
    if (requestId !== analysisRequestId) return;

    console.error("AI Analysis loading error:", error);

    resetAnalysisDisplay(
      "Unable to load simulation data."
    );
  }
}

async function analyzeSelectedSimulation() {
  const id = Number(analysisSimulationSelect.value);

  if (!Number.isSafeInteger(id) || id <= 0) {
    resetAnalysisDisplay("Select a valid simulation.");
    return;
  }

  const requestId = ++analysisRequestId;

  resetAnalysisDisplay("Analyzing security events...");

  try {
    const simulation = await apiRequest(
      `/simulations/${id}`,
      { cache: "no-store" }
    );

    if (requestId !== analysisRequestId) return;

    const events = Array.isArray(simulation.events)
      ? simulation.events
      : [];

    const riskScore =
      Number(simulation.final_risk_score) || 0;

    const threatLevel =
      simulation.final_threat_level || "LOW";

    updateAnalysisRisk(riskScore, threatLevel);

    const detectedRules = [];

    events.forEach(event => {
      const rule = getThreatRule(event.event_name);

      if (
        rule &&
        !detectedRules.some(item => item.title === rule.title)
      ) {
        detectedRules.push(rule);
      }
    });

    document.getElementById(
      "analysisIndicatorCount"
    ).textContent = detectedRules.length;

    // Summary
    let summary;

    if (!events.length) {
      summary =
        "This simulation contains no recorded security events. " +
        "There is insufficient evidence for a threat assessment.";

    } else if (riskScore >= 80) {
      summary =
        "Critical risk detected. The simulated attack chain " +
        "indicates severe security compromise and potential " +
        "ransomware-like activity. Immediate containment is recommended.";

    } else if (riskScore >= 60) {
      summary =
        "High risk detected. Suspicious activities indicate " +
        "possible unauthorized operations and endpoint exposure.";

    } else if (riskScore >= 30) {
      summary =
        "Moderate risk detected. Security anomalies require " +
        "investigation before further escalation.";

    } else {
      summary =
        "Low accumulated risk. Review the recorded events " +
        "and continue monitoring for suspicious activity.";
    }

    document.getElementById(
      "analysisSummary"
    ).textContent = summary;

    // Detected indicators
    if (detectedRules.length) {
      analysisIndicators.innerHTML =
        detectedRules.map(rule => `
          <div class="analysis-list-item">
            <span class="analysis-item-icon">
              <i data-lucide="alert-triangle"></i>
            </span>

            <div>
              <strong>${escapeHTML(rule.title)}</strong>
              <p>${escapeHTML(rule.explanation)}</p>
            </div>
          </div>
        `).join("");
    } else {
      analysisIndicators.innerHTML = `
        <p class="analysis-empty">
          No recognized attack indicators in the saved events.
        </p>
      `;
    }

    // Defensive recommendations
    const recommendations = [
      ...new Set(
        detectedRules.map(rule => rule.recommendation)
      )
    ];

    if (recommendations.length) {
      analysisRecommendations.innerHTML =
        recommendations.map((recommendation, index) => `
          <div class="analysis-list-item">
            <span class="analysis-step-number">
              ${index + 1}
            </span>

            <div>
              <p>${escapeHTML(recommendation)}</p>
            </div>
          </div>
        `).join("");
    } else {
      analysisRecommendations.innerHTML = `
        <p class="analysis-empty">
          No event-specific defensive actions identified.
        </p>
      `;
    }

    // Event explanations
    if (!events.length) {
      analysisEventsBody.innerHTML = `
        <tr>
          <td colspan="5" class="empty">
            No security events recorded for this simulation.
          </td>
        </tr>
      `;
    } else {
      analysisEventsBody.innerHTML =
        events.map(event => {
          const rule = getThreatRule(event.event_name);

          const explanation = rule
            ? rule.explanation
            : "Security event recorded. Further investigation may be required.";

          return `
            <tr>
              <td>${escapeHTML(event.event_name)}</td>

              <td>${escapeHTML(event.source)}</td>

              <td>
                <span class="severity ${
                  severityClass(event.severity)
                }">
                  ${escapeHTML(event.severity)}
                </span>
              </td>

              <td>
                ${escapeHTML(event.risk_score)} / 100
              </td>

              <td>${escapeHTML(explanation)}</td>
            </tr>
          `;
        }).join("");
    }

    refreshIcons();

  } catch (error) {
    if (requestId !== analysisRequestId) return;

    console.error("Simulation analysis error:", error);

    resetAnalysisDisplay(
      "Unable to analyze the selected simulation."
    );
  }
}

analysisSimulationSelect.addEventListener(
  "change",
  analyzeSelectedSimulation
);

document.getElementById("refreshAnalysisBtn")
  .addEventListener("click", loadAIAnalysis);

/* ==========================================
   AI ANALYSIS NAVIGATION INTEGRATION
========================================== */

// Extend the existing navigation without replacing
// Dashboard, History, Alerts or Logs logic.

const existingNavigateToPage = navigateToPage;

navigateToPage = function () {
  const hash = window.location.hash || "#dashboard";
  const showAnalysis = hash === "#analysis";

  if (showAnalysis) {
    dashboardPage.hidden = true;
    historyPage.hidden = true;
    alertsPage.hidden = true;
    logsPage.hidden = true;
    analysisPage.hidden = false;

    document.querySelectorAll(".side-nav .nav-item")
      .forEach(link => {
        link.classList.toggle(
          "active",
          link.getAttribute("href") === hash
        );
      });

    loadAIAnalysis();
    window.scrollTo(0, 0);
  } else {
    analysisPage.hidden = true;
    existingNavigateToPage();
  }
};

// Replace the previous hashchange listener with
// the extended navigation handler.
window.removeEventListener(
  "hashchange",
  existingNavigateToPage
);

window.addEventListener(
  "hashchange",
  navigateToPage
);

// Handle opening the page directly using #analysis.
navigateToPage();
