const form = document.querySelector("#analysisForm");
const textInput = document.querySelector("#textInput");
const sourceInput = document.querySelector("#sourceInput");
const urlInput = document.querySelector("#urlInput");
const textField = document.querySelector("#textField");
const urlField = document.querySelector("#urlField");
const textModeButton = document.querySelector("#textModeButton");
const urlModeButton = document.querySelector("#urlModeButton");
const analyzeButton = document.querySelector("#analyzeButton");
const sampleButton = document.querySelector("#sampleButton");
const clearButton = document.querySelector("#clearButton");
const requestState = document.querySelector("#requestState");
const charCounter = document.querySelector("#charCounter");
const riskMetric = document.querySelector("#riskMetric");
const scoreMetric = document.querySelector("#scoreMetric");
const wordMetric = document.querySelector("#wordMetric");
const signalMetric = document.querySelector("#signalMetric");
const riskPill = document.querySelector("#riskPill");
const scoreBlock = document.querySelector("#scoreBlock");
const scoreFill = document.querySelector("#scoreFill");
const dialScore = document.querySelector("#dialScore");
const recommendation = document.querySelector("#recommendation");
const thresholdValue = document.querySelector("#thresholdValue");
const signalsTable = document.querySelector("#signalsTable");
const dimensionGrid = document.querySelector("#dimensionGrid");
const profileGrid = document.querySelector("#profileGrid");
const sourceCard = document.querySelector("#sourceCard");
const sourceKind = document.querySelector("#sourceKind");
const sourceTitle = document.querySelector("#sourceTitle");
const sourceUrl = document.querySelector("#sourceUrl");

const sampleText =
  "This revolutionary solution leverages next-generation synergy to unlock unprecedented outcomes with no evidence provided. Experts agree it will always optimize every workflow, yet the report does not include dates, measurements, owner names, or source links.";

const riskLabels = {
  low: "Low",
  moderate: "Moderate",
  high: "High",
};

let inputMode = "text";

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatSignalName(name) {
  return name.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function formatPercent(value) {
  return `${Math.round((Number(value) || 0) * 100)}%`;
}

function safeHttpUrl(value) {
  if (typeof value !== "string" || value === "") {
    return null;
  }
  try {
    const parsed = new URL(value);
    if (parsed.protocol === "http:" || parsed.protocol === "https:") {
      return parsed.href;
    }
  } catch (_) {
    return null;
  }
  return null;
}

function setState(label, isBusy = false) {
  requestState.textContent = label;
  analyzeButton.disabled = isBusy;
}

function setMode(mode) {
  inputMode = mode;
  const isUrlMode = mode === "website";
  textField.hidden = isUrlMode;
  urlField.hidden = !isUrlMode;
  textInput.required = !isUrlMode;
  urlInput.required = isUrlMode;
  textModeButton.classList.toggle("active", !isUrlMode);
  urlModeButton.classList.toggle("active", isUrlMode);
  textModeButton.setAttribute("aria-selected", String(!isUrlMode));
  urlModeButton.setAttribute("aria-selected", String(isUrlMode));
  updateCounter();
  if (isUrlMode) {
    urlInput.focus();
  } else {
    textInput.focus();
  }
}

function updateCounter() {
  if (inputMode === "website") {
    charCounter.textContent = `${urlInput.value.length.toLocaleString()} URL chars`;
    return;
  }
  charCounter.textContent = `${textInput.value.length.toLocaleString()} chars`;
}

function setRiskClass(risk) {
  riskPill.className = `risk-pill ${risk || "neutral"}`;
  scoreBlock.dataset.risk = risk || "neutral";
}

function renderSignals(signals = []) {
  if (!signals.length) {
    signalsTable.innerHTML = '<tr><td colspan="5" class="empty-cell">No signals recorded.</td></tr>';
    return;
  }

  signalsTable.innerHTML = signals
    .map(
      (signal) => `
        <tr>
          <td>${escapeHtml(formatSignalName(signal.name))}</td>
          <td>${escapeHtml(formatSignalName(signal.category))}</td>
          <td>${Number(signal.weight).toFixed(2)}</td>
          <td>${Number(signal.count).toLocaleString()}</td>
          <td>${escapeHtml(signal.description)}</td>
        </tr>
      `,
    )
    .join("");
}

function renderDimensions(dimensions = []) {
  if (!dimensions.length) {
    dimensionGrid.innerHTML = '<div class="empty-block">No dimension scores.</div>';
    return;
  }

  dimensionGrid.innerHTML = dimensions
    .map(
      (dimension) => `
        <article class="dimension-card ${escapeHtml(dimension.status)}">
          <div>
            <span>${escapeHtml(dimension.name)}</span>
            <strong>${formatPercent(dimension.score)}</strong>
          </div>
          <div class="dimension-track" aria-hidden="true">
            <div style="width: ${formatPercent(dimension.score)}"></div>
          </div>
          <small>${escapeHtml(dimension.status)}</small>
        </article>
      `,
    )
    .join("");
}

function renderProfile(profile) {
  if (!profile) {
    profileGrid.innerHTML = '<div class="empty-block">No profile data.</div>';
    return;
  }

  const items = [
    ["Algorithm", profile.algorithm],
    ["Sentences", Number(profile.sentence_count).toLocaleString()],
    ["Avg sentence", Number(profile.average_sentence_length).toFixed(1)],
    ["Specificity", formatPercent(profile.specificity_ratio)],
    ["Evidence", formatPercent(profile.evidence_density)],
    ["Repetition", formatPercent(profile.repetition_density)],
    ["Links", Number(profile.link_count).toLocaleString()],
    ["Numbers", Number(profile.numeric_detail_count).toLocaleString()],
    ["Citations", Number(profile.citation_count).toLocaleString()],
  ];

  profileGrid.innerHTML = items
    .map(
      ([label, value]) => `
        <div class="profile-item">
          <span>${escapeHtml(label)}</span>
          <strong>${escapeHtml(value)}</strong>
        </div>
      `,
    )
    .join("");
}

function renderSource(payload) {
  if (payload.website) {
    sourceCard.hidden = false;
    sourceKind.textContent = "Website";
    sourceTitle.textContent = payload.website.title || payload.source || "Fetched page";
    const finalUrl = payload.website.final_url || "";
    const safeUrl = safeHttpUrl(finalUrl);
    sourceUrl.textContent = finalUrl;
    if (safeUrl) {
      sourceUrl.href = safeUrl;
    } else {
      sourceUrl.removeAttribute("href");
    }
    return;
  }

  if (payload.source) {
    sourceCard.hidden = false;
    sourceKind.textContent = "Text";
    sourceTitle.textContent = payload.source;
    sourceUrl.textContent = "";
    sourceUrl.removeAttribute("href");
    return;
  }

  sourceCard.hidden = true;
}

function renderResult(payload) {
  const score = Number(payload.score) || 0;
  const risk = payload.risk || "neutral";
  const riskLabel = riskLabels[risk] || "Ready";
  const scorePercent = Math.round(score * 100);
  const signals = payload.signals || [];

  riskMetric.textContent = riskLabel;
  scoreMetric.textContent = score.toFixed(3);
  wordMetric.textContent = Number(payload.word_count || 0).toLocaleString();
  signalMetric.textContent = signals.length.toLocaleString();
  riskPill.textContent = riskLabel;
  setRiskClass(risk);
  scoreFill.style.width = `${scorePercent}%`;
  dialScore.textContent = `${scorePercent}%`;
  recommendation.textContent = payload.recommendation || "Run an analysis to populate the review profile.";
  renderSource(payload);
  renderDimensions(payload.dimensions || []);
  renderProfile(payload.profile);
  renderSignals(signals);
}

async function analyzeText(event) {
  event.preventDefault();
  const source = sourceInput.value.trim() || null;
  const text = textInput.value.trim();
  const url = urlInput.value.trim();

  if (inputMode === "text" && !text) {
    textInput.focus();
    setState("Text required");
    return;
  }

  if (inputMode === "website" && !url) {
    urlInput.focus();
    setState("URL required");
    return;
  }

  setState("Analyzing", true);

  try {
    const endpoint = inputMode === "website" ? "/api/v1/analyze-url" : "/api/v1/analyze";
    const body = inputMode === "website" ? { source, url } : { source, text };
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });

    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.detail || `Analysis failed with ${response.status}`);
    }

    renderResult(payload);
    setState("Complete");
  } catch (error) {
    setState("Request failed");
    recommendation.textContent = error.message;
  }
}

async function loadThreshold() {
  try {
    const response = await fetch("/api/v1/threshold");
    if (!response.ok) {
      throw new Error("Unavailable");
    }

    const payload = await response.json();
    thresholdValue.textContent = payload.alert_threshold.toFixed(2);
  } catch {
    thresholdValue.textContent = "Unavailable";
  }
}

sampleButton.addEventListener("click", () => {
  setMode("text");
  sourceInput.value = "sample-review";
  textInput.value = sampleText;
  updateCounter();
});

clearButton.addEventListener("click", () => {
  sourceInput.value = "";
  textInput.value = "";
  urlInput.value = "";
  updateCounter();
  setState("Idle");
  renderResult({
    score: 0,
    risk: "neutral",
    word_count: 0,
    signals: [],
    dimensions: [],
    profile: null,
    recommendation: "Run an analysis to populate the review profile.",
  });
});

textModeButton.addEventListener("click", () => setMode("text"));
urlModeButton.addEventListener("click", () => setMode("website"));
textInput.addEventListener("input", updateCounter);
urlInput.addEventListener("input", updateCounter);
form.addEventListener("submit", analyzeText);
updateCounter();
loadThreshold();
renderDimensions([]);
renderProfile(null);
