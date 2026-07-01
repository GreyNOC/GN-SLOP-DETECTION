const form = document.querySelector("#analysisForm");
const textInput = document.querySelector("#textInput");
const sourceInput = document.querySelector("#sourceInput");
const urlInput = document.querySelector("#urlInput");
const mediaInput = document.querySelector("#mediaInput");
const textField = document.querySelector("#textField");
const urlField = document.querySelector("#urlField");
const mediaField = document.querySelector("#mediaField");
const codeField = document.querySelector("#codeField");
const textModeButton = document.querySelector("#textModeButton");
const urlModeButton = document.querySelector("#urlModeButton");
const mediaModeButton = document.querySelector("#mediaModeButton");
const codeModeButton = document.querySelector("#codeModeButton");
const codeTargetTypeSelect = document.querySelector("#codeTargetTypeSelect");
const codeTargetInput = document.querySelector("#codeTargetInput");
const codeTargetTextWrap = document.querySelector("#codeTargetTextWrap");
const codeTargetArchiveWrap = document.querySelector("#codeTargetArchiveWrap");
const codeArchiveInput = document.querySelector("#codeArchiveInput");
const codeArchiveInputName = document.querySelector("#codeArchiveInputName");
const mediaInputName = document.querySelector("#mediaInputName");
const codeExcludeInput = document.querySelector("#codeExcludeInput");
const codeLlmMode = document.querySelector("#codeLlmMode");
const codeLlmProvider = document.querySelector("#codeLlmProvider");
const codeLlmModel = document.querySelector("#codeLlmModel");
const codeLlmKey = document.querySelector("#codeLlmKey");
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
const healthButton = document.querySelector("#healthButton");
const healthDot = document.querySelector("#healthDot");
const healthLabel = document.querySelector("#healthLabel");
const signalsTableHead = document.querySelector("#signalsTableHead");
const findingsActions = document.querySelector("#findingsActions");
const expandAllButton = document.querySelector("#expandAllButton");
const downloadReportButton = document.querySelector("#downloadReportButton");
const downloadJsonButton = document.querySelector("#downloadJsonButton");
const downloadSarifButton = document.querySelector("#downloadSarifButton");
const findingsBanner = document.querySelector("#findingsBanner");
const findingsSeverityFilter = document.querySelector("#findingsSeverityFilter");
const findingsCategoryFilter = document.querySelector("#findingsCategoryFilter");
const findingsTextFilter = document.querySelector("#findingsTextFilter");
const wordMetricLabel = document.querySelector("#wordMetricLabel");
const signalMetricLabel = document.querySelector("#signalMetricLabel");
const codeIncludeInput = document.querySelector("#codeIncludeInput");
const aiLlmDetails = document.querySelector("#aiLlmDetails");
const aiLlmHint = document.querySelector("#aiLlmHint");
const aiLlmEnable = document.querySelector("#aiLlmEnable");
const aiLlmProvider = document.querySelector("#aiLlmProvider");
const aiLlmModel = document.querySelector("#aiLlmModel");
const aiLlmKey = document.querySelector("#aiLlmKey");
const aiVerdict = document.querySelector("#aiVerdict");
const pqReadiness = document.querySelector("#pqReadiness");
const dialLabel = document.querySelector("#dialLabel");
const mediaNote = document.querySelector("#mediaNote");

const TEXT_SIGNALS_HEADERS = ["Signal", "Category", "Weight", "Count", "Description"];
const CODE_SIGNALS_HEADERS = [
  "Rule",
  "Severity / Confidence",
  "Category",
  "Location",
  "Title",
];

let lastCodePayload = null;

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
  const isText = mode === "text";
  const isUrl = mode === "website";
  const isMedia = mode === "media";
  const isCode = mode === "code";
  textField.hidden = !isText;
  urlField.hidden = !isUrl;
  if (mediaField) {
    mediaField.hidden = !isMedia;
  }
  if (codeField) {
    codeField.hidden = !isCode;
  }
  textInput.required = isText;
  urlInput.required = isUrl;
  if (mediaInput) {
    mediaInput.required = isMedia;
  }
  textModeButton.classList.toggle("active", isText);
  urlModeButton.classList.toggle("active", isUrl);
  if (mediaModeButton) {
    mediaModeButton.classList.toggle("active", isMedia);
  }
  if (codeModeButton) {
    codeModeButton.classList.toggle("active", isCode);
  }
  textModeButton.setAttribute("aria-selected", String(isText));
  urlModeButton.setAttribute("aria-selected", String(isUrl));
  if (mediaModeButton) {
    mediaModeButton.setAttribute("aria-selected", String(isMedia));
  }
  if (codeModeButton) {
    codeModeButton.setAttribute("aria-selected", String(isCode));
  }
  updateCounter();
  setMetricLabels(mode);
  updateAiLlmPanel(mode);
  if (isUrl) {
    urlInput.focus();
  } else if (isMedia && mediaInput) {
    mediaInput.focus();
  } else if (isCode && codeTargetInput) {
    codeTargetInput.focus();
  } else {
    textInput.focus();
  }
}

function updateCounter() {
  if (inputMode === "website") {
    charCounter.textContent = `${urlInput.value.length.toLocaleString()} URL chars`;
    return;
  }
  if (inputMode === "media") {
    const file = mediaInput?.files?.[0];
    if (file) {
      const kb = Math.max(1, Math.round(file.size / 1024));
      charCounter.textContent = `${kb.toLocaleString()} KB ${file.name}`;
    } else {
      charCounter.textContent = "no file selected";
    }
    return;
  }
  if (inputMode === "code") {
    const type = codeTargetTypeSelect?.value || "path";
    if (type === "archive") {
      const file = codeArchiveInput?.files?.[0];
      charCounter.textContent = file
        ? `${Math.max(1, Math.round(file.size / 1024)).toLocaleString()} KB ${file.name}`
        : "no archive selected";
    } else {
      const target = codeTargetInput?.value || "";
      charCounter.textContent = target ? `target: ${target.slice(0, 60)}` : "no target";
    }
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

  // We avoid `style="width:…"` in the inline HTML on purpose: the dashboard
  // CSP intentionally drops `'unsafe-inline'` from style-src, so any
  // parser-inserted inline style attribute is silently discarded and the
  // bars never fill. JS-set `.style.width` goes through the CSSOM and is
  // not subject to the inline-style CSP restriction.
  dimensionGrid.innerHTML = dimensions
    .map(
      (dimension, index) => `
        <article class="dimension-card ${escapeHtml(dimension.status)}">
          <div>
            <span>${escapeHtml(dimension.name)}</span>
            <strong>${formatPercent(dimension.score)}</strong>
          </div>
          <div class="dimension-track" aria-hidden="true">
            <div data-dimension-fill="${index}"></div>
          </div>
          <small>${escapeHtml(dimension.status)}</small>
        </article>
      `,
    )
    .join("");
  dimensions.forEach((dimension, index) => {
    const fill = dimensionGrid.querySelector(`[data-dimension-fill="${index}"]`);
    if (fill) {
      fill.style.width = formatPercent(dimension.score);
    }
  });
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

function renderMediaResult(payload) {
  setSignalsHeaders(TEXT_SIGNALS_HEADERS);
  if (findingsActions) findingsActions.hidden = true;
  lastCodePayload = null;
  const score = Number(payload.score) || 0;
  const risk = payload.risk || "neutral";
  const riskLabel = riskLabels[risk] || "Ready";
  const scorePercent = Math.round(score * 100);
  riskMetric.textContent = riskLabel;
  scoreMetric.textContent = score.toFixed(3);
  wordMetric.textContent = Number(payload.byte_size || 0).toLocaleString();
  signalMetric.textContent = Number((payload.findings || []).length).toLocaleString();
  riskPill.textContent = riskLabel;
  setRiskClass(risk);
  scoreFill.style.width = `${scorePercent}%`;
  dialScore.textContent = `${scorePercent}%`;
  recommendation.textContent =
    payload.recommendation || "No major media provenance markers detected.";

  if (sourceCard) {
    sourceCard.hidden = false;
    sourceKind.textContent = `Media · ${payload.format || "unknown"}`;
    sourceTitle.textContent = payload.file_name || payload.source || "Uploaded media";
    sourceUrl.textContent = "";
    sourceUrl.removeAttribute("href");
  }

  const findings = payload.findings || [];
  if (!findings.length) {
    signalsTable.innerHTML = '<tr><td colspan="5" class="empty-cell">No provenance markers detected.</td></tr>';
  } else {
    signalsTable.innerHTML = findings
      .map(
        (finding) => `
          <tr>
            <td>${escapeHtml(finding.marker)}</td>
            <td>${escapeHtml(finding.confidence)}</td>
            <td>—</td>
            <td>1</td>
            <td>${escapeHtml(finding.detail || "")}</td>
          </tr>
        `,
      )
      .join("");
  }

  const flags = [
    ["C2PA manifest", payload.has_c2pa_manifest ? "Yes" : "No"],
    ["JUMBF box", payload.has_jumbf_box ? "Yes" : "No"],
    ["XMP packet", payload.has_xmp_packet ? "Yes" : "No"],
    ["SynthID marker", payload.has_synthid_marker ? "Yes" : "No"],
    ["Tool fingerprints", (payload.tool_fingerprints || []).join(", ") || "None"],
    ["Trailing bytes", Number(payload.trailing_bytes || 0).toLocaleString()],
    ["Format", payload.format || "unknown"],
    ["Kind", payload.kind || "unknown"],
    ["Algorithm", payload.algorithm || "media-picture-v1"],
  ];
  profileGrid.innerHTML = flags
    .map(
      ([label, value]) => `
        <div class="profile-item">
          <span>${escapeHtml(label)}</span>
          <strong>${escapeHtml(String(value))}</strong>
        </div>
      `,
    )
    .join("");

  dimensionGrid.innerHTML =
    '<div class="empty-block">Dimension scores apply to text analysis only.</div>';

  // Honest framing: the media score is a provenance/marker score, not an
  // AI-probability. A low score means "no embedded markers found", which is
  // common for stripped/exported files and is NOT an authenticity verdict.
  if (dialLabel) dialLabel.textContent = "Provenance score";
  if (mediaNote) {
    mediaNote.innerHTML = payload.vision
      ? "<strong>Metadata + vision scan.</strong> The score above reflects only provenance markers embedded in the file (C2PA, SynthID, generator fingerprints), not the pixels. See the vision verdict below for the pixel-level opinion."
      : "<strong>Metadata scan only.</strong> The score above reflects only provenance markers embedded in the file (C2PA, SynthID, generator fingerprints), not the pixels. A low score means none were found — common for screenshots, exports, and re-saved images — and is <strong>not</strong> a verdict that the image is authentic. Enable the frontier vision pass below for a pixel-level opinion.";
    mediaNote.hidden = false;
  }

  renderPqReadiness(null);
  renderAiVerdict(payload);
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
  setSignalsHeaders(TEXT_SIGNALS_HEADERS);
  if (findingsActions) findingsActions.hidden = true;
  lastCodePayload = null;
  resetScoreFraming();
  renderPqReadiness(null);
  renderSource(payload);
  renderDimensions(payload.dimensions || []);
  renderProfile(payload.profile);
  renderSignals(signals);
  renderAiVerdict(payload);
}

async function analyzeText(event) {
  event.preventDefault();
  const source = sourceInput.value.trim() || null;
  const text = textInput.value.trim();
  const url = urlInput.value.trim();
  const mediaFile = mediaInput?.files?.[0] || null;

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

  if (inputMode === "media" && !mediaFile) {
    mediaInput?.focus();
    setState("Media file required");
    return;
  }

  if (inputMode === "code") {
    await runCodeScan();
    return;
  }

  setState("Analyzing", true);

  try {
    let response;
    if (inputMode === "media") {
      const formData = new FormData();
      formData.append("file", mediaFile);
      if (source) {
        formData.append("source", source);
      }
      const ai = buildAiLlmPayload();
      if (ai) {
        formData.append("llm_provider", ai.provider);
        formData.append("llm_model", ai.model);
        formData.append("llm_api_key", ai.api_key);
        formData.append("llm_mode", "vision");
      }
      response = await fetch("/api/v1/analyze-media", {
        method: "POST",
        body: formData,
      });
    } else {
      const endpoint = inputMode === "website" ? "/api/v1/analyze-url" : "/api/v1/analyze";
      const body = inputMode === "website" ? { source, url } : { source, text };
      if (inputMode === "text") {
        const ai = buildAiLlmPayload();
        if (ai) {
          body.llm = { mode: "judge_text", ...ai };
        }
      }
      response = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
    }

    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.detail || `Analysis failed with ${response.status}`);
    }

    if (inputMode === "media") {
      renderMediaResult(payload);
    } else {
      renderResult(payload);
    }
    setState("Complete");
  } catch (error) {
    setState("Request failed");
    recommendation.textContent = error.message;
  }
}

async function runCodeScan() {
  const type = codeTargetTypeSelect?.value || "path";
  const archiveFile = codeArchiveInput?.files?.[0] || null;
  const target = codeTargetInput?.value?.trim() || "";

  if (type !== "archive" && !target) {
    codeTargetInput?.focus();
    setState("Target required");
    return;
  }
  if (type === "archive" && !archiveFile) {
    codeArchiveInput?.focus();
    setState("Archive required");
    return;
  }

  setState("Scanning", true);
  try {
    const parseGlobs = (raw) =>
      (raw || "")
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
    const includeGlobs = parseGlobs(codeIncludeInput?.value);
    const excludeGlobs = parseGlobs(codeExcludeInput?.value);
    let response;
    if (type === "archive") {
      const formData = new FormData();
      formData.append("file", archiveFile);
      if (includeGlobs.length) formData.append("include_globs", includeGlobs.join(","));
      if (excludeGlobs.length) formData.append("exclude_globs", excludeGlobs.join(","));
      response = await fetch("/api/v1/scan-code/upload", { method: "POST", body: formData });
    } else {
      const llm = buildLlmPayload();
      const body = {
        target,
        target_type: type,
        include_globs: includeGlobs,
        exclude_globs: excludeGlobs,
      };
      if (llm) {
        body.llm = llm;
      }
      response = await fetch("/api/v1/scan-code", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
    }
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.detail || `Scan failed with ${response.status}`);
    }
    // Stash the scope the user actually scanned with so subsequent
    // exports (notably SARIF, which re-posts to the backend) reuse the
    // same include/exclude globs and don't quietly leak excluded files.
    payload._scan_include_globs = includeGlobs;
    payload._scan_exclude_globs = excludeGlobs;
    renderCodeResult(payload);
    setState("Complete");
  } catch (error) {
    setState("Request failed");
    recommendation.textContent = error.message;
  }
}

function buildLlmPayload() {
  const mode = codeLlmMode?.value || "off";
  if (mode === "off") return null;
  const provider = codeLlmProvider?.value || "openai";
  const model = (codeLlmModel?.value || "").trim();
  const apiKey = (codeLlmKey?.value || "").trim();
  if (!model || !apiKey) return null;
  return { mode, provider, model, api_key: apiKey };
}

function updateAiLlmPanel(mode) {
  if (!aiLlmDetails) return;
  const show = mode === "text" || mode === "media";
  aiLlmDetails.hidden = !show;
  if (aiLlmHint) {
    aiLlmHint.textContent =
      mode === "media"
        ? "Have a frontier vision model inspect the actual pixels for AI-generation artifacts. Anthropic only; PNG/JPEG/WebP/GIF. Keys are never persisted."
        : "Get a frontier-model AI-likelihood + slop second opinion on this text. Anthropic or OpenAI-compatible. Keys are never persisted.";
  }
  if (!show && aiVerdict) {
    aiVerdict.hidden = true;
    aiVerdict.innerHTML = "";
  }
}

function buildAiLlmPayload() {
  if (!aiLlmEnable || !aiLlmEnable.checked) return null;
  const provider = aiLlmProvider?.value || "anthropic";
  const model = (aiLlmModel?.value || "").trim();
  const apiKey = (aiLlmKey?.value || "").trim();
  if (!model || !apiKey) return null;
  return { provider, model, api_key: apiKey };
}

function resetScoreFraming() {
  if (dialLabel) dialLabel.textContent = "Composite score";
  if (mediaNote) {
    mediaNote.hidden = true;
    mediaNote.innerHTML = "";
  }
}

function renderAiVerdict(payload) {
  if (!aiVerdict) return;
  const parts = [];

  if (payload.llm) {
    const judge = payload.llm;
    parts.push(`
      <div class="ai-verdict-row">
        <span class="ai-verdict-label">Frontier judge · ${escapeHtml(judge.model || "")}</span>
        <span class="ai-verdict-badge ${escapeHtml(judge.ai_likelihood)}">AI-likelihood: ${escapeHtml(judge.ai_likelihood)}</span>
        <span class="ai-verdict-badge ${escapeHtml(judge.slop_verdict)}">Slop: ${escapeHtml(judge.slop_verdict)}</span>
      </div>
      ${judge.rationale ? `<p class="ai-verdict-note">${escapeHtml(judge.rationale)}</p>` : ""}
    `);
  }

  if (payload.model_detection && payload.model_detection.available) {
    const md = payload.model_detection;
    const pct = md.ai_likelihood != null ? `${Math.round(md.ai_likelihood * 100)}%` : "n/a";
    parts.push(`
      <div class="ai-verdict-row">
        <span class="ai-verdict-label">Model detector · ${escapeHtml(md.method || "")}</span>
        <span class="ai-verdict-badge">AI-likelihood: ${escapeHtml(pct)}</span>
        ${md.raw_perplexity != null ? `<span class="ai-verdict-badge">ppl: ${escapeHtml(String(md.raw_perplexity))}</span>` : ""}
      </div>
    `);
  }

  if (payload.vision) {
    const vis = payload.vision;
    if (vis.status === "ok") {
      const artifacts = (vis.ai_artifacts || []).map(escapeHtml).join(", ");
      parts.push(`
        <div class="ai-verdict-row">
          <span class="ai-verdict-label">Vision · ${escapeHtml(vis.model || "")}</span>
          <span class="ai-verdict-badge ${escapeHtml(vis.verdict)}">${escapeHtml(formatSignalName(vis.verdict))}</span>
          <span class="ai-verdict-badge">confidence: ${escapeHtml(vis.confidence)}</span>
        </div>
        ${artifacts ? `<p class="ai-verdict-note">Artifacts: ${artifacts}</p>` : ""}
        ${vis.rationale ? `<p class="ai-verdict-note">${escapeHtml(vis.rationale)}</p>` : ""}
      `);
    } else {
      parts.push(`
        <div class="ai-verdict-row">
          <span class="ai-verdict-label">Vision</span>
          <span class="ai-verdict-badge">skipped · ${escapeHtml(vis.status)}</span>
        </div>
        ${vis.rationale ? `<p class="ai-verdict-note">${escapeHtml(vis.rationale)}</p>` : ""}
      `);
    }
  }

  if (!parts.length) {
    aiVerdict.hidden = true;
    aiVerdict.innerHTML = "";
    return;
  }
  aiVerdict.innerHTML = `<span class="ai-verdict-title">AI second opinion</span>${parts.join("")}`;
  aiVerdict.hidden = false;
}

function renderPqReadiness(pq) {
  if (!pqReadiness) return;
  if (!pq || !pq.status || pq.status === "no_crypto_detected") {
    pqReadiness.hidden = true;
    pqReadiness.innerHTML = "";
    return;
  }
  const families = pq.families || {};
  const familyBadges = Object.entries(families)
    .map(
      ([name, count]) =>
        `<span class="ai-verdict-badge">${escapeHtml(formatSignalName(name))}: ${escapeHtml(String(count))}</span>`,
    )
    .join("");
  pqReadiness.innerHTML = `
    <span class="ai-verdict-title">Post-quantum readiness</span>
    <div class="ai-verdict-row">
      <span class="ai-verdict-badge ${escapeHtml(pq.status)}">${escapeHtml(formatSignalName(pq.status))}</span>
      <span class="ai-verdict-badge">Harvest-now-decrypt-later: ${escapeHtml(String(pq.hndl_exposure ?? 0))}</span>
      <span class="ai-verdict-badge">Classical: ${escapeHtml(String(pq.classical_findings ?? 0))}</span>
      <span class="ai-verdict-badge">PQC: ${escapeHtml(String(pq.pqc_findings ?? 0))}</span>
    </div>
    ${familyBadges ? `<div class="ai-verdict-row">${familyBadges}</div>` : ""}
    ${pq.recommendation ? `<p class="ai-verdict-note">${escapeHtml(pq.recommendation)}</p>` : ""}
  `;
  pqReadiness.hidden = false;
}

function setSignalsHeaders(labels) {
  if (!signalsTableHead) return;
  signalsTableHead.innerHTML = `
    <tr>${labels.map((label) => `<th>${escapeHtml(label)}</th>`).join("")}</tr>
  `;
}

function setMetricLabels(mode) {
  if (!wordMetricLabel || !signalMetricLabel) return;
  if (mode === "media") {
    wordMetricLabel.textContent = "Bytes";
    signalMetricLabel.textContent = "Findings";
  } else if (mode === "code") {
    wordMetricLabel.textContent = "Files scanned";
    signalMetricLabel.textContent = "Findings";
  } else {
    wordMetricLabel.textContent = "Words";
    signalMetricLabel.textContent = "Signals";
  }
}

function renderCodeResult(payload) {
  lastCodePayload = payload;
  setMetricLabels("code");
  const score = Number(payload.score) || 0;
  const risk = payload.risk || "neutral";
  const riskLabel = riskLabels[risk] || "Ready";
  const scorePercent = Math.round(score * 100);
  riskMetric.textContent = riskLabel;
  scoreMetric.textContent = score.toFixed(3);
  wordMetric.textContent = Number(payload.files_scanned || 0).toLocaleString();
  signalMetric.textContent = Number((payload.findings || []).length).toLocaleString();
  riskPill.textContent = riskLabel;
  setRiskClass(risk);
  scoreFill.style.width = `${scorePercent}%`;
  dialScore.textContent = `${scorePercent}%`;
  recommendation.textContent =
    payload.recommendation || "Scan complete.";

  if (sourceCard) {
    sourceCard.hidden = false;
    sourceKind.textContent = `Code · ${payload.target_type || "path"}`;
    sourceTitle.textContent = payload.target || "Scan target";
    sourceUrl.textContent = "";
    sourceUrl.removeAttribute("href");
  }

  setSignalsHeaders(CODE_SIGNALS_HEADERS);
  const findings = payload.findings || [];
  // Populate the category filter from the actual findings so the dropdown
  // only offers categories that exist in this scan.
  if (findingsCategoryFilter) {
    const seen = new Set();
    const options = ['<option value="">All categories</option>'];
    for (const finding of findings) {
      const value = finding.category || "uncategorised";
      if (!seen.has(value)) {
        seen.add(value);
        options.push(`<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`);
      }
    }
    findingsCategoryFilter.innerHTML = options.join("");
    findingsCategoryFilter.value = "";
  }
  if (findingsSeverityFilter) findingsSeverityFilter.value = "";
  if (findingsTextFilter) findingsTextFilter.value = "";

  const renderableCount = Math.min(findings.length, 250);
  if (!findings.length) {
    signalsTable.innerHTML =
      '<tr><td colspan="5" class="empty-cell">No findings detected at this scan depth.</td></tr>';
    if (findingsActions) findingsActions.hidden = true;
  } else {
    const rendered = findings.slice(0, renderableCount);
    signalsTable.innerHTML = rendered
      .map((finding, index) => buildCodeFindingRows(finding, index))
      .join("");
    bindFindingExpanders();
    if (findingsActions) findingsActions.hidden = false;
  }
  if (findingsBanner) {
    const messages = [];
    if (findings.length > renderableCount) {
      messages.push(
        `Showing ${renderableCount.toLocaleString()} of ${findings.length.toLocaleString()} findings.`,
      );
    }
    if (payload.redactions_present) {
      messages.push("Secret values were redacted; original literals never leave the engine.");
    }
    if (payload.suppressed_count > 0) {
      messages.push(`${payload.suppressed_count} finding(s) suppressed via gn-slop comments.`);
    }
    if (payload.rule_errors && payload.rule_errors.length) {
      messages.push(`${payload.rule_errors.length} rule(s) errored — see report for details.`);
    }
    if (messages.length) {
      findingsBanner.textContent = messages.join("  ");
      findingsBanner.hidden = false;
    } else {
      findingsBanner.hidden = true;
    }
  }
  applyCodeFilters();

  const counts = payload.finding_counts || {};
  const flags = [
    ["Algorithm", payload.algorithm || "code-picture-v1"],
    ["Files scanned", Number(payload.files_scanned || 0).toLocaleString()],
    ["Files skipped", Number(payload.files_skipped || 0).toLocaleString()],
    ["Bytes scanned", Number(payload.bytes_scanned || 0).toLocaleString()],
    ["Elapsed (s)", (Number(payload.elapsed_seconds) || 0).toFixed(2)],
    ["Critical", Number(counts.critical || 0).toLocaleString()],
    ["High", Number(counts.high || 0).toLocaleString()],
    ["Medium", Number(counts.medium || 0).toLocaleString()],
    ["Low/Info", (
      Number(counts.low || 0) + Number(counts.info || 0)
    ).toLocaleString()],
  ];
  profileGrid.innerHTML = flags
    .map(
      ([label, value]) => `
        <div class="profile-item">
          <span>${escapeHtml(label)}</span>
          <strong>${escapeHtml(String(value))}</strong>
        </div>
      `,
    )
    .join("");

  dimensionGrid.innerHTML =
    '<div class="empty-block">Dimension scores apply to text analysis only.</div>';
  resetScoreFraming();
  renderPqReadiness(payload.pq_readiness);
  if (aiVerdict) {
    aiVerdict.hidden = true;
    aiVerdict.innerHTML = "";
  }
}

function buildCodeFindingRows(finding, index) {
  const llmRow = finding.llm_verdict
    ? `
            <div class="finding-detail-section">
              <span class="finding-detail-label">LLM verification (${escapeHtml(finding.llm_verdict)})</span>
              <div>${escapeHtml(finding.llm_rationale || "")}</div>
            </div>`
    : "";
  const redactedNote = finding.redacted
    ? '<small style="color: var(--amber)">Snippet redacted — secret value never leaves the engine.</small>'
    : "";
  return `
    <tr class="finding-row expandable"
        data-finding-index="${index}"
        data-severity="${escapeHtml(finding.severity)}"
        data-category="${escapeHtml(finding.category || "")}"
        tabindex="0"
        role="button"
        aria-expanded="false">
      <td>${escapeHtml(finding.rule_id)}</td>
      <td>
        <span class="finding-severity-pill ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span>
        <span class="finding-severity-pill ${escapeHtml(finding.confidence)}">${escapeHtml(finding.confidence)}</span>
      </td>
      <td>${escapeHtml(finding.category || "")}</td>
      <td>${escapeHtml(finding.file_path)}:${escapeHtml(String(finding.line_start))}</td>
      <td>${escapeHtml(finding.title)}</td>
    </tr>
    <tr class="finding-detail-row" data-detail-for="${index}" hidden>
      <td colspan="5">
        <div class="finding-detail">
          <div class="finding-detail-section">
            <span class="finding-detail-label">Description</span>
            <div>${escapeHtml(finding.description || finding.title)}</div>
          </div>
          <div class="finding-detail-section">
            <span class="finding-detail-label">Probe (offending code)</span>
            <pre class="finding-detail-snippet">${escapeHtml(finding.snippet || "(no snippet captured)")}</pre>
            ${redactedNote}
          </div>
          <div class="finding-detail-section">
            <span class="finding-detail-label">Suggested fix</span>
            <div class="finding-detail-remediation">${escapeHtml(finding.remediation || "(no remediation provided for this rule)")}</div>
          </div>
          ${llmRow}
        </div>
      </td>
    </tr>
  `;
}

function bindFindingExpanders() {
  signalsTable.querySelectorAll(".finding-row").forEach((row) => {
    row.addEventListener("click", () => toggleFindingRow(row));
    row.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        toggleFindingRow(row);
      }
    });
  });
}

function applyCodeFilters() {
  if (!signalsTable) return;
  const severity = findingsSeverityFilter?.value || "";
  const category = findingsCategoryFilter?.value || "";
  const query = (findingsTextFilter?.value || "").toLowerCase().trim();
  const rows = signalsTable.querySelectorAll(".finding-row");
  rows.forEach((row) => {
    const detail = signalsTable.querySelector(
      `.finding-detail-row[data-detail-for="${row.dataset.findingIndex}"]`,
    );
    let visible = true;
    if (severity && row.dataset.severity !== severity) visible = false;
    if (category && row.dataset.category !== category) visible = false;
    if (query) {
      const text = row.textContent.toLowerCase();
      if (!text.includes(query)) visible = false;
    }
    row.hidden = !visible;
    if (detail) detail.hidden = !visible || !row.classList.contains("expanded");
  });
}

function toggleFindingRow(row) {
  const index = row.dataset.findingIndex;
  if (!index) return;
  const detail = signalsTable.querySelector(
    `.finding-detail-row[data-detail-for="${index}"]`,
  );
  if (!detail) return;
  const expanded = !detail.hidden;
  detail.hidden = expanded;
  row.classList.toggle("expanded", !expanded);
  row.setAttribute("aria-expanded", String(!expanded));
}

function setAllFindingsExpanded(expanded) {
  signalsTable.querySelectorAll(".finding-detail-row").forEach((row) => {
    row.hidden = !expanded;
  });
  signalsTable.querySelectorAll(".finding-row").forEach((row) => {
    row.classList.toggle("expanded", expanded);
  });
  if (expandAllButton) {
    expandAllButton.textContent = expanded ? "Collapse all" : "Expand all";
    expandAllButton.setAttribute("aria-pressed", String(expanded));
  }
}

function escapeReportHtml(value) {
  return escapeHtml(value);
}

function buildReportHtml(payload) {
  const generated = new Date().toISOString();
  const score = Number(payload.score) || 0;
  const findings = payload.findings || [];
  const ruleErrors = payload.rule_errors || [];
  const grouped = {};
  for (const finding of findings) {
    const key = finding.severity || "info";
    (grouped[key] ||= []).push(finding);
  }
  const severityOrder = ["critical", "high", "medium", "low", "info"];
  const counts = payload.finding_counts || {};
  const gitRows = Object.entries(payload.git_metadata || {})
    .map(
      ([key, value]) =>
        `<tr><th>${escapeReportHtml(key)}</th><td>${escapeReportHtml(String(value))}</td></tr>`,
    )
    .join("");

  const sections = severityOrder
    .filter((severity) => grouped[severity] && grouped[severity].length)
    .map((severity) => {
      const rows = grouped[severity]
        .map(
          (finding) => `
            <article class="finding">
              <header>
                <span class="pill ${escapeReportHtml(severity)}">${escapeReportHtml(severity)}</span>
                <span class="pill confidence">confidence: ${escapeReportHtml(finding.confidence || "")}</span>
                <span class="rule-id">${escapeReportHtml(finding.rule_id)}</span>
              </header>
              <h3>${escapeReportHtml(finding.title)}</h3>
              <p class="meta">
                <strong>File:</strong> <code>${escapeReportHtml(finding.file_path)}</code>:${escapeReportHtml(String(finding.line_start))}${finding.line_end && finding.line_end !== finding.line_start ? "-" + escapeReportHtml(String(finding.line_end)) : ""}
                &nbsp;&nbsp; <strong>Category:</strong> ${escapeReportHtml(finding.category || "")}
              </p>
              <p>${escapeReportHtml(finding.description || "")}</p>
              <div class="block">
                <span class="block-label">Probe (offending code)</span>
                <pre>${escapeReportHtml(finding.snippet || "(no snippet captured)")}</pre>
              </div>
              <div class="block">
                <span class="block-label">Suggested fix</span>
                <p>${escapeReportHtml(finding.remediation || "(no remediation provided for this rule)")}</p>
              </div>
              ${
                finding.redacted
                  ? '<p class="redaction-note"><strong>Redacted.</strong> The secret value was removed before this report was generated; the original literal never leaves the engine.</p>'
                  : ""
              }
              ${
                finding.llm_verdict
                  ? `<div class="block"><span class="block-label">LLM verification (${escapeReportHtml(finding.llm_verdict)})</span><p>${escapeReportHtml(finding.llm_rationale || "")}</p></div>`
                  : ""
              }
            </article>
          `,
        )
        .join("");
      return `
        <section>
          <h2>${escapeReportHtml(severity.toUpperCase())} findings (${grouped[severity].length})</h2>
          ${rows}
        </section>
      `;
    })
    .join("");

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>GreyNOC Code Scan Report — ${escapeReportHtml(payload.target || "scan")}</title>
<style>
  :root { color-scheme: light; }
  body { margin: 0; padding: 32px 48px; font-family: Inter, system-ui, sans-serif; background: #fafafa; color: #111; }
  h1 { margin-top: 0; font-size: 1.6rem; }
  h2 { margin-top: 36px; font-size: 1.2rem; border-bottom: 2px solid #ddd; padding-bottom: 6px; }
  h3 { margin: 0 0 6px 0; font-size: 1.05rem; }
  table.summary { border-collapse: collapse; margin-bottom: 18px; }
  table.summary th, table.summary td { border: 1px solid #ddd; padding: 4px 10px; font-size: 0.9rem; text-align: left; }
  .findings-summary { display: flex; gap: 14px; margin: 14px 0 28px 0; flex-wrap: wrap; }
  .count-card { padding: 8px 14px; border: 1px solid #ddd; border-radius: 2px; background: #fff; min-width: 80px; }
  .count-card span { display: block; font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.04em; color: #666; }
  .count-card strong { font-size: 1.3rem; }
  .finding { background: #fff; border: 1px solid #ddd; padding: 14px 18px; margin-bottom: 18px; }
  .finding header { display: flex; gap: 8px; align-items: center; margin-bottom: 8px; flex-wrap: wrap; }
  .pill { padding: 2px 8px; font-size: 0.72rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em; background: #eee; }
  .pill.confidence { background: #e7eef9; color: #1a4380; }
  .pill.critical { background: #fde2e2; color: #9b1c1c; }
  .pill.high { background: #fdebcd; color: #92410d; }
  .pill.medium { background: #e2eaff; color: #1d3b80; }
  .pill.low, .pill.info { background: #d4f1de; color: #1c6b32; }
  .rule-id { font-family: ui-monospace, monospace; color: #555; font-size: 0.85rem; }
  .meta { margin: 4px 0 8px 0; font-size: 0.85rem; color: #555; }
  .block { margin-top: 10px; }
  .block-label { display: block; font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.06em; color: #666; margin-bottom: 4px; }
  pre { background: #0f1419; color: #e6e7e9; padding: 10px 14px; overflow-x: auto; white-space: pre-wrap; word-break: break-word; font-family: ui-monospace, monospace; font-size: 0.85rem; }
  code { font-family: ui-monospace, monospace; background: #f0f0f0; padding: 1px 4px; }
  .redaction-banner { background: #fff7d6; border: 1px solid #f0b429; padding: 8px 12px; }
  .redaction-note { background: #fff7d6; border-left: 3px solid #f0b429; padding: 6px 10px; margin-top: 8px; font-size: 0.85rem; }
  footer { margin-top: 36px; padding-top: 12px; border-top: 1px solid #ddd; color: #666; font-size: 0.8rem; }
</style>
</head>
<body>
  <h1>GreyNOC Code Scan Report</h1>
  <table class="summary">
    <tr><th>Target</th><td>${escapeReportHtml(payload.target || "")}</td></tr>
    <tr><th>Target type</th><td>${escapeReportHtml(payload.target_type || "")}</td></tr>
    <tr><th>Algorithm</th><td>${escapeReportHtml(payload.algorithm || "")}</td></tr>
    <tr><th>Generated</th><td>${escapeReportHtml(generated)}</td></tr>
    <tr><th>Files scanned</th><td>${escapeReportHtml(String(payload.files_scanned || 0))}</td></tr>
    <tr><th>Files skipped</th><td>${escapeReportHtml(String(payload.files_skipped || 0))}</td></tr>
    <tr><th>Bytes scanned</th><td>${escapeReportHtml(String(payload.bytes_scanned || 0))}</td></tr>
    <tr><th>Elapsed (s)</th><td>${escapeReportHtml(String(payload.elapsed_seconds || 0))}</td></tr>
    <tr><th>Risk</th><td>${escapeReportHtml(payload.risk || "")}</td></tr>
    <tr><th>Composite score</th><td>${score.toFixed(3)}</td></tr>
    ${gitRows}
  </table>
  <p><strong>Recommendation:</strong> ${escapeReportHtml(payload.recommendation || "")}</p>
  <div class="findings-summary">
    ${severityOrder
      .map(
        (severity) =>
          `<div class="count-card"><span>${escapeReportHtml(severity)}</span><strong>${counts[severity] || 0}</strong></div>`,
      )
      .join("")}
  </div>
  ${
    payload.redactions_present
      ? '<p class="redaction-banner"><strong>Redactions applied.</strong> Secret values in this report have been redacted to short prefix + sha256 placeholders. Originals never left the engine.</p>'
      : ""
  }
  ${
    sections ||
    '<p><em>No findings recorded. The scanner did not match any of its bundled rules against the target.</em></p>'
  }
  ${
    payload.suppressed_count
      ? `<h2>Suppressed</h2><p>${escapeReportHtml(String(payload.suppressed_count))} finding(s) suppressed via gn-slop: ignore comments in source.</p>`
      : ""
  }
  ${
    ruleErrors.length
      ? `<h2>Rule errors</h2><ul>${ruleErrors
          .map(
            (err) =>
              `<li><code>${escapeReportHtml(err.rule_id)}</code> on <code>${escapeReportHtml(err.file || "")}</code>: ${escapeReportHtml(err.error || "")}</li>`,
          )
          .join("")}</ul>`
      : ""
  }
  <footer>
    Generated by GreyNOC Slop Detection — local-only static scan, no model bundled.
    This report is a heuristic surface. Validate each finding before acting.
  </footer>
</body>
</html>`;
}

function triggerDownload(filename, content, mime) {
  const blob = new Blob([content], { type: `${mime};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  setTimeout(() => URL.revokeObjectURL(url), 4000);
}

function isoStamp() {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

function downloadFullReport() {
  if (!lastCodePayload) return;
  const html = buildReportHtml(lastCodePayload);
  triggerDownload(`greynoc-code-scan-${isoStamp()}.html`, html, "text/html");
}

function downloadJsonPayload() {
  if (!lastCodePayload) return;
  triggerDownload(
    `greynoc-code-scan-${isoStamp()}.json`,
    JSON.stringify(lastCodePayload, null, 2),
    "application/json",
  );
}

async function downloadSarifPayload() {
  if (!lastCodePayload) return;
  // For non-archive targets we ask the backend for an authoritative
  // SARIF; for archive scans the original archive is gone, so we
  // synthesize a minimal SARIF from the cached payload.
  const targetType = lastCodePayload.target_type;
  if (targetType === "archive" || !lastCodePayload.target) {
    triggerDownload(
      `greynoc-code-scan-${isoStamp()}.sarif.json`,
      JSON.stringify(buildClientSarif(lastCodePayload), null, 2),
      "application/sarif+json",
    );
    return;
  }
  try {
    // Reuse the include/exclude globs from the original scan so the
    // SARIF result matches what the dashboard already shows. Without
    // this, the backend would do a fresh unscoped scan and return
    // findings for files the user explicitly excluded.
    const response = await fetch("/api/v1/scan-code/sarif", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target: lastCodePayload.target,
        target_type: targetType,
        include_globs: lastCodePayload._scan_include_globs || [],
        exclude_globs: lastCodePayload._scan_exclude_globs || [],
      }),
    });
    if (!response.ok) {
      throw new Error("SARIF endpoint returned non-2xx");
    }
    const sarif = await response.json();
    triggerDownload(
      `greynoc-code-scan-${isoStamp()}.sarif.json`,
      JSON.stringify(sarif, null, 2),
      "application/sarif+json",
    );
  } catch (_error) {
    triggerDownload(
      `greynoc-code-scan-${isoStamp()}.sarif.json`,
      JSON.stringify(buildClientSarif(lastCodePayload), null, 2),
      "application/sarif+json",
    );
  }
}

function buildClientSarif(payload) {
  const findings = payload.findings || [];
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "GreyNOC Slop Detection",
            version: payload.algorithm || "code-picture-v2",
          },
        },
        results: findings.map((finding) => ({
          ruleId: finding.rule_id,
          level: ({ critical: "error", high: "error", medium: "warning" }[finding.severity] || "note"),
          message: { text: finding.description || finding.title },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: finding.file_path },
                region: { startLine: finding.line_start, endLine: finding.line_end },
              },
            },
          ],
          properties: {
            category: finding.category,
            confidence: finding.confidence,
            redacted: !!finding.redacted,
            llm_verdict: finding.llm_verdict || null,
          },
        })),
        properties: {
          target: payload.target,
          score: payload.score,
          risk: payload.risk,
          suppressed_count: payload.suppressed_count || 0,
          redactions_present: !!payload.redactions_present,
        },
      },
    ],
  };
}

function setHealth(state, label) {
  if (!healthDot || !healthLabel) {
    return;
  }
  healthDot.classList.remove("ok", "error");
  if (state === "ok" || state === "error") {
    healthDot.classList.add(state);
  }
  healthLabel.textContent = label;
}

async function checkHealth() {
  setHealth(null, "Checking service");
  try {
    const response = await fetch("/health", { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const payload = await response.json();
    const environment = payload.environment ? ` • ${payload.environment}` : "";
    setHealth("ok", `Backend ok${environment}`);
  } catch (error) {
    setHealth("error", "Backend unreachable");
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
if (mediaModeButton) {
  mediaModeButton.addEventListener("click", () => setMode("media"));
}
if (codeModeButton) {
  codeModeButton.addEventListener("click", () => setMode("code"));
}
textInput.addEventListener("input", updateCounter);
urlInput.addEventListener("input", updateCounter);
if (mediaInput) {
  mediaInput.addEventListener("change", () => {
    if (mediaInputName) {
      const file = mediaInput.files?.[0];
      mediaInputName.textContent = file ? file.name : "No file chosen";
    }
    updateCounter();
  });
}
if (codeTargetTypeSelect) {
  codeTargetTypeSelect.addEventListener("change", () => {
    const isArchive = codeTargetTypeSelect.value === "archive";
    if (codeTargetTextWrap) codeTargetTextWrap.hidden = isArchive;
    if (codeTargetArchiveWrap) codeTargetArchiveWrap.hidden = !isArchive;
    updateCounter();
  });
}
if (codeTargetInput) {
  codeTargetInput.addEventListener("input", updateCounter);
}
if (codeArchiveInput) {
  codeArchiveInput.addEventListener("change", () => {
    if (codeArchiveInputName) {
      const file = codeArchiveInput.files?.[0];
      codeArchiveInputName.textContent = file ? file.name : "No archive chosen";
    }
    updateCounter();
  });
}
if (expandAllButton) {
  expandAllButton.addEventListener("click", () => {
    const anyCollapsed = Array.from(
      signalsTable.querySelectorAll(".finding-detail-row"),
    ).some((row) => row.hidden);
    setAllFindingsExpanded(anyCollapsed);
  });
}
if (downloadReportButton) {
  downloadReportButton.addEventListener("click", downloadFullReport);
}
if (downloadJsonButton) {
  downloadJsonButton.addEventListener("click", downloadJsonPayload);
}
if (downloadSarifButton) {
  downloadSarifButton.addEventListener("click", downloadSarifPayload);
}
if (findingsSeverityFilter) {
  findingsSeverityFilter.addEventListener("change", applyCodeFilters);
}
if (findingsCategoryFilter) {
  findingsCategoryFilter.addEventListener("change", applyCodeFilters);
}
if (findingsTextFilter) {
  findingsTextFilter.addEventListener("input", applyCodeFilters);
}
form.addEventListener("submit", analyzeText);
updateCounter();
updateAiLlmPanel(inputMode);
loadThreshold();
renderDimensions([]);
renderProfile(null);

if (healthButton) {
  healthButton.addEventListener("click", () => {
    checkHealth();
  });
}
checkHealth();
window.setInterval(checkHealth, 30000);
