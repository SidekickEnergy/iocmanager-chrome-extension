/* popup.js */

async function getBaseUrl() {
  return new Promise((resolve) => {
    chrome.storage.local.get(["baseUrl"], (data) => {
      // default to production if not set
      resolve((data.baseUrl && data.baseUrl.trim()));
    });
  });
}

function getStoredApiKeys() {
  return new Promise((resolve) => {
    chrome.storage.local.get([
      "virustotal_apiKey",
      "misp_url",
      "misp_apiKey",
      "edl_url",
      "edl_apiKey",
      "dnsdb_apiKey",
      "dnsdb_url",
      "abuseipdb_apiKey",
      "otx_apiKey",
      "umbrella_apiKey",
      "umbrella_apiSecret"
    ], (data) => {
      const api_keys = {};
      if (data.virustotal_apiKey) api_keys.virustotal = { apiKey: data.virustotal_apiKey };
      if (data.misp_apiKey || data.misp_url) {
        api_keys.misp = {
          apiKey: data.misp_apiKey || "",
          baseUrl: data.misp_url || ""
        };
      }

      if (data.edl_apiKey || data.edl_url) {
        api_keys.edl = {
          apiKey: data.edl_apiKey || "",
          baseUrl: data.edl_url || ""
        };
      }
      
      if (data.dnsdb_apiKey || data.dnsdb_url) {
        api_keys.dnsdb = { apiKey: data.dnsdb_apiKey || "", baseUrl: data.dnsdb_url || "" };
      }

      if (data.abuseipdb_apiKey) {
        api_keys.abuseipdb = { apiKey: data.abuseipdb_apiKey };
      }
      
      if (data.otx_apiKey) api_keys.otx = { apiKey: data.otx_apiKey };

      if (data.umbrella_apiKey && data.umbrella_apiSecret) {
        api_keys.umbrella = {
          apiKey: data.umbrella_apiKey,
          apiSecret: data.umbrella_apiSecret
        };
      }

      resolve(api_keys);
    });
  });
}

function logStatus(message) {
  const logArea = document.getElementById("statusLog");
  if (!logArea) return;
  logArea.textContent += message + "\n";
}

async function enrichIoCs(iocList) {
  const loadingIndicator = document.getElementById("loading");
  const output = document.getElementById("results");

  try {
    loadingIndicator.style.display = "block";
    output.innerHTML = "";

    const api_keys = await getStoredApiKeys();

    const baseUrl = await getBaseUrl();
    const response = await fetch(`${baseUrl}/enrich`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        iocs: iocList,
        verbose: true,
        api_keys  // new nested structure
      })
    });


    // Always try to parse the JSON body, even on error
    const text = await response.text();
    let result = null;

    try {
      result = JSON.parse(text);
    } catch (parseError) {
      console.error("Failed to parse JSON:", parseError);
      output.textContent = "Malformed response from backend.";
      return;
    }

    if (!Array.isArray(result)) {
      console.error("Unexpected API result format:", result);
      output.textContent = "Unexpected response format.";
      return;
    }

    // Show partial results even if some enrichments failed
    chrome.storage.local.set({ iocResults: result }, () => {
      displaySummary(result);
      displayResults(result);
    });

  } catch (error) {
    console.error("Enrichment failed:", error);
    output.textContent = "Error occurred during enrichment.";
  } finally {
    loadingIndicator.style.display = "none";
  }
}


function displaySummary(results) {
  const summary = document.getElementById("summary");
  summary.innerHTML = "";

  results.forEach((ioc) => {
  const card = document.createElement("div");
  card.classList.add("summary-card");

  // Title + Block link wrapper
  const titleRow = document.createElement("div");
  titleRow.classList.add("summary-title-row");

  const title = document.createElement("h4");
  title.textContent = `${ioc.ioc} (${ioc.type})`;

  const blockLink = document.createElement("a");
  blockLink.textContent = "Block";
  const encodedIoC = encodeURIComponent(ioc.ioc);
  blockLink.href = chrome.runtime.getURL(`block/block.html?ioc=${encodedIoC}`);
  blockLink.target = "_blank";
  blockLink.className = "block-link";

  titleRow.appendChild(title);
  titleRow.appendChild(blockLink);
  card.appendChild(titleRow);

    const enrichment = ioc.enrichment || {};

    // === Intelligence Section ===
    const intelList = document.createElement("ul");
    let hasIntel = false;
    const intelBlocks = {};

    if (enrichment.abuseipdb?.abuse_score !== undefined) {
      const abuse = enrichment.abuseipdb;
      const score = abuse.abuse_score;
      const severityClass = score >= 61 ? "bad" : score >= 1 ? "warn" : "good";

      const subsection = document.createElement("div");
      subsection.className = "intel-subsection";

      subsection.innerHTML = `
        <div class="intel-subtitle">
          <a href="https://www.abuseipdb.com/check/${ioc.ioc}" target="_blank" rel="noopener noreferrer">AbuseIPDB</a>
        </div>

        <div class="vt-score-row">
          <div class="vt-score-box ${severityClass}">
            <div class="score">${score}%</div>
            <div class="label">Confidence of abuse</div>
          </div>
        </div>
        <ul class="abuse-details">
          <li>ISP: ${abuse.isp || "N/A"}</li>
          <li>Country: ${abuse.country || "N/A"}</li>
          <li>Total Reports: ${abuse.total_reports || 0}</li>
          <li>Last Reported: ${abuse.last_reported ? new Date(abuse.last_reported).toLocaleDateString() : "N/A"}</li>
        </ul>
      `;

      intelBlocks["abuseipdb"] = subsection;   // for AbuseIPDB
      hasIntel = true;
    }


    if (enrichment.dnsdb && (enrichment.dnsdb.related_ips?.length || enrichment.dnsdb.related_domains?.length)) {
      const dns = enrichment.dnsdb;
      const subsection = document.createElement("div");
      subsection.className = "intel-subsection";

      subsection.innerHTML = `
        <div class="intel-subtitle"><span>DNSDB</span></div>
        <ul class="dnsdb-list">
          <li><strong>Raw Query Count:</strong> ${dns.raw_count ?? "N/A"}</li>
          ${dns.related_domains?.length ? `<li><strong>Related Domains:</strong> ${dns.related_domains.join(", ")}</li>` : ""}
          ${dns.related_ips?.length ? `<li><strong>Related IPs:</strong> ${dns.related_ips.join(", ")}</li>` : ""}
        </ul>
      `;

      intelBlocks["dnsdb"] = subsection;
      hasIntel = true;
    }

    if (enrichment.misp?.hits?.length > 0) {
      const hits = enrichment.misp.hits;
      const firstHit = hits[0];

      const subsection = document.createElement("div");
      subsection.className = "intel-subsection";

      subsection.innerHTML = `
        <div class="intel-subtitle"><span>MISP</span></div>
        <ul class="misp-list">
          <li><strong>Category:</strong> ${firstHit.category || "N/A"}</li>
          <li><strong>Comment:</strong> ${firstHit.comment || "N/A"}</li>
          <li><strong>Event:</strong> ${firstHit.event_info || "N/A"}</li>
          <li><strong>Published:</strong> ${firstHit.event_published || "N/A"}</li>
          <li><strong>Type:</strong> ${firstHit.type || "N/A"}</li>
        </ul>
      `;

      intelBlocks["misp"] = subsection;
      hasIntel = true;
    }

if (enrichment.virustotal) {
  const vt = enrichment.virustotal;
  const stats = vt.last_analysis_stats || {};
  const tags = (vt.tags || []).join(", ");
  const vtLink = vt.vt_link || `https://www.virustotal.com/gui/search/${ioc.ioc}`;

  const vtBlock = document.createElement("div");
  vtBlock.className = "intel-subsection";

  const vtTitle = document.createElement("div");
  vtTitle.className = "intel-subtitle";
  vtTitle.innerHTML = `<a href="${vtLink}" target="_blank" rel="noopener noreferrer">VirusTotal</a>`;
  vtBlock.appendChild(vtTitle);

  const vtScores = document.createElement("div");
  vtScores.className = "vt-score-row";

  const repBox = document.createElement("div");
  repBox.className = "vt-score-box";
  repBox.innerHTML = `<div class="score">${vt.reputation ?? "N/A"}</div><div class="label">Reputation</div>`;
  vtScores.appendChild(repBox);

  const malBox = document.createElement("div");
  malBox.className = "vt-score-box";
  if ((stats.malicious || 0) > 0) malBox.classList.add("bad");
  malBox.innerHTML = `<div class="score">${stats.malicious || 0}</div><div class="label">Malicious</div>`;
  vtScores.appendChild(malBox);

  const suspBox = document.createElement("div");
  suspBox.className = "vt-score-box";
  if ((stats.suspicious || 0) > 0) suspBox.classList.add("bad");
  suspBox.innerHTML = `<div class="score">${stats.suspicious || 0}</div><div class="label">Suspicious</div>`;
  vtScores.appendChild(suspBox);

  vtBlock.appendChild(vtScores);

  if (tags) {
    const tagLine = document.createElement("div");
    tagLine.className = "vt-tags";
    tagLine.textContent = `Tags: ${tags}`;
    vtBlock.appendChild(tagLine);
  }

  intelBlocks["virustotal"] = vtBlock;
  hasIntel = true;
}




if (enrichment.otx?.pulse_count > 0) {
  const pulses = enrichment.otx.pulses || [];

  const subsection = document.createElement("div");
  subsection.className = "intel-subsection";

  const otxType = (ioc.type === "ipv4" || ioc.type === "ipv6") ? "ip" : ioc.type;
  subsection.innerHTML = `
    <div class="intel-subtitle">
      <a href="https://otx.alienvault.com/indicator/${otxType}/${ioc.ioc}" target="_blank" rel="noopener noreferrer">AlienVault OTX</a>
    </div>
    <div class="otx-pulse-count">
      ${pulses.length} pulse${pulses.length !== 1 ? "s" : ""} found
    </div>
  `;

  // Collect all unique tags across pulses
  const tagSet = new Set();
  pulses.forEach(p => (p.tags || []).forEach(tag => tagSet.add(tag)));
  if (tagSet.size > 0) {
    const tagWrap = document.createElement("div");
    tagWrap.className = "otx-tags";
    [...tagSet].slice(0, 10).forEach(tag => {
      const tagElem = document.createElement("span");
      tagElem.className = "tag";
      tagElem.textContent = tag;
      tagWrap.appendChild(tagElem);
    });
    subsection.appendChild(tagWrap);
  }

  // Expandable pulse list
  const toggleBtn = document.createElement("div");
  toggleBtn.className = "otx-desc-toggle";
  toggleBtn.textContent = "Show all pulses";
  subsection.appendChild(toggleBtn);

  const pulseContainer = document.createElement("div");
  pulseContainer.style.display = "none";

  pulses.sort((a, b) => new Date(b.created) - new Date(a.created));
  pulses.forEach(pulse => {
    const pulseBox = document.createElement("div");
    pulseBox.className = "otx-pulse";

    const title = document.createElement("div");
    title.className = "otx-title";
    const date = pulse.created ? new Date(pulse.created).toISOString().split("T")[0] : "Unknown";
    const cleanName = pulse.name?.replace(/<[^>]*>/g, "").trim() || "Unnamed Pulse";

    if (pulse.id) {
      const url = `https://otx.alienvault.com/pulse/${pulse.id}`;
      title.innerHTML = `<a href="${url}" target="_blank" class="otx-pulse-link">${cleanName}</a> <span class="otx-date">(${date})</span>`;
    } else {
      title.innerHTML = `${cleanName} <span class="otx-date">(${date})</span>`;
    }
    pulseBox.appendChild(title);

    // Description toggle
    if (pulse.description?.trim()) {
      const descToggle = document.createElement("div");
      descToggle.className = "otx-desc-toggle";
      descToggle.textContent = "Show Description";

      const descBox = document.createElement("div");
      descBox.className = "otx-description";
      descBox.textContent = pulse.description;
      descBox.style.display = "none";

      descToggle.onclick = () => {
        const isHidden = descBox.style.display === "none";
        descBox.style.display = isHidden ? "block" : "none";
        descToggle.textContent = isHidden ? "Hide Description" : "Show Description";
      };

      pulseBox.appendChild(descToggle);
      pulseBox.appendChild(descBox);
    }

    // Tags inside pulse
    if (pulse.tags?.length) {
      const tags = document.createElement("div");
      tags.className = "otx-tags";
      pulse.tags.slice(0, 10).forEach(tag => {
        const span = document.createElement("span");
        span.className = "tag";
        span.textContent = tag;
        tags.appendChild(span);
      });
      pulseBox.appendChild(tags);
    }

    pulseContainer.appendChild(pulseBox);
  });

  toggleBtn.onclick = () => {
    const expanded = pulseContainer.style.display === "block";
    pulseContainer.style.display = expanded ? "none" : "block";
    toggleBtn.textContent = expanded ? "Show all pulses" : "Hide pulses";
  };

  subsection.appendChild(pulseContainer);
  intelBlocks["otx"] = subsection;
  hasIntel = true;
}





if (hasIntel) {
  const section = document.createElement("div");
  section.classList.add("summary-section");
  section.innerHTML = `<strong>Intelligence:</strong>`;

    const order = ["virustotal", "abuseipdb", "otx", "misp", "dnsdb", "defender"];
    order.forEach(key => {
      if (intelBlocks[key]) section.appendChild(intelBlocks[key]);
    });

    card.appendChild(section);
  }

   // === Protection Section ===
const protectList = document.createElement("div");
protectList.className = "protection-list";
let hasProtection = false;

if (enrichment.defender) {
  hasProtection = true;

  const defenderSection = document.createElement("div");
  defenderSection.classList.add("intel-subsection");

  const subtitle = document.createElement("div");
  subtitle.classList.add("intel-subtitle");
  subtitle.textContent = "Microsoft Defender";
  defenderSection.appendChild(subtitle);

  const summaryText = document.createElement("div");
  summaryText.classList.add("defender-summary");
  summaryText.textContent = enrichment.defender.found_in_hunting
    ? "Observed in telemetry"
    : "Not found in telemetry";
  defenderSection.appendChild(summaryText);

  const counts = { informational: 0, low: 0, medium: 0, high: 0, unknown: 0 };
  enrichment.defender.alerts?.forEach(alert => {
    const sev = alert.Severity?.toLowerCase();
    if (counts.hasOwnProperty(sev)) counts[sev]++;
    else counts.unknown++;
  });

  const countRow = document.createElement("div");
  countRow.className = "defender-score-row";

  ["informational", "low", "medium", "high"].forEach(level => {
    const countBox = document.createElement("div");
    countBox.className = `defender-score-box ${counts[level] > 0 ? level : ""}`;
    countBox.innerHTML = `
      <div class="score">${counts[level]}</div>
      <div class="label">${level.charAt(0).toUpperCase() + level.slice(1)}</div>
    `;
    countRow.appendChild(countBox);
  });

  defenderSection.appendChild(countRow);

  if (enrichment.defender.alerts?.length > 0) {
    const toggle = document.createElement("div");
    toggle.classList.add("defender-toggle");
    toggle.textContent = "Show alerts";

    const alertList = document.createElement("div");
    alertList.classList.add("defender-alerts");
    alertList.style.display = "none";

    enrichment.defender.alerts.forEach(alert => {
      const box = document.createElement("div");
      const severity = alert.Severity?.toLowerCase() || "unknown";
      box.className = `defender-alert-box ${severity}`;

      const title = document.createElement("div");
      title.innerHTML = `<strong><a class="defender-alert-link" href="${alert.AlertLink}" target="_blank">${alert.Title || "Unknown Title"}</a></strong> (${alert.Severity || "Unknown"})`;

      const time = document.createElement("div");
      time.textContent = `Detected: ${new Date(alert.TimeGenerated).toLocaleString()}`;

      const details = document.createElement("div");
      details.style.color = "#111";
      details.innerHTML = [alert.DeviceName ? `Device: ${alert.DeviceName}` : "", alert.RemoteIP ? `Remote IP: ${alert.RemoteIP}` : "", alert.RemoteUrl ? `Remote URL: ${alert.RemoteUrl}` : ""].filter(Boolean).join(" | ");

      box.appendChild(title);
      box.appendChild(time);
      if (details.innerHTML) box.appendChild(details);

      alertList.appendChild(box);
    });

    toggle.addEventListener("click", () => {
      const isVisible = alertList.style.display === "block";
      alertList.style.display = isVisible ? "none" : "block";
      toggle.textContent = isVisible ? "Show alerts" : "Hide alerts";
    });

    defenderSection.appendChild(toggle);
    defenderSection.appendChild(alertList);
    
  }

  protectList.appendChild(defenderSection);
}

/* if (enrichment.umbrella?.blocked !== undefined) {
  hasProtection = true;
  const umb = document.createElement("div");
  umb.className = "intel-subsection";

  const subtitle = document.createElement("div");
  subtitle.classList.add("intel-subtitle");
  subtitle.textContent = "Cisco Umbrella";

  const status = document.createElement("div");
  status.textContent = enrichment.umbrella.blocked ? "BLOCKED" : "Not blocked";

  umb.appendChild(subtitle);
  umb.appendChild(status);
  protectList.appendChild(umb);
} */

if (enrichment.edl?.blocked !== undefined) {
  hasProtection = true;

  const edlBox = document.createElement("div");
  edlBox.className = "intel-subsection";

  const subtitle = document.createElement("div");
  subtitle.className = "intel-subtitle";
  subtitle.textContent = "EDL";

  const status = document.createElement("div");
  status.textContent = enrichment.edl.blocked ? "BLOCKED" : "Not blocked";

  edlBox.appendChild(subtitle);
  edlBox.appendChild(status);
  protectList.appendChild(edlBox);
}


if (hasProtection) {
  const section = document.createElement("div");
  section.classList.add("summary-section");
  section.innerHTML = `<strong>Protection:</strong>`;
  section.appendChild(protectList);
  card.appendChild(section);
}

    summary.appendChild(card);
  });
}

function displayResults(results) {
  const output = document.getElementById("results");
  output.innerHTML = "";

  results.forEach((ioc) => {
    const wrapper = document.createElement("div");
    wrapper.classList.add("ioc-block");

    const header = document.createElement("h4");
    header.textContent = `${ioc.ioc} (${ioc.type})`;
    wrapper.appendChild(header);

    const enrichment = ioc.enrichment || {};
    Object.entries(enrichment).forEach(([source, data]) => {
      const section = document.createElement("div");
      section.classList.add("source-block");

      const title = document.createElement("div");
      title.textContent = source.toUpperCase();
      title.classList.add("collapsible-title");
      section.appendChild(title);

      const content = document.createElement("div");
      content.classList.add("collapsible-content");

      const list = document.createElement("ul");
      appendDataAsListItems(list, data, 1);
      content.appendChild(list);

      section.appendChild(content);
      wrapper.appendChild(section);
    });

    output.appendChild(wrapper);
    output.appendChild(document.createElement("hr"));
  });
}

function appendDataAsListItems(parent, data, depth) {
  if (typeof data !== "object" || data === null) return;

  Object.entries(data).forEach(([key, val]) => {
    const item = document.createElement("li");

    if (Array.isArray(val)) {
      item.innerHTML = `<strong>${key}:</strong>`;
      const nestedList = document.createElement("ul");
      val.forEach((v) => {
        const li = document.createElement("li");
        if (typeof v === "object" && v !== null) {
          const subList = document.createElement("ul");
          appendDataAsListItems(subList, v, depth + 1);
          li.appendChild(subList);
        } else {
          li.textContent = v;
        }
        nestedList.appendChild(li);
      });
      item.appendChild(nestedList);
    } else if (typeof val === "object" && val !== null) {
      item.innerHTML = `<strong>${key}:</strong>`;
      const nestedList = document.createElement("ul");
      appendDataAsListItems(nestedList, val, depth + 1);
      item.appendChild(nestedList);
    } else {
      item.innerHTML = `<strong>${key}:</strong> ${val}`;
    }

    parent.appendChild(item);
  });
}

document.getElementById("enrichBtn").addEventListener("click", () => {
  chrome.storage.local.remove("iocResults");
  const input = document.getElementById("iocInput").value;
  const iocList = input.split(/\s+/).filter(Boolean);
  if (iocList.length > 0) enrichIoCs(iocList);
});

document.getElementById("iocInput").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    document.getElementById("enrichBtn").click();
  }
});

document.addEventListener("DOMContentLoaded", () => {
  chrome.storage.local.get(["iocResults", "selectedIoC"], (data) => {
    if (data.selectedIoC) {
      const inputField = document.getElementById("iocInput");
      inputField.value = data.selectedIoC;
      chrome.storage.local.remove("selectedIoC");
      enrichIoCs([data.selectedIoC]);
    } else if (data.iocResults) {
      displaySummary(data.iocResults);
      displayResults(data.iocResults);
    }
  });
});

document.addEventListener("click", function (e) {
  if (e.target.classList.contains("collapsible-title")) {
    e.target.classList.toggle("active");
    const content = e.target.nextElementSibling;
    if (content) {
      content.style.display = content.style.display === "block" ? "none" : "block";
    }
  }
});
