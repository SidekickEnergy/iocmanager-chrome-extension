const STORAGE_KEY = 'ioc_block_settings';
let userProfile = {};

async function getBaseUrl() {
  return new Promise((resolve) => {
    chrome.storage.local.get(["baseUrl"], (data) => {
      // default to production if not set
      resolve((data.baseUrl && data.baseUrl.trim()) || "https://iocmanager.azurewebsites.net");
    });
  });
}

// === Reusable IP Validator ===
function isValidIP(ip) {
  return /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(ip);
}

document.addEventListener("DOMContentLoaded", async () => {
  const params = new URLSearchParams(window.location.search);
  const ioc = params.get("ioc") || "";
  const iocInput = document.getElementById("ioc");

  // === Enable/Disable EDL Section Based on IP Validity ===
  function updateEDLSectionState(iocValue) {
    const edlSection = document.querySelector('[data-service="edl"]');
    const edlCheckbox = edlSection.querySelector('.service-toggle');

    const isValid = isValidIP(iocValue.trim());

    edlCheckbox.disabled = !isValid;
    edlSection.classList.toggle("disabled", !isValid);

    if (!isValid) {
      edlCheckbox.checked = false;  // 🔧 force uncheck
    }

    console.log(`[EDL] ${isValid ? "Enabled" : "Disabled"} for value: ${iocValue}`);
  }

  // === Initialize Input Field ===
  if (iocInput) {
    iocInput.value = ioc;
    updateEDLSectionState(ioc);

    iocInput.addEventListener("input", () => {
      updateEDLSectionState(iocInput.value.trim());
    });
  }

  // === Load User Profile from Local Storage ===
  chrome.storage.local.get(["userFirstName", "userLastName", "userOrg", "userEmail"], (data) => {
    userProfile = {
      first_name: data.userFirstName || "",
      last_name: data.userLastName || "",
      organization: data.userOrg || "",
      email: data.userEmail || ""
    };
  });

  // === Load Umbrella Lists & Restore Block Settings ===
  await loadUmbrellaLists();
  restoreSettingsFromLocalStorage(ioc);
});




// Save settings to localStorage
function saveSettingsToLocalStorage() {
  const settingsData = {
    ioc: document.getElementById('ioc').value.trim(),
    services: {}
  };

  document.querySelectorAll('.service-section').forEach(section => {
    const service = section.dataset.service;
    const isEnabled = section.querySelector('.service-toggle').checked;
    const config = {};

    section.querySelectorAll('select').forEach(select => {
      const label = select.previousSibling.textContent.trim().replace(/:$/, '');
      config[label] = select.value;
    });

    settingsData.services[service] = { enabled: isEnabled, config };
  });

  localStorage.setItem(STORAGE_KEY, JSON.stringify(settingsData));
}

// Restore settings
function restoreSettingsFromLocalStorage(initialIoc = "") {
  const saved = localStorage.getItem(STORAGE_KEY);
  if (!saved) return;

  try {
    const data = JSON.parse(saved);

    const iocInput = document.getElementById('ioc');
    if (iocInput && !initialIoc && data.ioc) {
      // Only overwrite if URL param wasn't used
      iocInput.value = data.ioc;
    }

    Object.entries(data.services).forEach(([service, { enabled, config }]) => {
      const section = document.querySelector(`.service-section[data-service="${service}"]`);
      if (!section) return;

      const toggle = section.querySelector('.service-toggle');

      // Skip restoring EDL toggle if IoC is invalid
      if (service === "edl") {
        const iocValue = document.getElementById("ioc").value.trim();
        const isValid = isValidIP(iocValue);
        toggle.disabled = !isValid;
        section.classList.toggle("disabled", !isValid);

        if (!isValid) {
          toggle.checked = false;
          console.warn("Skipping EDL toggle: IoC is not a valid IP");
        } else {
          toggle.checked = enabled;
          toggle.dispatchEvent(new Event('change'));
        }
      } else {
        toggle.checked = enabled;
        toggle.dispatchEvent(new Event('change'));
      }


      // Restore toggle as normal for all other services
      if (!(service === "edl" && !isValidIP(document.getElementById("ioc").value.trim()))) {
        toggle.checked = enabled;
        toggle.dispatchEvent(new Event('change'));
      }

      section.querySelectorAll('select').forEach(select => {
        const label = select.previousSibling.textContent.trim().replace(/:$/, '');
        if (config[label]) {
          select.value = config[label];
        }
      });
    });
  } catch (e) {
    console.error("Failed to load saved settings:", e);
  }
}


// Handle toggles
document.querySelectorAll('.service-toggle').forEach(toggle => {
  toggle.addEventListener('change', () => {
    const section = toggle.closest('.service-section');
    section.classList.toggle('active', toggle.checked);
    saveSettingsToLocalStorage();
  });
});

// Save on change/input
document.querySelectorAll('select, #ioc').forEach(input => {
  input.addEventListener('change', saveSettingsToLocalStorage);
  input.addEventListener('input', saveSettingsToLocalStorage);
});

// Submit
document.getElementById('submit').addEventListener('click', () => {
  const ioc = document.getElementById('ioc').value.trim();
  if (!ioc) {
    alert("Please enter an IoC.");
    return;
  }

 const selectedServices = [];

  document.querySelectorAll('.service-toggle:checked').forEach(toggle => {
    const section = toggle.closest('.service-section');
    const service = section.dataset.service;

    const config = {};
    section.querySelectorAll('select, input[type="text"]').forEach(input => {
      if (input.name) {
        config[input.name] = input.value;
      }
    });

    selectedServices.push({ service, config });
  });


  console.log("Submitting IoC:", ioc);
  console.log("With services:", selectedServices);

      selectedServices.forEach(async ({ service, config }) => {

        if (service === "misp") {
          const { misp_apiKey, misp_url } = await new Promise((resolve) => {
            chrome.storage.local.get(["misp_apiKey", "misp_url"], (data) => {
              resolve({ misp_apiKey: data.misp_apiKey || null, misp_url: data.misp_url || "" });
            });
          });

          if (!misp_apiKey) {
            alert("Missing MISP API key — please configure it in the extension options.");
            return;
          }

          const payload = {
            ioc,
            ioc_type: "domain", // optionally dynamic
            tlp: config["tlp"],
            comment: config["comment"],
            api_key: misp_apiKey,
            base_url: misp_url || "",
            ...userProfile
          };

          try {
            const baseUrl = await getBaseUrl();
            const res = await fetch(`${baseUrl}/misp/block`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(payload)
            });

            const result = await res.json();
            if (res.ok && result && result.success && result.event_id) {
              alert(`MISP: IoC added to event ID ${result.event_id}`);
            } else {
              alert(`MISP Error: ${result?.error || "Unexpected response"}`);
            }
          } catch (err) {
            console.error("Failed to submit to MISP:", err);
            alert("Failed to submit to MISP.");
          }
        }



        if (service === "edl") {
          chrome.storage.local.get(["edl_apiKey", "edl_url"], async (res) => {
            const payload = {
              ip: ioc,
              action: config["action"],
              apikey: res.edl_apiKey,
              edl_base_url: res.edl_url
            };

            try {
              const baseUrl = await getBaseUrl();
              const resp = await fetch(`${baseUrl}/edl/block`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
              });

              const result = await resp.json();
              if (resp.ok) {
                alert(`EDL: ${payload.action} successful`);
              } else {
                alert(`EDL Error: ${result.error || "unknown error"}`);
              }
            } catch (err) {
              console.error("Failed to submit to EDL:", err);
              alert("Failed to submit to EDL.");
            }
          });
        }



      
        if (service === "umbrella") {
          const now = new Date();
          const day = String(now.getDate()).padStart(2, '0');
          const month = String(now.getMonth() + 1).padStart(2, '0');
          const year = now.getFullYear();
          const hours = String(now.getHours()).padStart(2, '0');
          const minutes = String(now.getMinutes()).padStart(2, '0');

          const timestamp = `${day}/${month}/${year} ${hours}:${minutes}`;
          let comment = config["comment"]?.trim();
          if (!comment) {
            comment = `Added by ${userProfile.first_name} ${userProfile.last_name} @ ${timestamp}`;
          }


          const { umbrella_apiKey, umbrella_apiSecret } = await new Promise((resolve) =>
            chrome.storage.local.get(["umbrella_apiKey", "umbrella_apiSecret"], resolve)
          );

          if (!umbrella_apiKey || !umbrella_apiSecret) {
            alert("Missing Umbrella credentials — please set them in the options page.");
            return;
          }

          const payload = {
            ioc,
            list_id: config["destination_list"],
            comment: comment,
            api_key: umbrella_apiKey,
            api_secret: umbrella_apiSecret
          };


          console.log("Payload being sent:", payload);
          try {
            const baseUrl = await getBaseUrl();
            const res = await fetch(`${baseUrl}/enrich`, {
              method: "POST",
              headers: {
                "Content-Type": "application/json"
              },
              body: JSON.stringify(payload)
            });

            const result = await res.json();
            if (res.ok) {
              alert(`Umbrella: ${result.message}`);
            } else {
              console.error(result.error);
              alert(`Umbrella Error: ${result.error}`);
            }
          } catch (err) {
            console.error("Failed to submit to Umbrella:", err);
            alert("Failed to submit to Umbrella.");
          }
        }

      // Future services (e.g. defender) can go here
    });

});

// Load Umbrella lists
async function loadUmbrellaLists() {
  try {
    const { umbrella_apiKey, umbrella_apiSecret } = await new Promise((resolve) =>
      chrome.storage.local.get(["umbrella_apiKey", "umbrella_apiSecret"], resolve)
    );

    if (!umbrella_apiKey || !umbrella_apiSecret) {
      console.warn("Missing Umbrella credentials — skipping list fetch.");
      return;
    }

    const baseUrl = await getBaseUrl();
    const url = new URL(`${baseUrl}/umbrella/destination-lists`);
    url.searchParams.set("api_key", umbrella_apiKey);
    url.searchParams.set("api_secret", umbrella_apiSecret);

    const res = await fetch(url.toString());
    const data = await res.json();

    const select = document.querySelector("#umbrella-list-select");
    select.innerHTML = "";

    if (!Array.isArray(data)) {
      console.warn("Umbrella destination list fetch failed:", data.error || data);
      const option = document.createElement("option");
      option.disabled = true;
      option.textContent = `Failed to load lists: ${data.error || "Unknown error"}`;
      select.appendChild(option);
      return;
    }

    data.forEach(list => {
      const option = document.createElement("option");
      option.value = list.id;
      option.textContent = list.name;
      select.appendChild(option);
    });

  } catch (err) {
    console.error("Failed to fetch Umbrella destination lists:", err);
    const select = document.querySelector("#umbrella-list-select");
    select.innerHTML = "";
    const option = document.createElement("option");
    option.disabled = true;
    option.textContent = "Failed to load lists";
    select.appendChild(option);
  }
}

