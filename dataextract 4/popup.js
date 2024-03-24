const VTOTAL_API_KEY = "3fe4c1183f7fa6781431595ee9fe2437bac4fa9552a94254717c0d6dab2c5313";

document.addEventListener("DOMContentLoaded", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
    const activeTab = tabs[0];
    chrome.scripting.executeScript(
      {
        target: { tabId: activeTab.id },
        func: () => {
          return document.location.href;
        },
      },
      async (response) => {
        const currentTabUrl = response[0].result;

        if (!currentTabUrl) {
          console.log("Could not get data from page.");
          return;
        }

        try {
          const scanResult = await scanPage(currentTabUrl);
          const stats = await getAnalytics(scanResult);
          insertData(stats);
        } catch (error) {
          console.error(error);
        }
      }
    );
  });
});

async function scanPage(url) {
  const response = await fetch(`https://www.virustotal.com/api/v3/urls`, {
    headers: {
      "X-Apikey": VTOTAL_API_KEY,
      "accept": "application/json",
      "content-type": "application/x-www-form-urlencoded",
    },
    method: "POST",
    body: new URLSearchParams({ url: url }),
  });
  const data = await response.json();
  
  console.log(data.data.links.self);
  return data.data.links.self;
}

async function getAnalytics(url) {
  const response = await fetch(url, {
    headers: {
      "X-Apikey": VTOTAL_API_KEY,
      "accept": "application/json",
    },
    method: "GET",
  });
  const data = await response.json();
  console.log(data.data.attributes.stats);
  return data.data.attributes.stats;
}

function insertData(stats) {
  var mal = stats.malicious || 0;
  var sus = stats.suspicious || 0;
  var undec = stats.undetected || 0;
  var harm = stats.harmless || 0;
  var time = stats.timeout || 0;

  var total = mal + sus + undec + harm + time;
  var average = total / 5;
  var finalCalc = (average / 100) * 100;

  if (finalCalc < 30) {
    alert("This site is not safe to view");
  }
  document.getElementById("malicious").innerHTML = mal.toString();
  document.getElementById("suspicious").innerHTML = sus.toString();
  document.getElementById("harm").innerHTML = harm.toString();
  document.getElementById("timeout").innerHTML = time.toString();
  document.getElementById("undetect").innerHTML = undec.toString();
}
