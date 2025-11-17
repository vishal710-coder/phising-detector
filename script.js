let riskChartInstance = null;

// ------------------ HEURISTIC RULES ------------------
const HEURISTIC_RULES = {
    urlLength: {
        name: "AI Feature 1: URL Length (> 75 chars)",
        weight: 20,
        check: (url) => url.length > 75,
        description: "Long URLs can obscure suspicious domains."
    },
    ipAddressInHost: {
        name: "AI Feature 2: IP Address in Hostname",
        weight: 40,
        check: (url, parsed) => {
            if (!parsed.hostname) return false;
            const ipV4Regex = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
            return ipV4Regex.test(parsed.hostname);
        },
        description: "IP addresses bypass domain safety checks."
    },
    atSymbolPresence: {
        name: "AI Feature 3: '@' Symbol",
        weight: 30,
        check: (url) => url.includes('@'),
        description: "'@' symbol can redirect to malicious targets."
    },
    subdomainDepth: {
        name: "AI Feature 4: Excessive Subdomain Depth (>2)",
        weight: 25,
        check: (url, parsed) => parsed.hostname.split('.').length > 3,
        description: "Too many subdomains may hide malicious roots."
    },
    suspiciousKeywords: {
        name: "AI Feature 5: Suspicious Keywords",
        weight: 15,
        check: (url) => {
            const keywords = ['login', 'secure', 'verify', 'account', 'update', 'banking'];
            const lower = url.toLowerCase();
            return keywords.some(k => lower.includes(k));
        },
        description: "Keywords used to trigger urgency."
    }
};

// ------------------ MAIN ANALYSIS ------------------
function analyzeURL(url) {
    let phishScore = 0;
    let featureResults = [];
    let parsed;

    try {
        parsed = new URL(url);
    } catch {
        return {
            phishScore: 100,
            verdict: "Error: Invalid URL",
            colorClass: "phishing",
            featureResults: []
        };
    }

    for (let key in HEURISTIC_RULES) {
        const rule = HEURISTIC_RULES[key];
        const triggered = rule.check(url, parsed);
        const score = triggered ? rule.weight : 0;

        phishScore += score;

        featureResults.push({
            name: rule.name,
            score,
            maxScore: rule.weight,
            isTriggered: triggered,
            description: rule.description
        });
    }

    let verdict = "Legitimate";
    let colorClass = "legitimate";

    if (phishScore >= 70) {
        verdict = "Phishing Risk: High";
        colorClass = "phishing";
    } else if (phishScore >= 30) {
        verdict = "Suspicious Risk: Medium";
        colorClass = "suspicious";
    }

    return { phishScore, verdict, colorClass, featureResults };
}

// ------------------ CHART UPDATE ------------------
function updateVisualization(featureResults) {
    const labels = featureResults.map(f => f.name.replace(/AI Feature \d: /, ''));
    const data = featureResults.map(f => f.score);

    if (riskChartInstance) riskChartInstance.destroy();

    const ctx = document.getElementById("riskChart").getContext("2d");
    riskChartInstance = new Chart(ctx, {
        type: 'radar',
        data: {
            labels,
            datasets: [{
                data,
                backgroundColor: 'rgba(239, 68, 68, 0.4)',
                borderColor: '#ef4444',
                borderWidth: 2
            }]
        },
        options: {
            plugins: { legend: { display: false } },
            scales: { r: { ticks: { display: false } } }
        }
    });
}

// ------------------ UI UPDATE ------------------
function updateUI(a) {
    document.getElementById("phishScore").textContent = a.phishScore;
    document.getElementById("verdictText").textContent = a.verdict;

    const vb = document.getElementById("verdictBox");
    vb.className = "p-6 rounded-xl mb-8 text-center";
    vb.classList.add(a.colorClass);

    document.getElementById("featureTable").innerHTML = a.featureResults.map(f => `
        <div class="border-b border-gray-700 pb-3">
            <div class="flex justify-between text-lg">
                <span>${f.name}</span>
                <span class="${f.isTriggered ? 'text-red-400' : 'text-green-400'}">
                    ${f.isTriggered ? "🚨" : "✅"} (${f.score}/${f.maxScore})
                </span>
            </div>
            <p class="text-sm text-gray-500">${f.description}</p>
        </div>
    `).join('');

    document.getElementById("resultsContainer").classList.remove("hidden");
    document.getElementById("placeholder").classList.add("hidden");

    updateVisualization(a.featureResults);
}

// ------------------ EVENTS ------------------
document.getElementById("analyzeButton").addEventListener("click", () => {
    const url = document.getElementById("urlInput").value.trim();
    if (url) updateUI(analyzeURL(url));
});

document.querySelectorAll("#exampleUrls a").forEach(a => {
    a.addEventListener("click", (e) => {
        e.preventDefault();
        const url = e.target.dataset.url;
        document.getElementById("urlInput").value = url;
        updateUI(analyzeURL(url));
    });
});

// Auto-run initial value
window.onload = () => {
    const url = document.getElementById("urlInput").value.trim();
    updateUI(analyzeURL(url));
};
