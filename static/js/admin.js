function sendAction(action) {
    fetch("/admin/control", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ action: action })
    })
    .then(res => res.json())
    .then(data => {
        document.getElementById("statusText").innerHTML = `
            Detection: ${data.detection ? "🟢 ON" : "🔴 OFF"}<br>
            Alerts: ${data.alerts ? "🔔 ENABLED" : "🔕 DISABLED"}
        `;
    });
}
