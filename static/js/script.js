document.addEventListener("DOMContentLoaded", () => {

    /* ======================================================
       GLOBAL STATE
    ====================================================== */
    let attackCount = 0;
    let normalCount = 0;
    let sirenPlaying = false;
    let audioUnlocked = false;

    /* ======================================================
       ELEMENT REFERENCES
    ====================================================== */
    const attackEl = document.getElementById("attackCount");
    const normalEl = document.getElementById("normalCount");
    const activeEl = document.getElementById("activeThreats");
    const lastScanEl = document.getElementById("lastScan");

    const footerAttack = document.getElementById("footerAttackCount");
    const footerNormal = document.getElementById("footerNormalCount");

    const alertSound = document.getElementById("alertSound");
    const alertBox = document.getElementById("alertBox");
    const enableBtn = document.getElementById("enableSoundBtn");

    /* ======================================================
       🔊 AUDIO UNLOCK (MANDATORY FOR CHROME)
    ====================================================== */
    enableBtn.addEventListener("click", () => {
        alertSound.play().then(() => {
            alertSound.pause();
            alertSound.currentTime = 0;
            audioUnlocked = true;

            enableBtn.textContent = "🔔 Alerts Enabled";
            enableBtn.style.background = "green";

            console.log("🔓 Audio unlocked successfully");
        }).catch(err => {
            console.error("Audio unlock failed:", err);
        });
    });

    /* ======================================================
       🌍 MAP INITIALIZATION (Leaflet)
    ====================================================== */
    const map = L.map("map").setView([20, 0], 2);

    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
        maxZoom: 18
    }).addTo(map);

    /* ======================================================
       📈 CHART INITIALIZATION (Chart.js)
    ====================================================== */
    const ctx = document.getElementById("attackChart").getContext("2d");

    const attackChart = new Chart(ctx, {
        type: "line",
        data: {
            labels: [],
            datasets: [{
                label: "Threat Detection",
                data: [],
                borderColor: "#ff4c4c",
                backgroundColor: "rgba(255,76,76,0.2)",
                tension: 0.4,
                fill: true
            }]
        },
        options: {
            animation: false,
            responsive: true,
            scales: {
                y: {
                    min: 0,
                    max: 1,
                    ticks: {
                        stepSize: 1,
                        callback: v => v === 1 ? "Attack" : "Normal"
                    }
                }
            }
        }
    });

    /* ======================================================
       🔌 SOCKET.IO CONNECTION
    ====================================================== */
    const socket = io();

    socket.on("new_attack", (data) => {

        const isAttack = data.attack_type !== "Normal";
        const color = isAttack ? "#ff4c4c" : "#00ff88";

        /* ---------------- MAP MARKER ---------------- */
        L.circleMarker([data.lat, data.lon], {
            radius: 8,
            color: color,
            fillColor: color,
            fillOpacity: 0.9
        }).addTo(map);

        /* ---------------- ALERT FEED ---------------- */
        const msg = document.createElement("div");
        msg.style.color = color;
        msg.innerHTML = `
            ${data.time} →
            <b>${isAttack ? "ATTACK" : "NORMAL"}</b>
            (${data.attack_type})
        `;
        alertBox.prepend(msg);

        if (alertBox.children.length > 10) {
            alertBox.removeChild(alertBox.lastChild);
        }

        /* ---------------- COUNTERS & SIREN ---------------- */
        if (isAttack) {
            attackCount++;
            activeEl.textContent = "1";

            if (audioUnlocked && !sirenPlaying) {
                alertSound.loop = true;
                alertSound.play().catch(() => {});
                sirenPlaying = true;
            }

        } else {
            normalCount++;
            activeEl.textContent = "0";

            if (sirenPlaying) {
                alertSound.pause();
                alertSound.currentTime = 0;
                sirenPlaying = false;
            }
        }

        /* ---------------- UI UPDATE ---------------- */
        attackEl.textContent = attackCount;
        normalEl.textContent = normalCount;
        footerAttack.textContent = attackCount;
        footerNormal.textContent = normalCount;
        lastScanEl.textContent = data.time;

        /* ---------------- GRAPH UPDATE ---------------- */
        attackChart.data.labels.push(data.time);
        attackChart.data.datasets[0].data.push(isAttack ? 1 : 0);

        if (attackChart.data.labels.length > 15) {
            attackChart.data.labels.shift();
            attackChart.data.datasets[0].data.shift();
        }

        attackChart.update();
    });

    /* ======================================================
       📅 FOOTER YEAR
    ====================================================== */
    document.getElementById("year").textContent =
        new Date().getFullYear();
});

/* ---------------- toggleMenu ---------------- */
function toggleMenu() {
    document
        .getElementById("navMenu")
        .classList.toggle("show");
}

// Auto close menu after clicking an item

const menuLinks = document.querySelectorAll("#navMenu a");

menuLinks.forEach(link => {
    link.addEventListener("click", () => {
        document
            .getElementById("navMenu")
            .classList.remove("show");
    });
});