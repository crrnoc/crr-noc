(function () {
  let inactivityTimer;

  // 🔄 Reset inactivity timer
  function resetTimer() {
    clearTimeout(inactivityTimer);
    inactivityTimer = setTimeout(logout, 15 * 60 * 1000); // 15 min
  }

  // 🚪 Logout function
  function logout() {
    fetch("/logout", { method: "GET", credentials: "include" })
      .then(() => {
        sessionStorage.clear();
        localStorage.clear();
        // 🔑 Clear all cookies
        document.cookie.split(";").forEach((c) => {
          document.cookie = c
            .replace(/^ +/, "")
            .replace(/=.*/, "=;expires=" + new Date().toUTCString() + ";path=/");
        });
        window.location.replace("/index.html");
      })
      .catch(() => {
        window.location.replace("/index.html");
      });
  }

  // 🖱️ Activity listeners (reset inactivity timer)
  ["click", "mousemove", "keydown", "scroll", "touchstart"].forEach((evt) => {
    window.addEventListener(evt, resetTimer, false);
  });

  // 🔍 Check session validity immediately + every 2 minutes
  function checkSession() {
    fetch("/check-session", { credentials: "include" })
      .then((res) => {
        if (!res.ok) throw new Error("Session expired");
        return res.json();
      })
      .then((data) => {
        if (!data.success) logout();
      })
      .catch(() => {
        logout();
      });
  }
  checkSession(); // run on page load
  setInterval(checkSession, 2 * 60 * 1000);

  // 🛑 Prevent navigating back after logout
  window.addEventListener("pageshow", function (event) {
    if (event.persisted) {
      window.location.replace("/index.html");
    }
  });

  // ⛔ Stop cached pages from showing on back/forward
  window.history.pushState(null, "", window.location.href);
  window.onpopstate = function () {
    window.history.pushState(null, "", window.location.href);
    window.location.replace("/index.html");
  };

  // Start inactivity timer immediately
  resetTimer();
})();
