(function () {
  "use strict";

  var key = "archisec-theme";
  var root = document.documentElement;
  // Apply the preference before the stylesheet and first paint.
  try {
    if (window.localStorage.getItem(key) === "dark") root.dataset.theme = "dark";
  } catch (error) { /* light default when storage is unavailable */ }

  function bindToggle() {
    var button = document.getElementById("theme-toggle");
    if (!button) return;

    function currentTheme() {
      return root.dataset.theme === "dark" ? "dark" : "light";
    }

    function setTheme(theme, persist) {
      var dark = theme === "dark";
      if (dark) root.dataset.theme = "dark";
      else root.removeAttribute("data-theme");
      button.setAttribute("aria-pressed", String(dark));
      var label = dark ? "Включить светлую тему" : "Включить тёмную тему";
      button.setAttribute("aria-label", label);
      button.setAttribute("title", label);
      var text = button.querySelector(".theme-toggle-text");
      if (text) text.textContent = dark ? "Светлая тема" : "Тёмная тема";
      if (persist) {
        try { window.localStorage.setItem(key, dark ? "dark" : "light"); } catch (error) { /* optional preference storage */ }
      }
    }

    setTheme(currentTheme(), false);
    button.addEventListener("click", function () {
      setTheme(currentTheme() === "dark" ? "light" : "dark", true);
    });
    button.hidden = false;
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bindToggle, { once: true });
  } else {
    bindToggle();
  }
}());
