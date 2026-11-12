/* Buildless, local-only interactions. No analytics or external requests. */
(() => {
  "use strict";
  const english = {
    skip: "Skip to content",
    navCapabilities: "Capabilities",
    navRecovery: "Recovery",
    navProject: "The project",
    navDownload: "Get AntiOS",
    heroEyebrow: "INDEPENDENT SECURITY. OPEN SOURCE.",
    heroLine1: "Peace of mind.",
    heroLine2: "Under your",
    heroLine3: "control.",
    heroLead:
      "Understand what’s happening on your device. Check files, preserve what matters, and take the next step with AntiOS.",
    getAntiOS: "Get AntiOS",
    explore: "Explore the system",
    alphaNote: "Public alpha · In active development",
    visualization: "INTERACTIVE VISUALIZATION",
    visualCaption: "A new perspective on your system.",
    awareness: "AWARENESS IS YOUR FIRST LINE OF DEFENSE",
    stripOpen: "Open by design",
    stripLocal: "Your data stays local",
    stripControl: "You make the decisions",
    capKicker: "CAPABILITIES",
    capTitle1: "See more.",
    capTitle2: "Act with clarity.",
    capIntro:
      "From a single file to the bigger picture. Tools that help you understand your system and look after what matters.",
    tabScan: "Check",
    tabRecover: "Preserve",
    tabInspect: "Understand",
    illustration: "ILLUSTRATION",
    scanTitle: "An informed look at every file.",
    scanIntro:
      "Scan selected files and folders. Review findings, isolate suspicious items in quarantine, and keep track of protection status.",
    scan1: "On-demand scanning and optional resident protection",
    scan2: "Clear distinction between findings, skips and errors",
    scan3: "Coexists with supported antivirus products",
    scanLink: "About file protection",
    scanCaption: "You choose what to check.",
    recoverTitle: "Keep what you can’t replace.",
    recoverIntro:
      "Select files and folders, create a saved baseline, and check their integrity. Restore saved content to a safe destination when you need it.",
    recover1: "You define the content to preserve",
    recover2: "Saved content is checked before recovery",
    recover3: "File recovery, not a full Windows rollback",
    recoverLink: "About recovery",
    recoverCaption: "A reference point for your files.",
    inspectTitle: "Less guesswork. More clarity.",
    inspectIntro:
      "Explore system diagnostics, local incident views and storage tools. Find cleanup candidates and decide what happens next.",
    inspect1: "Windows security and system diagnostics",
    inspect2: "Storage cleanup and duplicate candidates",
    inspect3: "Destructive actions require explicit confirmation",
    inspectLink: "About storage intelligence",
    inspectCaption: "Understand first. Then decide.",
    system: "System",
    files: "Files",
    freeSpace: "Free space",
    recoveryKicker: "A POINT OF RETURN",
    recoveryTitle1: "Important files.",
    recoveryTitle2: "A little more peace of mind.",
    recoveryIntro:
      "Your work, your ideas, your projects. Create a reference copy before you need it.",
    step1Title: "Choose what matters",
    step1Body:
      "Add the files and folders you want to preserve. You define the scope.",
    step2Title: "Create a baseline",
    step2Body:
      "Save a reference copy and use integrity checks to identify changes.",
    step3Title: "Recover when needed",
    step3Body: "Check the saved content and recover it to a safe destination.",
    recoveryLimit:
      "File recovery does not replace a full system backup and does not guarantee that restored content is malware-free.",
    trustKicker: "BUILT ON TRUST",
    trustTitle1: "Nothing hidden.",
    trustTitle2: "No magic promises.",
    trustIntro:
      "Good security starts with honest expectations. AntiOS is an independent open-source project with visible capabilities and clear limitations.",
    source: "Explore the source",
    privacyTitle: "Your data is yours",
    privacyBody:
      "Security and diagnostic data is processed locally by default. AntiOS does not enable automatic project telemetry. Review diagnostic exports before sharing them.",
    privacyLink: "Privacy policy ↗",
    openTitle: "Open code. Visible progress.",
    openBody:
      "The v2 source is available under Apache 2.0. Releases and automated checks are published on GitHub, so you can follow the project as it develops.",
    openLink: "View automated checks ↗",
    alphaTitle: "Alpha means work in progress",
    alphaBody:
      "AntiOS is pre-release software and a supplemental layer. It does not claim certified primary-antivirus status or detection of every threat. Keep your primary protection enabled.",
    alphaLink: "Compatibility and limitations ↗",
    platformTitle: "Which systems are supported?",
    platformBody:
      "The desktop target is Windows 10 22H2 x64 and newer Windows 11 builds. Linux companion support is supplemental. Check the release notes for package requirements.",
    platformLink: "Release notes ↗",
    downloadTitle1: "Your system.",
    downloadTitle2: "Your rules.",
    downloadIntro:
      "Take a closer look. Try AntiOS and help shape what comes next.",
    releaseButton: "Releases for Windows",
    linuxLink: "Linux companion & documentation",
    downloadWarning:
      "Pre-release software. Review release notes and keep backups of important data.",
    footerTagline: "Awareness. Control. Peace of mind.",
    privacy: "Privacy",
    security: "Security",
    independent: "INDEPENDENT BY DESIGN.",
    top: "BACK TO TOP ↑",
  };
  const englishLabels = {
    navigation: "Main navigation",
    menu: "Toggle menu",
    mobileNavigation: "Mobile navigation",
    next: "Next: capabilities",
    tabs: "AntiOS capabilities",
    projectLinks: "Project links",
  };
  const texts = Array.from(
    document.querySelectorAll("[data-i18n]"),
    (node) => ({ node, key: node.dataset.i18n, ru: node.textContent }),
  );
  const labels = Array.from(
    document.querySelectorAll("[data-label]"),
    (node) => ({
      node,
      key: node.dataset.label,
      ru: node.getAttribute("aria-label"),
    }),
  );
  const langButton = document.getElementById("langButton");
  const russianTitle = document.title;
  const description = document.querySelector('meta[name="description"]');
  const russianDescription = description.content;

  function setLanguage(language) {
    const lang = language === "en" ? "en" : "ru";
    document.documentElement.lang = lang;
    texts.forEach(({ node, key, ru }) => {
      node.textContent = lang === "en" ? english[key] || ru : ru;
    });
    labels.forEach(({ node, key, ru }) => {
      node.setAttribute(
        "aria-label",
        lang === "en" ? englishLabels[key] || ru : ru,
      );
    });
    document.title =
      lang === "en" ? "AntiOS — Your system. Your rules." : russianTitle;
    description.content =
      lang === "en"
        ? "AntiOS — open-source file security, diagnostics and recovery. Your system. Your rules."
        : russianDescription;
    langButton.textContent = lang === "ru" ? "EN ↗" : "RU ↗";
    langButton.setAttribute(
      "aria-label",
      lang === "ru" ? "Switch to English" : "Переключить на русский",
    );
    // Language preference is the only data stored by the landing page.
    try {
      localStorage.setItem("antios-language", lang);
    } catch {
      /* Storage may be unavailable. */
    }
    document.dispatchEvent(new CustomEvent("antios:language"));
  }
  let language = navigator.language?.toLowerCase().startsWith("ru")
    ? "ru"
    : "en";
  try {
    const saved = localStorage.getItem("antios-language");
    if (saved === "ru" || saved === "en") language = saved;
  } catch {
    /* Use browser language. */
  }
  setLanguage(language);
  langButton.hidden = false;
  langButton.addEventListener("click", () =>
    setLanguage(document.documentElement.lang === "ru" ? "en" : "ru"),
  );
  document.getElementById("year").textContent = new Date().getFullYear();

  const menuButton = document.getElementById("menuButton");
  const mobileNav = document.getElementById("mobileNav");
  menuButton.hidden = false;
  function closeMenu() {
    menuButton.setAttribute("aria-expanded", "false");
    mobileNav.hidden = true;
  }
  menuButton.addEventListener("click", () => {
    const open = menuButton.getAttribute("aria-expanded") !== "true";
    menuButton.setAttribute("aria-expanded", String(open));
    mobileNav.hidden = !open;
  });
  mobileNav.addEventListener("click", (event) => {
    const link = event.target.closest("a");
    if (!link) return;
    closeMenu();
    const target = document.querySelector(link.getAttribute("href"));
    target?.setAttribute("tabindex", "-1");
    target?.focus({ preventScroll: true });
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !mobileNav.hidden) {
      closeMenu();
      menuButton.focus();
    }
  });
  const desktop = matchMedia("(min-width: 741px)");
  desktop.addEventListener("change", (event) => {
    if (event.matches) closeMenu();
  });

  const tabs = Array.from(document.querySelectorAll('[role="tab"]'));
  function selectTab(selected, focus = false) {
    tabs.forEach((tab) => {
      const active = tab === selected;
      tab.setAttribute("aria-selected", String(active));
      tab.tabIndex = active ? 0 : -1;
      document.getElementById(tab.getAttribute("aria-controls")).hidden =
        !active;
    });
    if (focus) selected.focus();
  }
  tabs.forEach((tab, index) => {
    tab.addEventListener("click", () => selectTab(tab));
    tab.addEventListener("keydown", (event) => {
      const targets = {
        ArrowRight: (index + 1) % tabs.length,
        ArrowLeft: (index + tabs.length - 1) % tabs.length,
        Home: 0,
        End: tabs.length - 1,
      };
      if (!(event.key in targets)) return;
      event.preventDefault();
      selectTab(tabs[targets[event.key]], true);
    });
  });
})();
