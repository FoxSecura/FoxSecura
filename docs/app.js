/* SPDX-FileCopyrightText: 2026 FoxSecura contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 */

(() => {
  "use strict";

  const translations = {
    en: {
      "a11y.language": "Language",
      "architecture.kicker": "Readable architecture",
      "architecture.lead": "FoxSecura keeps responsibilities simple: Discord provides events, engines analyze them, decisions stay typed, and logs plus persistence retain the context.",
      "architecture.nodeCore": "Orchestration",
      "architecture.nodeDetect": "Detection",
      "architecture.nodeDiscord": "Input",
      "architecture.nodeObserve": "Observability",
      "architecture.nodePersist": "Persistence",
      "architecture.p1Text": "Easy to test, without unnecessary Discord dependencies.",
      "architecture.p1Title": "Pure detectors whenever possible",
      "architecture.p2Text": "Time windows, URL signals and shared decisions stay centralized.",
      "architecture.p2Title": "Shared primitives",
      "architecture.p3Text": "SQLite, versioned migrations and understandable repositories.",
      "architecture.p3Title": "Explicit persistence",
      "architecture.title": "Separate concerns to secure them better.",
      "commands.config": "Opens the private dashboard with a category selector to administer FoxSecura.",
      "commands.config1": "Ephemeral response",
      "commands.config2": "11 organized categories",
      "commands.config3": "Interface translated in EN / FR / DE",
      "commands.guildOnly": "server only",
      "commands.help": "Shows the bot’s main commands in the user’s language.",
      "commands.help1": "Simple and fast",
      "commands.help2": "No gimmick commands",
      "commands.help3": "Localized information",
      "commands.kicker": "Minimal interface",
      "commands.lead": "FoxSecura deliberately keeps its command surface small. Complex configuration goes through interactive panels instead of a collection of hard-to-remember commands.",
      "commands.private": "private",
      "commands.status": "Shows the runtime, Gateway, framework, commands and security engine status.",
      "commands.status1": "Application status",
      "commands.status2": "Versions and framework",
      "commands.status3": "Protection engines",
      "commands.title": "Three commands. No noise.",
      "common.copy": "Copy",
      "common.engineReady": "Engine ready",
      "common.feature": "Feature",
      "common.required": "Required",
      "cta.issues": "View issues",
      "cta.kicker": "Build it cleanly",
      "cta.repo": "Open repository",
      "cta.text": "Development is public. Explore the code, tests and architecture decisions directly on GitHub.",
      "cta.title": "Follow FoxSecura’s evolution.",
      "details.aiLabel": "Semantic moderation",
      "details.aiText": "FoxSecura uses only `omni-moderation-latest` through the Moderations endpoint. The provider never sees Discord objects and can never directly apply a sanction.",
      "details.aiTitle": "OpenAI, with strict boundaries.",
      "details.dbLabel": "Persistence",
      "details.dbText": "The database foundation uses rusqlite with bundled SQLite, WAL, foreign keys, versioned migrations and typed repositories.",
      "details.dbTitle": "Simple, versioned SQLite.",
      "details.i18nLabel": "Internationalization",
      "details.i18nText": "No forest of JSON files. Keys are typed and every text must exist in English, French and German.",
      "details.i18nTitle": "Three languages, one typed catalog.",
      "details.logsLabel": "Observability",
      "details.logsText": "Six channel types separate messages, server, members, channels, roles and moderation. Human-facing labels go through the i18n catalog.",
      "details.logsTitle": "Structured, localized logs.",
      "faq.a1": "Not yet. The engines and their tests are advanced, but complete wiring to Discord events, persistent configuration and final actions is still in progress.",
      "faq.a2": "For a performant, safe, explicit and maintainable foundation suited to the concurrent workload of a security bot.",
      "faq.a3": "No. The AI provider classifies content. FoxSecura rules decide the consequence, and the action layer remains separate.",
      "faq.a4": "English, French and German. Discord locale variants such as en-US, fr-FR or de-DE are resolved automatically.",
      "faq.a5": "Yes. The repository is public under AGPL-3.0-only. Check the issues and keep changes focused, tested and consistent with the architecture.",
      "faq.issue": "Open an issue",
      "faq.lead": "The important answers about FoxSecura’s philosophy and current state.",
      "faq.q1": "Is FoxSecura production-ready?",
      "faq.q2": "Why Rust?",
      "faq.q3": "Can AI ban a member directly?",
      "faq.q4": "Which languages are supported?",
      "faq.q5": "Can I contribute?",
      "faq.title": "Frequently asked questions.",
      "footer.backTop": "Back to top",
      "footer.developers": "Developers",
      "footer.product": "Product",
      "footer.project": "Project",
      "footer.text": "Modern, modular and open-source Discord security written in Rust.",
      "hero.activity": "Protection engines",
      "hero.ctaDocs": "Get started",
      "hero.ctaGithub": "View source",
      "hero.eventNuke": "Bursts of sensitive actions",
      "hero.eventRaid": "Joins, webhooks, identities",
      "hero.eyebrow": "Open-source Discord security, written in Rust",
      "hero.floatingDetectors": "specialized detectors",
      "hero.lead": "FoxSecura builds a modern Discord security layer around specialized engines, clear configuration, structured logs and tightly controlled AI moderation.",
      "hero.metaI18n": "multilingual",
      "hero.metaLicense": "open source",
      "hero.metaRuntime": "performance-focused",
      "hero.metricCommands": "Commands",
      "hero.metricFamilies": "Families",
      "hero.metricLanguages": "Languages",
      "hero.operational": "engines loaded",
      "hero.panelSubtitle": "Security runtime",
      "hero.ready": "ready",
      "hero.tested": "tested",
      "hero.title1": "Protect your server.",
      "hero.title2": "Stay in control.",
      "nav.architecture": "Architecture",
      "nav.beta": "dev",
      "nav.docs": "Documentation",
      "nav.github": "GitHub",
      "nav.protections": "Protections",
      "nav.status": "Status",
      "protections.actionPrinciple": "The action layer applies",
      "protections.ai": "Semantic classification with OpenAI `omni-moderation-latest`, FoxSecura policy, strict validation, cache, concurrency limits and a circuit breaker.",
      "protections.aiPrinciple": "The model classifies",
      "protections.automod": "Invites, adult links, blocked words, member profiles and reconciliation of native Discord AutoMod rules.",
      "protections.kicker": "Defense in depth",
      "protections.lead": "Each family owns a clear responsibility. Common primitives are shared to prevent duplicate detection and competing counters.",
      "protections.nuke": "Mass actions, resource deletion, sensitive changes, permissions, server integrity and panic mode.",
      "protections.raid": "Join bursts, bots, new accounts, alt accounts, impersonation, honeypot and webhook monitoring.",
      "protections.rulesPrinciple": "FoxSecura decides",
      "protections.spam": "Flooding, mass mentions, ghost ping, malicious links, suspicious attachments, scams and automatic slowmode.",
      "protections.title": "Five engines. One strategy.",
      "quickstart.kicker": "Development",
      "quickstart.lead": "The repository pins its main versions to keep the environment reproducible. Rust 1.98.1 is defined in the project toolchain.",
      "quickstart.reqIntent": "privileged intent required",
      "quickstart.reqOpenAI": "for AI Moderation",
      "quickstart.reqRust": "project toolchain",
      "quickstart.title": "Run FoxSecura locally.",
      "reference.action": "Action",
      "reference.database": "Database",
      "reference.databaseText": "The client’s default path is `data/foxsecura.sqlite3`. The schema starts at version 1 and migrations are transactional.",
      "reference.decision": "Decision",
      "reference.defaultPath": "Path",
      "reference.detect": "Detection",
      "reference.discordToken": "Required to connect the bot to the Discord Gateway.",
      "reference.environment": "Environment variables",
      "reference.input": "Event",
      "reference.intents": "Discord intents",
      "reference.intentsText": "FoxSecura currently requests three Gateway intents. `GUILD_MEMBERS` is privileged and must be enabled in the Discord Developer Portal.",
      "reference.kicker": "Reference",
      "reference.license": "License",
      "reference.licenseText": "FoxSecura is distributed under GNU Affero General Public License v3.0 only, SPDX `AGPL-3.0-only`.",
      "reference.openaiKey": "Enables the OpenAI provider for AI Moderation.",
      "reference.readLicense": "Read the license",
      "reference.schema": "Schema",
      "reference.secretNote": "Never commit these secrets to Git.",
      "reference.security": "Security model",
      "reference.securityText": "Engines produce typed signals and decisions. Detection logic is separate from Discord side effects. For AI, the provider receives no Discord objects and never returns a sanction.",
      "reference.title": "What you need to know.",
      "search.caption": "Quick navigation",
      "search.emptyText": "Try a module, command or technology.",
      "search.emptyTitle": "No results",
      "search.placeholder": "Search the documentation...",
      "stack.built": "Built with",
      "status.ci": "Every Rust change is validated with cargo check and cargo test before main.",
      "status.done": "Implemented and tested",
      "status.itemActions": "Discord action layer and final sanctions",
      "status.itemCommands": "Commands /config, /help and /status",
      "status.itemConfig": "Full persistence for /config dashboard settings",
      "status.itemDb": "SQLite foundation, migrations and initial repositories",
      "status.itemEvents": "Full wiring of engines to Discord events",
      "status.itemI18n": "Typed EN / FR / DE i18n",
      "status.itemLogChannels": "Automatic creation and maintenance of log channels",
      "status.itemLogs": "Log models and formatting",
      "status.itemProtections": "Anti-Spam, Anti-Raid, Anti-Nuke, AutoMod and AI Moderation engines",
      "status.kicker": "Project status",
      "status.lead": "This site separates what is already implemented from what still needs integration so FoxSecura is never presented as finished before it is.",
      "status.progress": "Integration in progress",
      "status.title": "A solid foundation, still being integrated.",
      "status.viewCi": "View CI"
    },
    de: {
      "a11y.language": "Sprache",
      "architecture.kicker": "Klare Architektur",
      "architecture.lead": "FoxSecura hält Verantwortlichkeiten einfach: Discord liefert Ereignisse, die Engines analysieren sie, Entscheidungen bleiben typisiert und Logs sowie Persistenz bewahren den Kontext.",
      "architecture.nodeCore": "Orchestrierung",
      "architecture.nodeDetect": "Erkennung",
      "architecture.nodeDiscord": "Eingang",
      "architecture.nodeObserve": "Beobachtung",
      "architecture.nodePersist": "Persistenz",
      "architecture.p1Text": "Leicht testbar, ohne unnötige Discord-Abhängigkeiten.",
      "architecture.p1Title": "Reine Detektoren, wann immer möglich",
      "architecture.p2Text": "Zeitfenster, URL-Signale und gemeinsame Entscheidungen bleiben zentralisiert.",
      "architecture.p2Title": "Gemeinsame Bausteine",
      "architecture.p3Text": "SQLite, versionierte Migrationen und verständliche Repositories.",
      "architecture.p3Title": "Explizite Persistenz",
      "architecture.title": "Trennen, um besser zu schützen.",
      "commands.config": "Öffnet das private Dashboard mit einer Kategorieauswahl zur Verwaltung von FoxSecura.",
      "commands.config1": "Ephemere Antwort",
      "commands.config2": "11 strukturierte Kategorien",
      "commands.config3": "Oberfläche auf EN / FR / DE",
      "commands.guildOnly": "nur Server",
      "commands.help": "Zeigt die wichtigsten Bot-Befehle in der Sprache des Benutzers.",
      "commands.help1": "Einfach und schnell",
      "commands.help2": "Keine unnötigen Befehle",
      "commands.help3": "Lokalisierte Informationen",
      "commands.kicker": "Minimale Oberfläche",
      "commands.lead": "FoxSecura hält die Befehlsoberfläche bewusst klein. Komplexe Konfiguration erfolgt über interaktive Panels statt über eine schwer merkbare Sammlung von Befehlen.",
      "commands.private": "privat",
      "commands.status": "Zeigt den Status von Runtime, Gateway, Framework, Befehlen und Sicherheits-Engines.",
      "commands.status1": "Anwendungsstatus",
      "commands.status2": "Versionen und Framework",
      "commands.status3": "Schutz-Engines",
      "commands.title": "Drei Befehle. Kein Ballast.",
      "common.copy": "Kopieren",
      "common.engineReady": "Engine bereit",
      "common.feature": "Funktion",
      "common.required": "Erforderlich",
      "cta.issues": "Issues ansehen",
      "cta.kicker": "Sauber entwickeln",
      "cta.repo": "Repository öffnen",
      "cta.text": "Die Entwicklung ist öffentlich. Code, Tests und Architekturentscheidungen sind direkt auf GitHub einsehbar.",
      "cta.title": "Verfolge die Entwicklung von FoxSecura.",
      "details.aiLabel": "Semantische Moderation",
      "details.aiText": "FoxSecura verwendet ausschließlich `omni-moderation-latest` über den Moderations-Endpunkt. Der Provider sieht keine Discord-Objekte und kann niemals direkt eine Sanktion ausführen.",
      "details.aiTitle": "OpenAI mit klaren Grenzen.",
      "details.dbLabel": "Persistenz",
      "details.dbText": "Die Datenbankbasis nutzt rusqlite mit eingebettetem SQLite, WAL, Fremdschlüsseln, versionierten Migrationen und typisierten Repositories.",
      "details.dbTitle": "Einfaches, versioniertes SQLite.",
      "details.i18nLabel": "Internationalisierung",
      "details.i18nText": "Kein Wald aus JSON-Dateien. Schlüssel sind typisiert und jeder Text muss auf Englisch, Französisch und Deutsch vorhanden sein.",
      "details.i18nTitle": "Drei Sprachen, ein typisierter Katalog.",
      "details.logsLabel": "Beobachtbarkeit",
      "details.logsText": "Sechs Kanaltypen trennen Nachrichten, Server, Mitglieder, Kanäle, Rollen und Moderation. Lesbare Bezeichnungen laufen durch den i18n-Katalog.",
      "details.logsTitle": "Strukturierte, lokalisierte Logs.",
      "faq.a1": "Noch nicht. Die Engines und ihre Tests sind weit fortgeschritten, aber die vollständige Anbindung an Discord-Ereignisse, persistente Konfiguration und finale Aktionen ist noch in Arbeit.",
      "faq.a2": "Für eine performante, sichere, explizite und wartbare Basis, die zu den parallelen Aufgaben eines Sicherheits-Bots passt.",
      "faq.a3": "Nein. Der KI-Provider klassifiziert Inhalte. Danach entscheiden die FoxSecura-Regeln über die Konsequenz, während die Aktionsschicht getrennt bleibt.",
      "faq.a4": "Englisch, Französisch und Deutsch. Discord-Locale-Varianten wie en-US, fr-FR oder de-DE werden automatisch aufgelöst.",
      "faq.a5": "Ja. Das Repository ist unter AGPL-3.0-only öffentlich. Nutze die Issues und halte Änderungen fokussiert, getestet und architekturkonform.",
      "faq.issue": "Issue öffnen",
      "faq.lead": "Die wichtigsten Antworten zur Philosophie und zum aktuellen Stand von FoxSecura.",
      "faq.q1": "Ist FoxSecura produktionsbereit?",
      "faq.q2": "Warum Rust?",
      "faq.q3": "Kann die KI ein Mitglied direkt bannen?",
      "faq.q4": "Welche Sprachen werden unterstützt?",
      "faq.q5": "Kann ich beitragen?",
      "faq.title": "Häufige Fragen.",
      "footer.backTop": "Nach oben",
      "footer.developers": "Entwickler",
      "footer.product": "Produkt",
      "footer.project": "Projekt",
      "footer.text": "Moderne, modulare und quelloffene Discord-Sicherheit in Rust.",
      "hero.activity": "Schutz-Engines",
      "hero.ctaDocs": "Loslegen",
      "hero.ctaGithub": "Code ansehen",
      "hero.eventNuke": "Serien sensibler Aktionen",
      "hero.eventRaid": "Beitritte, Webhooks, Identitäten",
      "hero.eyebrow": "Open-Source Discord-Sicherheit in Rust",
      "hero.floatingDetectors": "spezialisierte Detektoren",
      "hero.lead": "FoxSecura baut eine moderne Discord-Sicherheitsschicht aus spezialisierten Engines, klarer Konfiguration, strukturierten Logs und streng kontrollierter KI-Moderation.",
      "hero.metaI18n": "mehrsprachig",
      "hero.metaLicense": "Open Source",
      "hero.metaRuntime": "performante Basis",
      "hero.metricCommands": "Befehle",
      "hero.metricFamilies": "Familien",
      "hero.metricLanguages": "Sprachen",
      "hero.operational": "Engines geladen",
      "hero.panelSubtitle": "Security runtime",
      "hero.ready": "bereit",
      "hero.tested": "getestet",
      "hero.title1": "Schütze deinen Server.",
      "hero.title2": "Behalte die Kontrolle.",
      "nav.architecture": "Architektur",
      "nav.beta": "dev",
      "nav.docs": "Dokumentation",
      "nav.github": "GitHub",
      "nav.protections": "Schutz",
      "nav.status": "Status",
      "protections.actionPrinciple": "Die Aktionsschicht führt aus",
      "protections.ai": "Semantische Klassifizierung mit OpenAI `omni-moderation-latest`, FoxSecura-Policy, strikter Validierung, Cache, Parallelitätslimit und Circuit Breaker.",
      "protections.aiPrinciple": "Das Modell klassifiziert",
      "protections.automod": "Einladungen, Adult-Links, gesperrte Wörter, Mitgliederprofile und Abgleich nativer Discord-AutoMod-Regeln.",
      "protections.kicker": "Mehrschichtiger Schutz",
      "protections.lead": "Jede Familie besitzt eine klare Verantwortung. Gemeinsame Bausteine werden geteilt, um doppelte Erkennung und konkurrierende Zähler zu vermeiden.",
      "protections.nuke": "Massenaktionen, Ressourcenlöschung, sensible Änderungen, Berechtigungen, Serverintegrität und Panikmodus.",
      "protections.raid": "Beitrittsserien, Bots, neue Konten, Zweitkonten, Identitätsmissbrauch, Honeypot und Webhook-Überwachung.",
      "protections.rulesPrinciple": "FoxSecura entscheidet",
      "protections.spam": "Flooding, Massenmentions, Ghost Ping, schädliche Links, verdächtige Anhänge, Scam und automatischer Slowmode.",
      "protections.title": "Fünf Engines. Eine Strategie.",
      "quickstart.kicker": "Entwicklung",
      "quickstart.lead": "Das Repository fixiert die wichtigsten Versionen für eine reproduzierbare Umgebung. Rust 1.98.1 ist im Projekt-Toolchain definiert.",
      "quickstart.reqIntent": "privilegierter Intent erforderlich",
      "quickstart.reqOpenAI": "für AI Moderation",
      "quickstart.reqRust": "Projekt-Toolchain",
      "quickstart.title": "FoxSecura lokal starten.",
      "reference.action": "Aktion",
      "reference.database": "Datenbank",
      "reference.databaseText": "Der Standardpfad des Clients ist `data/foxsecura.sqlite3`. Das Schema startet bei Version 1 und Migrationen laufen transaktional.",
      "reference.decision": "Entscheidung",
      "reference.defaultPath": "Pfad",
      "reference.detect": "Erkennung",
      "reference.discordToken": "Erforderlich, um den Bot mit dem Discord Gateway zu verbinden.",
      "reference.environment": "Umgebungsvariablen",
      "reference.input": "Ereignis",
      "reference.intents": "Discord Intents",
      "reference.intentsText": "FoxSecura fordert aktuell drei Gateway-Intents an. `GUILD_MEMBERS` ist privilegiert und muss im Discord Developer Portal aktiviert werden.",
      "reference.kicker": "Referenz",
      "reference.license": "Lizenz",
      "reference.licenseText": "FoxSecura wird ausschließlich unter der GNU Affero General Public License v3.0 veröffentlicht, SPDX `AGPL-3.0-only`.",
      "reference.openaiKey": "Aktiviert den OpenAI-Provider für AI Moderation.",
      "reference.readLicense": "Lizenz lesen",
      "reference.schema": "Schema",
      "reference.secretNote": "Diese Geheimnisse niemals in Git committen.",
      "reference.security": "Sicherheitsmodell",
      "reference.securityText": "Die Engines erzeugen typisierte Signale und Entscheidungen. Erkennungslogik ist von Discord-Nebenwirkungen getrennt. Für KI erhält der Provider keine Discord-Objekte und gibt niemals eine Sanktion zurück.",
      "reference.title": "Was du wissen solltest.",
      "search.caption": "Schnellnavigation",
      "search.emptyText": "Versuche ein Modul, einen Befehl oder eine Technologie.",
      "search.emptyTitle": "Keine Ergebnisse",
      "search.placeholder": "Dokumentation durchsuchen...",
      "stack.built": "Gebaut mit",
      "status.ci": "Jede Rust-Änderung wird vor main mit cargo check und cargo test validiert.",
      "status.done": "Implementiert und getestet",
      "status.itemActions": "Discord-Aktionsschicht und finale Sanktionen",
      "status.itemCommands": "Befehle /config, /help und /status",
      "status.itemConfig": "Vollständige Persistenz der /config-Dashboard-Einstellungen",
      "status.itemDb": "SQLite-Basis, Migrationen und erste Repositories",
      "status.itemEvents": "Vollständige Anbindung der Engines an Discord-Ereignisse",
      "status.itemI18n": "Typisiertes i18n für EN / FR / DE",
      "status.itemLogChannels": "Automatische Erstellung und Pflege der Log-Kanäle",
      "status.itemLogs": "Log-Modelle und Formatierung",
      "status.itemProtections": "Anti-Spam, Anti-Raid, Anti-Nuke, AutoMod und AI Moderation Engines",
      "status.kicker": "Projektstatus",
      "status.lead": "Diese Seite trennt klar zwischen bereits implementierten Teilen und noch ausstehender Integration, damit FoxSecura nie zu früh als fertig dargestellt wird.",
      "status.progress": "Integration läuft",
      "status.title": "Eine solide Basis, noch in Integration.",
      "status.viewCi": "CI ansehen"
    }
  };

  const titleByLanguage = {
    fr: "FoxSecura - Sécurité Discord moderne",
    en: "FoxSecura - Modern Discord Security",
    de: "FoxSecura - Moderne Discord-Sicherheit"
  };

  const descriptionByLanguage = {
    fr: "FoxSecura, bot Discord de sécurité open source écrit en Rust. Protection anti-spam, anti-raid, anti-nuke, AutoMod, modération IA, logs et configuration multilingue.",
    en: "FoxSecura, an open-source Discord security bot written in Rust. Anti-spam, anti-raid, anti-nuke, AutoMod, AI moderation, logs and multilingual configuration.",
    de: "FoxSecura, ein quelloffener Discord-Sicherheitsbot in Rust. Anti-Spam, Anti-Raid, Anti-Nuke, AutoMod, KI-Moderation, Logs und mehrsprachige Konfiguration."
  };

  const supportedLanguages = new Set(["fr", "en", "de"]);
  const languageSelect = document.querySelector("#language-select");
  const translatableNodes = [...document.querySelectorAll("[data-i18n]")];
  const placeholderNodes = [...document.querySelectorAll("[data-i18n-placeholder]")];

  translatableNodes.forEach((node) => {
    node.dataset.i18nOriginal = node.textContent;
  });

  placeholderNodes.forEach((node) => {
    node.dataset.i18nPlaceholderOriginal = node.getAttribute("placeholder") || "";
  });

  function resolveInitialLanguage() {
    const stored = localStorage.getItem("foxsecura-docs-language");
    if (stored && supportedLanguages.has(stored)) return stored;

    const browserLanguage = (navigator.language || "fr").toLowerCase().split(/[-_]/)[0];
    return supportedLanguages.has(browserLanguage) ? browserLanguage : "fr";
  }

  function translationFor(language, key, fallback) {
    if (language === "fr") return fallback;
    return translations[language]?.[key] || fallback;
  }

  function applyLanguage(language) {
    const resolved = supportedLanguages.has(language) ? language : "fr";
    document.documentElement.lang = resolved;
    localStorage.setItem("foxsecura-docs-language", resolved);

    translatableNodes.forEach((node) => {
      const key = node.dataset.i18n;
      const fallback = node.dataset.i18nOriginal || node.textContent;
      node.textContent = translationFor(resolved, key, fallback);
    });

    placeholderNodes.forEach((node) => {
      const key = node.dataset.i18nPlaceholder;
      const fallback = node.dataset.i18nPlaceholderOriginal || "";
      node.setAttribute("placeholder", translationFor(resolved, key, fallback));
    });

    document.title = titleByLanguage[resolved];
    const metaDescription = document.querySelector('meta[name="description"]');
    if (metaDescription) metaDescription.setAttribute("content", descriptionByLanguage[resolved]);

    if (languageSelect) languageSelect.value = resolved;
    refreshSearchIndex();
    renderSearchResults(document.querySelector("#search-input")?.value || "");
  }

  if (languageSelect) {
    languageSelect.addEventListener("change", (event) => applyLanguage(event.target.value));
  }

  applyLanguage(resolveInitialLanguage());

  const root = document.documentElement;
  const themeToggle = document.querySelector("#theme-toggle");

  function initialTheme() {
    const stored = localStorage.getItem("foxsecura-docs-theme");
    if (stored === "light" || stored === "dark") return stored;
    return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }

  function setTheme(theme) {
    root.dataset.theme = theme;
    localStorage.setItem("foxsecura-docs-theme", theme);
    if (themeToggle) {
      themeToggle.setAttribute(
        "aria-label",
        theme === "dark" ? "Activer le thème clair" : "Activer le thème sombre"
      );
    }
  }

  setTheme(initialTheme());

  themeToggle?.addEventListener("click", () => {
    setTheme(root.dataset.theme === "dark" ? "light" : "dark");
  });

  const header = document.querySelector(".site-header");
  const progress = document.querySelector("#scroll-progress");

  function updateScrollUi() {
    const scrollTop = window.scrollY;
    header?.classList.toggle("scrolled", scrollTop > 10);

    const scrollable = document.documentElement.scrollHeight - window.innerHeight;
    const ratio = scrollable > 0 ? Math.min(1, scrollTop / scrollable) : 0;
    if (progress) progress.style.width = `${ratio * 100}%`;
  }

  updateScrollUi();
  window.addEventListener("scroll", updateScrollUi, { passive: true });
  window.addEventListener("resize", updateScrollUi);

  const mobileButton = document.querySelector("#mobile-menu-button");
  const mobileNav = document.querySelector("#mobile-nav");

  function closeMobileNav() {
    mobileNav?.classList.remove("open");
    mobileButton?.setAttribute("aria-expanded", "false");
  }

  mobileButton?.addEventListener("click", () => {
    const open = mobileNav?.classList.toggle("open");
    mobileButton.setAttribute("aria-expanded", open ? "true" : "false");
  });

  mobileNav?.querySelectorAll("a").forEach((link) => link.addEventListener("click", closeMobileNav));

  document.addEventListener("click", (event) => {
    if (!mobileNav?.classList.contains("open")) return;
    if (mobileNav.contains(event.target) || mobileButton?.contains(event.target)) return;
    closeMobileNav();
  });

  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const revealNodes = [...document.querySelectorAll(".reveal")];

  if (reducedMotion || !("IntersectionObserver" in window)) {
    revealNodes.forEach((node) => node.classList.add("visible"));
  } else {
    const revealObserver = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        const delay = Number(entry.target.dataset.delay || 0);
        window.setTimeout(() => entry.target.classList.add("visible"), delay);
        revealObserver.unobserve(entry.target);
      });
    }, { threshold: 0.12, rootMargin: "0px 0px -35px" });

    revealNodes.forEach((node) => revealObserver.observe(node));
  }

  const mainSections = [...document.querySelectorAll("main > section[id]")];
  const desktopLinks = [...document.querySelectorAll(".desktop-nav a[href^='#']")];

  if ("IntersectionObserver" in window) {
    const navObserver = new IntersectionObserver((entries) => {
      const visible = entries
        .filter((entry) => entry.isIntersecting)
        .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];

      if (!visible) return;
      desktopLinks.forEach((link) => {
        link.classList.toggle("active", link.getAttribute("href") === `#${visible.target.id}`);
      });
    }, { threshold: [0.18, 0.35, 0.55], rootMargin: "-20% 0px -60%" });

    mainSections.forEach((section) => navObserver.observe(section));
  }

  const referenceArticles = [...document.querySelectorAll(".reference-article")];
  const referenceLinks = [...document.querySelectorAll("[data-reference-link]")];

  if ("IntersectionObserver" in window) {
    const referenceObserver = new IntersectionObserver((entries) => {
      const active = entries.find((entry) => entry.isIntersecting);
      if (!active) return;

      referenceLinks.forEach((link) => {
        link.classList.toggle("active", link.getAttribute("href") === `#${active.target.id}`);
      });
    }, { rootMargin: "-20% 0px -65%", threshold: 0 });

    referenceArticles.forEach((article) => referenceObserver.observe(article));
  }

  document.querySelectorAll("[data-copy-target]").forEach((button) => {
    button.addEventListener("click", async () => {
      const target = document.querySelector(`#${CSS.escape(button.dataset.copyTarget)}`);
      if (!target) return;

      try {
        await navigator.clipboard.writeText(target.innerText);
        const language = document.documentElement.lang;
        const copied = language === "de" ? "Kopiert" : language === "en" ? "Copied" : "Copié";
        const original = translationFor(
          language,
          "common.copy",
          button.dataset.i18nOriginal || "Copier"
        );
        button.textContent = copied;
        window.setTimeout(() => {
          button.textContent = original;
        }, 1300);
      } catch {
        // Clipboard may be unavailable on an insecure local origin.
      }
    });
  });

  const searchDialog = document.querySelector("#search-dialog");
  const searchInput = document.querySelector("#search-input");
  const searchResults = document.querySelector("#search-results");
  const searchEmpty = document.querySelector("#search-empty");
  let searchIndex = [];

  function targetForSearchNode(node) {
    if (node.id) return `#${node.id}`;

    const section = node.closest("section[id]");
    return section ? `#${section.id}` : "#home";
  }

  function labelForSearchNode(node) {
    const heading = node.matches("h1,h2,h3,h4,code,strong")
      ? node
      : node.querySelector("h1,h2,h3,h4,.command-line code,strong");

    return (heading?.textContent || node.dataset.search || "FoxSecura").trim();
  }

  function refreshSearchIndex() {
    searchIndex = [...document.querySelectorAll("[data-search]")].map((node) => ({
      label: labelForSearchNode(node),
      href: targetForSearchNode(node),
      keywords: `${node.dataset.search || ""} ${node.textContent || ""}`.toLowerCase()
    }));

    const navigationEntries = [
      ["Protections", "#protections"],
      ["Architecture", "#architecture"],
      ["Documentation", "#docs"],
      ["Quickstart", "#quickstart"],
      ["Status", "#status"]
    ];

    navigationEntries.forEach(([label, href]) => {
      if (!searchIndex.some((entry) => entry.href === href && entry.label === label)) {
        searchIndex.push({ label, href, keywords: `${label} ${href}`.toLowerCase() });
      }
    });
  }

  function resultMeta(href) {
    const language = document.documentElement.lang;
    if (href === "#protections") return language === "de" ? "Schutz" : language === "en" ? "Protection" : "Protection";
    if (href === "#architecture") return language === "de" ? "Architektur" : "Architecture";
    if (href === "#quickstart") return language === "de" ? "Entwicklung" : language === "en" ? "Development" : "Développement";
    if (href === "#status") return language === "de" ? "Status" : language === "en" ? "Status" : "État";
    return language === "de" ? "Dokumentation" : language === "en" ? "Documentation" : "Documentation";
  }

  function renderSearchResults(query = "") {
    if (!searchResults || !searchEmpty) return;

    const normalized = query.trim().toLowerCase();
    const matches = searchIndex
      .filter((entry) => !normalized || entry.keywords.includes(normalized))
      .slice(0, 9);

    searchResults.innerHTML = "";
    searchEmpty.hidden = matches.length > 0;

    matches.forEach((entry, index) => {
      const link = document.createElement("a");
      link.className = `search-result${index === 0 ? " active" : ""}`;
      link.href = entry.href;

      const label = document.createElement("span");
      label.textContent = entry.label;

      const meta = document.createElement("small");
      meta.textContent = resultMeta(entry.href);

      link.append(label, meta);
      link.addEventListener("click", closeSearch);
      searchResults.append(link);
    });
  }

  function openSearch() {
    if (!searchDialog) return;
    searchDialog.hidden = false;
    document.body.style.overflow = "hidden";
    renderSearchResults(searchInput?.value || "");
    window.requestAnimationFrame(() => searchInput?.focus());
  }

  function closeSearch() {
    if (!searchDialog) return;
    searchDialog.hidden = true;
    document.body.style.overflow = "";
  }

  refreshSearchIndex();

  document.querySelectorAll("[data-search-open]").forEach((button) => {
    button.addEventListener("click", openSearch);
  });

  document.querySelectorAll("[data-search-close]").forEach((element) => {
    element.addEventListener("click", closeSearch);
  });

  searchInput?.addEventListener("input", (event) => renderSearchResults(event.target.value));

  document.addEventListener("keydown", (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      openSearch();
      return;
    }

    if (event.key === "Escape" && !searchDialog?.hidden) {
      closeSearch();
      return;
    }

    if (event.key === "Enter" && !searchDialog?.hidden && document.activeElement === searchInput) {
      const firstResult = searchResults?.querySelector(".search-result");
      if (firstResult) {
        event.preventDefault();
        firstResult.click();
      }
    }
  });

  const details = [...document.querySelectorAll(".faq-list details")];
  details.forEach((detail) => {
    detail.addEventListener("toggle", () => {
      if (!detail.open) return;
      details.forEach((other) => {
        if (other !== detail) other.open = false;
      });
    });
  });
})();
