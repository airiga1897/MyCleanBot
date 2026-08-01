function csrfToken() {
  return document.querySelector('input[name="csrfmiddlewaretoken"]')?.value || "";
}

document.querySelectorAll(".js-single-submit").forEach((form) => {
  form.addEventListener("submit", () => {
    const button = form.querySelector('button[type="submit"]');
    if (!button) return;
    button.disabled = true;
    button.textContent = "Создаём аккаунт…";
  });
});

document.querySelectorAll(".js-copy-invite").forEach((button) => {
  button.addEventListener("click", async () => {
    const input = document.getElementById(button.dataset.target);
    const result = button.parentElement.querySelector(".copy-result");
    if (!input || !result) return;
    try {
      await navigator.clipboard.writeText(input.value);
      result.textContent = "Ссылка скопирована";
    } catch {
      input.select();
      result.textContent = "Скопируйте выделенную ссылку";
    }
  });
});

document.querySelectorAll(".js-reveal-rule").forEach((button) => {
  button.addEventListener("click", async () => {
    const target = document.getElementById(button.dataset.target);
    if (!target) return;
    if (button.dataset.revealed === "true") {
      target.textContent = "••••••••";
      button.textContent = "Показать";
      button.dataset.revealed = "false";
      return;
    }
    const response = await fetch(button.dataset.url, {
      method: "POST",
      headers: {"X-CSRFToken": csrfToken()},
      credentials: "same-origin",
      cache: "no-store",
    });
    if (!response.ok) return;
    const data = await response.json();
    target.textContent = data.phrase;
    button.textContent = "Скрыть";
    button.dataset.revealed = "true";
  });
});

document.querySelectorAll(".js-test-rule").forEach((form) => {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const result = form.querySelector(".test-result");
    const response = await fetch(form.action, {
      method: "POST",
      body: new FormData(form),
      credentials: "same-origin",
      cache: "no-store",
    });
    const data = await response.json();
    result.textContent = response.ok
      ? (data.matched ? "Совпадение найдено" : "Совпадения нет")
      : (data.error || "Проверка не выполнена");
  });
});

const statusRoot = document.querySelector("[data-dashboard-status-url]");
if (statusRoot) {
  const pollMs = Math.max(
    5000,
    Number(statusRoot.dataset.dashboardPollSeconds || 15) * 1000,
  );
  const activePollMs = Math.max(
    2000,
    Number(statusRoot.dataset.activeScanPollSeconds || 5) * 1000,
  );
  let nextPollMs = pollMs;
  let pollTimer = null;
  const sourceNames = {body: "текст", caption: "подпись", link_target: "ссылка"};
  const chatNames = {
    saved: "Избранное",
    private: "личный чат",
    group: "группа",
    supergroup: "супергруппа",
    channel: "канал",
  };
  const formatTime = (value) => value ? new Date(value).toLocaleString("ru-RU") : "пока нет";
  const updateDashboard = async () => {
    nextPollMs = pollMs;
    const response = await fetch(statusRoot.dataset.dashboardStatusUrl, {
      credentials: "same-origin",
      cache: "no-store",
    });
    if (!response.ok) return;
    const data = await response.json();
    if (data.history_scan && ["queued", "running"].includes(data.history_scan.status_code)) {
      nextPollMs = activePollMs;
    }
    document.getElementById("account-status").textContent = data.account.status;
    document.getElementById("account-heartbeat").textContent = formatTime(data.account.heartbeat);
    document.getElementById("account-update").textContent = formatTime(data.account.last_update);
    document.getElementById("stat-total").textContent = data.stats.total;
    document.getElementById("stat-successful").textContent = data.stats.successful;
    document.getElementById("stat-failed").textContent = data.stats.failed;
    document.getElementById("mini-stat-total").textContent = data.mini_app_stats.total;
    document.getElementById("mini-stat-successful").textContent = data.mini_app_stats.successful;
    document.getElementById("mini-stat-failed").textContent = data.mini_app_stats.failed;
    Object.entries(data.rule_scans || {}).forEach(([ruleId, scan]) => {
      const root = document.getElementById(`rule-history-${ruleId}`);
      if (!root) return;
      ["status", "messages_scanned", "matches_found", "deleted_self", "failed_actions"]
        .forEach((field) => {
          const element = root.querySelector(`[data-field="${field}"]`);
          if (element) element.textContent = scan[field];
        });
    });
    const historyRoot = document.querySelector(".history-status");
    if (historyRoot && data.history_scan) {
      const scan = data.history_scan;
      [
        ["history-phase", scan.phase],
        ["history-status", scan.status],
        ["history-dialogs", scan.dialogs_scanned],
        ["history-messages", scan.messages_scanned],
        ["history-matches", scan.matches_found],
        ["history-deleted", scan.deleted_self],
        ["history-skipped", scan.skipped_global],
        ["history-failed", scan.failed_actions],
      ].forEach(([id, value]) => {
        const element = document.getElementById(id);
        if (element) element.textContent = value;
      });
      if (historyRoot.dataset.historyStatus !== scan.status_code &&
          ["awaiting_confirmation", "completed", "cancelled", "failed"].includes(scan.status_code)) {
        window.location.reload();
        return;
      }
    }
    const body = document.getElementById("event-table-body");
    body.replaceChildren();
    if (!data.events.length) {
      const row = body.insertRow();
      const cell = row.insertCell();
      cell.colSpan = 6;
      cell.textContent = "Событий пока нет.";
    } else {
      data.events.forEach((item) => {
        const row = body.insertRow();
        [
          formatTime(item.created_at),
          item.rule_ids.map((id) => `#${id}`).join(", "),
          item.direction,
          sourceNames[item.source] || item.source,
          chatNames[item.chat_type] || item.chat_type,
          item.result,
        ].forEach((value) => {
          row.insertCell().textContent = value;
        });
      });
    }
    const miniBody = document.getElementById("mini-event-table-body");
    miniBody.replaceChildren();
    if (!data.mini_app_events.length) {
      const row = miniBody.insertRow();
      const cell = row.insertCell();
      cell.colSpan = 5;
      cell.textContent = "Событий пока нет.";
    } else {
      data.mini_app_events.forEach((item) => {
        const row = miniBody.insertRow();
        const rule = item.rule_id
          ? `#${item.rule_id}`
          : (item.legacy_rule_id ? `служебное #${item.legacy_rule_id}` : "—");
        const bot = [item.bot_id || "", item.bot_username ? `@${item.bot_username}` : ""]
          .filter(Boolean).join(" ");
        [formatTime(item.created_at), rule, item.event_type, bot, item.result]
          .forEach((value) => row.insertCell().textContent = value);
      });
    }
  };
  const scheduleUpdate = (delay = pollMs) => {
    window.clearTimeout(pollTimer);
    pollTimer = window.setTimeout(async () => {
      try {
        if (!document.hidden) await updateDashboard();
      } finally {
        scheduleUpdate(nextPollMs);
      }
    }, delay);
  };
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) scheduleUpdate(0);
  });
  scheduleUpdate();
}
