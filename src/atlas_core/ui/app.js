"use strict";

const state = {
  token: sessionStorage.getItem("atlasToken") || "",
  settings: null,
  developmentControl: null,
  developmentControlBusy: false,
  developmentControlSequence: 0,
  providers: [],
  agents: [],
  projects: [],
  conversations: [],
  approvals: [],
  identity: null,
  permissions: null,
  googleConnection: null,
  currentConversationId: null,
  currentRunId: null,
  conversationLoadSequence: 0,
  supervisorV2Task: null,
  supervisorV3Task: null,
  editMemoryId: null,
  editProjectSlug: null,
  busy: false,
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

function authHeaders(extra = {}) {
  const headers = { ...extra };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  return headers;
}

async function api(path, options = {}) {
  const init = { ...options };
  init.headers = authHeaders(init.headers || {});
  if (init.body && !(init.body instanceof FormData) && typeof init.body !== "string") {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(init.body);
  }
  const response = await fetch(path, init);
  if (response.status === 401) {
    showTokenModal();
  }
  const contentType = response.headers.get("content-type") || "";
  let payload = null;
  if (contentType.includes("application/json")) {
    payload = await response.json().catch(() => null);
  } else if (response.status !== 204) {
    payload = await response.text().catch(() => "");
  }
  if (!response.ok) {
    const detail = payload?.detail || payload?.error || payload || `${response.status} ${response.statusText}`;
    throw new Error(String(detail));
  }
  return payload;
}

async function streamNDJSON(path, payload, onEvent) {
  const response = await fetch(path, {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(payload || {}),
  });
  if (response.status === 401) showTokenModal();
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const body = await response.json();
      detail = body.detail || body.error || detail;
    } catch (_) {
      // Keep the HTTP status.
    }
    throw new Error(detail);
  }
  if (!response.body) throw new Error("This browser cannot read streaming responses.");

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop() || "";
      for (const line of lines) {
        if (!line.trim()) continue;
        if (await onEvent(JSON.parse(line)) === true) return;
      }
    }
    buffer += decoder.decode();
    if (buffer.trim()) await onEvent(JSON.parse(buffer));
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

function escapeHTML(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function inlineMarkdown(value) {
  return escapeHTML(value)
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/\*([^*]+)\*/g, "<em>$1</em>");
}

function markdown(value) {
  const lines = String(value ?? "").replaceAll("\r\n", "\n").split("\n");
  const html = [];
  let code = false;
  let codeLines = [];
  let list = false;
  let paragraph = [];

  const closeParagraph = () => {
    if (paragraph.length) {
      html.push(`<p>${paragraph.map(inlineMarkdown).join("<br>")}</p>`);
      paragraph = [];
    }
  };
  const closeList = () => {
    if (list) {
      html.push("</ul>");
      list = false;
    }
  };

  for (const line of lines) {
    if (line.trim().startsWith("```")) {
      closeParagraph();
      closeList();
      if (code) {
        html.push(`<pre><code>${escapeHTML(codeLines.join("\n"))}</code></pre>`);
        codeLines = [];
        code = false;
      } else {
        code = true;
      }
      continue;
    }
    if (code) {
      codeLines.push(line);
      continue;
    }
    const heading = line.match(/^(#{1,3})\s+(.*)$/);
    if (heading) {
      closeParagraph();
      closeList();
      const level = heading[1].length;
      html.push(`<h${level}>${inlineMarkdown(heading[2])}</h${level}>`);
      continue;
    }
    const bullet = line.match(/^\s*[-*]\s+(.*)$/);
    if (bullet) {
      closeParagraph();
      if (!list) {
        html.push("<ul>");
        list = true;
      }
      html.push(`<li>${inlineMarkdown(bullet[1])}</li>`);
      continue;
    }
    if (!line.trim()) {
      closeParagraph();
      closeList();
      continue;
    }
    closeList();
    paragraph.push(line);
  }
  if (code) html.push(`<pre><code>${escapeHTML(codeLines.join("\n"))}</code></pre>`);
  closeParagraph();
  closeList();
  return html.join("");
}

function formatDate(value) {
  if (!value) return "";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? String(value) : date.toLocaleString();
}

function clip(value, length = 180) {
  const text = String(value ?? "").replace(/\s+/g, " ").trim();
  return text.length > length ? `${text.slice(0, length)}…` : text;
}

let toastTimer = null;
function toast(message, type = "") {
  const node = $("#toast");
  node.textContent = message;
  node.className = `toast ${type}`.trim();
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => node.classList.add("hidden"), 4500);
}

function setRunStatus(label, tone = "") {
  const node = $("#run-status");
  node.textContent = label;
  node.className = `pill ${tone}`.trim();
  if (state.busy) $("#chat-status-label").textContent = label;
}

function showTokenModal() {
  $("#token-modal").classList.remove("hidden");
  $("#modal-token").focus();
}

function hideTokenModal() {
  $("#token-modal").classList.add("hidden");
}

function setView(name) {
  $$(".nav-button").forEach((button) => button.classList.toggle("active", button.dataset.view === name));
  $$(".view").forEach((view) => view.classList.toggle("active", view.id === `view-${name}`));
  closeSidebar();
  if (name === "memory") loadMemories().catch(handleError);
  if (name === "projects") loadProjects().catch(handleError);
  if (name === "approvals") loadApprovals().catch(handleError);
  if (name === "agents") renderAgents();
  if (name === "settings") loadSettingsView().catch(handleError);
  if (name === "audit") loadAudit().catch(handleError);
}

function openSidebar() {
  $("#sidebar").classList.add("open");
  $("#mobile-scrim").classList.add("open");
}

function closeSidebar() {
  $("#sidebar").classList.remove("open");
  $("#mobile-scrim").classList.remove("open");
}

function handleError(error) {
  console.error(error);
  toast(error?.message || String(error), "error");
  setRunStatus("Error", "danger");
}

function populateSelects() {
  const agentSelect = $("#agent-select");
  const selectedAgent = agentSelect.value || state.settings?.default_agent || "atlas";
  agentSelect.innerHTML = state.agents
    .map((agent) => `<option value="${escapeHTML(agent.slug)}">${escapeHTML(agent.name)}</option>`)
    .join("");
  if (state.agents.some((agent) => agent.slug === selectedAgent)) agentSelect.value = selectedAgent;

  const providerSelect = $("#provider-select");
  const selectedProvider = providerSelect.value || state.settings?.default_provider || "local";
  providerSelect.innerHTML = state.providers
    .map((provider) => {
      const suffix = provider.local ? "local" : provider.configured ? "cloud" : "not configured";
      return `<option value="${escapeHTML(provider.name)}">${escapeHTML(provider.name)} · ${escapeHTML(provider.model)} (${suffix})</option>`;
    })
    .join("");
  if (state.providers.some((provider) => provider.name === selectedProvider)) providerSelect.value = selectedProvider;

  const projectSelect = $("#project-select");
  const selectedProject = projectSelect.value;
  projectSelect.innerHTML = '<option value="">No project</option>' + state.projects
    .map((project) => `<option value="${escapeHTML(project.slug)}">${escapeHTML(project.name)}</option>`)
    .join("");
  if (state.projects.some((project) => project.slug === selectedProject)) projectSelect.value = selectedProject;
}

const developmentControlProject = "atlas-selfdev";
let developmentControlTimer = null;

function renderDevelopmentControl() {
  const control = state.developmentControl;
  const status = $("#development-control-status");
  const stop = $("#stop-development");
  const resume = $("#resume-development");
  stop.disabled = state.developmentControlBusy || control?.available === false;
  $("#refresh-development-control").disabled = state.developmentControlBusy;
  resume.disabled = state.developmentControlBusy || !control?.available || !control.stopped ||
    control.cleanup_required || Number(control.active_operations || 0) > 0;
  if (!control) status.textContent = "Control unavailable. A stop has not been confirmed; check status again.";
  else if (!control.available) status.textContent = "This development copy is not registered. Controls are unavailable.";
  else if (control.cleanup_required) status.textContent = "Development is blocked. Cleanup needs attention before it can resume.";
  else if (Number(control.active_operations || 0) > 0 && control.stopped) status.textContent = "Stopping development… waiting for work and cleanup to finish.";
  else if (control.stopped) status.textContent = "Development stopped. Resume allows new work; interrupted work stays stopped.";
  else status.textContent = "Development is allowed under its existing limits. No schedule is started here.";
}

async function refreshDevelopmentControl() {
  if (state.developmentControlBusy) return;
  const sequence = ++state.developmentControlSequence;
  clearTimeout(developmentControlTimer);
  try {
    const result = await api(`/v1/development-control?project=${developmentControlProject}`);
    if (sequence !== state.developmentControlSequence) return;
    state.developmentControl = result;
  } catch (_) {
    if (sequence !== state.developmentControlSequence) return;
    state.developmentControl = null;
  }
  renderDevelopmentControl();
  await refreshImprovement();
  if (state.developmentControl?.available && Number(state.developmentControl.active_operations || 0) > 0) {
    developmentControlTimer = setTimeout(refreshDevelopmentControl, 1000);
  }
}

async function changeDevelopmentControl(action) {
  if (state.developmentControlBusy) return;
  const control = state.developmentControl;
  if (action === "resume") {
    if (!control?.available || !control.stopped || control.cleanup_required || Number(control.active_operations || 0) > 0) return;
    if (!window.confirm("Resume Atlas development for the atlas-selfdev copy? This allows new work under its existing limits. Interrupted work will not restart.")) return;
  }
  state.developmentControlBusy = true;
  ++state.developmentControlSequence;
  clearTimeout(developmentControlTimer);
  renderDevelopmentControl();
  $("#development-control-status").textContent = action === "stop" ? "Sending the development stop request…" : "Requesting development resume…";
  try {
    state.developmentControl = await api(`/v1/development-control/${action}?project=${developmentControlProject}`, {
      method: "POST",
      ...(action === "resume" ? { body: { confirmation: "Resume Atlas development", expected_epoch: control.epoch } } : {}),
    });
  } catch (error) {
    state.developmentControl = null;
    toast(`Could not confirm development ${action}: ${error.message}`, "error");
  } finally {
    state.developmentControlBusy = false;
    renderDevelopmentControl();
    if (state.developmentControl?.available && Number(state.developmentControl.active_operations || 0) > 0) {
      developmentControlTimer = setTimeout(refreshDevelopmentControl, 1000);
    }
  }
}

async function bootstrap() {
  try {
    const health = await api("/health");
    $("#health-dot").classList.add("online");
    $("#health-label").textContent = `Atlas ${health.version}`;
    if (health.api_token_required && !state.token) {
      showTokenModal();
      return;
    }
    const [settings, providers, agents, projects, conversations, approvals] = await Promise.all([
      api("/v1/settings"),
      api("/v1/providers"),
      api("/v1/agents"),
      api("/v1/projects"),
      api("/v1/conversations?limit=200"),
      api("/v1/approvals?limit=200"),
    ]);
    state.settings = settings;
    state.providers = providers;
    state.agents = agents;
    state.projects = projects;
    state.conversations = conversations;
    state.approvals = approvals;
    populateSelects();
    renderConversations();
    renderProjects();
    renderApprovals();
    renderAgents();
    setRunStatus("Ready", "success");
    hideTokenModal();
    await refreshDevelopmentControl();
  } catch (error) {
    if (String(error.message).toLowerCase().includes("token")) showTokenModal();
    else handleError(error);
  }
}

function renderConversations() {
  const node = $("#conversation-list");
  if (!state.conversations.length) {
    node.innerHTML = '<div class="empty-mini">No conversations yet</div>';
    return;
  }
  node.innerHTML = state.conversations
    .map((conversation) => `
      <button class="conversation-item ${conversation.id === state.currentConversationId ? "active" : ""}" data-conversation-id="${escapeHTML(conversation.id)}" ${state.busy ? "disabled" : ""}>
        <div class="conversation-title">${escapeHTML(conversation.title || "Untitled conversation")}</div>
        <div class="conversation-preview">${escapeHTML(clip(conversation.last_message || "", 64))}</div>
      </button>`)
    .join("");
  node.querySelectorAll("[data-conversation-id]").forEach((button) => {
    button.addEventListener("click", () => loadConversation(button.dataset.conversationId).catch(handleError));
  });
}

function clearMessages(showWelcome = true) {
  const messages = $("#messages");
  messages.innerHTML = "";
  if (showWelcome) {
    const welcome = document.createElement("div");
    welcome.className = "welcome-card";
    welcome.id = "welcome-card";
    welcome.innerHTML = `
      <div class="welcome-mark">A</div>
      <h1>Atlas Core</h1>
      <p>Your identity, memory, projects, permissions, and agents live here—independent of any one model.</p>
      <div class="starter-grid">
        <button class="starter" data-prompt="Explain what you can do locally and where your memory is stored.">Explain this system</button>
        <button class="starter" data-prompt="List my active projects and summarize the next action for each.">Review my projects</button>
        <button class="starter" data-prompt="Search your explicit memory for anything related to Atlas Core.">Inspect memory</button>
      </div>`;
    messages.appendChild(welcome);
    bindStarters(welcome);
  }
}

function bindStarters(root = document) {
  root.querySelectorAll("[data-prompt]").forEach((button) => {
    button.addEventListener("click", () => {
      $("#message-input").value = button.dataset.prompt || "";
      resizeComposer();
      sendMessage().catch(handleError);
    });
  });
}

function addMessage(role, content, metadata = {}) {
  const welcome = $("#welcome-card");
  if (welcome) welcome.remove();
  const row = document.createElement("div");
  row.className = `message-row ${role}`;
  if (role === "assistant") {
    const avatar = document.createElement("div");
    avatar.className = "avatar";
    avatar.textContent = "A";
    row.appendChild(avatar);
  }
  const card = document.createElement("div");
  card.className = "message-card";
  card.innerHTML = markdown(content);
  if (metadata.label) {
    const meta = document.createElement("div");
    meta.className = "message-meta";
    meta.textContent = metadata.label;
    card.appendChild(meta);
  }
  row.appendChild(card);
  $("#messages").appendChild(row);
  $("#messages").scrollTop = $("#messages").scrollHeight;
  return { row, card, content: String(content || "") };
}

function nearLatestMessage() {
  const messages = $("#messages");
  return messages.scrollHeight - messages.clientHeight - messages.scrollTop < 80;
}

function updateAssistant(message, content, label = "") {
  const follow = nearLatestMessage();
  message.content = content;
  message.card.innerHTML = markdown(content);
  if (label) {
    const meta = document.createElement("div");
    meta.className = "message-meta";
    meta.textContent = label;
    message.card.appendChild(meta);
  }
  if (follow) $("#messages").scrollTop = $("#messages").scrollHeight;
}

function addTrace(text, tone = "") {
  const follow = nearLatestMessage();
  const node = document.createElement("div");
  node.className = `run-trace ${tone}`.trim();
  node.textContent = text;
  $("#messages").appendChild(node);
  if (follow) $("#messages").scrollTop = $("#messages").scrollHeight;
  return node;
}

async function loadConversation(id, { duringApproval = false } = {}) {
  if (!id || (state.busy && !duringApproval)) return;
  const sequence = ++state.conversationLoadSequence;
  const conversation = await api(`/v1/conversations/${encodeURIComponent(id)}`);
  const pendingRun = (conversation.runs || []).find((run) => run.status === "awaiting_approval");
  let approval = null;
  if (pendingRun?.pending_approval_id) {
    approval = state.approvals.find((item) => item.id === pendingRun.pending_approval_id)
      || await api(`/v1/approvals?approval_status=pending&limit=200`).then((items) => items.find((item) => item.id === pendingRun.pending_approval_id));
  }
  if ((state.busy && !duringApproval) || sequence !== state.conversationLoadSequence) return;
  state.currentConversationId = id;
  state.currentRunId = pendingRun?.id || null;
  clearMessages(false);
  for (const message of conversation.messages || []) {
    if (message.role === "user") addMessage("user", message.content, { label: formatDate(message.created_at) });
    if (message.role === "assistant" && message.content) {
      const label = [message.provider, message.model].filter(Boolean).join(" · ");
      addMessage("assistant", message.content, { label });
    }
  }
  if (!(conversation.messages || []).some((message) => ["user", "assistant"].includes(message.role))) {
    clearMessages(true);
  }
  $("#agent-select").value = conversation.agent_slug || state.settings?.default_agent || "atlas";
  $("#project-select").value = conversation.project_slug || "";
  if (approval) {
    showInlineApproval(approval);
  } else {
    hideInlineApproval();
  }
  renderConversations();
  setView("chat");
}

function newConversation() {
  if (state.busy) return;
  state.conversationLoadSequence++;
  state.currentConversationId = null;
  state.currentRunId = null;
  clearMessages(true);
  hideInlineApproval();
  renderConversations();
  setRunStatus("Ready", "success");
  setView("chat");
  $("#message-input").focus();
}

function setBusy(value) {
  state.busy = value;
  if (value) state.conversationLoadSequence++;
  $("#send-button").disabled = value;
  $("#message-input").disabled = value;
  $$("#new-conversation, .conversation-item, #agent-select, #provider-select, #project-select, #local-only, #tools-enabled").forEach((node) => { node.disabled = value; });
  $("#messages").setAttribute("aria-busy", String(value));
  $("#chat-status").classList.toggle("hidden", !value);
  if (value) setRunStatus("Atlas is thinking…", "warning");
}

async function processRunStream(path, payload, assistantMessage) {
  let result = null;
  let accumulated = assistantMessage?.content || "";
  // Only this request's run can be recovered; never reuse an earlier run ID.
  let runId = null;
  let serverFailed = false;
  let streamError = null;
  try {
    await streamNDJSON(path, payload, async (event) => {
      switch (event.event) {
        case "run.started":
        case "run.resumed":
          runId = event.run_id;
          state.currentRunId = runId;
          state.currentConversationId = event.conversation_id || state.currentConversationId;
          setRunStatus("Atlas is thinking…", "warning");
          break;
        case "model.started":
          setRunStatus("Atlas is thinking…", "warning");
          break;
        case "tool.started":
          addTrace(`Tool: ${event.tool}.${event.action}`, "working");
          setRunStatus(`Using ${event.tool || "a tool"}…`, "warning");
          break;
        case "tool.completed":
          addTrace("Tool result verified", "success");
          setRunStatus("Atlas is thinking…", "warning");
          break;
        case "approval.required":
          showInlineApproval(event.approval);
          setRunStatus("Approval required", "warning");
          break;
        case "text.delta":
          accumulated += event.delta || "";
          updateAssistant(assistantMessage, accumulated);
          setRunStatus("Atlas is replying…", "warning");
          break;
        case "run.failed":
        case "stream.error":
          serverFailed = true;
          throw new Error(event.detail || event.error || "Atlas run failed");
        case "run.completed":
          result = event;
          return true;
        case "stream.result":
          result = event.result;
          return true;
        default:
          break;
      }
    });
  } catch (error) {
    streamError = error;
  }
  if (serverFailed) throw streamError;
  if (!result && runId) {
    setRunStatus("Reconnecting to your response…", "warning");
    try {
      result = await recoverRunResult(runId);
    } catch (error) {
      streamError = error;
    }
  }
  if (!result) throw streamError || new Error("The connection ended before Atlas returned a complete response.");
  if (!["completed", "awaiting_approval"].includes(result.status)) {
    throw new Error(result.error || "Atlas did not complete this run.");
  }
  state.currentRunId = result.run_id || state.currentRunId;
  state.currentConversationId = result.conversation_id || state.currentConversationId;
  // The final result is authoritative even if some text deltas were missed.
  accumulated = result.content || accumulated;
  if (result.status === "awaiting_approval") {
    updateAssistant(assistantMessage, accumulated || "Awaiting your approval before continuing.");
    if (result.approval) showInlineApproval(result.approval);
    setRunStatus("Approval required", "warning");
  } else {
    updateAssistant(assistantMessage, accumulated || "Atlas completed this run without a text response.");
    hideInlineApproval();
    setRunStatus("Ready", "success");
  }
  return result;
}

async function recoverRunResult(runId) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);
  try {
    // Recovery only reads saved state. It never submits or resumes a model run.
    for (let attempt = 0; attempt < 10; attempt++) {
      if (controller.signal.aborted) break;
      const run = await api(`/v1/runs/${encodeURIComponent(runId)}`, { signal: controller.signal });
      if (run.id !== runId) throw new Error("Atlas returned a different run while reconnecting.");
      if (run.status === "completed") {
        const conversation = await api(`/v1/conversations/${encodeURIComponent(run.conversation_id)}`, { signal: controller.signal });
        const messageId = run.state?.last_message_id;
        const message = messageId && (conversation.messages || []).find((item) => item.id === messageId && item.role === "assistant");
        if (!message?.content) throw new Error("The saved response could not be recovered. Open this conversation again to check its status.");
        return { run_id: runId, conversation_id: run.conversation_id, status: "completed", content: message.content };
      }
      if (run.status === "awaiting_approval") {
        const approvals = await api("/v1/approvals?approval_status=pending&limit=200", { signal: controller.signal });
        return { run_id: runId, conversation_id: run.conversation_id, status: run.status, approval: approvals.find((item) => item.id === run.pending_approval_id) };
      }
      if (run.status !== "running") throw new Error(run.error || "Atlas stopped before completing this response.");
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    throw new Error("The connection is interrupted. Open this conversation again to check the saved response before sending another message.");
  } finally {
    clearTimeout(timeout);
  }
}

async function refreshAfterRun() {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);
  try {
    const options = { signal: controller.signal };
    const results = await Promise.allSettled([loadConversations(options), loadApprovals(options)]);
    if (results.some((result) => result.status === "rejected")) {
      toast("The conversation list or approvals could not refresh. Your current conversation is still available.", "error");
    }
  } finally {
    clearTimeout(timeout);
  }
}

function showRunError(assistant, error) {
  const partial = assistant.content ? `${assistant.content}\n\n` : "";
  updateAssistant(assistant, `${partial}Atlas could not complete this run.\n\n${error.message}`);
  setRunStatus("Interrupted", "danger");
}

async function sendMessage() {
  if (state.busy) return;
  const input = $("#message-input");
  const text = input.value.trim();
  if (!text) return;
  setBusy(true);
  state.currentRunId = null;
  input.value = "";
  resizeComposer();
  addMessage("user", text);
  const assistant = addMessage("assistant", "");
  assistant.card.innerHTML = '<span class="typing" aria-label="Atlas is thinking"><i></i><i></i><i></i></span>';
  hideInlineApproval();

  const payload = {
    message: text,
    conversation_id: state.currentConversationId,
    provider: $("#provider-select").value || null,
    model: null,
    project_slug: $("#project-select").value || null,
    agent_slug: $("#agent-select").value || null,
    local_only: $("#local-only").checked,
    tools_enabled: $("#tools-enabled").checked,
  };
  try {
    await processRunStream("/v1/chat/stream", payload, assistant);
  } catch (error) {
    showRunError(assistant, error);
    throw error;
  } finally {
    setBusy(false);
    input.focus();
  }
  await refreshAfterRun();
}

function showInlineApproval(approval) {
  if (!approval) return;
  const node = $("#inline-approval");
  node.classList.remove("hidden");
  node.innerHTML = `
    <div class="approval-text">
      <strong>Owner approval required</strong>
      <div>${escapeHTML(approval.tool)}.${escapeHTML(approval.action)}</div>
      <code>${escapeHTML(JSON.stringify(approval.arguments || {}, null, 2))}</code>
    </div>
    <div class="approval-buttons">
      <button class="secondary-button" data-inline-decision="rejected">Reject</button>
      <button class="primary-button" data-inline-decision="approved">Approve once</button>
    </div>`;
  node.querySelectorAll("[data-inline-decision]").forEach((button) => {
    button.addEventListener("click", () => decideApproval(approval, button.dataset.inlineDecision).catch(handleError));
  });
}

function hideInlineApproval() {
  $("#inline-approval").classList.add("hidden");
  $("#inline-approval").innerHTML = "";
}

async function decideApproval(approval, decision) {
  if (state.busy) return;
  const action = decision === "approved" ? "approve" : "reject";
  if (!window.confirm(`Confirm: ${action} ${approval.tool}.${approval.action}?`)) return;
  setBusy(true);
  let assistant = null;
  try {
    // Resolve the conversation before submitting the explicit owner decision.
    if (approval.run_id) {
      const run = await api(`/v1/runs/${encodeURIComponent(approval.run_id)}`);
      if (run.conversation_id !== state.currentConversationId) {
        await loadConversation(run.conversation_id, { duringApproval: true });
      }
    }
    const response = await api(`/v1/approvals/${encodeURIComponent(approval.id)}`, {
      method: "POST",
      body: { decision, resume_run: false },
    });
    toast(`Action ${decision}.`);
    hideInlineApproval();
    const runId = response.approval?.run_id || approval.run_id;
    if (runId) {
      setView("chat");
      assistant = addMessage("assistant", "");
      assistant.card.innerHTML = '<span class="typing" aria-label="Atlas is thinking"><i></i><i></i><i></i></span>';
      await processRunStream(`/v1/runs/${encodeURIComponent(runId)}/resume/stream`, {}, assistant);
    } else {
      setRunStatus("Ready", "success");
    }
  } catch (error) {
    if (assistant) showRunError(assistant, error);
    throw error;
  } finally {
    setBusy(false);
  }
  await refreshAfterRun();
}

async function loadConversations(options = {}) {
  state.conversations = await api("/v1/conversations?limit=200", options);
  renderConversations();
}

async function loadProjects() {
  state.projects = await api("/v1/projects");
  populateSelects();
  renderProjects();
}

function renderProjects() {
  const node = $("#project-list");
  if (!node) return;
  if (!state.projects.length) {
    node.innerHTML = '<div class="panel empty-state">No project records yet.</div>';
    return;
  }
  node.innerHTML = state.projects.map((project) => `
    <article class="card">
      <div class="card-header">
        <div><div class="card-title">${escapeHTML(project.name)}</div><div class="card-subtitle">${escapeHTML(project.slug)}</div></div>
        <span class="badge ${project.status === "active" ? "success" : ""}">${escapeHTML(project.status)}</span>
      </div>
      <div class="card-body">${escapeHTML(project.summary || "No summary yet.")}</div>
      <div class="next-action"><strong>Next:</strong> ${escapeHTML(project.next_action || "Not set")}</div>
      <div class="card-actions">
        <button class="secondary-button" data-project-chat="${escapeHTML(project.slug)}">Open in chat</button>
        <button class="secondary-button" data-project-edit="${escapeHTML(project.slug)}">Edit</button>
        <button class="danger-button" data-project-delete="${escapeHTML(project.slug)}">Delete</button>
      </div>
    </article>`).join("");
  node.querySelectorAll("[data-project-chat]").forEach((button) => button.addEventListener("click", () => {
    if (state.busy) return;
    $("#project-select").value = button.dataset.projectChat;
    newConversation();
    setView("chat");
  }));
  node.querySelectorAll("[data-project-edit]").forEach((button) => button.addEventListener("click", () => editProject(button.dataset.projectEdit)));
  node.querySelectorAll("[data-project-delete]").forEach((button) => button.addEventListener("click", () => deleteProject(button.dataset.projectDelete).catch(handleError)));
}

function editProject(slug) {
  const project = state.projects.find((item) => item.slug === slug);
  if (!project) return;
  state.editProjectSlug = slug;
  $("#project-slug").value = project.slug;
  $("#project-slug").disabled = true;
  $("#project-name").value = project.name;
  $("#project-status").value = project.status;
  $("#project-summary").value = project.summary || "";
  $("#project-next").value = project.next_action || "";
  $("#project-form").scrollIntoView({ behavior: "smooth" });
}

function resetProjectForm() {
  state.editProjectSlug = null;
  $("#project-form").reset();
  $("#project-slug").disabled = false;
  $("#project-status").value = "active";
}

async function saveProject(event) {
  event.preventDefault();
  const payload = {
    slug: $("#project-slug").value.trim(),
    name: $("#project-name").value.trim(),
    status: $("#project-status").value.trim() || "active",
    summary: $("#project-summary").value,
    next_action: $("#project-next").value,
    metadata: {},
  };
  await api("/v1/projects", { method: "POST", body: payload });
  toast("Project saved.");
  resetProjectForm();
  await loadProjects();
}

async function deleteProject(slug) {
  if (!window.confirm(`Delete project record '${slug}'? Conversations are not deleted.`)) return;
  await api(`/v1/projects/${encodeURIComponent(slug)}`, { method: "DELETE" });
  toast("Project record deleted.");
  await loadProjects();
}

async function loadMemories() {
  const query = $("#memory-search")?.value.trim() || "";
  const path = query ? `/v1/memories?q=${encodeURIComponent(query)}&limit=300` : "/v1/memories?limit=300";
  const memories = await api(path);
  renderMemories(memories);
}

function renderMemories(memories) {
  const node = $("#memory-list");
  if (!memories.length) {
    node.innerHTML = '<div class="panel empty-state">No matching memories.</div>';
    return;
  }
  node.innerHTML = memories.map((memory) => `
    <article class="card">
      <div class="card-header">
        <div><div class="card-title">${escapeHTML(memory.key)}</div><div class="card-subtitle">${escapeHTML(memory.namespace)} · ${escapeHTML(memory.kind)}</div></div>
        <span class="badge">importance ${memory.importance}</span>
      </div>
      <div class="card-body">${escapeHTML(memory.content)}</div>
      <div class="card-actions">
        <button class="secondary-button" data-memory-edit="${memory.id}">Edit</button>
        <button class="danger-button" data-memory-delete="${memory.id}">Forget</button>
      </div>
    </article>`).join("");
  node.querySelectorAll("[data-memory-edit]").forEach((button) => button.addEventListener("click", () => editMemory(memories.find((item) => item.id === Number(button.dataset.memoryEdit)))));
  node.querySelectorAll("[data-memory-delete]").forEach((button) => button.addEventListener("click", () => deleteMemory(Number(button.dataset.memoryDelete)).catch(handleError)));
}

function editMemory(memory) {
  if (!memory) return;
  state.editMemoryId = memory.id;
  $("#memory-namespace").value = memory.namespace;
  $("#memory-kind").value = memory.kind;
  $("#memory-key").value = memory.key;
  $("#memory-content").value = memory.content;
  $("#memory-importance").value = memory.importance;
  $("#memory-form button[type=submit]").textContent = "Update memory";
  $("#memory-form").scrollIntoView({ behavior: "smooth" });
}

function resetMemoryForm() {
  state.editMemoryId = null;
  $("#memory-form").reset();
  $("#memory-namespace").value = "global";
  $("#memory-kind").value = "note";
  $("#memory-importance").value = "5";
  $("#memory-form button[type=submit]").textContent = "Store memory";
}

async function saveMemory(event) {
  event.preventDefault();
  const payload = {
    namespace: $("#memory-namespace").value.trim(),
    kind: $("#memory-kind").value.trim(),
    key: $("#memory-key").value.trim(),
    content: $("#memory-content").value,
    importance: Number($("#memory-importance").value),
    metadata: {},
  };
  const path = state.editMemoryId ? `/v1/memories/${state.editMemoryId}` : "/v1/memories";
  await api(path, { method: state.editMemoryId ? "PUT" : "POST", body: payload });
  toast(state.editMemoryId ? "Memory updated." : "Memory stored.");
  resetMemoryForm();
  await loadMemories();
}

async function deleteMemory(id) {
  if (!window.confirm("Forget this explicit memory?")) return;
  await api(`/v1/memories/${id}`, { method: "DELETE" });
  toast("Memory forgotten.");
  await loadMemories();
}

async function loadApprovals(options = {}) {
  state.approvals = await api("/v1/approvals?limit=300", options);
  renderApprovals();
}

function renderApprovals() {
  const pending = state.approvals.filter((approval) => approval.status === "pending");
  const count = $("#approval-count");
  count.textContent = String(pending.length);
  count.classList.toggle("hidden", pending.length === 0);
  const node = $("#approval-list");
  if (!node) return;
  if (!state.approvals.length) {
    node.innerHTML = '<div class="panel empty-state">No approval requests.</div>';
    return;
  }
  const ordered = [...state.approvals].sort((a, b) => (a.status === "pending" ? -1 : 1) - (b.status === "pending" ? -1 : 1));
  node.innerHTML = ordered.map((approval) => `
    <article class="card approval-card">
      <div class="card-header">
        <div><div class="card-title">${escapeHTML(approval.tool)}.${escapeHTML(approval.action)}</div><div class="card-subtitle">${escapeHTML(formatDate(approval.requested_at))}</div></div>
        <span class="badge ${approval.status === "pending" ? "warning" : approval.status === "executed" || approval.status === "approved" ? "success" : "danger"}">${escapeHTML(approval.status)}</span>
      </div>
      <pre class="arguments-box">${escapeHTML(JSON.stringify(approval.arguments || {}, null, 2))}</pre>
      ${approval.note ? `<div class="card-body">Note: ${escapeHTML(approval.note)}</div>` : ""}
      ${approval.status === "pending" ? `<div class="card-actions"><button class="secondary-button" data-approval-reject="${approval.id}">Reject</button><button class="primary-button" data-approval-approve="${approval.id}">Approve once</button></div>` : ""}
    </article>`).join("");
  node.querySelectorAll("[data-approval-approve]").forEach((button) => button.addEventListener("click", () => {
    const approval = state.approvals.find((item) => item.id === button.dataset.approvalApprove);
    decideApproval(approval, "approved").catch(handleError);
  }));
  node.querySelectorAll("[data-approval-reject]").forEach((button) => button.addEventListener("click", () => {
    const approval = state.approvals.find((item) => item.id === button.dataset.approvalReject);
    decideApproval(approval, "rejected").catch(handleError);
  }));
}

function renderAgents() {
  const node = $("#agent-list");
  if (!node) return;
  node.innerHTML = state.agents.map((agent) => `
    <article class="card agent-card" data-agent="${escapeHTML(agent.slug)}">
      <div class="card-header"><div><div class="card-title">${escapeHTML(agent.name)}</div><div class="card-subtitle">${escapeHTML(agent.slug)}</div></div>${agent.default ? '<span class="badge success">default</span>' : ""}</div>
      <div class="card-body">${escapeHTML(agent.description)}</div>
      <div class="agent-tools">${(agent.tools || []).map((tool) => `<span class="badge">${escapeHTML(tool)}</span>`).join("") || '<span class="badge">no tools</span>'}</div>
      <div class="card-subtitle agent-limit">Up to ${agent.max_steps} tool steps · ${agent.local_only ? "local only" : "provider selectable"}</div>
    </article>`).join("");
  node.querySelectorAll("[data-agent]").forEach((card) => card.addEventListener("click", () => {
    if (state.busy) return;
    $("#agent-select").value = card.dataset.agent;
    newConversation();
    setView("chat");
    toast(`${state.agents.find((item) => item.slug === card.dataset.agent)?.name || "Agent"} selected.`);
  }));
}

async function loadSettingsView() {
  const [settings, identity, permissions, googleConnection] = await Promise.all([
    api("/v1/settings"),
    api("/v1/identity"),
    api("/v1/permissions"),
    api("/v1/connectors/google/health"),
  ]);
  state.settings = settings;
  state.identity = identity;
  state.permissions = permissions;
  state.googleConnection = googleConnection;
  renderSettings();
}

function renderSettings() {
  const rows = [
    ["Version", state.settings.version],
    ["Project root", state.settings.project_root],
    ["Database", state.settings.database],
    ["Workspace", state.settings.workspace],
    ["Default model route", state.settings.default_provider],
    ["Identity fingerprint", state.identity?.fingerprint || ""],
  ];
  $("#settings-summary").innerHTML = rows.map(([key, value]) => `<div class="definition-row"><dt>${escapeHTML(key)}</dt><dd>${escapeHTML(value)}</dd></div>`).join("");
  $("#api-token").value = state.token;
  const select = $("#identity-select");
  const current = select.value;
  select.innerHTML = (state.identity?.documents || []).map((document) => `<option value="${escapeHTML(document.name)}">${escapeHTML(document.name)}</option>`).join("");
  if (current && (state.identity?.documents || []).some((document) => document.name === current)) select.value = current;
  showIdentityDocument();
  $("#identity-fingerprint").textContent = `Fingerprint: ${state.identity?.fingerprint || ""}`;
  $("#permissions-editor").value = state.permissions?.content || "";
  renderProviderSummary();
  renderGoogleConnection();
  renderMacInbox();
  renderPhoneCompanion();
  renderSupervisor();
  renderSupervisorV2();
  renderSupervisorV3();
  renderSupervisorV4();
}

function renderMacInbox() {
  const operator = state.settings?.mac_inbox || {};
  const node = $("#mac-inbox-status");
  if (!node) return;
  const label = operator.ready ? "ready" : operator.paused ? "paused" : "disabled";
  const tone = operator.ready ? "success" : operator.paused ? "warning" : "danger";
  node.innerHTML = `
    <div class="status-item">
      <div><strong>Atlas Inbox</strong><div class="muted">${escapeHTML(operator.root || "No folder configured")}</div></div>
      <span class="badge ${tone}">${escapeHTML(label)}</span>
    </div>
    <div class="connection-detail">Fresh preview required before every action · Trash is recoverable · No permanent delete</div>`;
}

function renderPhoneCompanion() {
  const companion = state.settings?.phone_companion || {};
  const node = $("#phone-companion-status");
  if (!node) return;
  let label = "bridge stopped";
  let tone = "warning";
  if (!companion.enabled) {
    label = "disabled";
    tone = "danger";
  } else if (companion.paused) {
    label = "paused";
  } else if (companion.device_connected) {
    label = "device connected";
    tone = "success";
  } else if (companion.bridge_active) {
    label = "waiting for iPhone";
  }
  const device = companion.device_model
    ? `${companion.device_model} · ${companion.os_name || "iOS"} ${companion.os_version || ""}`.trim()
    : "No current device status receipt";
  const battery = typeof companion.battery_level === "number"
    ? ` · Battery ${Math.round(companion.battery_level * 100)}%`
    : "";
  node.innerHTML = `
    <div class="status-item">
      <div><strong>Atlas Companion</strong><div class="muted">${escapeHTML(device)}${escapeHTML(battery)}</div></div>
      <span class="badge ${tone}">${escapeHTML(label)}</span>
    </div>
    <div class="connection-detail">Explicit certificate comparison · One-time pairing · One in-memory session · Read-only status</div>`;
}

function renderSupervisor() {
  const supervisor = state.settings?.supervisor || {};
  const node = $("#supervisor-status");
  if (!node) return;
  const label = !supervisor.enabled ? "disabled" : supervisor.paused ? "paused" : "ready on demand";
  const tone = !supervisor.enabled ? "danger" : supervisor.paused ? "warning" : "success";
  const taskCount = Object.values(supervisor.task_counts || {}).reduce((total, count) => total + Number(count || 0), 0);
  node.innerHTML = `
    <div class="status-item">
      <div><strong>Software Development</strong><div class="muted">${taskCount} persistent task receipt${taskCount === 1 ? "" : "s"}</div></div>
      <span class="badge ${tone}">${escapeHTML(label)}</span>
    </div>
    <div class="connection-detail">Manual plan · Exact confirmation · One attempt · Immediate pause control</div>`;
  const button = $("#toggle-supervisor");
  button.disabled = !supervisor.enabled;
  button.textContent = supervisor.paused ? "Resume" : "Pause";
}

async function toggleSupervisor() {
  const supervisor = state.settings?.supervisor || {};
  if (!supervisor.enabled) return;
  const action = supervisor.paused ? "resume" : "pause";
  setRunStatus(action === "pause" ? "Pausing Supervisor" : "Resuming Supervisor", "warning");
  state.settings.supervisor = await api(`/v1/supervisor/${action}`, { method: "POST" });
  renderSupervisor();
  setRunStatus("Ready", "success");
  toast(`Atlas Supervisor ${action === "pause" ? "paused" : "resumed"}.`);
}

function renderSupervisorV2() {
  const supervisor = state.settings?.supervisor_v2 || {};
  const node = $("#supervisor-v2-status");
  if (!node) return;
  const available = supervisor.enabled && !supervisor.paused && Number(supervisor.attempts_remaining || 0) > 0;
  const label = !supervisor.enabled ? "disabled" : supervisor.paused ? "paused" : available ? "one attempt available" : "attempt consumed";
  const tone = available ? "success" : supervisor.paused ? "warning" : "danger";
  const taskCount = Object.values(supervisor.task_counts || {}).reduce((total, count) => total + Number(count || 0), 0);
  node.innerHTML = `
    <div class="status-item">
      <div><strong>Fixture candidate pilot</strong><div class="muted">${taskCount} privacy-minimized task receipt${taskCount === 1 ? "" : "s"}</div></div>
      <span class="badge ${tone}">${escapeHTML(label)}</span>
    </div>
    <div class="connection-detail">Pinned ${escapeHTML(supervisor.model || "model")} · Codex service transport · Named beta permission profile · No experimental API · No command network · No canonical mutation · ${Number(supervisor.attempts_remaining || 0)} attempt remaining</div>`;
  $("#check-supervisor-v2").disabled = !supervisor.enabled;
  $("#plan-supervisor-v2").disabled = !available;
  const task = state.supervisorV2Task;
  $("#run-supervisor-v2").disabled = !available || !task || task.status !== "planned";
}

async function checkSupervisorV2() {
  setRunStatus("Checking protocol pin", "warning");
  const result = await api("/v1/supervisor-v2/readiness", { method: "POST" });
  $("#supervisor-v2-result").textContent = result.ready
    ? `Pinned ${result.cli_version}; ${result.schema_file_count} stable schema files and the ${result.permission_profile?.profile_id || "fixture"} permission profile verified offline. No model was run.`
    : `Stopped: ${(result.mismatches || []).join("; ")}`;
  setRunStatus(result.ready ? "Ready" : "Stopped", result.ready ? "success" : "danger");
}

async function planSupervisorV2() {
  setRunStatus("Planning fixture recipe", "warning");
  const task = await api("/v1/supervisor-v2/plan", {
    method: "POST",
    body: { recipe: "fixture-small-bugfix" },
  });
  state.supervisorV2Task = task;
  $("#supervisor-v2-confirmation").value = "";
  $("#supervisor-v2-confirmation").placeholder = task.required_confirmation;
  $("#supervisor-v2-result").textContent = `Plan ${task.id.slice(0, 8)} is bound and expires at ${task.expires_at}. To commission the sole attempt, type exactly: ${task.required_confirmation}`;
  state.settings.supervisor_v2 = await api("/v1/supervisor-v2");
  renderSupervisorV2();
  setRunStatus("Ready", "success");
  toast("Supervisor v2 fixture plan recorded. No model was run; exact confirmation is still required.");
}

async function runSupervisorV2() {
  const task = state.supervisorV2Task;
  if (!task || task.status !== "planned") return;
  const confirmation = $("#supervisor-v2-confirmation").value;
  setRunStatus("Running the one disposable-fixture attempt", "warning");
  $("#run-supervisor-v2").disabled = true;
  const completed = await api(`/v1/supervisor-v2/tasks/${encodeURIComponent(task.id)}/run`, {
    method: "POST",
    body: { confirmation },
  });
  state.supervisorV2Task = completed;
  state.settings.supervisor_v2 = await api("/v1/supervisor-v2");
  renderSupervisorV2();
  const candidate = completed.result?.candidate;
  $("#supervisor-v2-result").textContent = completed.status === "candidate_ready"
    ? `Candidate ready in the disposable clone: ${(candidate?.changed_paths || []).join(", ")}; patch ${candidate?.patch_sha256 || "unavailable"}. It was not applied to the canonical fixture.`
    : `Attempt ended ${completed.status}: ${completed.error || "no candidate was accepted"}. The attempt cannot be retried.`;
  setRunStatus(completed.status === "candidate_ready" ? "Candidate ready" : "Stopped", completed.status === "candidate_ready" ? "success" : "danger");
  toast("Supervisor v2 attempt finished. The canonical fixture was not changed.");
}

function renderSupervisorV3() {
  const supervisor = state.settings?.supervisor_v3 || {};
  const node = $("#supervisor-v3-status");
  if (!node) return;
  const canaryAvailable = Boolean(supervisor.canary_plan_available);
  const successorAvailable = Boolean(supervisor.successor_canary_plan_available);
  const fixtureAvailable = Boolean(supervisor.fixture_plan_available);
  const recoveryCanaryAvailable = Boolean(supervisor.recovery_canary_plan_available);
  const recoveryFixtureAvailable = Boolean(supervisor.recovery_fixture_plan_available);
  const label = !supervisor.enabled
    ? "disabled"
    : supervisor.paused
      ? "paused"
      : supervisor.next_gate === "recovery_canary_owner_authorization"
        ? "offline recovery ready; canary needs owner authorization"
      : supervisor.next_gate === "recovery_canary_exact_confirmation"
        ? "recovery canary awaits exact phrase"
      : supervisor.next_gate === "recovery_fixture_owner_authorization"
        ? "recovery canary passed; fixture needs owner authorization"
      : supervisor.next_gate === "recovery_fixture_exact_confirmation"
        ? "recovery fixture awaits exact phrase"
      : supervisor.next_gate === "recovery_candidate_owner_review"
        ? "recovery candidate ready for owner review"
      : recoveryCanaryAvailable
        ? "recovery canary ready to plan"
      : recoveryFixtureAvailable
        ? "recovery fixture ready to plan"
      : supervisor.next_gate === "successor_canary_attempt_exhausted"
        ? "successor attempt exhausted; stopped safely"
        : supervisor.next_gate === "successor_canary_exact_confirmation"
          ? "successor plan awaits exact phrase"
        : successorAvailable
          ? "successor canary ready to plan"
        : canaryAvailable
          ? "original canary gate enabled"
          : "offline ready; live gate disabled";
  const tone = recoveryCanaryAvailable || recoveryFixtureAvailable || successorAvailable || canaryAvailable
    ? "success"
    : supervisor.paused || supervisor.next_gate?.includes("owner_authorization")
      ? "warning"
      : "danger";
  const taskCount = Object.values(supervisor.task_counts || {}).reduce((total, count) => total + Number(count || 0), 0);
  node.innerHTML = `
    <div class="status-item">
      <div><strong>Fixture-recovery SDK pilot</strong><div class="muted">${taskCount} privacy-minimized task receipt${taskCount === 1 ? "" : "s"}</div></div>
      <span class="badge ${tone}">${escapeHTML(label)}</span>
    </div>
    <div class="connection-detail">SDK ${escapeHTML(supervisor.sdk_version || "unavailable")} · No experimental API · Reject approvals · No command network · Original ${Number(supervisor.canary_attempts_used || 0)}/1 · Successor ${Number(supervisor.successor_canary_attempts_used || 0)}/1 · Fixture ${Number(supervisor.fixture_attempts_used || 0)}/1 · Recovery canary ${Number(supervisor.recovery_canary_attempts_used || 0)}/1 · Recovery fixture ${Number(supervisor.recovery_fixture_attempts_used || 0)}/1</div>`;
  $("#check-supervisor-v3").disabled = !supervisor.enabled;
  $("#plan-supervisor-v3-canary").disabled = !canaryAvailable;
  $("#plan-supervisor-v3-successor").disabled = !successorAvailable;
  $("#plan-supervisor-v3-fixture").disabled = !fixtureAvailable;
  $("#plan-supervisor-v3-recovery-canary").disabled = !recoveryCanaryAvailable;
  $("#plan-supervisor-v3-recovery-fixture").disabled = !recoveryFixtureAvailable;
  const task = state.supervisorV3Task;
  $("#run-supervisor-v3").disabled = !task || task.status !== "planned";
}

async function checkSupervisorV3() {
  setRunStatus("Checking Supervisor v3 offline controls", "warning");
  const result = await api("/v1/supervisor-v3/readiness", { method: "POST" });
  $("#supervisor-v3-result").textContent = result.ready
    ? `Verified SDK ${result.packages?.metadata?.sdk || "0.147.0"}, runtime ${result.runtime?.cli_version || "pinned"}, ${result.runtime?.notification_method_count || 0} classified stable notifications, and all five local sandbox profiles. No model was contacted.`
    : `Stopped: ${(result.mismatches || []).join("; ")}`;
  setRunStatus(result.ready ? "Offline build verified" : "Stopped", result.ready ? "success" : "danger");
}

async function planSupervisorV3(stage) {
  setRunStatus(`Planning Supervisor v3 ${stage}`, "warning");
  const routeStage = stage.replace(/_/g, "-");
  const task = await api(`/v1/supervisor-v3/plan/${routeStage}`, { method: "POST" });
  state.supervisorV3Task = task;
  $("#supervisor-v3-confirmation").value = "";
  $("#supervisor-v3-confirmation").placeholder = task.required_confirmation;
  $("#supervisor-v3-result").textContent = `Plan ${task.id.slice(0, 8)} is bound and expires at ${task.expires_at}. Type exactly: ${task.required_confirmation}`;
  state.settings.supervisor_v3 = await api("/v1/supervisor-v3");
  renderSupervisorV3();
  setRunStatus("Ready", "success");
}

async function runSupervisorV3() {
  const task = state.supervisorV3Task;
  if (!task || task.status !== "planned") return;
  const confirmation = $("#supervisor-v3-confirmation").value;
  setRunStatus(`Running Supervisor v3 ${task.stage}`, "warning");
  $("#run-supervisor-v3").disabled = true;
  const completed = await api(`/v1/supervisor-v3/tasks/${encodeURIComponent(task.id)}/run`, {
    method: "POST",
    body: { confirmation },
  });
  state.supervisorV3Task = completed;
  state.settings.supervisor_v3 = await api("/v1/supervisor-v3");
  renderSupervisorV3();
  $("#supervisor-v3-result").textContent = `The ${completed.stage} stage ended ${completed.status}. Model contact: ${completed.model_contacted ? "yes" : "no"}. No canonical change was authorized.`;
  setRunStatus(completed.status, completed.status === "canary_passed" || completed.status === "candidate_ready" ? "success" : "danger");
}

function renderSupervisorV4() {
  const supervisor = state.settings?.supervisor_v4 || {};
  const node = $("#supervisor-v4-status");
  if (!node) return;
  const offlineChecksRecorded = supervisor.latest_qualification?.status === "inactive";
  const recoveryLaunchesUsed = Number(supervisor.recovery_canary_launches_used ?? 0);
  const recoveryAttemptsUsed = Number(supervisor.recovery_canary_attempts_used ?? 0);
  const recoveryImplementedInactive = supervisor.option1_recovery_canary_implementation_state === "option1_synthetic_integration_recovery_canary_implemented_inactive";
  const recoveryCompleted = supervisor.option1_recovery_canary_implementation_state === "completed_inactive"
    && supervisor.option1_canary_implementation_state === "failed_preclaim_terminal"
    && supervisor.next_gate === "owner_review_option1_synthetic_integration_recovery_canary_result";
  const recoveryReviewed = supervisor.option1_recovery_canary_result_review_state === "reviewed_inactive"
    && supervisor.option1_recovery_canary_result_reviewed === true
    && supervisor.option2_service_identity_and_vault_plan_state === "implemented_inactive"
    && supervisor.next_gate === "owner_review_option2_service_identity_and_vault_offline_plan";
  const option2ManifestReview = supervisor.option2_plan_owner_review_state === "reviewed_inactive"
    && supervisor.option2_plan_owner_reviewed === true
    && supervisor.option2_provisioner_contract_state === "implemented_inactive"
    && supervisor.option2_provisioner_dry_run_state === "qualified_inactive"
    && supervisor.option2_provisioner_dry_run_qualified === true
    && supervisor.option2_production_manifest_complete === false
    && supervisor.option2_host_apply_present === false
    && supervisor.next_gate === "owner_review_option2_service_identity_provisioning_manifest";
  const option2ManifestReviewed = supervisor.option2_provisioning_manifest_review_state === "reviewed_inactive"
    && supervisor.option2_provisioning_manifest_owner_reviewed === true
    && supervisor.option2_production_manifest_complete === false
    && supervisor.option2_host_apply_present === false
    && supervisor.option2_provisioning_authorized === false
    && supervisor.next_gate === "option2_identity_candidate_resolver_offline_implementation";
  const option2IdentityCandidate = supervisor.option2_identity_candidate_resolver_state === "qualified_inactive"
    && supervisor.option2_identity_candidate_fixture_qualified === true
    && supervisor.option2_identity_candidate_host_preflight_state === "not_performed"
    && supervisor.option2_identity_candidate_host_inspected === false
    && supervisor.option2_provisioning_authorized === false
    && supervisor.next_gate === "owner_review_option2_identity_only_host_preflight";
  const option2HostCandidate = [
    supervisor.option2_identity_candidate_host_preflight_state,
    supervisor.option2_identity_candidate_host_preflight_recovery_state,
  ].some((state) => ["candidate_generated_inactive", "recovery_candidate_generated_inactive"].includes(state))
    && supervisor.option2_host_candidate_active === true
    && supervisor.option2_identity_candidate_host_inspected === true
    && supervisor.option2_provisioning_authorized === false
    && supervisor.next_gate === "owner_review_option2_legacy_identity_candidate_non_authorizing";
  const option2HostCandidateExpired = ["candidate_expired_inactive", "candidate_stale_inactive"]
    .includes(supervisor.option2_identity_candidate_host_preflight_state)
    && supervisor.option2_host_candidate_active === false;
  const option2HostCandidateDanger = ["candidate_invalid_quarantined", "preflight_consumed_incomplete", "candidate_storage_unavailable"]
    .includes(supervisor.option2_identity_candidate_host_preflight_state)
    && supervisor.option2_host_candidate_active === false
    && [
      "owner_review_option2_identity_only_host_preflight_recovery",
      "owner_review_option2_identity_only_host_preflight_recovery_result",
    ].includes(supervisor.next_gate);
  const option2HostRecoveryAuthorizationRequired = supervisor.option2_identity_candidate_host_preflight_state === "preflight_consumed_incomplete"
    && supervisor.option2_identity_candidate_host_preflight_recovery_state === "recovery_implemented_inactive"
    && supervisor.option2_host_preflight_recovery_owner_authorized === false
    && supervisor.option2_host_candidate_active === false
    && supervisor.next_gate === "owner_authorize_option2_identity_only_host_preflight_recovery";
  const option2RecoveryResultReviewRequired = [
    "recovery_candidate_expired_inactive",
    "recovery_candidate_stale_inactive",
  ].includes(supervisor.option2_identity_candidate_host_preflight_recovery_state)
    && supervisor.option2_host_preflight_recovery_result_reviewed === false
    && supervisor.option2_host_candidate_active === false
    && supervisor.next_gate === "owner_review_option2_identity_only_host_preflight_recovery_result";
  const option2ReviewQuarantined = [
    "owner_review_option2_identity_only_host_preflight_recovery_result_quarantine",
    "owner_review_option2_point_action_qualification_quarantine",
    "owner_review_option2_native_preflight_offline_qualification_quarantine",
  ].includes(supervisor.next_gate);
  const option2RecoveryResultReviewed = supervisor.option2_host_preflight_recovery_result_review_state === "recovery_result_reviewed_inactive"
    && supervisor.option2_host_preflight_recovery_result_reviewed === true
    && supervisor.option2_point_action_fixture_qualified === false
    && supervisor.next_gate === "option2_point_action_fixture_qualification";
  const option2PointActionQualified = supervisor.option2_host_preflight_recovery_result_review_state === "recovery_result_reviewed_inactive"
    && supervisor.option2_point_action_contract_state === "implemented_inactive"
    && supervisor.option2_point_action_qualification_state === "qualified_inactive"
    && supervisor.option2_point_action_fixture_qualified === true
    && supervisor.option2_point_action_host_query_present === false
    && supervisor.option2_point_action_host_apply_present === false
    && supervisor.option2_point_action_administrator_prompt_present === false
    && supervisor.option2_provisioning_authorized === false
    && supervisor.option2_native_preflight_qualification_state === "qualification_required"
    && supervisor.next_gate === "option2_native_preflight_fixture_qualification";
  const option2NativeQualified = supervisor.option2_native_preflight_contract_state === "native_preflight_and_claim_ledger_implemented_inactive"
    && supervisor.option2_native_preflight_qualification_state === "native_preflight_and_claim_ledger_fixture_qualified_inactive"
    && supervisor.option2_native_preflight_fixture_qualified === true
    && supervisor.option2_native_root_owned_installation_present === false
    && supervisor.option2_native_separately_signed_installation_present === false
    && supervisor.option2_native_point_action_host_query_present === false
    && supervisor.option2_native_identity_mutation_present === false
    && supervisor.option2_provisioning_authorized === false
    && supervisor.next_gate === "owner_review_option2_native_preflight_installation_and_signing_plan";
  const recoveryAuthorizationRequired = recoveryImplementedInactive
    && supervisor.option1_canary_implementation_state === "failed_preclaim_terminal"
    && supervisor.option1_recovery_review_completed === true
    && supervisor.option1_recovery_canary_owner_authorized === false
    && supervisor.next_gate === "owner_authorize_option1_synthetic_integration_recovery_canary";
  const label = !supervisor.enabled
    ? "disabled"
    : option2ReviewQuarantined
      ? "Option 2 review evidence quarantined; exact owner review required"
    : option2NativeQualified
      ? "Option 2 native fixture qualified; installation, signing, and anchor plan review required"
    : option2PointActionQualified
      ? "Option 2 point-of-action design qualified; native fixture qualification pending"
    : option2RecoveryResultReviewed
      ? "Option 2 expired recovery result reviewed; offline design qualification pending"
    : option2RecoveryResultReviewRequired
      ? "Option 2 recovery candidate is historical only; result review required"
    : option2HostRecoveryAuthorizationRequired
      ? "Option 2 read-only recovery is ready; exact owner authorization required"
    : option2HostCandidateDanger
      ? "Option 2 host preflight quarantined; owner recovery review required"
    : option2HostCandidate
      ? "Option 2 legacy host candidate is non-authorizing; owner review required"
    : option2HostCandidateExpired
      ? "Option 2 host candidate expired or drifted; fresh review required"
    : option2IdentityCandidate
      ? "Option 2 identity candidate qualified inactive; host-preflight review required"
    : option2ManifestReviewed
      ? "Option 2 incomplete manifest reviewed; identity candidate work pending"
    : option2ManifestReview
      ? "Option 2 inactive manifest contract ready; owner review required"
    : recoveryReviewed
      ? "Option 2 offline plan ready; owner review required"
      : recoveryCompleted
      ? "recovery canary passed; result review required"
      : recoveryAuthorizationRequired
      ? "recovery canary implemented; authorization required"
      : recoveryImplementedInactive
        ? "recovery canary state review required"
        : offlineChecksRecorded
          ? "offline checks recorded; production inactive"
          : "implemented inactive; qualification pending";
  const tone = option2PointActionQualified || option2RecoveryResultReviewed || option2IdentityCandidate || option2ManifestReviewed || option2ManifestReview || recoveryReviewed || recoveryCompleted ? "success" : option2ReviewQuarantined || option2HostCandidate || option2HostCandidateDanger || recoveryImplementedInactive ? "danger" : option2NativeQualified || option2RecoveryResultReviewRequired || option2HostRecoveryAuthorizationRequired || option2HostCandidateExpired || recoveryAuthorizationRequired ? "warning" : offlineChecksRecorded ? "success" : supervisor.enabled ? "warning" : "danger";
  const recoveryDetail = option2ReviewQuarantined
    ? `Option 2 review evidence is invalid or duplicated and remains quarantined · Automatic retry: no · Fresh host query/admin prompt: not performed · Service identities/vault: not provisioned · Account/group mutation: no · Real credential: no · Network/model contact: no · `
    : option2NativeQualified
    ? `Native fixture: 63 exact cases qualified inactive · Replay-after-restart and crash-quarantine projection: verified · Durable filesystem ledger and independent anchor: not verified · Root custody/signing/install: absent · Whole-host rollback resistance: unqualified · Fresh host query/admin prompt: not performed · Identity mutation: no · Real credential: no · Network/model contact: no · `
    : option2PointActionQualified
    ? `Expired recovery candidate: historical only, not reused · Point-of-action design: qualified inactive · Native fixture qualification: pending · Fresh host query/admin prompt: not performed · Identity-only apply implementation: absent · Service identities/vault: not provisioned · Account/group mutation: no · Real credential: no · Network/model contact: no · `
    : option2RecoveryResultReviewed
    ? `Expired recovery candidate: reviewed inactive and not reused · Point-of-action design: offline qualification pending · Fresh host query/admin prompt: not performed · Service identities/vault: not provisioned · Account/group mutation: no · Real credential: no · Network/model contact: no · `
    : option2RecoveryResultReviewRequired
    ? `Expired recovery candidate: historical only and unusable · Result review: required · Fresh host query/admin prompt: not performed · Service identities/vault: not provisioned · Account/group mutation: no · Real credential: no · Network/model contact: no · `
    : option2HostRecoveryAuthorizationRequired
    ? `Original Option 2 preflight: failed closed with claim preserved · Recovery: implemented inactive, not authorized · Second host query: no · Raw inventory retained: no · Service identities/vault: not provisioned · Account/group mutation: no · Real credential: no · Network/model contact: no · `
    : option2HostCandidateDanger
    ? `Option 2 host preflight is quarantined pending owner recovery review · Raw inventory retained: no · Service identities/vault: not provisioned · Account/group mutation: no · Real credential: no · Network/model contact: no · `
    : option2HostCandidate
    ? `Option 2 legacy host candidate: non-authorizing and cannot produce the retired apply phrase · Owner review required · Raw inventory retained: no · Service identities/vault: not provisioned · Account/group mutation: no · Real credential: no · Network/model contact: no · `
    : option2HostCandidateExpired
    ? `Option 2 host candidate is no longer usable · Raw inventory retained: no · Service identities/vault: not provisioned · Account/group mutation: no · Real credential: no · Network/model contact: no · `
    : option2IdentityCandidate
    ? `Original canary: failed-preclaim terminal · Recovery result: reviewed inactive · Option 2 plan and incomplete manifest: reviewed inactive · Identity candidate resolver: qualified inactive · Host preflight: not performed · Service identities/vault: not provisioned · Host inspection/apply: no · Real credential: no · Network/model contact: no · `
    : option2ManifestReviewed
    ? `Original canary: failed-preclaim terminal · Recovery result: reviewed inactive · Option 2 plan: reviewed inactive · Incomplete manifest: reviewed inactive · Identity candidate: offline implementation pending · Service identities/vault: not provisioned · Host inspection/apply: no · Real credential: no · Network/model contact: no · `
    : option2ManifestReview
    ? `Original canary: failed-preclaim terminal · Recovery result: reviewed inactive · Option 2 plan: reviewed inactive · Provisioner simulation: qualified inactive · Production manifest: incomplete · Service identities/vault: not provisioned · Host apply: no · Real credential: no · Network/model contact: no · `
    : recoveryReviewed
    ? `Original canary: failed-preclaim terminal · Recovery allowance: ${recoveryLaunchesUsed}/1 launch, ${recoveryAttemptsUsed}/1 data · Recovery result: passed with fixed synthetic sentinel · Result review: recorded inactive · Option 2: design only, not provisioned · Real credential: no · Network/model contact: no · `
    : recoveryCompleted
    ? `Original canary: failed-preclaim terminal · Recovery allowance: ${recoveryLaunchesUsed}/1 launch, ${recoveryAttemptsUsed}/1 data · Recovery result: passed with fixed synthetic sentinel · Real credential: no · Network/model contact: no · `
    : recoveryAuthorizationRequired
    ? `Original canary: failed-preclaim terminal · Recovery allowance: ${recoveryLaunchesUsed}/1 launch, ${recoveryAttemptsUsed}/1 data · Recovery launch: not authorized · Keychain query: no · Network/model contact: no · `
    : "";
  node.innerHTML = `
    <div class="status-item">
      <div><strong>Proposal-only compatibility lane</strong><div class="muted">Model contact: no · Live readiness: false</div></div>
      <span class="badge ${tone}">${escapeHTML(label)}</span>
    </div>
    <div class="connection-detail">${recoveryDetail}No API, UI, or ordinary-startup run route · No credentials · No canonical application · Next gate: ${escapeHTML(supervisor.next_gate || "owner review")}</div>`;
}

function showIdentityDocument() {
  const name = $("#identity-select").value;
  const document = (state.identity?.documents || []).find((item) => item.name === name);
  $("#identity-editor").value = document?.content || "";
}

async function saveIdentity() {
  const name = $("#identity-select").value;
  if (!name) return;
  state.identity = await api(`/v1/identity/${encodeURIComponent(name)}`, {
    method: "PUT",
    body: { content: $("#identity-editor").value },
  }).then((result) => ({
    fingerprint: result.fingerprint,
    documents: (state.identity.documents || []).map((item) => item.name === name ? result.document : item),
  }));
  renderSettings();
  toast("Identity document saved and versioned.");
}

async function savePermissions() {
  state.permissions = await api("/v1/permissions", {
    method: "PUT",
    body: { content: $("#permissions-editor").value },
  });
  toast("Permission policy saved and reloaded.");
  await loadApprovals();
}

function renderProviderSummary(health = null) {
  const records = health || state.providers;
  const node = $("#provider-health");
  node.innerHTML = records.map((provider) => {
    const ok = provider.ok ?? provider.configured;
    const label = provider.enabled === false ? "disabled" : ok ? "ready" : "not ready";
    return `<div class="status-item"><div><strong>${escapeHTML(provider.provider || provider.name)}</strong><div class="muted">${escapeHTML(provider.model || "")}</div></div><span class="badge ${ok ? "success" : "danger"}">${escapeHTML(label)}</span></div>`;
  }).join("");
}

function renderGoogleConnection() {
  const connection = state.googleConnection || {};
  const labels = {
    ready: "connected",
    reconnect_required: "reconnect needed",
    setup_required: "setup needed",
    not_enabled: "not enabled",
  };
  const stateName = connection.state || "not_checked";
  const label = labels[stateName] || "not checked";
  const tone = connection.healthy ? "success" : stateName === "reconnect_required" ? "danger" : "warning";
  const account = connection.account || connection.connected_account || connection.expected_account || "Not connected";
  const calendar = connection.calendar || "primary";
  const permissions = (connection.scopes || []).length;
  $("#google-connection-status").innerHTML = `
    <div class="status-item">
      <div><strong>Google account</strong><div class="muted">${escapeHTML(connection.message || "Check the saved connection.")}</div></div>
      <span class="badge ${tone}">${escapeHTML(label)}</span>
    </div>
    <div class="definition-list compact">
      <div class="definition-row"><dt>Account</dt><dd>${escapeHTML(account)}</dd></div>
      <div class="definition-row"><dt>Calendar</dt><dd>${escapeHTML(calendar)}</dd></div>
      <div class="definition-row"><dt>Permissions</dt><dd>${permissions ? `${permissions} approved` : "None verified"}</dd></div>
      <div class="definition-row"><dt>Sending email</dt><dd>${connection.send_mail_available ? "Available" : "Unavailable"}</dd></div>
    </div>`;
}

async function checkGoogleConnection() {
  setRunStatus("Checking Google", "warning");
  state.googleConnection = await api("/v1/connectors/google/health");
  renderGoogleConnection();
  if (state.googleConnection.healthy) {
    setRunStatus("Ready", "success");
    toast("Google connection verified.");
  } else {
    setRunStatus("Reconnect needed", "warning");
    toast(state.googleConnection.message || "Google connection needs attention.", "error");
  }
}

function toggleGoogleReconnectGuide() {
  const guide = $("#google-reconnect-guide");
  guide.classList.toggle("hidden");
  $("#toggle-google-reconnect").textContent = guide.classList.contains("hidden")
    ? "Reconnect instructions"
    : "Hide reconnect instructions";
}

async function checkProviders() {
  setRunStatus("Checking models", "warning");
  const health = await api("/v1/providers/health");
  renderProviderSummary(health);
  setRunStatus("Ready", "success");
}

async function runImport() {
  const file = $("#import-file").files[0];
  if (!file) throw new Error("Choose an import file first.");
  const form = new FormData();
  form.append("file", file);
  form.append("source", $("#import-source").value);
  const projectSlug = $("#project-select").value;
  if (projectSlug) form.append("project_slug", projectSlug);
  form.append("dry_run", "false");
  setRunStatus("Importing", "warning");
  const result = await api("/v1/import", { method: "POST", body: form });
  const box = $("#import-result");
  box.textContent = JSON.stringify(result, null, 2);
  box.classList.remove("hidden");
  await loadConversations();
  await loadMemories();
  setRunStatus("Ready", "success");
  toast("Import completed.");
}

async function createBackup() {
  setRunStatus("Creating backup", "warning");
  const response = await fetch("/v1/backups", {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ include_workspace: true }),
  });
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try { detail = (await response.json()).detail || detail; } catch (_) {}
    throw new Error(detail);
  }
  const blob = await response.blob();
  const disposition = response.headers.get("content-disposition") || "";
  const match = disposition.match(/filename="?([^";]+)"?/i);
  const filename = match?.[1] || "atlas-backup.zip";
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
  setRunStatus("Ready", "success");
  toast("Portable backup created.");
}

async function loadAudit() {
  const events = await api("/v1/audit?limit=500");
  $("#audit-body").innerHTML = events.map((event) => `
    <tr>
      <td>${escapeHTML(formatDate(event.created_at))}</td>
      <td>${escapeHTML(event.actor)}</td>
      <td>${escapeHTML(event.action)}</td>
      <td><span class="badge ${event.outcome === "success" || event.outcome === "approved" ? "success" : event.outcome === "failed" || event.outcome === "denied" ? "danger" : ""}">${escapeHTML(event.outcome)}</span></td>
      <td>${escapeHTML(event.resource)}</td>
    </tr>`).join("") || '<tr><td colspan="5" class="empty-state">No audit events yet.</td></tr>';
}

function resizeComposer() {
  const input = $("#message-input");
  input.style.height = "auto";
  input.style.height = `${Math.min(input.scrollHeight, 190)}px`;
}

function bindEvents() {
  $("#stop-development").addEventListener("click", () => changeDevelopmentControl("stop"));
  $("#resume-development").addEventListener("click", () => changeDevelopmentControl("resume"));
  $("#refresh-development-control").addEventListener("click", refreshDevelopmentControl);
  $$(".nav-button").forEach((button) => button.addEventListener("click", () => setView(button.dataset.view)));
  $("#new-conversation").addEventListener("click", newConversation);
  $("#send-button").addEventListener("click", () => sendMessage().catch(handleError));
  $("#message-input").addEventListener("input", resizeComposer);
  $("#message-input").addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey && !event.isComposing) {
      event.preventDefault();
      sendMessage().catch(handleError);
    }
  });
  $("#project-form").addEventListener("submit", (event) => saveProject(event).catch(handleError));
  $("#refresh-projects").addEventListener("click", () => loadProjects().catch(handleError));
  $("#memory-form").addEventListener("submit", (event) => saveMemory(event).catch(handleError));
  $("#search-memory").addEventListener("click", () => loadMemories().catch(handleError));
  $("#memory-search").addEventListener("keydown", (event) => {
    if (event.key === "Enter") loadMemories().catch(handleError);
  });
  $("#refresh-approvals").addEventListener("click", () => loadApprovals().catch(handleError));
  $("#refresh-audit").addEventListener("click", () => loadAudit().catch(handleError));
  $("#check-providers").addEventListener("click", () => checkProviders().catch(handleError));
  $("#check-google").addEventListener("click", () => checkGoogleConnection().catch(handleError));
  $("#toggle-google-reconnect").addEventListener("click", toggleGoogleReconnectGuide);
  $("#toggle-supervisor").addEventListener("click", () => toggleSupervisor().catch(handleError));
  $("#check-supervisor-v2").addEventListener("click", () => checkSupervisorV2().catch(handleError));
  $("#plan-supervisor-v2").addEventListener("click", () => planSupervisorV2().catch(handleError));
  $("#run-supervisor-v2").addEventListener("click", () => runSupervisorV2().catch(handleError));
  $("#check-supervisor-v3").addEventListener("click", () => checkSupervisorV3().catch(handleError));
  $("#plan-supervisor-v3-canary").addEventListener("click", () => planSupervisorV3("canary").catch(handleError));
  $("#plan-supervisor-v3-successor").addEventListener("click", () => planSupervisorV3("successor_canary").catch(handleError));
  $("#plan-supervisor-v3-fixture").addEventListener("click", () => planSupervisorV3("fixture").catch(handleError));
  $("#plan-supervisor-v3-recovery-canary").addEventListener("click", () => planSupervisorV3("recovery_canary").catch(handleError));
  $("#plan-supervisor-v3-recovery-fixture").addEventListener("click", () => planSupervisorV3("recovery_fixture").catch(handleError));
  $("#run-supervisor-v3").addEventListener("click", () => runSupervisorV3().catch(handleError));
  $("#identity-select").addEventListener("change", showIdentityDocument);
  $("#save-identity").addEventListener("click", () => saveIdentity().catch(handleError));
  $("#save-permissions").addEventListener("click", () => savePermissions().catch(handleError));
  $("#run-import").addEventListener("click", () => runImport().catch(handleError));
  $("#export-backup").addEventListener("click", () => createBackup().catch(handleError));
  $("#save-token").addEventListener("click", () => {
    state.token = $("#api-token").value.trim();
    sessionStorage.setItem("atlasToken", state.token);
    toast("Token saved for this browser session.");
    bootstrap();
  });
  $("#submit-token").addEventListener("click", () => {
    state.token = $("#modal-token").value.trim();
    sessionStorage.setItem("atlasToken", state.token);
    bootstrap();
  });
  $("#modal-token").addEventListener("keydown", (event) => {
    if (event.key === "Enter") $("#submit-token").click();
  });
  $("#open-sidebar").addEventListener("click", openSidebar);
  $("#close-sidebar").addEventListener("click", closeSidebar);
  $("#mobile-scrim").addEventListener("click", closeSidebar);
  bindStarters(document);
}

bindEvents();
bootstrap();

// Background results are owner-visible; receipt text is rendered as text only.
async function refreshImprovement() {
  const node = $("#improvement-status");
  if (!node) return;
  try {
    const info = await api("/v1/improvement");
    node.textContent = info.enabled
      ? `${info.state}. ${info.reason || ""}. Last result: ${info.last_outcome?.status || "none"}. Next eligible: ${new Date(info.next_eligible_utc).toLocaleString()}. ${info.pending} queued. ${info.pending_source_proposals} source proposals.`
      : `Background learning ${info.state}.`;
    $("#pause-improvement").disabled = !info.enabled || info.paused;
    $("#resume-improvement").disabled = !info.enabled || !info.paused;
  } catch (_) { node.textContent = "Background status unavailable; no successful action is confirmed."; }
}
for (const action of ["pause", "resume"]) {
  document.querySelector(`#${action}-improvement`)?.addEventListener("click", async () => {
    try { await api(`/v1/improvement/${action}`, {method: "POST"}); }
    catch (error) { handleError(error); }
    await refreshImprovement();
  });
}
document.querySelector("#refresh-improvement")?.addEventListener("click", refreshImprovement);
