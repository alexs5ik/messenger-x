// Messenger X web client — UI, local state, and wiring between the API, the WebSocket
// gateway, and the crypto module.

import { register, publishPrekeys, MxSocket, type Identity, type WireEnvelope } from "./api";
import { encrypt, decrypt, provisionAccount, pqStatus } from "./crypto";

interface Contact {
  userId: string;
  name: string;
}
interface Msg {
  mine: boolean;
  text: string;
  ts: number;
}

const SS = {
  identity: "mx.identity",
  contacts: "mx.contacts",
  msgs: (peer: string) => `mx.msgs.${peer}`,
};

let identity: Identity | null = null;
let contacts: Contact[] = [];
let active: string | null = null;
const threads = new Map<string, Msg[]>();
const unread = new Map<string, number>();
let socket: MxSocket | null = null;

const $ = (sel: string) => document.querySelector(sel) as HTMLElement;
const root = () => $("#app");
const esc = (s: string) =>
  s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!);
const shortId = (id: string) => id.slice(0, 8);

function loadThread(peer: string): Msg[] {
  if (!threads.has(peer)) {
    const raw = sessionStorage.getItem(SS.msgs(peer));
    threads.set(peer, raw ? (JSON.parse(raw) as Msg[]) : []);
  }
  return threads.get(peer)!;
}
function saveThread(peer: string): void {
  sessionStorage.setItem(SS.msgs(peer), JSON.stringify(threads.get(peer) ?? []));
}
function saveContacts(): void {
  sessionStorage.setItem(SS.contacts, JSON.stringify(contacts));
}
function ensureContact(userId: string, name?: string): void {
  if (!contacts.some((c) => c.userId === userId)) {
    contacts.push({ userId, name: name ?? shortId(userId) });
    saveContacts();
  }
}

export function mount(): void {
  const rawId = sessionStorage.getItem(SS.identity);
  if (rawId) {
    identity = JSON.parse(rawId) as Identity;
    contacts = JSON.parse(sessionStorage.getItem(SS.contacts) ?? "[]") as Contact[];
    startApp();
  } else {
    renderLogin();
  }
}

// ---------- Login ----------
function renderLogin(): void {
  root().innerHTML = `
    <div class="login">
      <div class="login-card">
        <div class="brand"><i class="ti ti-shield-lock"></i> Messenger&nbsp;X</div>
        <p class="muted">Защищённый супер-мессенджер · демо-клиент</p>
        <input id="uname" placeholder="Ваше имя" autocomplete="off" />
        <button id="go" class="primary"><i class="ti ti-arrow-right"></i> Создать аккаунт</button>
        <p class="hint" id="loginhint">Откройте вторую вкладку и создайте второго пользователя, чтобы переписываться.</p>
      </div>
    </div>`;
  const input = $("#uname") as HTMLInputElement;
  input.focus();
  const submit = async () => {
    const name = input.value.trim();
    if (!name) return;
    $("#loginhint").textContent = "Регистрация…";
    try {
      identity = await register(name);
      // Provision the device's PQXDH account and publish its pre-key bundle so peers can
      // start encrypted sessions against it.
      $("#loginhint").textContent = "Генерация ключей (PQXDH)…";
      const bundle = await provisionAccount(identity.deviceId);
      await publishPrekeys(bundle);
      sessionStorage.setItem(SS.identity, JSON.stringify(identity));
      startApp();
    } catch (e) {
      $("#loginhint").textContent = "Ошибка: запущен ли mx-server на :9990? " + (e as Error).message;
    }
  };
  $("#go").addEventListener("click", submit);
  input.addEventListener("keydown", (e) => {
    if ((e as KeyboardEvent).key === "Enter") submit();
  });
}

// ---------- App ----------
function startApp(): void {
  renderApp();
  socket = new MxSocket(identity!.token, onIncoming, (s) => {
    const dot = document.querySelector("#status") as HTMLElement | null;
    if (dot) {
      dot.className = "status " + s;
      dot.textContent = s === "online" ? "на связи" : s === "connecting" ? "подключение" : "оффлайн";
    }
  });
  // The server pushes messages over the WebSocket in real time (queued ones on connect,
  // live ones via its per-session hub), so the client just listens — no polling.
  socket.connect();

  // Prove the post-quantum crypto core runs in-browser (wasm) and reflect it in the badge.
  void pqStatus().then((s) => {
    const badge = document.querySelector("#pqbadge") as HTMLElement | null;
    if (!badge) return;
    if (s.ok) {
      badge.className = "badge ok";
      badge.innerHTML = `<i class="ti ti-shield-check"></i> PQ ✓ ${s.kem ?? ""}`;
      badge.title = "Hybrid PQXDH (X25519 + ML-KEM-768) + Double Ratchet verified in wasm";
    } else {
      badge.className = "badge";
      badge.innerHTML = `<i class="ti ti-shield-x"></i> PQ ✗`;
      badge.title = s.error ?? "self-test failed";
    }
  });
}

function renderApp(): void {
  root().innerHTML = `
    <div class="app">
      <aside class="side">
        <div class="side-hd">
          <div class="me">
            <div class="avatar">${esc(identity!.username.slice(0, 2).toUpperCase())}</div>
            <div class="me-info">
              <div class="me-name">${esc(identity!.username)}</div>
              <div id="status" class="status offline">оффлайн</div>
            </div>
          </div>
          <button id="logout" class="icon" title="Выйти" aria-label="Выйти"><i class="ti ti-logout"></i></button>
        </div>
        <button id="copyid" class="myid" title="Скопировать ваш ID">
          <i class="ti ti-id"></i> <span>${esc(shortId(identity!.userId))}…</span> <i class="ti ti-copy"></i>
        </button>
        <button id="newchat" class="newchat"><i class="ti ti-plus"></i> Новый чат</button>
        <div id="contacts" class="contacts"></div>
        <div class="side-ft">
          <span id="pqbadge" class="badge"><i class="ti ti-shield-lock"></i> PQ…</span>
          <span class="badge"><i class="ti ti-cpu"></i> on-device AI</span>
        </div>
      </aside>
      <main id="main" class="main"></main>
    </div>`;
  $("#logout").addEventListener("click", () => {
    socket?.close();
    sessionStorage.clear();
    location.reload();
  });
  $("#copyid").addEventListener("click", async () => {
    await navigator.clipboard.writeText(identity!.userId);
    const el = $("#copyid").querySelector("span")!;
    const prev = el.textContent;
    el.textContent = "скопировано!";
    setTimeout(() => (el.textContent = prev), 1200);
  });
  $("#newchat").addEventListener("click", newChat);
  renderContacts();
  renderMain();
}

function renderContacts(): void {
  const box = $("#contacts");
  if (!contacts.length) {
    box.innerHTML = `<p class="empty">Нет чатов. Нажмите «Новый чат» и вставьте ID собеседника.</p>`;
    return;
  }
  box.innerHTML = contacts
    .map((c) => {
      const t = loadThread(c.userId);
      const last = t.length ? t[t.length - 1] : null;
      const u = unread.get(c.userId) ?? 0;
      return `<button class="contact ${c.userId === active ? "active" : ""}" data-id="${c.userId}">
        <div class="avatar sm">${esc(c.name.slice(0, 2).toUpperCase())}</div>
        <div class="c-info">
          <div class="c-name">${esc(c.name)}</div>
          <div class="c-last">${last ? esc((last.mine ? "Вы: " : "") + last.text).slice(0, 32) : "нет сообщений"}</div>
        </div>
        ${u ? `<span class="unread">${u}</span>` : ""}
      </button>`;
    })
    .join("");
  box.querySelectorAll(".contact").forEach((b) =>
    b.addEventListener("click", () => selectPeer((b as HTMLElement).dataset.id!)),
  );
}

function renderMain(): void {
  const main = $("#main");
  if (!active) {
    main.innerHTML = `<div class="placeholder"><i class="ti ti-messages"></i><p>Выберите чат или начните новый</p></div>`;
    return;
  }
  const contact = contacts.find((c) => c.userId === active)!;
  main.innerHTML = `
    <div class="chat-hd">
      <div class="avatar sm">${esc(contact.name.slice(0, 2).toUpperCase())}</div>
      <div class="chat-hd-info">
        <div class="chat-name">${esc(contact.name)}</div>
        <div class="chat-sub"><i class="ti ti-lock"></i> E2E · ML-KEM-768 · ${esc(shortId(contact.userId))}…</div>
      </div>
      <button class="icon" title="Аудиозвонок" aria-label="Звонок"><i class="ti ti-phone"></i></button>
      <button class="icon" title="Видеозвонок" aria-label="Видео"><i class="ti ti-video"></i></button>
    </div>
    <div id="feed" class="feed"></div>
    <div class="inbar">
      <button class="icon" aria-label="Вложение"><i class="ti ti-plus"></i></button>
      <input id="msg" placeholder="Сообщение… (шифруется на устройстве)" autocomplete="off" />
      <button class="icon ai" title="AI" aria-label="AI"><i class="ti ti-sparkles"></i></button>
      <button id="send" class="icon send" aria-label="Отправить"><i class="ti ti-send"></i></button>
    </div>`;
  renderFeed();
  const input = $("#msg") as HTMLInputElement;
  input.focus();
  const send = () => sendMessage(input);
  $("#send").addEventListener("click", send);
  input.addEventListener("keydown", (e) => {
    if ((e as KeyboardEvent).key === "Enter") send();
  });
}

function renderFeed(): void {
  const feed = document.querySelector("#feed") as HTMLElement | null;
  if (!feed || !active) return;
  const msgs = loadThread(active);
  feed.innerHTML = msgs
    .map(
      (m) =>
        `<div class="bubble ${m.mine ? "out" : "in"}"><span>${esc(m.text)}</span><time>${new Date(
          m.ts,
        ).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</time></div>`,
    )
    .join("");
  feed.scrollTop = feed.scrollHeight;
}

function selectPeer(id: string): void {
  active = id;
  unread.delete(id);
  renderContacts();
  renderMain();
}

function newChat(): void {
  const id = prompt("Вставьте ID собеседника (из его кнопки ID):")?.trim();
  if (!id) return;
  if (id === identity!.userId) {
    alert("Это ваш собственный ID 🙂");
    return;
  }
  const name = prompt("Имя для чата (необязательно):")?.trim();
  ensureContact(id, name || shortId(id));
  renderContacts();
  selectPeer(id);
}

async function sendMessage(input: HTMLInputElement): Promise<void> {
  const text = input.value.trim();
  if (!text || !active || !identity) return;
  input.value = "";
  const payload = await encrypt(identity.userId, active, text);
  const env: WireEnvelope = {
    id: crypto.randomUUID(),
    from: identity.deviceId,
    to: { direct: active },
    kind: "chat",
    ciphertext: Array.from(payload),
    ts: Date.now(),
  };
  socket?.send(env);
  const t = loadThread(active);
  t.push({ mine: true, text, ts: env.ts });
  saveThread(active);
  renderFeed();
  renderContacts();
}

async function onIncoming(env: WireEnvelope): Promise<void> {
  if (!identity) return;
  try {
    const { from, text } = await decrypt(Uint8Array.from(env.ciphertext));
    ensureContact(from);
    const t = loadThread(from);
    t.push({ mine: false, text, ts: env.ts || Date.now() });
    saveThread(from);
    if (from === active) {
      renderFeed();
    } else {
      unread.set(from, (unread.get(from) ?? 0) + 1);
    }
    renderContacts();
  } catch (e) {
    console.warn("decrypt failed (key mismatch or tamper):", e);
  }
}
