// Messenger X web client — UI, local state, and wiring between the API, the WebSocket
// gateway, and the crypto module.

import { register, publishPrekeys, MxSocket, type Identity, type WireEnvelope } from "./api";
import { encrypt, decrypt, provisionAccount, pqStatus } from "./crypto";

interface Contact {
  userId: string;
  name: string;
}
type MsgStatus = "pending" | "sent" | "delivered";
interface Msg {
  id?: string;
  mine: boolean;
  text: string;
  ts: number;
  status?: MsgStatus;
  from?: string; // sender userId — used to label incoming group messages
}

// Client-side editable profile, persisted in localStorage (survives a tab close, unlike
// the sessionStorage-backed identity/threads).
interface Profile {
  name?: string;
  status?: string;
  avatar?: string; // data URL
}
// Communities/channels/groups (pairwise fan-out over the working 1:1 E2E). Stored locally.
type GroupKind = "community" | "channel" | "group";
interface Group {
  id: string;
  name: string;
  kind: GroupKind;
  members: string[]; // userIds, including self
}

// The STRING passed to encrypt() (and parsed after decrypt()) is JSON of this shape.
// 1:1 chat wraps as {t:"text"}; groups use ginvite/gtext. Non-JSON or missing `t` is
// treated as a legacy plain-text message for backward compatibility.
type AppMsg =
  | { t: "text"; text: string }
  | { t: "ginvite"; g: string; name: string; kind: GroupKind; members: string[] }
  | { t: "gtext"; g: string; text: string };

const LS = { profile: "mx.profile", groups: "mx.groups" };

// Bump when the shape of any stored data changes so old tabs auto-reset instead of breaking.
const STORAGE_VERSION = "5";

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

// ---------- Editable profile (client-side) ----------
let profile: Profile = {};
function loadProfile(): void {
  try {
    profile = JSON.parse(localStorage.getItem(LS.profile) ?? "{}") as Profile;
  } catch {
    profile = {};
  }
}
function saveProfile(): void {
  localStorage.setItem(LS.profile, JSON.stringify(profile));
}
function displayName(): string {
  return profile.name?.trim() || identity!.username;
}
function selfInitials(): string {
  return esc(displayName().slice(0, 2).toUpperCase());
}
// Render an avatar's inner content: <img> when a data URL is set, else initials text.
function avatarInner(avatar: string | undefined, initials: string): string {
  return avatar ? `<img src="${esc(avatar)}" alt="" class="mx-av-img" />` : initials;
}

// Read an image File, center-crop into a <=256px square canvas, return a JPEG data URL.
function fileToAvatar(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const img = new Image();
    const url = URL.createObjectURL(file);
    img.onload = () => {
      URL.revokeObjectURL(url);
      const size = 256;
      const side = Math.min(img.width, img.height);
      const sx = (img.width - side) / 2;
      const sy = (img.height - side) / 2;
      const cv = document.createElement("canvas");
      cv.width = size;
      cv.height = size;
      const ctx = cv.getContext("2d")!;
      ctx.drawImage(img, sx, sy, side, side, 0, 0, size, size);
      resolve(cv.toDataURL("image/jpeg", 0.85));
    };
    img.onerror = () => {
      URL.revokeObjectURL(url);
      reject(new Error("bad image"));
    };
    img.src = url;
  });
}

// ---------- Communities / channels / groups (client-side, pairwise fan-out) ----------
let groups: Group[] = [];
function loadGroups(): void {
  try {
    groups = JSON.parse(localStorage.getItem(LS.groups) ?? "[]") as Group[];
  } catch {
    groups = [];
  }
}
function saveGroups(): void {
  localStorage.setItem(LS.groups, JSON.stringify(groups));
}
function findGroup(id: string): Group | undefined {
  return groups.find((g) => g.id === id);
}
function upsertGroup(g: Group): void {
  if (!findGroup(g.id)) {
    groups.push(g);
    saveGroups();
  }
}
const KIND_ICON: Record<GroupKind, string> = {
  community: "ti-users-group",
  channel: "ti-speakerphone",
  group: "ti-users",
};
const KIND_LABEL: Record<GroupKind, string> = {
  community: "Сообщество",
  channel: "Канал",
  group: "Группа",
};

// Encrypt a structured AppMsg to one peer and send it as a Direct chat envelope.
async function sendApp(peer: string, msg: AppMsg): Promise<void> {
  if (!identity) return;
  const payload = await encrypt(identity.userId, peer, JSON.stringify(msg));
  socket?.send({
    id: crypto.randomUUID(),
    from: identity.deviceId,
    to: { direct: peer },
    kind: "chat",
    ciphertext: Array.from(payload),
    ts: Date.now(),
  });
}

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

const STATUS_RANK: Record<MsgStatus, number> = { pending: 0, sent: 1, delivered: 2 };

// Upgrade an outgoing message's delivery status (never downgrades) and re-render.
function markStatus(id: string, status: MsgStatus): void {
  for (const [peer, msgs] of threads) {
    const m = msgs.find((x) => x.id === id);
    if (m) {
      if (!m.status || STATUS_RANK[status] > STATUS_RANK[m.status]) {
        m.status = status;
        saveThread(peer);
        if (peer === active) renderFeed();
      }
      return;
    }
  }
}

// One check = sent (server accepted); two checks = delivered to the recipient.
function statusIcon(s?: MsgStatus): string {
  if (s === "delivered")
    return ` <i class="ti ti-checks" style="color:var(--accent)" title="доставлено"></i>`;
  if (s === "sent") return ` <i class="ti ti-check" title="отправлено"></i>`;
  return ` <i class="ti ti-clock" title="отправка…"></i>`;
}

// Send a delivery receipt for `msgId` back to `toUser` (an opaque Control envelope).
function sendReceipt(toUser: string, msgId: string): void {
  if (!socket || !identity) return;
  const payload = new TextEncoder().encode(JSON.stringify({ t: "receipt", id: msgId }));
  socket.send({
    id: crypto.randomUUID(),
    from: identity.deviceId,
    to: { direct: toUser },
    kind: "control",
    ciphertext: Array.from(payload),
    ts: Date.now(),
  });
}

const THEMES = ["graphite", "ivory", "onyx"] as const;
type Theme = (typeof THEMES)[number];
const THEME_LABEL: Record<Theme, string> = { graphite: "Графит", ivory: "Айвори", onyx: "Оникс" };

function applyTheme(t: Theme): void {
  document.documentElement.dataset.theme = t;
  localStorage.setItem("mx.theme", t);
}
function currentTheme(): Theme {
  const t = localStorage.getItem("mx.theme") as Theme | null;
  return t && THEMES.includes(t) ? t : "graphite";
}
function cycleTheme(): void {
  const next = THEMES[(THEMES.indexOf(currentTheme()) + 1) % THEMES.length];
  applyTheme(next);
  const btn = document.querySelector("#theme") as HTMLElement | null;
  if (btn) btn.title = `Тема: ${THEME_LABEL[next]}`;
}

export function mount(): void {
  applyTheme(currentTheme());
  // Self-heal: if stored data is from an older client (different format) or the device was
  // never provisioned with crypto secrets, wipe and start fresh so nothing silently breaks.
  const stale =
    sessionStorage.getItem("mx.ver") !== STORAGE_VERSION ||
    (sessionStorage.getItem(SS.identity) && !sessionStorage.getItem("mx.secrets"));
  if (stale) {
    sessionStorage.clear();
    sessionStorage.setItem("mx.ver", STORAGE_VERSION);
  }
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
  loadProfile();
  loadGroups();
  renderApp();
  socket = new MxSocket(identity!.token, onIncoming, (s) => {
    const dot = document.querySelector("#status") as HTMLElement | null;
    if (dot) {
      dot.className = "status " + s;
      dot.textContent = s === "online" ? "на связи" : s === "connecting" ? "подключение" : "оффлайн";
    }
  }, (messageId) => markStatus(messageId, "sent"));
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
            <div id="meAvatar" class="avatar" role="button" tabindex="0" aria-label="Профиль и настройки">${avatarInner(profile.avatar, selfInitials())}</div>
            <div class="me-info">
              <div class="me-name">${esc(displayName())}</div>
              ${profile.status ? `<div class="me-status" id="meStatus">${esc(profile.status)}</div>` : ""}
              <div id="status" class="status offline">оффлайн</div>
            </div>
          </div>
          <button id="theme" class="icon" title="Тема: ${esc(THEME_LABEL[currentTheme()])}" aria-label="Сменить тему"><i class="ti ti-palette"></i></button>
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
  $("#theme").addEventListener("click", cycleTheme);
  $("#logout").addEventListener("click", doLogout);
  const meAvatar = $("#meAvatar");
  meAvatar.addEventListener("click", openProfile);
  meAvatar.addEventListener("keydown", (e) => {
    const k = (e as KeyboardEvent).key;
    if (k === "Enter" || k === " ") {
      e.preventDefault();
      openProfile();
    }
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
  mountProfilePanel();
}

// ---------- Logout (shared by rail button and profile footer) ----------
function doLogout(): void {
  socket?.close();
  sessionStorage.clear();
  // Reset device-bound profile & groups so the next account starts clean (keep theme).
  localStorage.removeItem(LS.profile);
  localStorage.removeItem(LS.groups);
  location.reload();
}

// ---------- Profile & settings panel (right-slide overlay) ----------
const APP_VERSION = "v0.4.0";
let mxEscHandler: ((e: KeyboardEvent) => void) | null = null;
let mxLastFocus: HTMLElement | null = null;

// Build the panel markup. Real data from `identity`; the rest is on-brand placeholder.
function renderProfilePanel(): string {
  const uname = displayName();
  const initials = esc(uname.slice(0, 2).toUpperCase());
  const handle = esc("@" + identity!.username.toLowerCase());
  const sid = esc(shortId(identity!.userId));
  const theme = currentTheme();

  const swatch: Record<Theme, [string, string]> = {
    graphite: ["#202023", "#ffffff"],
    ivory: ["#e3e3e8", "#ffffff"],
    onyx: ["#161618", "#2a2a2d"],
  };
  const themeTiles = THEMES.map((t) => {
    const active = t === theme;
    const [l, r] = swatch[t];
    return `<button class="mx-theme ${active ? "is-active" : ""}" data-theme="${t}" aria-pressed="${active}">
      <span class="mx-theme__sw"><span style="background:${l}"></span><span style="background:${r}"></span></span>
      <span class="mx-theme__lbl">${esc(THEME_LABEL[t])}</span>
      ${active ? `<i class="ti ti-check mx-theme__chk"></i>` : ""}
    </button>`;
  }).join("");

  return `
  <div class="mx-backdrop" data-close></div>
  <aside class="mx-panel" role="dialog" aria-modal="true" aria-label="Профиль и настройки">
    <header class="mx-head">
      <div class="mx-head__bar">
        <button class="mx-close" data-close aria-label="Закрыть"><i class="ti ti-x"></i></button>
      </div>
      <div class="mx-id">
        <div class="avatar lg mx-id__av">${avatarInner(profile.avatar, initials)}</div>
        <div class="mx-id__txt">
          <div class="mx-id__name">${esc(uname)}</div>
          ${profile.status ? `<div class="mx-id__status">${esc(profile.status)}</div>` : ""}
          <div class="mx-id__line">
            <span>${handle}</span><span class="mx-id__dot">·</span>
            <button id="mxCopyId" class="mx-id__copy" title="Скопировать ваш ID">
              <span class="mx-id__sid">${sid}…</span> <i class="ti ti-copy"></i>
            </button>
          </div>
          <button class="mx-status" type="button"><i class="ti ti-mood-smile"></i> Установить статус</button>
        </div>
      </div>
      <button class="mx-edit" type="button"><i class="ti ti-edit"></i> Редактировать профиль</button>
    </header>

    <div class="mx-body">
      <button class="mx-card mx-card--btn" type="button">
        <div class="mx-card__head">
          <i class="ti ti-wallet mx-card__lead"></i>
          <span class="mx-card__title">Кошелёк</span>
          <i class="ti ti-chevron-right mx-card__chev"></i>
        </div>
        <div class="mx-card__meta">1 240,50 ₮ · доступно</div>
        <div class="mx-card__rule"></div>
        <div class="mx-card__pills">
          <span class="mx-pill"><i class="ti ti-arrows-exchange"></i> Платежи</span>
          <span class="mx-pill"><i class="ti ti-package"></i> Цифровые товары</span>
          <span class="mx-pill"><i class="ti ti-coin"></i> Подписки и доходы</span>
        </div>
      </button>

      <button class="mx-card mx-card--btn" type="button">
        <div class="mx-card__head">
          <i class="ti ti-sparkles mx-card__lead mx-accent"></i>
          <span class="mx-card__title">AI-ассистент</span>
          <i class="ti ti-chevron-right mx-card__chev"></i>
        </div>
        <div class="mx-card__meta">Включён · на устройстве</div>
        <div class="mx-card__rule"></div>
        <div class="mx-row mx-row--incard">
          <i class="ti ti-robot mx-row__ic"></i>
          <span class="mx-row__label">AI-агенты</span>
          <span class="mx-row__trail"><span class="mx-row__val">Маркетплейс</span><i class="ti ti-chevron-right mx-row__chev"></i></span>
        </div>
      </button>

      <div class="mx-cap">Сообщество и контент</div>
      <button class="mx-row" type="button" data-create="community"><i class="ti ti-users-group mx-row__ic"></i><span class="mx-row__label">Создать сообщество</span><span class="mx-row__trail"><i class="ti ti-chevron-right mx-row__chev"></i></span></button>
      <button class="mx-row" type="button" data-create="channel"><i class="ti ti-speakerphone mx-row__ic"></i><span class="mx-row__label">Создать канал</span><span class="mx-row__trail"><i class="ti ti-chevron-right mx-row__chev"></i></span></button>
      <button class="mx-row" type="button" data-create="group"><i class="ti ti-message-circle-2 mx-row__ic"></i><span class="mx-row__label">Создать группу</span><span class="mx-row__trail"><i class="ti ti-chevron-right mx-row__chev"></i></span></button>

      <div class="mx-cap">Аккаунты</div>
      <div class="mx-row mx-row--static"><i class="ti ti-user-circle mx-row__ic"></i><span class="mx-row__label">${handle}</span><span class="mx-row__trail"><span class="mx-badge">Текущий</span></span></div>
      <button class="mx-row" type="button"><i class="ti ti-switch-horizontal mx-row__ic"></i><span class="mx-row__label">Сменить аккаунт</span><span class="mx-row__trail"><i class="ti ti-chevron-right mx-row__chev"></i></span></button>
      <button class="mx-row" type="button"><i class="ti ti-plus mx-row__ic"></i><span class="mx-row__label">Добавить аккаунт</span><span class="mx-row__trail"><i class="ti ti-chevron-right mx-row__chev"></i></span></button>

      <div class="mx-cap">Приватность и безопасность</div>
      <div class="mx-card mx-card--pq">
        <div class="mx-card__head">
          <i class="ti ti-shield-check mx-card__lead mx-accent" id="mxPqIcon"></i>
          <span class="mx-card__title" id="mxPqState">Постквантовая защита</span>
          <span class="mx-badge">Активно</span>
        </div>
        <div class="mx-card__meta" id="mxPqSub">Hybrid PQXDH · X25519 + ML-KEM-768</div>
      </div>
      <button class="mx-row" type="button"><i class="ti ti-devices mx-row__ic"></i><span class="mx-row__label">Активные сессии</span><span class="mx-row__trail"><span class="mx-row__val">1 устройство</span><i class="ti ti-chevron-right mx-row__chev"></i></span></button>
      <button class="mx-row" type="button"><i class="ti ti-lock mx-row__ic"></i><span class="mx-row__label">Конфиденциальность</span><span class="mx-row__trail"><i class="ti ti-chevron-right mx-row__chev"></i></span></button>
      <button class="mx-row" type="button"><i class="ti ti-key mx-row__ic"></i><span class="mx-row__label">Ключи шифрования</span><span class="mx-row__trail"><i class="ti ti-chevron-right mx-row__chev"></i></span></button>

      <div class="mx-cap">Связь</div>
      <button class="mx-row" type="button"><i class="ti ti-address-book mx-row__ic"></i><span class="mx-row__label">Контакты</span><span class="mx-row__trail"><span class="mx-row__val mx-num">${contacts.length}</span><i class="ti ti-chevron-right mx-row__chev"></i></span></button>
      <button class="mx-row" type="button"><i class="ti ti-phone mx-row__ic"></i><span class="mx-row__label">Звонки</span><span class="mx-row__trail"><i class="ti ti-chevron-right mx-row__chev"></i></span></button>
      <button class="mx-row" type="button"><i class="ti ti-bookmark mx-row__ic"></i><span class="mx-row__label">Избранное</span><span class="mx-row__trail"><i class="ti ti-chevron-right mx-row__chev"></i></span></button>

      <div class="mx-cap">Оформление</div>
      <div class="mx-themes">${themeTiles}</div>

      <div class="mx-cap">Настройки</div>
      <div class="mx-row mx-row--static"><i class="ti ti-bell mx-row__ic"></i><span class="mx-row__label">Уведомления</span><span class="mx-row__trail"><button class="mx-toggle" id="mxNotif" role="switch" aria-checked="true" aria-label="Уведомления"></button></span></div>
      <button class="mx-row" type="button"><i class="ti ti-language mx-row__ic"></i><span class="mx-row__label">Язык</span><span class="mx-row__trail"><span class="mx-row__val">Русский</span><i class="ti ti-chevron-right mx-row__chev"></i></span></button>
      <button class="mx-row" type="button"><i class="ti ti-settings mx-row__ic"></i><span class="mx-row__label">Настройки</span><span class="mx-row__trail"><i class="ti ti-chevron-right mx-row__chev"></i></span></button>
    </div>

    <footer class="mx-foot">
      <span class="mx-ver"><i class="ti ti-shield-lock"></i> Messenger X · ${APP_VERSION}</span>
      <button class="mx-logout" id="mxLogout" type="button"><i class="ti ti-logout"></i> Выйти</button>
    </footer>
  </aside>`;
}

// ---------- Edit-profile form (swaps the panel body in place) ----------
function renderEditForm(): string {
  const av = profile.avatar;
  return `
  <form class="mx-edit-form" id="mxEditForm">
    <div class="mx-cap">Редактирование профиля</div>
    <div class="mx-edit-av">
      <div class="avatar lg" id="mxEditAv">${avatarInner(av, selfInitials())}</div>
      <label class="mx-edit-pick">
        <i class="ti ti-camera"></i> Загрузить фото
        <input type="file" accept="image/*" id="mxAvFile" hidden />
      </label>
      ${av ? `<button type="button" class="mx-edit-rm" id="mxAvRm"><i class="ti ti-trash"></i> Убрать</button>` : ""}
    </div>
    <label class="mx-field"><span>Имя</span>
      <input id="mxName" maxlength="48" value="${esc(profile.name ?? "")}" placeholder="${esc(identity!.username)}" /></label>
    <label class="mx-field"><span>Статус</span>
      <input id="mxStatus" maxlength="80" value="${esc(profile.status ?? "")}" placeholder="Например: на связи 🙂" /></label>
    <div class="mx-edit-actions">
      <button type="button" class="mx-btn-ghost" id="mxEditCancel">Отмена</button>
      <button type="submit" class="mx-btn-primary" id="mxEditSave">Сохранить</button>
    </div>
  </form>`;
}

function enterEdit(wrap: HTMLElement, focusStatus: boolean): void {
  const body = wrap.querySelector(".mx-body") as HTMLElement;
  body.innerHTML = renderEditForm();
  wireEditForm(wrap, body, focusStatus);
}

function wireEditForm(wrap: HTMLElement, body: HTMLElement, focusStatus: boolean): void {
  let pendingAvatar = profile.avatar; // local until Save
  const avBox = body.querySelector("#mxEditAv") as HTMLElement;
  const file = body.querySelector("#mxAvFile") as HTMLInputElement;
  file.addEventListener("change", async () => {
    const f = file.files?.[0];
    if (!f) return;
    try {
      pendingAvatar = await fileToAvatar(f);
      avBox.innerHTML = `<img src="${esc(pendingAvatar)}" alt="" class="mx-av-img" />`;
    } catch {
      /* ignore bad image */
    }
  });
  body.querySelector("#mxAvRm")?.addEventListener("click", () => {
    pendingAvatar = undefined;
    avBox.textContent = displayName().slice(0, 2).toUpperCase();
  });
  body.querySelector("#mxEditCancel")?.addEventListener("click", () => exitEdit(wrap));
  (body.querySelector("#mxEditForm") as HTMLFormElement).addEventListener("submit", (e) => {
    e.preventDefault();
    const name = (body.querySelector("#mxName") as HTMLInputElement).value.trim();
    const status = (body.querySelector("#mxStatus") as HTMLInputElement).value.trim();
    profile = { name: name || undefined, status: status || undefined, avatar: pendingAvatar };
    saveProfile();
    exitEdit(wrap);
    // Reflect in the sidebar without rebuilding the whole app.
    const meAv = document.querySelector("#meAvatar") as HTMLElement | null;
    if (meAv) meAv.innerHTML = avatarInner(profile.avatar, selfInitials());
    const meName = document.querySelector(".me-name") as HTMLElement | null;
    if (meName) meName.textContent = displayName();
    // Keep the sidebar profile-status line in sync (insert / update / remove).
    const meInfo = document.querySelector(".me-info") as HTMLElement | null;
    if (meInfo) {
      let st = meInfo.querySelector("#meStatus") as HTMLElement | null;
      if (profile.status) {
        if (!st) {
          st = document.createElement("div");
          st.id = "meStatus";
          st.className = "me-status";
          meInfo.insertBefore(st, meInfo.querySelector("#status"));
        }
        st.textContent = profile.status;
      } else if (st) {
        st.remove();
      }
    }
  });
  const focusEl = body.querySelector(focusStatus ? "#mxStatus" : "#mxName") as HTMLInputElement | null;
  focusEl?.focus();
}

// Rebuild the panel content cleanly (header reflects the new name/avatar/status) while keeping it open.
function exitEdit(wrap: HTMLElement): void {
  const wasOpen = wrap.classList.contains("open");
  wrap.innerHTML = renderProfilePanel();
  wireProfilePanel(wrap);
  if (wasOpen) {
    wrap.classList.add("open");
    wrap.setAttribute("aria-hidden", "false");
  }
}

// ---------- Create community/channel/group (swaps the panel body, same as edit) ----------
function renderCreateForm(kind: GroupKind): string {
  const opts =
    contacts
      .map(
        (c) =>
          `<label class="mx-pick"><input type="checkbox" value="${esc(c.userId)}" /><span>${esc(c.name)}</span></label>`,
      )
      .join("") || `<p class="empty">Сначала добавьте контакты через «Новый чат».</p>`;
  return `
  <form class="mx-edit-form" id="mxCreateForm">
    <div class="mx-cap">Создать: ${esc(KIND_LABEL[kind])}</div>
    <label class="mx-field"><span>Название</span>
      <input id="mxGName" maxlength="48" placeholder="${esc(KIND_LABEL[kind])}" /></label>
    <div class="mx-cap">Участники</div>
    <div class="mx-picklist">${opts}</div>
    <div class="mx-edit-actions">
      <button type="button" class="mx-btn-ghost" id="mxCCancel">Отмена</button>
      <button type="submit" class="mx-btn-primary">Создать</button>
    </div>
  </form>`;
}

function openCreateGroup(kind: GroupKind): void {
  const wrap = document.querySelector(".mx-wrap") as HTMLElement | null;
  if (!wrap) return;
  const body = wrap.querySelector(".mx-body") as HTMLElement;
  body.innerHTML = renderCreateForm(kind);
  body.querySelector("#mxCCancel")?.addEventListener("click", () => exitEdit(wrap));
  (body.querySelector("#mxCreateForm") as HTMLFormElement).addEventListener("submit", async (e) => {
    e.preventDefault();
    const name =
      (body.querySelector("#mxGName") as HTMLInputElement).value.trim() || KIND_LABEL[kind];
    const picked = Array.from(
      body.querySelectorAll<HTMLInputElement>(".mx-pick input:checked"),
    ).map((i) => i.value);
    const members = Array.from(new Set([identity!.userId, ...picked]));
    const g: Group = { id: crypto.randomUUID(), name, kind, members };
    upsertGroup(g);
    // Fan-out an invite to every member except self over their per-peer 1:1 channel.
    for (const m of members) {
      if (m === identity!.userId) continue;
      await sendApp(m, { t: "ginvite", g: g.id, name, kind, members });
    }
    closeProfile();
    renderContacts();
    selectPeer(g.id);
  });
  const focusEl = body.querySelector("#mxGName") as HTMLInputElement | null;
  focusEl?.focus();
}

// Attach listeners after the panel is in the DOM.
function wireProfilePanel(wrap: HTMLElement): void {
  wrap.querySelectorAll("[data-close]").forEach((el) =>
    el.addEventListener("click", closeProfile),
  );

  wrap.querySelector(".mx-edit")?.addEventListener("click", () => enterEdit(wrap, false));
  wrap.querySelector(".mx-status")?.addEventListener("click", () => enterEdit(wrap, true));

  wrap
    .querySelectorAll<HTMLElement>("[data-create]")
    .forEach((b) =>
      b.addEventListener("click", () => openCreateGroup(b.dataset.create as GroupKind)),
    );

  const copyBtn = wrap.querySelector("#mxCopyId") as HTMLElement | null;
  copyBtn?.addEventListener("click", async () => {
    await navigator.clipboard.writeText(identity!.userId);
    const el = copyBtn.querySelector(".mx-id__sid")!;
    const prev = el.textContent;
    el.textContent = "скопировано!";
    setTimeout(() => (el.textContent = prev), 1200);
  });

  const notif = wrap.querySelector("#mxNotif") as HTMLElement | null;
  notif?.addEventListener("click", () => {
    notif.setAttribute("aria-checked", notif.getAttribute("aria-checked") === "true" ? "false" : "true");
  });

  wrap.querySelectorAll(".mx-theme").forEach((tile) =>
    tile.addEventListener("click", () => {
      const t = (tile as HTMLElement).dataset.theme as Theme;
      applyTheme(t);
      wrap.querySelectorAll(".mx-theme").forEach((el) => {
        const active = (el as HTMLElement).dataset.theme === t;
        el.classList.toggle("is-active", active);
        el.setAttribute("aria-pressed", String(active));
        const old = el.querySelector(".mx-theme__chk");
        if (active && !old) {
          const chk = document.createElement("i");
          chk.className = "ti ti-check mx-theme__chk";
          el.appendChild(chk);
        } else if (!active && old) {
          old.remove();
        }
      });
      const railBtn = document.querySelector("#theme") as HTMLElement | null;
      if (railBtn) railBtn.title = `Тема: ${THEME_LABEL[t]}`;
    }),
  );

  wrap.querySelector("#mxLogout")?.addEventListener("click", doLogout);

  // Semi-real PQ status, mirroring the sidebar #pqbadge wiring.
  void pqStatus().then((s) => {
    const title = wrap.querySelector("#mxPqState") as HTMLElement | null;
    const sub = wrap.querySelector("#mxPqSub") as HTMLElement | null;
    const icon = wrap.querySelector("#mxPqIcon") as HTMLElement | null;
    if (!title || !sub || !icon) return;
    if (s.ok) {
      sub.textContent = `E2E · ${s.kem ?? "ML-KEM-768"} ✓`;
    } else {
      icon.className = "ti ti-shield-x mx-card__lead";
      sub.textContent = s.error ?? "self-test failed";
    }
  });
}

// (Re)build the panel as a body-level sibling of #app so renderApp() can't destroy it.
function mountProfilePanel(): void {
  document.querySelectorAll(".mx-wrap").forEach((el) => el.remove());
  const wrap = document.createElement("div");
  wrap.className = "mx-wrap";
  wrap.setAttribute("aria-hidden", "true");
  wrap.innerHTML = renderProfilePanel();
  document.body.appendChild(wrap);
  wireProfilePanel(wrap);
}

function openProfile(): void {
  const wrap = document.querySelector(".mx-wrap") as HTMLElement | null;
  if (!wrap || wrap.classList.contains("open")) return;
  mxLastFocus = document.activeElement as HTMLElement | null;
  wrap.classList.add("open");
  wrap.setAttribute("aria-hidden", "false");

  const close = wrap.querySelector(".mx-close") as HTMLElement | null;
  close?.focus();

  if (!mxEscHandler) {
    mxEscHandler = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        closeProfile();
        return;
      }
      if (e.key === "Tab") trapTab(wrap, e);
    };
    document.addEventListener("keydown", mxEscHandler);
  }
}

function closeProfile(): void {
  const wrap = document.querySelector(".mx-wrap") as HTMLElement | null;
  if (!wrap) return;
  wrap.classList.remove("open");
  wrap.setAttribute("aria-hidden", "true");
  if (mxEscHandler) {
    document.removeEventListener("keydown", mxEscHandler);
    mxEscHandler = null;
  }
  mxLastFocus?.focus();
  mxLastFocus = null;
}

// Cycle Tab focus within the panel.
function trapTab(wrap: HTMLElement, e: KeyboardEvent): void {
  const focusables = Array.from(
    wrap.querySelectorAll<HTMLElement>(
      'button:not([disabled]), [href], input, [tabindex]:not([tabindex="-1"])',
    ),
  ).filter((el) => el.offsetParent !== null);
  if (!focusables.length) return;
  const first = focusables[0];
  const last = focusables[focusables.length - 1];
  const act = document.activeElement;
  if (e.shiftKey && act === first) {
    e.preventDefault();
    last.focus();
  } else if (!e.shiftKey && act === last) {
    e.preventDefault();
    first.focus();
  }
}

function renderContacts(): void {
  const box = $("#contacts");
  if (!contacts.length && !groups.length) {
    box.innerHTML = `<p class="empty">Нет чатов. Нажмите «Новый чат» и вставьте ID собеседника.</p>`;
    return;
  }
  const groupRows = groups
    .map((g) => {
      const t = loadThread(g.id);
      const last = t.length ? t[t.length - 1] : null;
      const u = unread.get(g.id) ?? 0;
      const sub = last
        ? esc((last.mine ? "Вы: " : "") + last.text).slice(0, 32)
        : `${KIND_LABEL[g.kind]} · ${g.members.length}`;
      return `<button class="contact ${g.id === active ? "active" : ""}" data-id="${g.id}" data-group="1">
        <div class="avatar sm mx-grp-av"><i class="ti ${KIND_ICON[g.kind]}"></i></div>
        <div class="c-info">
          <div class="c-name">${esc(g.name)}</div>
          <div class="c-last">${sub}</div>
        </div>
        ${u ? `<span class="unread">${u}</span>` : ""}
      </button>`;
    })
    .join("");
  const contactRows = contacts
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
  box.innerHTML = groupRows + contactRows;
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
  const grp = findGroup(active);
  if (grp) {
    main.innerHTML = `
    <div class="chat-hd">
      <div class="avatar sm mx-grp-av"><i class="ti ${KIND_ICON[grp.kind]}"></i></div>
      <div class="chat-hd-info">
        <div class="chat-name">${esc(grp.name)}</div>
        <div class="chat-sub"><i class="ti ti-lock"></i> ${KIND_LABEL[grp.kind]} · ${grp.members.length} участн. · E2E pairwise</div>
      </div>
    </div>
    <div id="feed" class="feed"></div>
    <div class="inbar">
      <input id="msg" placeholder="Сообщение в «${esc(grp.name)}»…" autocomplete="off" />
      <button id="send" class="icon send" aria-label="Отправить"><i class="ti ti-send"></i></button>
    </div>`;
    renderFeed();
    const ginput = $("#msg") as HTMLInputElement;
    ginput.focus();
    const gsend = () => sendMessage(ginput);
    $("#send").addEventListener("click", gsend);
    ginput.addEventListener("keydown", (e) => {
      if ((e as KeyboardEvent).key === "Enter") gsend();
    });
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

function senderLabel(userId: string): string {
  const c = contacts.find((x) => x.userId === userId);
  return c ? c.name : shortId(userId);
}

function renderFeed(): void {
  const feed = document.querySelector("#feed") as HTMLElement | null;
  if (!feed || !active) return;
  const grp = findGroup(active);
  const msgs = loadThread(active);
  feed.innerHTML = msgs
    .map((m) => {
      const time = new Date(m.ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      // Groups don't carry per-message receipts, so no tick there.
      const tick = m.mine && !grp ? statusIcon(m.status) : "";
      // In a group, label each incoming bubble with the sender so 3+ way chats are clear.
      const sender =
        grp && !m.mine && m.from
          ? `<div class="bubble-sender">${esc(senderLabel(m.from))}</div>`
          : "";
      return `<div class="bubble ${m.mine ? "out" : "in"}">${sender}<span>${esc(m.text)}</span><time>${time}${tick}</time></div>`;
    })
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

  const grp = findGroup(active);
  if (grp) {
    // Fan-out the message to each member's per-peer 1:1 channel. Groups skip receipts.
    for (const m of grp.members) {
      if (m === identity.userId) continue;
      await sendApp(m, { t: "gtext", g: grp.id, text });
    }
    const gt = loadThread(grp.id);
    gt.push({ id: crypto.randomUUID(), mine: true, text, ts: Date.now() });
    saveThread(grp.id);
    renderFeed();
    renderContacts();
    return;
  }

  // 1:1 — wrap as {t:"text"} but keep the SAME envelope id so receipts still correlate.
  const payload = await encrypt(identity.userId, active, JSON.stringify({ t: "text", text }));
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
  t.push({ id: env.id, mine: true, text, ts: env.ts, status: "pending" });
  saveThread(active);
  renderFeed();
  renderContacts();
}

async function onIncoming(env: WireEnvelope): Promise<void> {
  if (!identity) return;

  // Control frames carry delivery receipts (cleartext), not chat content.
  if (env.kind === "control") {
    try {
      const ctrl = JSON.parse(new TextDecoder().decode(Uint8Array.from(env.ciphertext))) as {
        t?: string;
        id?: string;
      };
      if (ctrl.t === "receipt" && ctrl.id) markStatus(ctrl.id, "delivered");
    } catch {
      /* ignore malformed control frame */
    }
    return;
  }

  try {
    const { from, text } = await decrypt(Uint8Array.from(env.ciphertext));

    // The plaintext is JSON {t:...} for v5 clients; non-JSON or missing `t` is legacy text.
    let app: AppMsg | null = null;
    try {
      const parsed = JSON.parse(text) as { t?: unknown };
      if (parsed && typeof parsed.t === "string") app = parsed as AppMsg;
    } catch {
      /* not JSON → legacy plain text */
    }

    if (app && app.t === "ginvite") {
      upsertGroup({ id: app.g, name: app.name, kind: app.kind, members: app.members });
      renderContacts();
      // Groups don't use delivery receipts.
      return;
    }

    if (app && app.t === "gtext") {
      if (!findGroup(app.g)) {
        upsertGroup({ id: app.g, name: "Группа", kind: "group", members: [identity.userId, from] });
      }
      const gt = loadThread(app.g);
      gt.push({ id: env.id, mine: false, text: app.text, ts: env.ts || Date.now(), from });
      saveThread(app.g);
      if (app.g === active) {
        renderFeed();
      } else {
        unread.set(app.g, (unread.get(app.g) ?? 0) + 1);
      }
      renderContacts();
      return;
    }

    // 1:1 text — {t:"text"} or a legacy raw string.
    const body = app && app.t === "text" ? app.text : text;
    ensureContact(from);
    const t = loadThread(from);
    t.push({ id: env.id, mine: false, text: body, ts: env.ts || Date.now() });
    saveThread(from);
    if (from === active) {
      renderFeed();
    } else {
      unread.set(from, (unread.get(from) ?? 0) + 1);
    }
    renderContacts();
    // Acknowledge receipt back to the sender → their message shows two checks.
    sendReceipt(from, env.id);
  } catch (e) {
    console.warn("decrypt failed (key mismatch or tamper):", e);
  }
}
