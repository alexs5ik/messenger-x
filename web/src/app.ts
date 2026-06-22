// Messenger X web client — UI, local state, and wiring between the API, the WebSocket
// gateway, and the crypto module.

import {
  register,
  publishPrekeys,
  adminFetch,
  MxSocket,
  type Identity,
  type RegisterMethod,
  type WireEnvelope,
} from "./api";
import { encrypt, decrypt, provisionAccount, storedBundle, pqStatus } from "./crypto";
import { initDevice, isMobile, type DeviceClass } from "./device";

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

// Client-side editable profile, persisted in localStorage alongside the identity, keys and
// threads — so a session survives a tab/browser close and stays signed in until explicit logout.
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
  members: string[]; // userIds, including self; members[0] is the creator by convention
  creator?: string; // explicit creator userId (defaults to self on create)
}

// The STRING passed to encrypt() (and parsed after decrypt()) is JSON of this shape.
// 1:1 chat wraps as {t:"text"}; groups use ginvite/gtext. Non-JSON or missing `t` is
// treated as a legacy plain-text message for backward compatibility.
type AppMsg =
  | { t: "text"; text: string }
  | { t: "ginvite"; g: string; name: string; kind: GroupKind; members: string[]; creator?: string }
  | { t: "gtext"; g: string; text: string };

const LS = { profile: "mx.profile", groups: "mx.groups", admin: "mx.admin" };

// Bump when the shape of any stored data changes so old clients auto-reset instead of breaking.
// 7: identity/keys/threads persist in localStorage (stay signed in across closes). Ratchet sessions
//    stay in sessionStorage (see crypto.ts) so delivery self-heals each session — no bump needed
//    for that fix; the orphaned v7 localStorage session blobs are simply ignored, and the prekey
//    bundle is re-announced on startup (republishPrekeys) to recover from server state loss.
const STORAGE_VERSION = "7";

// Account data lives in localStorage so a registered session persists across tab/browser closes
// (was sessionStorage, which evaporated on close and forced a re-registration every time).
const SS = {
  identity: "mx.identity",
  contacts: "mx.contacts",
  msgs: (peer: string) => `mx.msgs.${peer}`,
};

// Wipe every account-scoped key (everything under "mx." except the cosmetic theme) — used on
// logout and on a storage-version bump. Keeping mx.theme preserves the user's chosen theme.
function clearAccount(): void {
  for (let i = localStorage.length - 1; i >= 0; i--) {
    const k = localStorage.key(i);
    if (k && k.startsWith("mx.") && k !== "mx.theme") localStorage.removeItem(k);
  }
}

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
// Upsert that UPDATES an existing group's name/members/kind/creator (unlike upsertGroup,
// which only inserts when absent). This is what lets roster re-broadcasts sync everyone.
function upsertGroupSync(g: Group): void {
  const ex = findGroup(g.id);
  if (!ex) groups.push(g);
  else {
    ex.name = g.name;
    ex.members = g.members;
    ex.kind = g.kind;
    if (g.creator) ex.creator = g.creator;
  }
  saveGroups();
}
// Admin = the explicit creator, or you for locally-held groups with no recorded creator
// (legacy groups, or ones orphaned by an identity reset). In this client-side model the
// device that holds the group manages it.
function isGroupAdmin(g: Group): boolean {
  return !g.creator || g.creator === identity!.userId || g.members[0] === identity!.userId;
}

// Adopt locally-held groups that have no creator (created before the field existed, or left
// orphaned when the identity reset on a storage-version bump): make the current account their
// owner and ensure it is a member, so management + sending work.
function migrateGroups(): void {
  let changed = false;
  for (const g of groups) {
    if (!g.creator) {
      g.creator = identity!.userId;
      changed = true;
    }
    if (!g.members.includes(identity!.userId)) {
      g.members.unshift(identity!.userId);
      changed = true;
    }
  }
  if (changed) saveGroups();
}
// Re-send the current group definition as a ginvite to a set of recipients (sync roster/name).
async function broadcastRoster(g: Group, to: string[]): Promise<void> {
  for (const m of to) {
    if (m === identity!.userId) continue;
    await sendApp(m, {
      t: "ginvite",
      g: g.id,
      name: g.name,
      kind: g.kind,
      members: g.members,
      creator: g.creator,
    });
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
    const raw = localStorage.getItem(SS.msgs(peer));
    threads.set(peer, raw ? (JSON.parse(raw) as Msg[]) : []);
  }
  return threads.get(peer)!;
}
function saveThread(peer: string): void {
  localStorage.setItem(SS.msgs(peer), JSON.stringify(threads.get(peer) ?? []));
}
function saveContacts(): void {
  localStorage.setItem(SS.contacts, JSON.stringify(contacts));
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

// ---------- Chat wallpaper ----------
// Built-in vertical wallpapers live in /public/wallpapers as wp-N.jpg (full) + wp-N-t.jpg (thumb).
// The chosen id ("" = none, "wp-N" = built-in, "custom" = user upload) is persisted per account,
// and applied to the chat feed via the --chat-wp CSS variable + data-wp on <html>.
const WALLPAPER_COUNT = 10;
const WP_KEY = "mx.wallpaper";
const WP_CUSTOM_KEY = "mx.wallpaper.custom";

function currentWallpaper(): string {
  return localStorage.getItem(WP_KEY) ?? "";
}
function wallpaperUrl(id: string): string {
  if (!id) return "";
  if (id === "custom") return localStorage.getItem(WP_CUSTOM_KEY) ?? "";
  return `/wallpapers/${id}.jpg`;
}
function applyWallpaper(id: string): void {
  const root = document.documentElement;
  const url = wallpaperUrl(id);
  if (url) {
    root.style.setProperty("--chat-wp", `url("${url}")`);
    root.dataset.wp = "on";
  } else {
    root.style.removeProperty("--chat-wp");
    root.dataset.wp = "off";
  }
  localStorage.setItem(WP_KEY, id);
}
// Downscale an uploaded image to a <=1080px-wide JPEG data URL (keeps localStorage small).
function fileToWallpaper(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const img = new Image();
    const url = URL.createObjectURL(file);
    img.onload = () => {
      URL.revokeObjectURL(url);
      const maxW = 1080;
      const scale = Math.min(1, maxW / img.width);
      const cv = document.createElement("canvas");
      cv.width = Math.round(img.width * scale);
      cv.height = Math.round(img.height * scale);
      cv.getContext("2d")!.drawImage(img, 0, 0, cv.width, cv.height);
      resolve(cv.toDataURL("image/jpeg", 0.7));
    };
    img.onerror = () => {
      URL.revokeObjectURL(url);
      reject(new Error("bad image"));
    };
    img.src = url;
  });
}

export function mount(): void {
  initDevice(onDeviceChange);
  applyTheme(currentTheme());
  // Self-heal: if stored data is from an older client (different format) or the device was
  // never provisioned with crypto secrets, wipe and start fresh so nothing silently breaks.
  const stale =
    localStorage.getItem("mx.ver") !== STORAGE_VERSION ||
    (localStorage.getItem(SS.identity) && !localStorage.getItem("mx.secrets"));
  if (stale) {
    clearAccount();
    localStorage.setItem("mx.ver", STORAGE_VERSION);
  }
  applyWallpaper(currentWallpaper());
  const rawId = localStorage.getItem(SS.identity);
  if (rawId) {
    identity = JSON.parse(rawId) as Identity;
    contacts = JSON.parse(localStorage.getItem(SS.contacts) ?? "[]") as Contact[];
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
        <div class="login-methods" role="tablist">
          <button class="login-method is-active" data-method="email"><i class="ti ti-mail"></i> Email</button>
          <button class="login-method" data-method="phone"><i class="ti ti-phone"></i> Телефон</button>
          <button class="login-method" data-method="name"><i class="ti ti-user"></i> Имя</button>
        </div>
        <input id="uname" type="email" placeholder="you@example.com" autocomplete="off" />
        <div id="otpStep" class="login-otp" hidden>
          <p class="hint" id="otpInfo"></p>
          <input id="otpCode" inputmode="numeric" maxlength="6" placeholder="6-значный код" autocomplete="off" />
        </div>
        <button id="go" class="primary"><i class="ti ti-arrow-right"></i> Продолжить</button>
        <p class="hint" id="loginhint">Откройте вторую вкладку и создайте второго пользователя, чтобы переписываться.</p>
      </div>
    </div>`;

  let method: RegisterMethod = "email";
  let demoCode: string | null = null;
  const input = $("#uname") as HTMLInputElement;
  const otpStep = $("#otpStep");
  const otpInfo = $("#otpInfo");
  const otpCode = $("#otpCode") as HTMLInputElement;
  const go = $("#go") as HTMLButtonElement;
  input.focus();

  // Method switch updates the input type/placeholder and resets the demo-OTP step.
  root()
    .querySelectorAll<HTMLElement>(".login-method")
    .forEach((btn) =>
      btn.addEventListener("click", () => {
        root().querySelectorAll(".login-method").forEach((b) => b.classList.remove("is-active"));
        btn.classList.add("is-active");
        method = btn.dataset.method as RegisterMethod;
        input.type = method === "email" ? "email" : method === "phone" ? "tel" : "text";
        input.placeholder =
          method === "email"
            ? "you@example.com"
            : method === "phone"
              ? "+7 900 000-00-00"
              : "Ваше имя";
        input.value = "";
        otpStep.hidden = true;
        demoCode = null;
        go.innerHTML = `<i class="ti ti-arrow-right"></i> Продолжить`;
        input.focus();
      }),
    );

  const doRegister = async () => {
    $("#loginhint").textContent = "Регистрация…";
    try {
      identity = await register(input.value.trim(), method);
      // Provision the device's PQXDH account and publish its pre-key bundle so peers can
      // start encrypted sessions against it.
      $("#loginhint").textContent = "Генерация ключей (PQXDH)…";
      const bundle = await provisionAccount(identity.deviceId);
      await publishPrekeys(bundle);
      localStorage.setItem(SS.identity, JSON.stringify(identity));
      localStorage.setItem("mx.ver", STORAGE_VERSION);
      startApp();
    } catch (e) {
      $("#loginhint").textContent =
        "Ошибка: запущен ли mx-server на :9990? " + (e as Error).message;
    }
  };

  const submit = async () => {
    const val = input.value.trim();
    if (!val) return;
    // Name registers directly; email/phone pass through a local DEMO 6-digit code first.
    if (method === "name") return doRegister();
    if (!demoCode) {
      demoCode = String(Math.floor(100000 + Math.random() * 900000));
      otpStep.hidden = false;
      otpInfo.innerHTML =
        `Демо-код: <b>${demoCode}</b> — обычно приходит на ${method === "email" ? "email" : "SMS"}. ` +
        `Это локальная демонстрация (реальные сообщения не отправляются).`;
      go.innerHTML = `<i class="ti ti-check"></i> Подтвердить и войти`;
      otpCode.focus();
      return;
    }
    if (otpCode.value.trim() !== demoCode) {
      $("#loginhint").textContent = "Неверный код. Попробуйте ещё раз.";
      return;
    }
    await doRegister();
  };

  go.addEventListener("click", submit);
  input.addEventListener("keydown", (e) => {
    if ((e as KeyboardEvent).key === "Enter") submit();
  });
  otpCode.addEventListener("keydown", (e) => {
    if ((e as KeyboardEvent).key === "Enter") submit();
  });
}

// ---------- App ----------
// Re-publish this device's prekey bundle (or provision one if missing) so peers can start sessions
// with us even after the server lost state. Silent on failure — the WS still works for receiving.
async function republishPrekeys(): Promise<void> {
  if (!identity) return;
  try {
    const bundle = storedBundle() ?? (await provisionAccount(identity.deviceId));
    await publishPrekeys(bundle);
  } catch {
    /* offline or server unavailable — peers will reconnect later */
  }
}

function startApp(): void {
  loadProfile();
  loadGroups();
  migrateGroups();
  setMobileView("list"); // phones start on the chat list
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

  // Returning user: re-announce our prekey bundle so a server that lost its directory (restart or
  // redeploy on an ephemeral host) can still hand it to peers who want to message us. Best-effort.
  void republishPrekeys();

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
  mountGroupAdmin();
  // Restore a docked admin panel if the active chat is a group you administer.
  if (active) {
    const g = findGroup(active);
    if (g && isGroupAdmin(g) && isGroupPinned()) openGroupAdmin(g.id);
  }
}

// ---------- Logout (shared by rail button and profile footer) ----------
function doLogout(): void {
  socket?.close();
  // Clear everything account-scoped (identity, keys, contacts, threads, profile, groups, …) so the
  // next account starts clean; the theme is intentionally preserved.
  clearAccount();
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

  // Wallpaper picker: "none" tile + built-in thumbnails + an upload tile (custom photo).
  const wp = currentWallpaper();
  const chk = `<i class="ti ti-check mx-wp__chk"></i>`;
  const noneTile = `<button class="mx-wp mx-wp--none ${wp === "" ? "is-active" : ""}" data-wp="" aria-label="Без обоев"><i class="ti ti-ban mx-wp__ic"></i>${wp === "" ? chk : ""}</button>`;
  const builtinTiles = Array.from({ length: WALLPAPER_COUNT }, (_, i) => {
    const id = `wp-${i + 1}`;
    const active = wp === id;
    return `<button class="mx-wp ${active ? "is-active" : ""}" data-wp="${id}" style="background-image:url('/wallpapers/${id}-t.jpg')" aria-label="Обои ${i + 1}">${active ? chk : ""}</button>`;
  }).join("");
  const customActive = wp === "custom";
  const customStyle = customActive ? ` style="background-image:url('${esc(wallpaperUrl("custom"))}')"` : "";
  const uploadTile = `<label class="mx-wp mx-wp--upload ${customActive ? "is-active" : ""}"${customStyle} title="Своё фото">
    <input type="file" accept="image/*" id="mxWpFile" hidden />
    ${customActive ? chk : `<i class="ti ti-photo-plus mx-wp__ic"></i>`}
  </label>`;
  const wpTiles = noneTile + builtinTiles + uploadTile;

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
          ${identity!.contact ? `<div class="mx-id__contact"><i class="ti ${identity!.method === "phone" ? "ti-phone" : "ti-mail"}"></i> ${esc(identity!.contact)}</div>` : ""}
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

      <div class="mx-cap">Обои чата</div>
      <div class="mx-wps">${wpTiles}</div>

      <div class="mx-cap">Настройки</div>
      <div class="mx-row mx-row--static"><i class="ti ti-bell mx-row__ic"></i><span class="mx-row__label">Уведомления</span><span class="mx-row__trail"><button class="mx-toggle" id="mxNotif" role="switch" aria-checked="true" aria-label="Уведомления"></button></span></div>
      <button class="mx-row" type="button"><i class="ti ti-language mx-row__ic"></i><span class="mx-row__label">Язык</span><span class="mx-row__trail"><span class="mx-row__val">Русский</span><i class="ti ti-chevron-right mx-row__chev"></i></span></button>
      <button class="mx-row" type="button"><i class="ti ti-settings mx-row__ic"></i><span class="mx-row__label">Настройки</span><span class="mx-row__trail"><i class="ti ti-chevron-right mx-row__chev"></i></span></button>
      <button class="mx-row" type="button" id="mxAdminEntry"><i class="ti ti-shield-cog mx-row__ic"></i><span class="mx-row__label">Админ-консоль</span><span class="mx-row__trail"><i class="ti ti-chevron-right mx-row__chev"></i></span></button>
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
    const g: Group = { id: crypto.randomUUID(), name, kind, members, creator: identity!.userId };
    upsertGroup(g);
    // Fan-out an invite to every member except self over their per-peer 1:1 channel.
    for (const m of members) {
      if (m === identity!.userId) continue;
      await sendApp(m, { t: "ginvite", g: g.id, name, kind, members, creator: g.creator });
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

  // Wallpaper picker: built-in tiles (incl. "none") + custom upload.
  const markWpActive = (el: Element | null) => {
    wrap.querySelectorAll(".mx-wp").forEach((t) => {
      const on = t === el;
      t.classList.toggle("is-active", on);
      const old = t.querySelector(".mx-wp__chk");
      if (on && !old) {
        const i = document.createElement("i");
        i.className = "ti ti-check mx-wp__chk";
        t.appendChild(i);
      } else if (!on && old) {
        old.remove();
      }
    });
  };
  wrap.querySelectorAll<HTMLElement>(".mx-wp[data-wp]").forEach((tile) =>
    tile.addEventListener("click", () => {
      applyWallpaper(tile.dataset.wp!);
      markWpActive(tile);
    }),
  );
  const wpFile = wrap.querySelector("#mxWpFile") as HTMLInputElement | null;
  wpFile?.addEventListener("change", async () => {
    const f = wpFile.files?.[0];
    if (!f) return;
    try {
      const data = await fileToWallpaper(f);
      localStorage.setItem(WP_CUSTOM_KEY, data);
      applyWallpaper("custom");
      const tile = wpFile.closest(".mx-wp");
      if (tile) (tile as HTMLElement).style.backgroundImage = `url("${data}")`;
      tile?.querySelector(".mx-wp__ic")?.remove();
      markWpActive(tile);
    } catch {
      /* ignore unreadable images */
    }
    wpFile.value = "";
  });

  wrap.querySelector("#mxAdminEntry")?.addEventListener("click", openAdminConsole);

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

// ---------- Super-admin console (full-screen overlay, gated by a secret key) ----------
interface AdminOverview {
  users: number;
  devices: number;
  queued_messages: number;
  maintenance: boolean;
}
interface AdminUserRow {
  user_id: string;
  username: string;
  email: string | null;
  phone: string | null;
  devices: number;
}

function getAdminToken(): string | null {
  return localStorage.getItem(LS.admin);
}

// Open the console; prompt for the secret key once and remember it locally.
async function openAdminConsole(): Promise<void> {
  let token = getAdminToken();
  if (!token) {
    token = prompt("Секретный ключ администратора:")?.trim() || null;
    if (!token) return;
    localStorage.setItem(LS.admin, token);
  }
  closeProfile();
  mountAdminOverlay();
  await refreshAdmin();
}

// Build the body-level overlay shell (rebuilt fresh on each open).
function mountAdminOverlay(): HTMLElement {
  document.querySelectorAll(".mx-admin").forEach((el) => el.remove());
  const ov = document.createElement("div");
  ov.className = "mx-admin";
  ov.innerHTML = `
    <header class="mx-admin__hd">
      <i class="ti ti-shield-cog mx-admin__lead"></i>
      <div class="mx-admin__ttl">
        <div class="mx-admin__title">Админ-консоль</div>
        <div class="mx-admin__sub">Полный доступ · защищено секретным ключом</div>
      </div>
      <button class="mx-close" id="adClose" aria-label="Закрыть"><i class="ti ti-x"></i></button>
    </header>
    <div class="mx-admin__stats" id="adStats"></div>
    <div class="mx-admin__sec">
      <div class="mx-cap">Режим обслуживания</div>
      <div class="mx-row mx-row--static"><i class="ti ti-tools mx-row__ic"></i><span class="mx-row__label">Заморозить отправку сообщений</span><span class="mx-row__trail"><button class="mx-toggle" id="adMaint" role="switch" aria-checked="false" aria-label="Режим обслуживания"></button></span></div>
    </div>
    <div class="mx-admin__sec">
      <div class="mx-cap">Объявление всем пользователям</div>
      <textarea class="mx-bcast" id="adBcast" placeholder="Текст объявления — придёт всем устройствам как системное сообщение…"></textarea>
      <div class="mx-admin__bcast-actions">
        <button class="mx-btn-primary" id="adSend"><i class="ti ti-speakerphone"></i> Отправить всем</button>
      </div>
    </div>
    <div class="mx-admin__sec">
      <div class="mx-cap">Пользователи</div>
      <div class="mx-admin__tablewrap">
        <table>
          <thead><tr><th>Имя</th><th>Email</th><th>Телефон</th><th>Устройства</th><th></th></tr></thead>
          <tbody id="adUsers"></tbody>
        </table>
      </div>
    </div>
    <p class="mx-admin__err" id="adErr" hidden></p>`;
  document.body.appendChild(ov);
  ov.querySelector("#adClose")?.addEventListener("click", closeAdminConsole);
  ov.querySelector("#adSend")?.addEventListener("click", adminBroadcast);
  ov.querySelector("#adMaint")?.addEventListener("click", adminToggleMaintenance);
  if (!mxAdminEscHandler) {
    mxAdminEscHandler = (e: KeyboardEvent) => {
      if (e.key === "Escape") closeAdminConsole();
    };
    document.addEventListener("keydown", mxAdminEscHandler);
  }
  return ov;
}

let mxAdminEscHandler: ((e: KeyboardEvent) => void) | null = null;

function closeAdminConsole(): void {
  document.querySelectorAll(".mx-admin").forEach((el) => el.remove());
  if (mxAdminEscHandler) {
    document.removeEventListener("keydown", mxAdminEscHandler);
    mxAdminEscHandler = null;
  }
}

function adminError(msg: string): void {
  const el = document.querySelector("#adErr") as HTMLElement | null;
  if (!el) return;
  el.textContent = msg;
  el.hidden = false;
}

// Fetch overview + users and paint them. 401 wipes the stored key and asks for re-entry.
async function refreshAdmin(): Promise<void> {
  const token = getAdminToken();
  if (!token) return;
  try {
    const ov = await adminFetch<AdminOverview>("/v1/admin/overview", token);
    const us = await adminFetch<AdminUserRow[]>("/v1/admin/users", token);
    renderAdminData(ov, us);
  } catch (e) {
    if ((e as Error).message === "unauthorized") {
      localStorage.removeItem(LS.admin);
      adminError("Неверный ключ. Доступ запрещён. Откройте консоль снова, чтобы ввести ключ.");
    } else {
      adminError("Ошибка: " + (e as Error).message);
    }
  }
}

function renderAdminData(ov: AdminOverview, users: AdminUserRow[]): void {
  const stats = document.querySelector("#adStats") as HTMLElement | null;
  if (stats) {
    stats.innerHTML = `
      <div class="mx-stat"><div class="mx-stat__num">${ov.users}</div><div class="mx-stat__lbl">Пользователи</div></div>
      <div class="mx-stat"><div class="mx-stat__num">${ov.devices}</div><div class="mx-stat__lbl">Устройства</div></div>
      <div class="mx-stat"><div class="mx-stat__num">${ov.queued_messages}</div><div class="mx-stat__lbl">В очереди</div></div>
      <div class="mx-stat"><div class="mx-stat__num">${ov.maintenance ? "Вкл" : "Выкл"}</div><div class="mx-stat__lbl">Обслуживание</div></div>`;
  }
  const maint = document.querySelector("#adMaint") as HTMLElement | null;
  if (maint) maint.setAttribute("aria-checked", String(ov.maintenance));

  const tbody = document.querySelector("#adUsers") as HTMLElement | null;
  if (tbody) {
    tbody.innerHTML = users.length
      ? users
          .map(
            (u) => `<tr>
              <td>${esc(u.username)}</td>
              <td>${u.email ? esc(u.email) : "—"}</td>
              <td>${u.phone ? esc(u.phone) : "—"}</td>
              <td>${u.devices}</td>
              <td><button class="mx-admin__del" data-del="${esc(u.user_id)}" title="Удалить" aria-label="Удалить пользователя"><i class="ti ti-trash"></i></button></td>
            </tr>`,
          )
          .join("")
      : `<tr><td colspan="5" class="mx-admin__empty">Нет пользователей.</td></tr>`;
    tbody.querySelectorAll<HTMLElement>("[data-del]").forEach((btn) =>
      btn.addEventListener("click", () => adminDeleteUser(btn.dataset.del!)),
    );
  }
  const err = document.querySelector("#adErr") as HTMLElement | null;
  if (err) err.hidden = true;
}

async function adminBroadcast(): Promise<void> {
  const token = getAdminToken();
  if (!token) return;
  const ta = document.querySelector("#adBcast") as HTMLTextAreaElement | null;
  const text = ta?.value.trim();
  if (!text) return;
  try {
    const r = await adminFetch<{ sent: number }>("/v1/admin/broadcast", token, {
      method: "POST",
      body: JSON.stringify({ text }),
    });
    if (ta) ta.value = "";
    showAnnounce(`Объявление отправлено · доставок: ${r.sent}`);
    await refreshAdmin();
  } catch (e) {
    adminError("Не удалось отправить: " + (e as Error).message);
  }
}

async function adminDeleteUser(id: string): Promise<void> {
  const token = getAdminToken();
  if (!token) return;
  if (!confirm("Удалить этого пользователя со всеми устройствами и сообщениями?")) return;
  try {
    await adminFetch("/v1/admin/users/" + id + "/delete", token, { method: "POST" });
    await refreshAdmin();
  } catch (e) {
    adminError("Не удалось удалить: " + (e as Error).message);
  }
}

async function adminToggleMaintenance(): Promise<void> {
  const token = getAdminToken();
  if (!token) return;
  const btn = document.querySelector("#adMaint") as HTMLElement | null;
  const current = btn?.getAttribute("aria-checked") === "true";
  try {
    const ov = await adminFetch<AdminOverview>("/v1/admin/maintenance", token, {
      method: "POST",
      body: JSON.stringify({ on: !current }),
    });
    // Re-render stats + toggle from the fresh overview (users list unchanged).
    const us = await adminFetch<AdminUserRow[]>("/v1/admin/users", token);
    renderAdminData(ov, us);
  } catch (e) {
    adminError("Не удалось переключить режим: " + (e as Error).message);
  }
}

// ---------- System announcement banner (operator → user, one-way) ----------
function showAnnounce(text: string): void {
  const el = document.createElement("div");
  el.className = "mx-announce";
  el.innerHTML = `
    <i class="ti ti-speakerphone mx-announce__ic"></i>
    <div class="mx-announce__txt">${esc(text)}</div>
    <button class="mx-announce__close" aria-label="Закрыть"><i class="ti ti-x"></i></button>`;
  document.body.appendChild(el);
  const dismiss = () => el.remove();
  el.querySelector(".mx-announce__close")?.addEventListener("click", dismiss);
  setTimeout(dismiss, 8000);
}

// ---------- Group / channel / community admin panel (left-slide, dockable) ----------
const LS_GPIN = "mx.gpin";
let mxGEscHandler: ((e: KeyboardEvent) => void) | null = null;

function isGroupPinned(): boolean {
  return localStorage.getItem(LS_GPIN) === "1";
}
function setGroupPinned(on: boolean): void {
  localStorage.setItem(LS_GPIN, on ? "1" : "0");
}

// Shift the main app column right to make room for the docked panel (CSS does the rest).
function applyGroupPinLayout(on: boolean): void {
  document.querySelector(".app")?.classList.toggle("app--gpinned", on);
}

// (Re)build the panel as a body-level sibling so renderApp()/renderMain() can't destroy it.
function mountGroupAdmin(): HTMLElement {
  document.querySelectorAll(".mx-gwrap").forEach((el) => el.remove());
  const wrap = document.createElement("div");
  wrap.className = "mx-gwrap";
  wrap.setAttribute("aria-hidden", "true");
  document.body.appendChild(wrap);
  return wrap;
}

function renderGroupAdmin(g: Group): string {
  const creator = g.creator ?? g.members[0];
  const memberRows = g.members
    .map((uid) => {
      const isCreator = uid === creator;
      const isSelf = uid === identity!.userId;
      const name = isSelf ? `${esc(displayName())} (вы)` : esc(senderLabel(uid));
      const rm =
        isCreator || isSelf
          ? ""
          : `<button class="mx-grow__rm icon" data-rm="${esc(uid)}" title="Удалить" aria-label="Удалить участника"><i class="ti ti-user-minus"></i></button>`;
      return `<div class="mx-grow">
        <div class="avatar sm">${esc((isSelf ? displayName() : senderLabel(uid)).slice(0, 2).toUpperCase())}</div>
        <span class="mx-grow__name">${name}</span>
        ${isCreator ? `<span class="mx-gadmin-badge">админ</span>` : ""}
        ${rm}
      </div>`;
    })
    .join("");

  // Contacts not yet members — candidates to add.
  const addable = contacts.filter((c) => !g.members.includes(c.userId));
  const addList = addable.length
    ? addable
        .map(
          (c) =>
            `<label class="mx-pick"><input type="checkbox" value="${esc(c.userId)}" /><span>${esc(c.name)}</span></label>`,
        )
        .join("")
    : `<p class="empty">Все контакты уже в составе.</p>`;

  const pinned = isGroupPinned();
  return `
  <div class="mx-gbackdrop" data-gclose></div>
  <aside class="mx-gpanel" role="dialog" aria-modal="${pinned ? "false" : "true"}" aria-label="Управление группой">
    <header class="mx-ghead">
      <div class="mx-ghead__bar">
        <i class="ti ${KIND_ICON[g.kind]} mx-ghead__ic"></i>
        <div class="mx-ghead__txt">
          <div class="mx-ghead__title">Управление</div>
          <div class="mx-ghead__sub">${esc(KIND_LABEL[g.kind])}</div>
        </div>
        <button class="mx-gpin" id="gPin" title="${pinned ? "Открепить" : "Зафиксировать"}" aria-pressed="${pinned}"><i class="ti ${pinned ? "ti-pinned" : "ti-pin"}"></i></button>
        <button class="mx-close" data-gclose aria-label="Закрыть"><i class="ti ti-x"></i></button>
      </div>
    </header>

    <div class="mx-gbody">
      <div class="mx-cap">Название</div>
      <div class="mx-edit-form" style="padding-top:0;">
        <div class="mx-gname-row">
          <input id="gName" class="mx-gname-input" maxlength="48" value="${esc(g.name)}" placeholder="${esc(KIND_LABEL[g.kind])}" />
          <button class="mx-btn-primary mx-gname-save" id="gNameSave" type="button"><i class="ti ti-check"></i></button>
        </div>
      </div>

      <div class="mx-cap">Участники · ${g.members.length}</div>
      <div class="mx-gmembers">${memberRows}</div>

      <div class="mx-cap">Добавить участника</div>
      <div class="mx-picklist">${addList}</div>
      ${addable.length ? `<div class="mx-gadd-actions"><button class="mx-btn-primary" id="gAdd" type="button"><i class="ti ti-user-plus"></i> Добавить выбранных</button></div>` : ""}

      <div class="mx-cap">Приглашение</div>
      <button class="mx-row" type="button" id="gCopy"><i class="ti ti-link mx-row__ic"></i><span class="mx-row__label">Скопировать ID (приглашение)</span><span class="mx-row__trail"><i class="ti ti-copy mx-row__chev"></i></span></button>

      <div class="mx-cap">Опасная зона</div>
      <button class="mx-row" type="button" id="gLeave"><i class="ti ti-door-exit mx-row__ic"></i><span class="mx-row__label">Покинуть ${esc(KIND_LABEL[g.kind].toLowerCase())}</span><span class="mx-row__trail"><i class="ti ti-chevron-right mx-row__chev"></i></span></button>
      <button class="mx-row mx-grow--danger" type="button" id="gDelete"><i class="ti ti-trash mx-row__ic"></i><span class="mx-row__label">Удалить ${esc(KIND_LABEL[g.kind].toLowerCase())}</span><span class="mx-row__trail"><i class="ti ti-chevron-right mx-row__chev"></i></span></button>
    </div>
  </aside>`;
}

// Re-render the panel body in place after a mutation (fresh group state, keep it open).
function refreshGroupAdmin(wrap: HTMLElement, groupId: string): void {
  const g = findGroup(groupId);
  if (!g || !isGroupAdmin(g)) {
    closeGroupAdmin();
    return;
  }
  const open = wrap.classList.contains("open");
  const pinned = wrap.classList.contains("pinned");
  wrap.innerHTML = renderGroupAdmin(g);
  wireGroupAdmin(wrap, groupId);
  if (open) {
    wrap.classList.add("open");
    wrap.setAttribute("aria-hidden", "false");
  }
  if (pinned) wrap.classList.add("pinned");
}

function wireGroupAdmin(wrap: HTMLElement, groupId: string): void {
  wrap.querySelectorAll("[data-gclose]").forEach((el) =>
    el.addEventListener("click", () => {
      // Backdrop click only closes when not pinned; the explicit X always closes.
      if ((el as HTMLElement).classList.contains("mx-gbackdrop") && isGroupPinned()) return;
      closeGroupAdmin();
    }),
  );

  // Pin / unpin (dock the panel beside the chat).
  wrap.querySelector("#gPin")?.addEventListener("click", () => {
    const now = !isGroupPinned();
    setGroupPinned(now);
    wrap.classList.toggle("pinned", now);
    applyGroupPinLayout(now);
    refreshGroupAdmin(wrap, groupId);
  });

  // Edit name → save locally + re-broadcast roster so everyone syncs.
  wrap.querySelector("#gNameSave")?.addEventListener("click", async () => {
    const g = findGroup(groupId);
    if (!g) return;
    const next = (wrap.querySelector("#gName") as HTMLInputElement).value.trim();
    if (!next || next === g.name) return;
    g.name = next;
    saveGroups();
    renderContacts();
    renderMain();
    await broadcastRoster(g, g.members);
    refreshGroupAdmin(wrap, groupId);
  });

  // Remove a member → splice locally + re-broadcast to the remaining roster.
  wrap.querySelectorAll<HTMLElement>("[data-rm]").forEach((btn) =>
    btn.addEventListener("click", async () => {
      const g = findGroup(groupId);
      if (!g) return;
      const uid = btn.dataset.rm!;
      g.members = g.members.filter((m) => m !== uid);
      saveGroups();
      renderContacts();
      renderMain();
      await broadcastRoster(g, g.members);
      refreshGroupAdmin(wrap, groupId);
    }),
  );

  // Add selected contacts → send a fresh ginvite to each new member AND sync existing ones.
  wrap.querySelector("#gAdd")?.addEventListener("click", async () => {
    const g = findGroup(groupId);
    if (!g) return;
    const picked = Array.from(
      wrap.querySelectorAll<HTMLInputElement>(".mx-picklist input:checked"),
    ).map((i) => i.value);
    if (!picked.length) return;
    const existing = g.members.slice();
    g.members = Array.from(new Set([...g.members, ...picked]));
    saveGroups();
    renderContacts();
    renderMain();
    // New members get the invite; existing members get the updated roster.
    await broadcastRoster(g, picked);
    await broadcastRoster(g, existing);
    refreshGroupAdmin(wrap, groupId);
  });

  // Copy group id as an invite.
  wrap.querySelector("#gCopy")?.addEventListener("click", async () => {
    await navigator.clipboard.writeText(groupId);
    const label = wrap.querySelector("#gCopy .mx-row__label");
    if (label) {
      const prev = label.textContent;
      label.textContent = "Скопировано!";
      setTimeout(() => (label.textContent = prev), 1200);
    }
  });

  // Leave → remove self, sync the rest, then tear the group down locally.
  wrap.querySelector("#gLeave")?.addEventListener("click", async () => {
    const g = findGroup(groupId);
    if (!g) return;
    if (!confirm(`Покинуть «${g.name}»?`)) return;
    const rest = g.members.filter((m) => m !== identity!.userId);
    g.members = rest;
    await broadcastRoster(g, rest);
    teardownGroup(groupId);
  });

  // Delete (local only — no server-side group state).
  wrap.querySelector("#gDelete")?.addEventListener("click", () => {
    const g = findGroup(groupId);
    if (!g) return;
    if (!confirm(`Удалить «${g.name}»? Это действие удалит ${KIND_LABEL[g.kind].toLowerCase()} только у вас.`))
      return;
    teardownGroup(groupId);
  });
}

// Remove a group locally and close the panel/chat.
function teardownGroup(groupId: string): void {
  groups = groups.filter((g) => g.id !== groupId);
  saveGroups();
  if (active === groupId) active = null;
  closeGroupAdmin(true);
  renderContacts();
  renderMain();
}

function openGroupAdmin(groupId: string): void {
  const g = findGroup(groupId);
  if (!g || !isGroupAdmin(g)) return; // never for 1:1 or non-admins
  const wrap = (document.querySelector(".mx-gwrap") as HTMLElement) ?? mountGroupAdmin();
  wrap.innerHTML = renderGroupAdmin(g);
  wireGroupAdmin(wrap, groupId);
  wrap.classList.add("open");
  wrap.setAttribute("aria-hidden", "false");
  if (isGroupPinned()) {
    wrap.classList.add("pinned");
    applyGroupPinLayout(true);
  }
  if (!mxGEscHandler) {
    mxGEscHandler = (e: KeyboardEvent) => {
      if (e.key === "Escape") closeGroupAdmin();
    };
    document.addEventListener("keydown", mxGEscHandler);
  }
}

// Hide the panel. Keeps the pinned flag (reopening restores the docked state) unless
// `clearPin` is set (used when the group is deleted/left).
function closeGroupAdmin(clearPin = false): void {
  const wrap = document.querySelector(".mx-gwrap") as HTMLElement | null;
  if (wrap) {
    wrap.classList.remove("open");
    wrap.setAttribute("aria-hidden", "true");
    if (clearPin) wrap.classList.remove("pinned");
  }
  if (clearPin) {
    setGroupPinned(false);
    applyGroupPinLayout(false);
  }
  if (mxGEscHandler) {
    document.removeEventListener("keydown", mxGEscHandler);
    mxGEscHandler = null;
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
    const admin = isGroupAdmin(grp);
    main.innerHTML = `
    <div class="chat-hd">
      <button class="icon mx-back" aria-label="Назад"><i class="ti ti-arrow-left"></i></button>
      <div class="avatar sm mx-grp-av${admin ? " mx-hd-open" : ""}"${admin ? ' role="button" tabindex="0" aria-label="Управление" title="Управление"' : ""}><i class="ti ${KIND_ICON[grp.kind]}"></i></div>
      <div class="chat-hd-info${admin ? " mx-hd-open" : ""}"${admin ? ' role="button" tabindex="0" aria-label="Управление" title="Открыть управление"' : ""}>
        <div class="chat-name">${esc(grp.name)}</div>
        <div class="chat-sub"><i class="ti ti-lock"></i> ${KIND_LABEL[grp.kind]} · ${grp.members.length} участн. · E2E pairwise</div>
      </div>
      ${admin ? `<button id="grpManage" class="icon" title="Управление" aria-label="Управление группой"><i class="ti ti-settings"></i></button>` : ""}
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
    main.querySelector(".mx-back")?.addEventListener("click", goBack);
    $("#grpManage")?.addEventListener("click", () => openGroupAdmin(grp.id));
    // Clicking the group icon or title in the header also opens the management panel.
    if (admin) {
      const openMgmt = () => openGroupAdmin(grp.id);
      main.querySelectorAll(".chat-hd .mx-hd-open").forEach((el) => {
        el.addEventListener("click", openMgmt);
        el.addEventListener("keydown", (e) => {
          const k = (e as KeyboardEvent).key;
          if (k === "Enter" || k === " ") {
            e.preventDefault();
            openMgmt();
          }
        });
      });
    }
    // If the panel is docked, keep the layout shifted after a re-render.
    if (isGroupPinned() && isGroupAdmin(grp)) applyGroupPinLayout(true);
    return;
  }
  const contact = contacts.find((c) => c.userId === active)!;
  main.innerHTML = `
    <div class="chat-hd">
      <button class="icon mx-back" aria-label="Назад"><i class="ti ti-arrow-left"></i></button>
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
  main.querySelector(".mx-back")?.addEventListener("click", goBack);
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

// On phones the list and the chat are separate full-screen views; this flag drives which one
// is shown (CSS slides the chat over the list). No effect on desktop (both panes visible).
function setMobileView(v: "list" | "chat"): void {
  document.documentElement.dataset.view = v;
}
// When the viewport crosses between mobile and desktop (resize, rotate, devtools), reset the
// single-pane mobile view so the desktop two-pane layout isn't left stuck on the chat screen.
function onDeviceChange(_d: DeviceClass): void {
  if (!isMobile()) setMobileView("list");
}
// Mobile "back": return from an open chat to the chat list.
function goBack(): void {
  setMobileView("list");
}

function selectPeer(id: string): void {
  active = id;
  unread.delete(id);
  renderContacts();
  renderMain();
  setMobileView("chat"); // on phones, slide into the chat view

  // Keep the group admin panel in sync with the active chat.
  const g = findGroup(id);
  if (g && isGroupAdmin(g) && isGroupPinned()) {
    openGroupAdmin(g.id); // re-dock for the newly selected administered group
  } else {
    // Switched to a 1:1 (or a group you don't admin): hide the panel + un-shift layout.
    closeGroupAdmin();
    applyGroupPinLayout(false);
  }
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

  // Control frames carry cleartext signals (delivery receipts, operator announcements),
  // not chat content.
  if (env.kind === "control") {
    try {
      const ctrl = JSON.parse(new TextDecoder().decode(Uint8Array.from(env.ciphertext))) as {
        t?: string;
        id?: string;
        text?: string;
      };
      if (ctrl.t === "receipt" && ctrl.id) markStatus(ctrl.id, "delivered");
      else if (ctrl.t === "announce" && ctrl.text) showAnnounce(ctrl.text);
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
      // Sync the full group definition (name/roster/creator) so re-broadcasts propagate edits.
      upsertGroupSync({
        id: app.g,
        name: app.name,
        kind: app.kind,
        members: app.members,
        creator: app.creator,
      });
      if (app.g === active) renderMain(); // reflect roster/name changes if this chat is open
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
