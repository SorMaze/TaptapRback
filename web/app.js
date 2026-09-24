"use strict";

const $ = (id) => document.getElementById(id);
const ui = {
  cn: $("region-cn"),
  global: $("region-global"),
  regionBlock: $("region-block"),
  note: $("region-note"),
  login: $("login-panel"),
  success: $("success-panel"),
  image: $("qr-image"),
  loading: $("qr-loading"),
  expired: $("qr-expired"),
  state: $("qr-state"),
  countdown: $("countdown"),
  status: $("status-text"),
  refresh: $("refresh-button"),
  open: $("open-link"),
  mobileOpen: $("mobile-open"),
  name: $("user-name"),
  avatar: $("user-avatar"),
  region: $("user-region"),
  id: $("user-id"),
  logout: $("logout-button"),
};

const PENDING_KEY = "taptap_pending_flow";

const isMobile = (() => {
  const ua = navigator.userAgent || "";
  if (/Android|iPhone|iPad|iPod|HarmonyOS|Mobile/i.test(ua)) return true;
  return window.matchMedia?.("(pointer: coarse)").matches ?? false;
})();
if (isMobile) document.body.classList.add("mobile");

let region = "cn";
let webLogin = false;
let generation = 0;
let pollTimer = null;
let countdownTimer = null;
let expiresAt = 0;
let activePoll = null;

function stopTimers() {
  clearTimeout(pollTimer);
  clearInterval(countdownTimer);
  pollTimer = null;
  countdownTimer = null;
  activePoll = null;
}

function savePending(pending) {
  sessionStorage.setItem(PENDING_KEY, JSON.stringify(pending));
}

function loadPending() {
  try {
    const pending = JSON.parse(sessionStorage.getItem(PENDING_KEY) || "null");
    if (
      !pending ||
      typeof pending.flow_id !== "string" ||
      !(pending.expires_at > Date.now())
    ) {
      clearPending();
      return null;
    }
    return pending;
  } catch {
    clearPending();
    return null;
  }
}

function clearPending() {
  sessionStorage.removeItem(PENDING_KEY);
}

function setStatus(message, state = "等待扫码") {
  ui.status.textContent = message;
  ui.state.lastChild.textContent = state;
}

function resetQr() {
  ui.image.hidden = true;
  ui.image.removeAttribute("src");
  ui.expired.hidden = true;
  ui.loading.hidden = false;
  ui.refresh.hidden = true;
  ui.open.hidden = true;
  ui.mobileOpen.hidden = true;
  ui.mobileOpen.removeAttribute("href");
  ui.countdown.textContent = "--:--";
}

function showFailure(message, expired = false) {
  stopTimers();
  clearPending();
  ui.loading.hidden = true;
  ui.image.hidden = true;
  ui.expired.hidden = !expired;
  ui.refresh.hidden = false;
  ui.open.hidden = true;
  ui.mobileOpen.hidden = true;
  setStatus(message, expired ? "二维码过期" : "连接失败");
}

function renderCountdown() {
  const left = Math.max(0, Math.ceil((expiresAt - Date.now()) / 1000));
  ui.countdown.textContent = `${String(Math.floor(left / 60)).padStart(2, "0")}:${String(left % 60).padStart(2, "0")}`;
  if (left === 0) showFailure("授权已过期，请重新发起。", true);
}

async function request(path, options = {}) {
  const response = await fetch(path, {
    cache: "no-store",
    ...options,
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
  });
  const data = await response.json();
  return { response, data };
}

function schedulePoll(flowId, current, delay) {
  activePoll = { flowId, current };
  pollTimer = setTimeout(() => poll(flowId, current), delay);
}

async function startLogin() {
  const current = ++generation;
  stopTimers();
  clearPending();
  ui.login.hidden = false;
  ui.success.hidden = true;
  ui.regionBlock.hidden = false;
  resetQr();
  setStatus("正在连接 TapTap 授权服务…", "连接中");
  try {
    if (isMobile && webLogin) {
      const { response, data } = await request("/auth/taptap/web", {
        method: "POST",
        body: JSON.stringify({ region }),
      });
      if (current !== generation) return;
      if (!response.ok) throw new Error(data.error || "无法发起授权");
      const authUrl = new URL(data.authorize_url);
      if (authUrl.protocol !== "https:") throw new Error("授权地址无效");
      setStatus("正在跳转到 TapTap 授权…", "跳转中");
      window.location.assign(authUrl.href);
      return;
    }
    const { response, data } = await request("/auth/taptap/device", {
      method: "POST",
      body: JSON.stringify({ region }),
    });
    if (current !== generation) return;
    if (!response.ok) throw new Error(data.error || "无法生成二维码");
    const authUrl = new URL(data.qrcode_url);
    if (authUrl.protocol !== "https:") throw new Error("授权地址无效");
    expiresAt = Date.now() + data.expires_in * 1000;
    renderCountdown();
    countdownTimer = setInterval(renderCountdown, 1000);
    if (isMobile) {
      ui.loading.hidden = true;
      ui.mobileOpen.href = authUrl.href;
      ui.mobileOpen.hidden = false;
      savePending({
        flow_id: data.flow_id,
        qrcode_url: authUrl.href,
        expires_at: expiresAt,
        region,
      });
      setStatus("点按按钮跳转 TapTap 完成授权，之后返回本页面。", "等待授权");
    } else {
      if (!data.qr_image?.startsWith("data:image/svg+xml;base64,"))
        throw new Error("二维码数据无效");
      ui.image.src = data.qr_image;
      ui.image.hidden = false;
      ui.loading.hidden = true;
      ui.open.href = authUrl.href;
      ui.open.hidden = false;
      setStatus("打开 TapTap 客户端扫描二维码并确认授权。", "等待扫码");
    }
    schedulePoll(data.flow_id, current, Math.max(1, data.interval) * 1000);
  } catch (error) {
    if (current === generation) showFailure(`连接失败：${error.message}`);
  }
}

function resumePending(pending) {
  const current = ++generation;
  stopTimers();
  ui.login.hidden = false;
  ui.success.hidden = true;
  ui.regionBlock.hidden = false;
  resetQr();
  ui.loading.hidden = true;
  if (pending.qrcode_url) {
    ui.mobileOpen.href = pending.qrcode_url;
    ui.mobileOpen.hidden = false;
  }
  expiresAt = pending.expires_at;
  renderCountdown();
  countdownTimer = setInterval(renderCountdown, 1000);
  setStatus("正在等待 TapTap 授权完成…", "等待授权");
  activePoll = { flowId: pending.flow_id, current };
  poll(pending.flow_id, current);
}

async function poll(flowId, current) {
  if (current !== generation) return;
  try {
    const { response, data } = await request(
      `/auth/taptap/device/${encodeURIComponent(flowId)}/poll`,
      { method: "POST" },
    );
    if (current !== generation) return;
    if (response.status === 202 && data.status === "pending") {
      setStatus("等待 TapTap 客户端确认授权…", isMobile ? "等待授权" : "等待扫码");
      schedulePoll(flowId, current, Math.max(1, data.retry_after) * 1000);
      return;
    }
    if (response.ok && data.status === "complete") {
      stopTimers();
      clearPending();
      await finishLogin(data.login);
      return;
    }
    if (response.status === 410)
      return showFailure("授权已过期，请重新发起。", true);
    if (data.error === "access_denied")
      return showFailure("授权已取消，请重新发起。");
    throw new Error(data.error || "授权校验失败");
  } catch (error) {
    if (current === generation) showFailure(`登录失败：${error.message}`);
  }
}

document.addEventListener("visibilitychange", () => {
  if (document.visibilityState !== "visible" || !activePoll || !pollTimer)
    return;
  clearTimeout(pollTimer);
  pollTimer = null;
  poll(activePoll.flowId, activePoll.current);
});

async function finishLogin(login) {
  const { response, data } = await request("/auth/me", {
    headers: { Authorization: `Bearer ${login.session_token}` },
  });
  if (
    !response.ok ||
    data.sub !== login.user.openid ||
    data.region !== login.region
  ) {
    throw new Error("游戏会话校验失败");
  }
  sessionStorage.setItem("taptap_game_session", login.session_token);
  sessionStorage.setItem(
    "taptap_game_profile",
    JSON.stringify({
      sub: data.sub,
      region: data.region,
      name: login.user.name || "TapTap 玩家",
      avatar: login.user.avatar || null,
    }),
  );
  ui.name.textContent = login.user.name || "TapTap 玩家";
  ui.region.textContent = login.region === "cn" ? "国内版" : "国际版";
  ui.id.textContent = data.sub;
  if (login.user.avatar?.startsWith("https://")) {
    ui.avatar.src = login.user.avatar;
    ui.avatar.hidden = false;
  } else {
    ui.avatar.hidden = true;
  }
  ui.login.hidden = true;
  ui.regionBlock.hidden = true;
  ui.success.hidden = false;
}

async function restoreSession() {
  const token = sessionStorage.getItem("taptap_game_session");
  if (!token) return false;
  try {
    const { response, data } = await request("/auth/me", {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!response.ok) throw new Error("expired");
    const cached = JSON.parse(
      sessionStorage.getItem("taptap_game_profile") || "null",
    );
    const display =
      cached?.sub === data.sub && cached?.region === data.region
        ? cached
        : null;
    ui.name.textContent = display?.name || "TapTap 玩家";
    ui.region.textContent = data.region === "cn" ? "国内版" : "国际版";
    ui.id.textContent = data.sub;
    if (display?.avatar?.startsWith("https://")) {
      ui.avatar.src = display.avatar;
      ui.avatar.hidden = false;
    } else {
      ui.avatar.hidden = true;
    }
    ui.login.hidden = true;
    ui.regionBlock.hidden = true;
    ui.success.hidden = false;
    return true;
  } catch {
    sessionStorage.removeItem("taptap_game_session");
    sessionStorage.removeItem("taptap_game_profile");
    return false;
  }
}

function applyRegion(next) {
  region = next;
  ui.cn.classList.toggle("active", next === "cn");
  ui.global.classList.toggle("active", next === "global");
  ui.cn.setAttribute("aria-pressed", String(next === "cn"));
  ui.global.setAttribute("aria-pressed", String(next === "global"));
  const label = next === "cn" ? "国内版" : "国际版";
  ui.note.textContent = isMobile
    ? `使用${label} TapTap 账号授权`
    : `使用${label} TapTap 客户端扫描`;
}

function chooseRegion(next) {
  if (
    region === next ||
    (next === "global" && ui.global.disabled) ||
    (next === "cn" && ui.cn.disabled)
  )
    return;
  applyRegion(next);
  startLogin();
}

ui.cn.addEventListener("click", () => chooseRegion("cn"));
ui.global.addEventListener("click", () => chooseRegion("global"));
ui.refresh.addEventListener("click", startLogin);
ui.logout.addEventListener("click", () => {
  sessionStorage.removeItem("taptap_game_session");
  sessionStorage.removeItem("taptap_game_profile");
  startLogin();
});
ui.avatar.addEventListener("error", () => {
  ui.avatar.hidden = true;
  ui.avatar.removeAttribute("src");
});

(async () => {
  try {
    const { response, data } = await request("/auth/config");
    if (!response.ok) throw new Error("服务配置不可用");
    ui.cn.disabled = !data.cn;
    ui.global.disabled = !data.global;
    if (!data.cn && !data.global) throw new Error("未配置 TapTap 应用");
    webLogin = Boolean(data.web);
    if (!data.cn && data.global) applyRegion("global");
    else applyRegion("cn");
    if (await restoreSession()) return;
    const pending = isMobile && !webLogin ? loadPending() : null;
    if (pending) {
      if (pending.region === "cn" || pending.region === "global")
        applyRegion(pending.region);
      resumePending(pending);
      return;
    }
    startLogin();
  } catch (error) {
    showFailure(`无法启动登录：${error.message}`);
  }
})();
