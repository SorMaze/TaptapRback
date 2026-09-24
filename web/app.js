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
  name: $("user-name"),
  avatar: $("user-avatar"),
  region: $("user-region"),
  id: $("user-id"),
  logout: $("logout-button"),
};

let region = "cn";
let generation = 0;
let pollTimer = null;
let countdownTimer = null;
let expiresAt = 0;

function stopTimers() {
  clearTimeout(pollTimer);
  clearInterval(countdownTimer);
  pollTimer = null;
  countdownTimer = null;
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
  ui.countdown.textContent = "--:--";
}

function showFailure(message, expired = false) {
  stopTimers();
  ui.loading.hidden = true;
  ui.image.hidden = true;
  ui.expired.hidden = !expired;
  ui.refresh.hidden = false;
  ui.open.hidden = true;
  setStatus(message, expired ? "二维码过期" : "连接失败");
}

function renderCountdown() {
  const left = Math.max(0, Math.ceil((expiresAt - Date.now()) / 1000));
  ui.countdown.textContent = `${String(Math.floor(left / 60)).padStart(2, "0")}:${String(left % 60).padStart(2, "0")}`;
  if (left === 0) showFailure("二维码已过期，请重新生成。", true);
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

async function startLogin() {
  const current = ++generation;
  stopTimers();
  ui.login.hidden = false;
  ui.success.hidden = true;
  ui.regionBlock.hidden = false;
  resetQr();
  setStatus("正在连接 TapTap 授权服务…", "连接中");
  try {
    const { response, data } = await request("/auth/taptap/device", {
      method: "POST",
      body: JSON.stringify({ region }),
    });
    if (current !== generation) return;
    if (!response.ok) throw new Error(data.error || "无法生成二维码");
    if (!data.qr_image?.startsWith("data:image/svg+xml;base64,"))
      throw new Error("二维码数据无效");
    ui.image.src = data.qr_image;
    ui.image.hidden = false;
    ui.loading.hidden = true;
    const authUrl = new URL(data.qrcode_url);
    if (authUrl.protocol !== "https:") throw new Error("授权地址无效");
    ui.open.href = authUrl.href;
    ui.open.hidden = false;
    expiresAt = Date.now() + data.expires_in * 1000;
    renderCountdown();
    countdownTimer = setInterval(renderCountdown, 1000);
    setStatus("打开 TapTap 客户端扫描二维码并确认授权。", "等待扫码");
    pollTimer = setTimeout(
      () => poll(data.flow_id, current),
      Math.max(1, data.interval) * 1000,
    );
  } catch (error) {
    if (current === generation) showFailure(`连接失败：${error.message}`);
  }
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
      setStatus("等待 TapTap 客户端确认授权…", "等待扫码");
      pollTimer = setTimeout(
        () => poll(flowId, current),
        Math.max(1, data.retry_after) * 1000,
      );
      return;
    }
    if (response.ok && data.status === "complete") {
      stopTimers();
      await finishLogin(data.login);
      return;
    }
    if (response.status === 410)
      return showFailure("二维码已过期，请重新生成。", true);
    if (data.error === "access_denied")
      return showFailure("授权已取消，请重新生成二维码。");
    throw new Error(data.error || "授权校验失败");
  } catch (error) {
    if (current === generation) showFailure(`登录失败：${error.message}`);
  }
}

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

function chooseRegion(next) {
  if (
    region === next ||
    (next === "global" && ui.global.disabled) ||
    (next === "cn" && ui.cn.disabled)
  )
    return;
  region = next;
  ui.cn.classList.toggle("active", next === "cn");
  ui.global.classList.toggle("active", next === "global");
  ui.cn.setAttribute("aria-pressed", String(next === "cn"));
  ui.global.setAttribute("aria-pressed", String(next === "global"));
  ui.note.textContent =
    next === "cn"
      ? "使用国内版 TapTap 客户端扫描"
      : "使用国际版 TapTap 客户端扫描";
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
    if (!data.cn && data.global) {
      region = "global";
      ui.cn.classList.remove("active");
      ui.global.classList.add("active");
      ui.cn.setAttribute("aria-pressed", "false");
      ui.global.setAttribute("aria-pressed", "true");
      ui.note.textContent = "使用国际版 TapTap 客户端扫描";
    }
    if (!(await restoreSession())) startLogin();
  } catch (error) {
    showFailure(`无法启动登录：${error.message}`);
  }
})();
