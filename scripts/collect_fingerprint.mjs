import puppeteer from "puppeteer-core";
import fs from "node:fs";
import path from "node:path";

const chromePath =
  process.env.CHROME_PATH || "/usr/bin/google-chrome-stable";
const outPath =
  process.argv[2] ||
  new URL("../workspace/cloudflare_test.json", import.meta.url).pathname;

const browser = await puppeteer.launch({
  executablePath: chromePath,
  headless: "new",
  args: [
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-dev-shm-usage",
    "--use-gl=angle",
    "--use-angle=swiftshader",
    "--enable-webgl",
    "--autoplay-policy=no-user-gesture-required",
    "--window-size=1920,1080",
  ],
});

const page = await browser.newPage();
await page.setViewport({ width: 1920, height: 1080 });
await page.goto("https://example.com", { waitUntil: "domcontentloaded" });

const fp = await page.evaluate(async () => {
  const sha256Hex = async (input) => {
    const data = new TextEncoder().encode(
      typeof input === "string" ? input : JSON.stringify(input)
    );
    const buf = await crypto.subtle.digest("SHA-256", data);
    return [...new Uint8Array(buf)]
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  };

  const md5ish32 = async (input) => (await sha256Hex(input)).slice(0, 32);

  const glInfo = () => {
    const canvas = document.createElement("canvas");
    canvas.width = 256;
    canvas.height = 256;
    const gl =
      canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
    if (!gl) {
      return {
        masked_vendor: "unknown",
        masked_renderer: "unknown",
        unmasked_vendor: "unknown",
        unmasked_renderer: "unknown",
        webgl_first_hash: "",
        webgl_second_hash: "",
      };
    }
    const debug = gl.getExtension("WEBGL_debug_renderer_info");
    const vendor = gl.getParameter(gl.VENDOR) || "";
    const renderer = gl.getParameter(gl.RENDERER) || "";
    const unmaskedVendor = debug
      ? gl.getParameter(debug.UNMASKED_VENDOR_WEBGL)
      : vendor;
    const unmaskedRenderer = debug
      ? gl.getParameter(debug.UNMASKED_RENDERER_WEBGL)
      : renderer;

    gl.clearColor(0.2, 0.4, 0.6, 1);
    gl.clear(gl.COLOR_BUFFER_BIT);
    const pixels = new Uint8Array(16);
    gl.readPixels(0, 0, 2, 2, gl.RGBA, gl.UNSIGNED_BYTE, pixels);

    return {
      vendor,
      renderer,
      unmaskedVendor,
      unmaskedRenderer,
      pixelSample: Array.from(pixels),
      canvasDataUrl: canvas.toDataURL(),
    };
  };

  const audioHash = async () => {
    try {
      const ctx = new OfflineAudioContext(1, 44100, 44100);
      const osc = ctx.createOscillator();
      osc.type = "triangle";
      osc.frequency.value = 10000;
      const compressor = ctx.createDynamicsCompressor();
      compressor.threshold.value = -50;
      compressor.knee.value = 40;
      compressor.ratio.value = 12;
      compressor.attack.value = 0;
      compressor.release.value = 0.25;
      osc.connect(compressor);
      compressor.connect(ctx.destination);
      osc.start(0);
      const buf = await ctx.startRendering();
      const data = buf.getChannelData(0);
      let sum = 0;
      for (let i = 4500; i < 5000; i++) sum += Math.abs(data[i]);
      return {
        first: await sha256Hex(Array.from(data.subarray(0, 32))),
        second: await sha256Hex(String(sum)),
      };
    } catch (e) {
      return { first: await sha256Hex("audio-unavailable"), second: await sha256Hex(String(e)) };
    }
  };

  const mathFingerprint = async () => {
    const vals = [
      Math.tan(-1e300),
      Math.sin(Math.PI / 6),
      Math.cos(10.000000000123),
      Math.exp(1),
      Math.log(Math.E),
      Math.acos(0.123456789),
      Math.asin(0.123456789),
      Math.atan(2),
      Math.sqrt(2),
      Math.pow(Math.PI, -100),
    ];
    return sha256Hex(vals.map((v) => v.toString()).join(","));
  };

  const computedStyleHash = async () => {
    const el = document.createElement("div");
    el.style.cssText =
      "position:absolute;left:-9999px;top:-9999px;font:16px Arial,sans-serif;";
    el.textContent = "mmmmmmmmmmlli";
    document.body.appendChild(el);
    const cs = getComputedStyle(el);
    const props = [];
    for (let i = 0; i < cs.length; i++) {
      const name = cs[i];
      props.push(`${name}:${cs.getPropertyValue(name)}`);
    }
    document.body.removeChild(el);
    return sha256Hex(props.join("|"));
  };

  const emojiCheck = () => {
    const measure = (ch) => {
      const span = document.createElement("span");
      span.style.cssText =
        "position:absolute;left:-9999px;font:32px /1 'Apple Color Emoji','Segoe UI Emoji','Noto Color Emoji',sans-serif;";
      span.textContent = ch;
      document.body.appendChild(span);
      const w = span.getBoundingClientRect().width;
      document.body.removeChild(span);
      return w;
    };
    const a = measure("😀");
    const b = measure("■");
    return a !== b && a > 0;
  };

  const htmlBounds = () => {
    const probes = [
      { tag: "div", text: "A", font: "16px Arial" },
      { tag: "div", text: "😀", font: "32px serif" },
      { tag: "span", text: "Cloudflare", font: "14px Times New Roman" },
      { tag: "p", text: "mmmmmmmmmmlli", font: "16px 'Courier New'" },
    ];
    const out = [];
    for (const p of probes) {
      const el = document.createElement(p.tag);
      el.style.cssText = `position:absolute;left:0;top:0;font:${p.font};visibility:hidden;`;
      el.textContent = p.text;
      document.body.appendChild(el);
      const r = el.getBoundingClientRect();
      out.push({
        tag: p.tag,
        text: p.text,
        font: p.font,
        x: r.x,
        y: r.y,
        width: r.width,
        height: r.height,
      });
      document.body.removeChild(el);
    }
    return out;
  };

  const gpuAdapter = async () => {
    if (!navigator.gpu) return null;
    try {
      const adapter = await navigator.gpu.requestAdapter();
      if (!adapter) return null;
      const info = adapter.info || {};
      return {
        vendor: info.vendor || "",
        architecture: info.architecture || "",
        device: info.device || "",
        description: info.description || "",
        features: [...adapter.features],
        limits: Object.fromEntries(
          Object.entries(adapter.limits || {}).map(([k, v]) => [k, v])
        ),
      };
    } catch {
      return null;
    }
  };

  const uaData = navigator.userAgentData
    ? await navigator.userAgentData.getHighEntropyValues([
        "architecture",
        "bitness",
        "model",
        "platformVersion",
        "fullVersionList",
        "wow64",
      ])
    : null;

  const gl = glInfo();
  const audio = await audioHash();
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const langs = [...(navigator.languages || [navigator.language])];
  const language = navigator.language || "en-US";

  let battery_info = null;
  try {
    if (navigator.getBattery) {
      const b = await navigator.getBattery();
      battery_info = {
        charging: b.charging,
        level: b.level,
        charging_time: Number.isFinite(b.chargingTime) ? b.chargingTime : -1,
        discharging_time: Number.isFinite(b.dischargingTime)
          ? b.dischargingTime
          : -1,
      };
    }
  } catch {
    battery_info = null;
  }

  const formatted_timezone = new Intl.DateTimeFormat("en-US", {
    timeZone: tz,
    timeZoneName: "longOffset",
    hour: "numeric",
    minute: "numeric",
  }).format(new Date());

  const formatted_language = new Intl.DisplayNames(["en"], {
    type: "language",
  }).of(language.split("-")[0]);

  const formatted_list = new Intl.ListFormat(language, {
    style: "long",
    type: "conjunction",
  }).format(langs.slice(0, 3));

  const formatted_notation = new Intl.NumberFormat(language, {
    notation: "scientific",
  }).format(1000);

  const headers = {
    "Accept-Language": `${language}${langs[1] ? "," + langs[1] + ";q=0.9" : ""}`,
    "User-Agent": navigator.userAgent,
  };
  if (navigator.userAgentData) {
    const brands = navigator.userAgentData.brands
      .map((b) => `"${b.brand}";v="${b.version}"`)
      .join(", ");
    headers["Sec-Ch-Ua"] = brands;
    headers["Sec-Ch-Ua-Mobile"] = navigator.userAgentData.mobile
      ? "?1"
      : "?0";
    headers["Sec-Ch-Ua-Platform"] = `"${navigator.userAgentData.platform}"`;
  }

  return {
    platform: navigator.platform,
    hardware_concurrency: navigator.hardwareConcurrency || 8,
    device_memory: navigator.deviceMemory || 8,
    user_agent: navigator.userAgent,
    user_agent_data: uaData
      ? {
          architecture: uaData.architecture || "",
          bitness: uaData.bitness || "",
          brands: (navigator.userAgentData.brands || []).map((b) => ({
            brand: b.brand,
            version: b.version,
          })),
          fullVersionList: (uaData.fullVersionList || []).map((b) => ({
            brand: b.brand,
            version: b.version,
          })),
          mobile: !!navigator.userAgentData.mobile,
          model: uaData.model || "",
          platform: navigator.userAgentData.platform || "",
          platformVersion: uaData.platformVersion || "",
        }
      : null,
    user_preferences: {
      dark_mode: matchMedia("(prefers-color-scheme: dark)").matches,
      forced_colors: matchMedia("(forced-colors: active)").matches,
      prefers_contrast: matchMedia("(prefers-contrast: more)").matches,
      prefers_reduced_motion: matchMedia("(prefers-reduced-motion: reduce)")
        .matches,
      battery_info,
    },
    audio: {
      first_audio_hash: audio.first,
      second_audio_hash: audio.second,
    },
    webgl: {
      navigator_gpu_data: await gpuAdapter(),
      masked_vendor: gl.vendor,
      masked_renderer: gl.renderer,
      unmasked_vendor: gl.unmaskedVendor,
      unmasked_renderer: gl.unmaskedRenderer,
      webgl_first_hash: await sha256Hex(gl.canvasDataUrl || "no-webgl"),
      webgl_second_hash: await sha256Hex(gl.pixelSample || []),
    },
    language_info: {
      language,
      languages: langs,
      formatted_timezone,
      formatted_language,
      formatted_list,
      formatted_notation,
    },
    emoji_check_matches: emojiCheck(),
    math_fingerprint: await mathFingerprint(),
    keys: {
      platform: navigator.platform,
      vendor: navigator.vendor,
      product: navigator.product,
      cookieEnabled: navigator.cookieEnabled,
      maxTouchPoints: navigator.maxTouchPoints,
      webdriver: navigator.webdriver || false,
    },
    computed_style_hash: await computedStyleHash(),
    headers,
    html_bounds: htmlBounds(),
    _collector_meta: {
      timezone: tz,
      href: location.href,
      chrome: true,
      computed_style_md5ish: await md5ish32("meta"),
    },
  };
});

await browser.close();

delete fp._collector_meta;
const wrapped = [fp];
fs.mkdirSync(path.dirname(outPath), { recursive: true });
fs.writeFileSync(outPath, JSON.stringify(wrapped, null, 2));
console.log("wrote", outPath);
console.log("ua", fp.user_agent);
console.log("platform", fp.platform);
console.log("webgl", fp.webgl.unmasked_vendor, fp.webgl.unmasked_renderer);
console.log("audio", fp.audio.first_audio_hash.slice(0, 16));
console.log("math", fp.math_fingerprint.slice(0, 16));
