//! Fetch the live Turnstile iframe and report protocol fields.
//!
//! This does **not** solve the challenge. It checks that iframe HTML still
//! parses, then probes the stale `orchestrate` URL and the current `/fo/` blob
//! so the next protocol break is obvious.
//!
//! Default target is the SolveGate invisible demo.
//!
//! ```text
//! cargo run --locked --bin probe_iframe
//! cargo run --locked --bin probe_iframe -- <sitekey> <href>
//! ```

use anyhow::{Context, Result};
use cf::solver::challenge::CloudflareChallengeOptions;
use cf::solver::protocol::{
    DEMO_HREF, DEMO_SITE_KEY, PUBLIC_API_JS, extract_fo_session, fo_blob_url, generate_widget_id,
    looks_like_javascript, looks_like_orchestrate_vm, orchestrate_url,
    parse_turnstile_api_js_response, turnstile_iframe_url,
};
use cf::{FoBlobAnalysis, analyze_fo_body};
use rquest::Client;
use rquest_util::Emulation::Chrome136;
use rquest_util::EmulationOS::Windows;
use rquest_util::EmulationOption;
use serde_json::{Value, json};
use std::env;
use std::time::Duration;

#[tokio::main]
async fn main() {
    let code = match run().await {
        Ok(v) => {
            println!("{}", serde_json::to_string_pretty(&v).unwrap());
            if v.get("ok").and_then(|x| x.as_bool()) == Some(true) {
                0
            } else {
                2
            }
        }
        Err(e) => {
            eprintln!("{e:#}");
            1
        }
    };
    std::process::exit(code);
}

async fn run() -> Result<Value> {
    let site_key = env::args()
        .nth(1)
        .unwrap_or_else(|| DEMO_SITE_KEY.to_string());
    let href = env::args().nth(2).unwrap_or_else(|| DEMO_HREF.to_string());

    let emulation = EmulationOption::builder()
        .emulation(Chrome136)
        .emulation_os(Windows)
        .build();
    let client = Client::builder()
        .emulation(emulation)
        .timeout(Duration::from_secs(20))
        .cookie_store(true)
        .redirect(rquest::redirect::Policy::limited(10))
        .build()
        .context("build chrome-emulated http client")?;

    let api = client
        .get(PUBLIC_API_JS)
        .header("Accept", "*/*")
        .header("Referer", &href)
        .send()
        .await
        .context("fetch api.js")?;
    let api_status = api.status().as_u16();
    let api_url = api.url().to_string();
    let api_location = api
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let api_bytes = api.bytes().await.context("api.js body")?.len();
    let version = parse_turnstile_api_js_response(&api_url, api_location.as_deref()).ok();

    let branch = version
        .as_ref()
        .map(|v| v.branch.as_str())
        .unwrap_or("g")
        .to_string();
    let widget = generate_widget_id();
    let iframe_url = turnstile_iframe_url(&branch, &site_key, &widget);

    let iframe = client
        .get(&iframe_url)
        .header(
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        )
        .header("Referer", &href)
        .send()
        .await
        .context("fetch iframe")?;
    let iframe_status = iframe.status().as_u16();
    let html = iframe.text().await.context("iframe body")?;

    let parsed = CloudflareChallengeOptions::from_html(&html).ok();
    let fo_session = parsed
        .as_ref()
        .map(|p| p.fo_session.clone())
        .filter(|s| !s.is_empty())
        .or_else(|| extract_fo_session(&html));

    let mut orchestrate = json!(null);
    let mut fo = json!(null);

    if let Some(opt) = &parsed {
        let orch_url = orchestrate_url(&opt.zone, &branch, &opt.c_ray);
        let orch_res = client
            .get(&orch_url)
            .header("Accept", "*/*")
            .header("Referer", &iframe_url)
            .redirect(rquest::redirect::Policy::none())
            .send()
            .await;
        match orch_res {
            Ok(res) => {
                let status = res.status().as_u16();
                let body = res.text().await.unwrap_or_default();
                orchestrate = json!({
                    "url": orch_url,
                    "status": status,
                    "bytes": body.len(),
                    "looks_like_js": looks_like_javascript(&body),
                    "looks_like_vm": looks_like_orchestrate_vm(&body),
                    "prefix": body.chars().take(80).collect::<String>(),
                });
            }
            Err(e) => {
                orchestrate = json!({ "url": orch_url, "error": e.to_string() });
            }
        }

        if let (Some(session), true) = (
            fo_session.as_ref(),
            !opt.ch.is_empty() && !opt.c_ray.is_empty(),
        ) {
            let url = fo_blob_url(&opt.zone, &branch, session, &opt.c_ray, &opt.ch);
            let origin = format!("https://{}", opt.zone);
            let get = sample_fo(
                &client,
                "GET",
                &url,
                &iframe_url,
                &origin,
                &opt.c_ray,
                None,
                false,
            )
            .await;
            let get_chl = sample_fo(
                &client,
                "GET",
                &url,
                &iframe_url,
                &origin,
                &opt.c_ray,
                Some(opt.ch.as_str()),
                false,
            )
            .await;
            let post_empty = sample_fo(
                &client,
                "POST",
                &url,
                &iframe_url,
                &origin,
                &opt.c_ray,
                Some(opt.ch.as_str()),
                true,
            )
            .await;
            fo = json!({
                "url": url,
                "note": "iframe XHR POSTs a compressed init body (wZ) with cf-chl; this probe does not reconstruct that payload",
                "get": get,
                "get_with_cf_chl": get_chl,
                "post_empty_with_cf_chl": post_empty,
            });
        } else if let Some(session) = &fo_session {
            fo = json!({
                "session": session,
                "skipped": "missing ch or c_ray; not fetching the blob",
            });
        }
    }

    let challenge = parsed.as_ref().map(|opt| {
        json!({
            "c_type": opt.c_type,
            "cv_id": opt.cv_id,
            "zone": opt.zone,
            "widget_id": opt.widget_id,
            "site_key": opt.site_key,
            "api_mode": opt.api_mode,
            "api_size": opt.api_size,
            "c_ray": opt.c_ray,
            "branch": opt.branch,
            "time": opt.time,
            "ch_len": opt.ch.len(),
            "md_len": opt.md.len(),
            "api_rcv_len": opt.api_rcv.len(),
            "reset_src_len": opt.reset_src.len(),
            "fo_session": opt.fo_session,
            "hint": opt.missing_orchestrate_hint(),
        })
    });

    let iframe_ok = iframe_status == 200 && parsed.is_some();
    let fo_packed = fo_sample_packed(&fo, "get")
        || fo_sample_packed(&fo, "get_with_cf_chl")
        || fo_sample_packed(&fo, "post_empty_with_cf_chl");
    let fo_json_error = fo_sample_json_error(&fo, "get")
        || fo_sample_json_error(&fo, "get_with_cf_chl")
        || fo_sample_json_error(&fo, "post_empty_with_cf_chl");
    let next_failure = if !iframe_ok {
        "iframe"
    } else if fo_packed {
        "runProgram_handlers"
    } else if fo_json_error {
        "packed_run_program"
    } else {
        "orchestrate_replaced_by_fo_blob"
    };

    Ok(json!({
        "ok": iframe_ok,
        "next_failure": next_failure,
        "site_key": site_key,
        "href": href,
        "api": {
            "requested": PUBLIC_API_JS,
            "final_url": api_url,
            "status": api_status,
            "bytes": api_bytes,
            "branch": version.as_ref().map(|v| &v.branch),
            "version": version.as_ref().map(|v| &v.version),
        },
        "iframe": {
            "url": iframe_url,
            "status": iframe_status,
            "bytes": html.len(),
            "parsed": parsed.is_some(),
        },
        "challenge": challenge,
        "orchestrate": orchestrate,
        "fo": fo,
    }))
}

#[allow(clippy::too_many_arguments)]
async fn sample_fo(
    client: &Client,
    method: &str,
    url: &str,
    iframe_url: &str,
    origin: &str,
    c_ray: &str,
    ch: Option<&str>,
    send_empty_body: bool,
) -> Value {
    let mut req = match method {
        "POST" => client.post(url),
        _ => client.get(url),
    };
    req = req
        .header("Accept", "*/*")
        .header("Sec-Fetch-Site", "same-origin")
        .header("Sec-Fetch-Mode", "cors")
        .header("Sec-Fetch-Dest", "empty")
        .header("Referer", iframe_url)
        .header("Priority", "u=2");
    if method == "POST" {
        req = req
            .header("Content-Type", "text/plain;charset=UTF-8")
            .header("Origin", origin);
    }
    if let Some(ch) = ch {
        req = req.header("cf-chl", ch).header("cf-chl-ra", "0");
    }
    if send_empty_body {
        req = req.header("Content-Length", "0").body("");
    }

    match req.send().await {
        Ok(res) => {
            let status = res.status().as_u16();
            let body = res.text().await.unwrap_or_default();
            let analysis = analyze_fo_body(c_ray, &body);
            fo_sample_json(method, status, &body, &analysis)
        }
        Err(e) => json!({ "method": method, "error": e.to_string() }),
    }
}

fn fo_sample_json(method: &str, status: u16, body: &str, analysis: &FoBlobAnalysis) -> Value {
    json!({
        "method": method,
        "status": status,
        "bytes": body.len(),
        "utf8_prefix": body.chars().take(24).collect::<String>(),
        "analysis": analysis,
        "summary": analysis.summary(),
    })
}

fn fo_sample_flag(fo: &Value, key: &str, field: &str) -> bool {
    fo.get(key)
        .and_then(|s| s.get("analysis"))
        .and_then(|a| a.get(field))
        .and_then(|v| v.as_bool())
        == Some(true)
}

fn fo_sample_packed(fo: &Value, key: &str) -> bool {
    fo_sample_flag(fo, key, "looks_like_packed_run_program")
}

fn fo_sample_json_error(fo: &Value, key: &str) -> bool {
    fo_sample_flag(fo, key, "looks_like_json_error")
}
