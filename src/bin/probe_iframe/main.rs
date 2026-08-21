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
use rquest::Client;
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

    let client = Client::builder()
        .timeout(Duration::from_secs(20))
        .cookie_store(true)
        .redirect(rquest::redirect::Policy::limited(10))
        .build()
        .context("build http client")?;

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
            let fo_res = client
                .get(&url)
                .header("Accept", "*/*")
                .header("Referer", &iframe_url)
                .send()
                .await;
            match fo_res {
                Ok(res) => {
                    let status = res.status().as_u16();
                    let bytes = res.bytes().await.unwrap_or_default();
                    let prefix =
                        String::from_utf8_lossy(bytes.as_ref().get(..24).unwrap_or(&bytes))
                            .into_owned();
                    let as_text = String::from_utf8_lossy(&bytes);
                    fo = json!({
                        "url": url,
                        "status": status,
                        "bytes": bytes.len(),
                        "looks_like_js": looks_like_javascript(&as_text),
                        "utf8_prefix": prefix,
                    });
                }
                Err(e) => {
                    fo = json!({ "url": url, "error": e.to_string() });
                }
            }
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
    let next_failure = if !iframe_ok {
        "iframe"
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
