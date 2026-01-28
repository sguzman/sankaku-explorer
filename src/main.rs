use anyhow::{anyhow, Context, Result};
use clap::Parser;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::Url;
use serde::Deserialize;
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use tokio::time::{sleep, Duration};

#[derive(Parser, Debug)]
#[command(author, version, about = "Discover Sankaku post URLs via the JSON API")]
struct Args {
    /// API endpoint that returns {meta, data} (default: Sankaku keyset endpoint)
    #[arg(long, default_value = "https://sankakuapi.com/v2/posts/keyset")]
    endpoint: String,

    /// Search tags (up to 3). Repeatable.
    #[arg(long = "tag", action = clap::ArgAction::Append)]
    tags: Vec<String>,

    /// Use an exact tags string instead of building from --tag/--order/--rating/--threshold
    #[arg(long)]
    tags_raw: Option<String>,

    /// order:<quality|popular|filesize|change> (function tag)
    #[arg(long, default_value = "quality")]
    order: String,

    /// rating filter(s). Examples: s, q, e, safe, questionable, explicit, g, r15, r18
    #[arg(long = "rating", action = clap::ArgAction::Append)]
    ratings: Vec<String>,

    /// threshold:<1..5> (function tag)
    #[arg(long)]
    threshold: Option<u8>,

    /// lang query parameter
    #[arg(long, default_value = "en")]
    lang: String,

    /// limit query parameter
    #[arg(long, default_value_t = 40)]
    limit: u32,

    /// default_threshold query parameter (not the same as tags threshold)
    #[arg(long)]
    default_threshold: Option<u8>,

    /// hide_posts_in_books query parameter
    #[arg(long)]
    hide_posts_in_books: Option<String>,

    /// Start from a known next cursor token
    #[arg(long)]
    start_next: Option<String>,

    /// Max number of pages to fetch (0 = no limit)
    #[arg(long, default_value_t = 0)]
    max_pages: u32,

    /// Sleep seconds between requests
    #[arg(long, default_value_t = 1.0)]
    sleep_secs: f64,

    /// Output directory
    #[arg(long, default_value = "out")]
    out: PathBuf,

    /// Output filename for URLs (inside --out)
    #[arg(long, default_value = "urls.txt")]
    urls_file: String,

    /// Append to urls file instead of overwrite
    #[arg(long)]
    append: bool,

    /// Save raw JSON pages into out/pages/page_XXXXX.json
    #[arg(long)]
    save_pages: bool,

    /// Base URL for post pages
    #[arg(long, default_value = "https://sankaku.app/posts/")]
    post_base: String,

    /// Bearer token for Authorization header (or set SANKAKU_TOKEN env)
    #[arg(long)]
    bearer: Option<String>,

    /// Read Sankaku credentials from gallery-dl config (default path)
    #[arg(long, default_value = "~/.config/gallery-dl/config.json")]
    gallery_dl_config: String,

    /// Do not read gallery-dl config for credentials
    #[arg(long)]
    no_config: bool,

    /// Extra header(s), e.g. --header 'Api-Version: 2'
    #[arg(long = "header", action = clap::ArgAction::Append)]
    headers: Vec<String>,

    /// Extra query param(s), e.g. --param 'page=2'
    #[arg(long = "param", action = clap::ArgAction::Append)]
    params: Vec<String>,
}

#[derive(Deserialize, Debug)]
struct Resp {
    meta: Meta,
    data: Vec<Post>,
}

#[derive(Deserialize, Debug)]
struct Meta {
    next: Option<String>,
}

#[derive(Deserialize, Debug)]
struct Post {
    id: String,
}

#[derive(Debug)]
struct Credentials {
    username: String,
    password: String,
}

fn normalize_rating(raw: &str) -> String {
    let r = raw.trim().to_ascii_lowercase();
    match r.as_str() {
        "s" | "safe" | "g" => "s".to_string(),
        "q" | "questionable" | "r15" => "q".to_string(),
        "e" | "explicit" | "r18" => "e".to_string(),
        _ => r,
    }
}

fn build_tags_param(args: &Args) -> Result<String> {
    if let Some(raw) = &args.tags_raw {
        return Ok(raw.trim().to_string());
    }

    if args.tags.len() > 3 {
        return Err(anyhow!(
            "expected up to 3 tags, got {}: {:?}",
            args.tags.len(),
            args.tags
        ));
    }

    let mut parts: Vec<String> = vec![];
    for t in &args.tags {
        let t = t.trim();
        if !t.is_empty() {
            parts.push(t.to_string());
        }
    }

    if !args.order.trim().is_empty() {
        parts.push(format!("order:{}", args.order.trim()));
    }

    for r in &args.ratings {
        let r = normalize_rating(r);
        if !r.is_empty() {
            parts.push(format!("rating:{}", r));
        }
    }

    if let Some(th) = args.threshold {
        if !(1..=5).contains(&th) {
            return Err(anyhow!("threshold must be 1..5, got {}", th));
        }
        parts.push(format!("threshold:{}", th));
    }

    Ok(parts.join(" ").trim().to_string())
}

fn ensure_dirs(out: &Path, save_pages: bool) -> Result<()> {
    fs::create_dir_all(out)?;
    if save_pages {
        fs::create_dir_all(out.join("pages"))?;
    }
    Ok(())
}

fn parse_headers(extra: &[String]) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("accept"),
        HeaderValue::from_static("application/vnd.sankaku.api+json;v=2"),
    );
    headers.insert(
        HeaderName::from_static("user-agent"),
        HeaderValue::from_static("sankaku-explorer/0.1"),
    );
    headers.insert(
        HeaderName::from_static("client-type"),
        HeaderValue::from_static("non-premium"),
    );
    headers.insert(
        HeaderName::from_static("platform"),
        HeaderValue::from_static("web-app"),
    );
    headers.insert(
        HeaderName::from_static("api-version"),
        HeaderValue::from_static("2"),
    );
    headers.insert(
        HeaderName::from_static("obfuscate-type"),
        HeaderValue::from_static("tag,wiki,comment"),
    );
    headers.insert(
        HeaderName::from_static("enable-new-tag-type"),
        HeaderValue::from_static("true"),
    );
    headers.insert(
        HeaderName::from_static("expiration-policy"),
        HeaderValue::from_static("reduced"),
    );
    headers.insert(
        HeaderName::from_static("origin"),
        HeaderValue::from_static("https://sankaku.app"),
    );
    headers.insert(
        HeaderName::from_static("referer"),
        HeaderValue::from_static("https://sankaku.app/"),
    );

    for h in extra {
        let (k, v) = split_kv(h).with_context(|| format!("bad header: {h}"))?;
        headers.insert(HeaderName::from_bytes(k.as_bytes())?, HeaderValue::from_str(&v)?);
    }

    Ok(headers)
}

fn split_kv(s: &str) -> Result<(String, String)> {
    if let Some((k, v)) = s.split_once(':') {
        return Ok((k.trim().to_string(), v.trim().to_string()));
    }
    if let Some((k, v)) = s.split_once('=') {
        return Ok((k.trim().to_string(), v.trim().to_string()));
    }
    Err(anyhow!("expected key:value or key=value"))
}

fn expand_tilde(path: &str) -> Result<PathBuf> {
    if let Some(stripped) = path.strip_prefix("~/") {
        let home = std::env::var("HOME").context("HOME not set for ~ expansion")?;
        return Ok(PathBuf::from(home).join(stripped));
    }
    if path == "~" {
        let home = std::env::var("HOME").context("HOME not set for ~ expansion")?;
        return Ok(PathBuf::from(home));
    }
    Ok(PathBuf::from(path))
}

fn load_gallerydl_credentials(path: &Path) -> Result<Credentials> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("read gallery-dl config {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&text)
        .with_context(|| format!("parse gallery-dl config {}", path.display()))?;

    let username = value
        .get("extractor")
        .and_then(|v| v.get("sankaku"))
        .and_then(|v| v.get("username"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let password = value
        .get("extractor")
        .and_then(|v| v.get("sankaku"))
        .and_then(|v| v.get("password"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    match (username, password) {
        (Some(u), Some(p)) if !u.is_empty() && !p.is_empty() => Ok(Credentials {
            username: u,
            password: p,
        }),
        _ => Err(anyhow!(
            "missing extractor.sankaku.username/password in {}",
            path.display()
        )),
    }
}

fn endpoint_root(endpoint: &str) -> Result<String> {
    let url = Url::parse(endpoint).context("parse endpoint URL")?;
    let scheme = url.scheme();
    let host = url.host_str().context("endpoint has no host")?;
    Ok(format!("{}://{}", scheme, host))
}

async fn authenticate(
    client: &reqwest::Client,
    root: &str,
    username: &str,
    password: &str,
) -> Result<String> {
    let url = format!("{}/auth/token", root);
    let resp = client
        .post(url)
        .json(&serde_json::json!({ "login": username, "password": password }))
        .send()
        .await?;

    let status = resp.status();
    let data: serde_json::Value = resp.json().await?;
    let success = data.get("success").and_then(|v| v.as_bool()).unwrap_or(true);
    if status.is_success() && success {
        if let Some(token) = data.get("access_token").and_then(|v| v.as_str()) {
            return Ok(token.to_string());
        }
    }
    let err = data
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or("authentication failed");
    Err(anyhow!(err.to_string()))
}

async fn fetch_page(
    client: &reqwest::Client,
    endpoint: &str,
    params: &[(String, String)],
    token: &mut Option<String>,
    creds: Option<&Credentials>,
    root: &str,
) -> Result<String> {
    let mut attempt = 0;
    loop {
        let mut req = client.get(endpoint).query(params);
        if let Some(tok) = token {
            req = req.bearer_auth(tok);
        }
        let resp = req.send().await?;
        let status = resp.status();
        if (status.as_u16() == 401 || status.as_u16() == 403) && creds.is_some() && attempt == 0 {
            if let Some(c) = creds {
                let new_token = authenticate(client, root, &c.username, &c.password).await?;
                *token = Some(new_token);
                attempt += 1;
                continue;
            }
        }
        return Ok(resp.error_for_status()?.text().await?);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    ensure_dirs(&args.out, args.save_pages)?;

    let tags_param = build_tags_param(&args)?;

    let headers = parse_headers(&args.headers)?;
    let client = reqwest::Client::builder()
        .default_headers(headers)
        .build()?
        .clone();

    let root = endpoint_root(&args.endpoint)?;

    let bearer = args
        .bearer
        .or_else(|| std::env::var("SANKAKU_TOKEN").ok());

    let creds = if bearer.is_none() && !args.no_config {
        let cfg_path = expand_tilde(&args.gallery_dl_config)?;
        Some(load_gallerydl_credentials(&cfg_path)?)
    } else {
        None
    };

    let mut token = bearer;
    if token.is_none() {
        if let Some(c) = creds.as_ref() {
            token = Some(authenticate(&client, &root, &c.username, &c.password).await?);
        }
    }

    let urls_path = args.out.join(&args.urls_file);
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(args.append)
        .truncate(!args.append)
        .open(&urls_path)
        .with_context(|| format!("open {}", urls_path.display()))?;
    let mut writer = BufWriter::new(file);

    let mut seen: HashSet<String> = HashSet::new();
    let mut next = args.start_next.clone();
    let mut prev_next: Option<String> = None;

    let mut page: u32 = 0;

    loop {
        if args.max_pages > 0 && page >= args.max_pages {
            break;
        }
        page += 1;

        let mut params: Vec<(String, String)> = vec![
            ("lang".to_string(), args.lang.clone()),
            ("limit".to_string(), args.limit.to_string()),
            ("tags".to_string(), tags_param.clone()),
        ];

        if let Some(dt) = args.default_threshold {
            params.push(("default_threshold".to_string(), dt.to_string()));
        }
        if let Some(hp) = &args.hide_posts_in_books {
            params.push(("hide_posts_in_books".to_string(), hp.to_string()));
        }
        if let Some(n) = &next {
            params.push(("next".to_string(), n.clone()));
        }
        for p in &args.params {
            let (k, v) = split_kv(p).with_context(|| format!("bad param: {p}"))?;
            params.push((k, v));
        }

        let text = fetch_page(&client, &args.endpoint, &params, &mut token, creds.as_ref(), &root)
            .await?;

        if args.save_pages {
            let page_path = args
                .out
                .join("pages")
                .join(format!("page_{:05}.json", page));
            fs::write(&page_path, &text)
                .with_context(|| format!("write {}", page_path.display()))?;
        }

        let parsed: Resp = serde_json::from_str(&text).context("parse JSON response")?;

        if parsed.data.is_empty() {
            break;
        }

        for post in parsed.data {
            if seen.insert(post.id.clone()) {
                let mut url = args.post_base.clone();
                if !url.ends_with('/') {
                    url.push('/');
                }
                url.push_str(&post.id);
                writeln!(writer, "{}", url)?;
            }
        }

        next = parsed.meta.next;
        if next.is_none() {
            break;
        }
        if next == prev_next {
            return Err(anyhow!("pagination cursor repeated; stopping to avoid loop"));
        }
        prev_next = next.clone();

        if args.sleep_secs > 0.0 {
            sleep(Duration::from_secs_f64(args.sleep_secs)).await;
        }
    }

    writer.flush()?;
    Ok(())
}
