use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser, Subcommand};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::Url;
use serde::Deserialize;
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::time::{sleep, Duration};
use tracing::{debug, info, warn};

#[derive(Parser, Debug)]
#[command(author, version, about = "Sankaku utilities: discover post URLs and export XMP")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    #[command(flatten)]
    discover: DiscoverArgs,

    /// Enable debug logging
    #[arg(long, short = 'v')]
    verbose: bool,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Convert Sankaku JSON sidecars to XMP
    Export(ExportArgs),
}

#[derive(Args, Debug, Clone)]
struct DiscoverArgs {
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

#[derive(Args, Debug, Clone)]
struct ExportArgs {
    /// Directory containing Sankaku JSON sidecars
    #[arg(long, default_value = ".")]
    dir: PathBuf,

    /// Process a single JSON sidecar file
    #[arg(long)]
    file: Option<PathBuf>,

    /// Recurse into subdirectories when using --dir
    #[arg(long, default_value_t = true)]
    recursive: bool,

    /// Overwrite existing .xmp files
    #[arg(long)]
    overwrite: bool,

    /// Don't write files; only log actions
    #[arg(long)]
    dry_run: bool,

    /// Output path for single-file mode (default: replace trailing .json with .xmp)
    #[arg(long)]
    out: Option<PathBuf>,
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

#[derive(Deserialize, Debug)]
struct SankakuAuthor {
    name: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
enum TagValue {
    Str(String),
    Obj { name: Option<String> },
}

#[derive(Deserialize, Debug)]
struct SankakuSidecar {
    id: Option<String>,
    md5: Option<String>,
    rating: Option<String>,
    date: Option<String>,
    created_at: Option<i64>,
    file_url: Option<String>,
    author: Option<SankakuAuthor>,
    tags: Option<Vec<TagValue>>,
    tag_names: Option<Vec<String>>,
    tag_string: Option<String>,
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

fn build_tags_param(args: &DiscoverArgs) -> Result<String> {
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

fn escape_xml(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 8);
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    out
}

fn json_to_xmp_path(json_path: &Path) -> Result<PathBuf> {
    let file_name = json_path
        .file_name()
        .and_then(|x| x.to_str())
        .ok_or_else(|| anyhow!("non-utf8 filename: {}", json_path.display()))?;

    if file_name.ends_with(".json") {
        let base = &file_name[..file_name.len() - 5];
        return Ok(json_path.with_file_name(format!("{base}.xmp")));
    }

    Ok(json_path.with_extension("xmp"))
}

fn is_json_sidecar(path: &Path) -> bool {
    path.extension().and_then(|e| e.to_str()) == Some("json")
}

fn collect_json_files(dir: &Path, recursive: bool, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("read dir {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            if recursive {
                collect_json_files(&path, recursive, out)?;
            }
            continue;
        }
        if path.is_file() && is_json_sidecar(&path) {
            out.push(path);
        }
    }
    Ok(())
}

fn tags_from_sidecar(sc: &SankakuSidecar) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();

    if let Some(tags) = sc.tags.as_ref() {
        for t in tags {
            match t {
                TagValue::Str(s) => out.push(s.clone()),
                TagValue::Obj { name } => {
                    if let Some(n) = name {
                        out.push(n.clone());
                    }
                }
            }
        }
    }

    if out.is_empty() {
        if let Some(tags) = sc.tag_names.as_ref() {
            out.extend(tags.iter().cloned());
        }
    }

    if out.is_empty() {
        if let Some(tag_string) = sc.tag_string.as_ref() {
            for part in tag_string.split_whitespace() {
                out.push(part.to_string());
            }
        }
    }

    let mut seen = HashSet::new();
    out.retain(|t| {
        let t = t.trim();
        !t.is_empty() && seen.insert(t.to_string())
    });

    out
}

fn iso8601_from_date_field(s: &str) -> Option<String> {
    let s = s.trim();
    if s.len() == 19 {
        if s.chars().nth(10) == Some(' ') {
            let mut out = s.to_string();
            out.replace_range(10..11, "T");
            return Some(out);
        }
        if s.chars().nth(10) == Some('T') {
            return Some(s.to_string());
        }
    }
    None
}

fn iso8601_from_unix(ts: i64) -> Option<String> {
    let dt = OffsetDateTime::from_unix_timestamp(ts).ok()?;
    dt.format(&Rfc3339).ok()
}

fn build_xmp(sc: &SankakuSidecar) -> Result<String> {
    let keywords = tags_from_sidecar(sc);

    let creator = sc
        .author
        .as_ref()
        .and_then(|a| a.name.as_ref())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let create_date = sc
        .date
        .as_ref()
        .and_then(|d| iso8601_from_date_field(d))
        .or_else(|| sc.created_at.and_then(iso8601_from_unix));

    let source = sc
        .file_url
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let label = {
        let mut bits: Vec<String> = Vec::new();
        if let Some(id) = sc.id.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
            bits.push(id.to_string());
        }
        if let Some(md5) = sc.md5.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
            bits.push(md5.to_string());
        }
        if bits.is_empty() {
            None
        } else {
            Some(format!("sankaku:{}", bits.join(":")))
        }
    };

    let kw_items = keywords
        .iter()
        .map(|k| format!("          <rdf:li>{}</rdf:li>", escape_xml(k)))
        .collect::<Vec<_>>()
        .join("\n");

    let dc_creator = creator
        .as_ref()
        .map(|c| {
            format!(
                r#"
    <dc:creator>
      <rdf:Seq>
        <rdf:li>{}</rdf:li>
      </rdf:Seq>
    </dc:creator>"#,
                escape_xml(c)
            )
        })
        .unwrap_or_default();

    let dc_source = source
        .as_ref()
        .map(|s| format!(r#"
    <dc:source>{}</dc:source>"#, escape_xml(s)))
        .unwrap_or_default();

    let xmp_createdate = create_date
        .as_ref()
        .map(|d| format!(r#"
    <xmp:CreateDate>{}</xmp:CreateDate>"#, escape_xml(d)))
        .unwrap_or_default();

    let xmp_label = label
        .as_ref()
        .map(|l| format!(r#"
    <xmp:Label>{}</xmp:Label>"#, escape_xml(l)))
        .unwrap_or_default();

    let subject = format!(
        r#"
    <dc:subject>
      <rdf:Bag>
{kw_items}
      </rdf:Bag>
    </dc:subject>"#,
        kw_items = kw_items
    );

    let xmp = format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
  <rdf:RDF xmlns:rdf="<http://www.w3.org/1999/02/22-rdf-syntax-ns#>">
    <rdf:Description
      rdf:about=""
      xmlns:dc="<http://purl.org/dc/elements/1.1/>"
      xmlns:xmp="<http://ns.adobe.com/xap/1.0/>">{dc_creator}{dc_source}{subject}{xmp_createdate}{xmp_label}
    </rdf:Description>
  </rdf:RDF>
</x:xmpmeta>
"#,
        dc_creator = dc_creator,
        dc_source = dc_source,
        subject = subject,
        xmp_createdate = xmp_createdate,
        xmp_label = xmp_label
    );

    Ok(xmp)
}

fn write_atomic(out_path: &Path, data: &str) -> Result<()> {
    let parent = out_path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).with_context(|| format!("create dir {}", parent.display()))?;

    let tmp_name = out_path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| format!("{n}.tmp"))
        .ok_or_else(|| anyhow!("non-utf8 filename: {}", out_path.display()))?;
    let tmp_path = out_path.with_file_name(tmp_name);

    fs::write(&tmp_path, data).with_context(|| format!("write {}", tmp_path.display()))?;
    fs::rename(&tmp_path, out_path).with_context(|| format!("rename {}", out_path.display()))?;
    Ok(())
}

fn process_sidecar_file(path: &Path, out_override: Option<&Path>, overwrite: bool, dry_run: bool) -> Result<()> {
    let out_path = if let Some(out) = out_override {
        out.to_path_buf()
    } else {
        json_to_xmp_path(path)?
    };

    if out_path.exists() && !overwrite {
        info!(xmp = %out_path.display(), "exists; skipping (use --overwrite)");
        return Ok(());
    }

    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let sidecar: SankakuSidecar = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse json {}", path.display()))?;

    let xmp = build_xmp(&sidecar).with_context(|| format!("build xmp {}", path.display()))?;

    if dry_run {
        info!(json = %path.display(), xmp = %out_path.display(), "dry-run: would write");
        return Ok(());
    }

    write_atomic(&out_path, &xmp)?;

    info!(
        json = %path.display(),
        xmp = %out_path.display(),
        id = sidecar.id.as_deref().unwrap_or(""),
        md5 = sidecar.md5.as_deref().unwrap_or(""),
        rating = sidecar.rating.as_deref().unwrap_or(""),
        tags = tags_from_sidecar(&sidecar).len(),
        "wrote xmp"
    );

    Ok(())
}

fn run_export(args: ExportArgs) -> Result<()> {
    if let Some(file) = args.file.as_ref() {
        let path = file
            .canonicalize()
            .with_context(|| format!("file not found: {}", file.display()))?;
        info!(file = %path.display(), "export single file");
        return process_sidecar_file(&path, args.out.as_deref(), args.overwrite, args.dry_run);
    }

    let dir = args
        .dir
        .canonicalize()
        .with_context(|| format!("dir not found: {}", args.dir.display()))?;

    info!(
        dir = %dir.display(),
        recursive = args.recursive,
        overwrite = args.overwrite,
        dry_run = args.dry_run,
        "export directory"
    );

    let mut files = Vec::new();
    collect_json_files(&dir, args.recursive, &mut files)?;

    info!(matched = files.len(), "found sidecar files");

    let mut written = 0usize;
    for path in files {
        if let Err(err) = process_sidecar_file(&path, None, args.overwrite, args.dry_run) {
            warn!(error = %err, json = %path.display(), "failed");
            continue;
        }
        written += 1;
    }

    info!(written, "export complete");
    Ok(())
}

async fn run_discover(args: DiscoverArgs) -> Result<()> {
    ensure_dirs(&args.out, args.save_pages)?;

    let tags_param = build_tags_param(&args)?;

    let headers = parse_headers(&args.headers)?;
    let client = reqwest::Client::builder()
        .default_headers(headers)
        .build()?
        .clone();

    let root = endpoint_root(&args.endpoint)?;

    let bearer = args.bearer.or_else(|| std::env::var("SANKAKU_TOKEN").ok());

    let creds = if bearer.is_none() && !args.no_config {
        let cfg_path = expand_tilde(&args.gallery_dl_config)?;
        info!("loading gallery-dl config from {}", cfg_path.display());
        Some(load_gallerydl_credentials(&cfg_path)?)
    } else {
        None
    };

    let mut token = bearer;
    if token.is_none() {
        if let Some(c) = creds.as_ref() {
            info!("authenticating as {}", c.username);
            token = Some(authenticate(&client, &root, &c.username, &c.password).await?);
        }
    }
    if token.is_none() {
        warn!("no bearer token available; requests may be unauthorized");
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

    info!("endpoint: {}", args.endpoint);
    info!("post base: {}", args.post_base);
    info!("tags: {}", tags_param);
    info!("limit: {}", args.limit);
    info!("sleep: {}s", args.sleep_secs);
    info!("save pages: {}", args.save_pages);
    info!("urls file: {}", urls_path.display());
    if args.max_pages == 0 {
        info!("max pages: unlimited");
    } else {
        info!("max pages: {}", args.max_pages);
    }
    if let Some(n) = &next {
        info!("start cursor: {}", n);
    }
    if tags_param.is_empty() {
        warn!("tags parameter is empty; query may be very large or slow");
    }

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

        debug!("page {} params: {:?}", page, params);
        let text = fetch_page(&client, &args.endpoint, &params, &mut token, creds.as_ref(), &root)
            .await?;
        debug!("page {} response bytes: {}", page, text.len());

        if args.save_pages {
            let page_path = args
                .out
                .join("pages")
                .join(format!("page_{:05}.json", page));
            fs::write(&page_path, &text)
                .with_context(|| format!("write {}", page_path.display()))?;
        }

        let parsed: Resp = serde_json::from_str(&text).context("parse JSON response")?;
        info!("page {} posts: {}", page, parsed.data.len());

        if parsed.data.is_empty() {
            info!("page {} returned 0 posts; stopping", page);
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
                debug!("emit {}", post.id);
            }
        }

        next = parsed.meta.next;
        if next.is_none() {
            info!("no next cursor; stopping");
            break;
        }
        debug!("next cursor: {}", next.as_deref().unwrap_or(""));
        if next == prev_next {
            return Err(anyhow!("pagination cursor repeated; stopping to avoid loop"));
        }
        prev_next = next.clone();

        if args.sleep_secs > 0.0 {
            debug!("sleep {}s", args.sleep_secs);
            sleep(Duration::from_secs_f64(args.sleep_secs)).await;
        }
    }

    writer.flush()?;
    info!("done: wrote {} unique urls to {}", seen.len(), urls_path.display());
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let level = if cli.verbose { "debug" } else { "info" };
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    match cli.command {
        Some(Command::Export(args)) => run_export(args),
        None => run_discover(cli.discover).await,
    }
}
