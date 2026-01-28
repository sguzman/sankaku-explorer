# sankaku-explorer

A small Rust CLI that discovers Sankaku post URLs via the JSON API and writes them to a file for downstream tools (e.g., gallery-dl). It **does not download** content and **does not enrich** metadata. It only walks pages, extracts post IDs, and emits post page URLs.

## What it does

- Calls the Sankaku keyset listing API (`/v2/posts/keyset`) or any compatible endpoint.
- Paginates via the `meta.next` cursor until the API ends or you cap pages.
- Extracts each `data[].id` and writes `https://sankaku.app/posts/<id>` URLs.
- Optionally saves raw JSON pages for auditing.

## What it does NOT do

- No downloading.
- No gallery-dl invocation.
- No metadata enrichment beyond saving raw pages (optional).

## Install / Build

```bash
cargo build
```

## Authentication

By default, the tool reads your gallery-dl credentials from:

```
~/.config/gallery-dl/config.json
```

It uses the same flow as gallery-dl:

- `POST /auth/token` with username/password
- Uses the returned bearer token on API requests

You can override or disable this behavior:

- `--bearer <TOKEN>`: Use a bearer token directly
- `SANKAKU_TOKEN` env var: Same as `--bearer`
- `--no-config`: Do not read gallery-dl config
- `--gallery-dl-config <PATH>`: Custom config path

If no token is available, requests may fail with 401/403.

## Logging

- Default: info-level logs
- `-v` / `--verbose`: debug logs
- You can also use `RUST_LOG=debug` to force debug output

## Quick start

```bash
cargo run -- \
  --tag pokemon --tag female --tag 1girl \
  --order quality \
  --rating g --rating r15 \
  --threshold 2 \
  --default-threshold 2 \
  --hide-posts-in-books in-larger-tags \
  --limit 40 \
  --max-pages 10 \
  --out out \
  --save-pages \
  -v
```

This writes URLs to `out/urls.txt` and raw JSON to `out/pages/page_00001.json` etc.

## Output

- `out/urls.txt`: one URL per line
- `out/pages/page_XXXXX.json` (optional): raw API payloads

## Flags (complete)

### Core query

- `--endpoint <URL>`
  - **Default:** `https://sankakuapi.com/v2/posts/keyset`
  - API endpoint that returns `{meta, data}`

- `--tag <TAG>` (repeatable, up to 3)
  - Adds plain tags (e.g., `pokemon`, `female`, `1girl`)
  - If omitted, only function tags (order/rating/threshold) are used

- `--tags-raw <STRING>`
  - Use an exact tags string instead of building from other flags
  - Example: `--tags-raw "order:quality rating:s rating:q threshold:2 pokemon female 1girl"`

- `--order <quality|popular|filesize|change>`
  - **Default:** `quality`
  - Adds `order:<value>` to tags

- `--rating <R>` (repeatable)
  - Adds `rating:<value>` to tags
  - If omitted, no rating filter is applied
  - Accepted aliases:
    - `g` or `safe` -> `s`
    - `r15` or `questionable` -> `q`
    - `r18` or `explicit` -> `e`

- `--threshold <1..5>`
  - Adds `threshold:<n>` to tags

### Pagination + API params

- `--lang <LANG>`
  - **Default:** `en`
  - Sets the `lang` query param

- `--limit <N>`
  - **Default:** `40`
  - Sets the `limit` query param (posts per request)

- `--default-threshold <N>`
  - Sets the `default_threshold` query param
  - This is separate from the `threshold:<n>` tag

- `--hide-posts-in-books <VALUE>`
  - Sets the `hide_posts_in_books` query param

- `--start-next <TOKEN>`
  - Start pagination from a known `meta.next` cursor token

- `--max-pages <N>`
  - **Default:** `0` (unlimited)
  - Maximum number of pages to fetch. `0` means keep going until `meta.next` is empty.

- `--sleep-secs <S>`
  - **Default:** `1.0`
  - Sleep time between requests (seconds)

### Output

- `--out <DIR>`
  - **Default:** `out`
  - Output directory

- `--urls-file <NAME>`
  - **Default:** `urls.txt`
  - Output filename inside `--out`

- `--append`
  - Append to existing `urls.txt`
  - Default is overwrite

- `--save-pages`
  - Save raw JSON pages into `out/pages/page_XXXXX.json`

### URL formatting

- `--post-base <URL>`
  - **Default:** `https://sankaku.app/posts/`
  - Base URL to prepend to each post ID

### Auth

- `--bearer <TOKEN>`
  - Use an explicit bearer token

- `SANKAKU_TOKEN` (env var)
  - Same behavior as `--bearer`

- `--gallery-dl-config <PATH>`
  - **Default:** `~/.config/gallery-dl/config.json`
  - Read `extractor.sankaku.username/password` from this config

- `--no-config`
  - Skip reading the gallery-dl config

### Extras

- `--header 'K: V'` (repeatable)
  - Add extra HTTP headers

- `--param 'k=v'` (repeatable)
  - Add extra query params

### Logging

- `-v` / `--verbose`
  - Enable debug logs

## Default behavior (no flags)

- Endpoint: `https://sankakuapi.com/v2/posts/keyset`
- Tags: `order:quality`
- Limit: `40`
- Sleep: `1s`
- Max pages: unlimited (until `meta.next` is empty)
- Output: `out/urls.txt` (overwritten)
- Auth: reads `~/.config/gallery-dl/config.json` if present

## Notes

- Tags are effectively case-insensitive on the API side; using lowercase is recommended.
- If you pass no tags or rating filters, the query can be very large and take a long time.
