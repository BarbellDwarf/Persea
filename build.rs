use pulldown_cmark::{html, Options, Parser};
use regex::Regex;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;

/// Ordered list of doc files to render. This order drives the docs page
/// section nav, so it doubles as the reading order: overview, install,
/// deploy, operations (HA, reverse proxies), reference material, then the
/// troubleshooting and theming guides near the end. FUNDING.md stays out.
const DOC_FILES: &[&str] = &[
    "overview.md",
    "installation.md",
    "deployment-guide.md",
    "high-availability.md",
    "reverse-proxies.md",
    "configuration.md",
    "credential-variables.md",
    "reports.md",
    "rdp-video-performance.md",
    "web-sessions.md",
    "vdi.md",
    "security-hardening.md",
    "roles-and-access-control.md",
    "integrations.md",
    "netbox.md",
    "migration.md",
    "api.md",
    "troubleshooting.md",
    "themes.md",
];

fn main() {
    println!("cargo::rerun-if-changed=docs/");

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let out_path = Path::new(&out_dir).join("docs-rendered.rs");
    let mut out = fs::File::create(&out_path).expect("Failed to create docs-rendered.rs");

    // Page-wide heading-id dedupe: all docs render on one page, so slugs
    // must be unique across the whole DOCS set, not just within one doc.
    let mut seen: HashMap<String, usize> = HashMap::new();

    writeln!(out, "#[allow(missing_docs)]").unwrap();
    writeln!(out, "pub const DOCS: &[(&str, &str, &str, &[(&str, &str)])] = &[").unwrap();

    for filename in DOC_FILES {
        let path = Path::new("docs").join(filename);
        let md = match fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("cargo:warning=Could not read {}: {}", path.display(), e);
                continue;
            }
        };

        // Derive slug from filename (strip .md)
        let slug = filename.trim_end_matches(".md");

        // Extract title from first # heading
        let title = md
            .lines()
            .find(|l| l.starts_with("# "))
            .map(|l| l.trim_start_matches("# ").trim())
            .unwrap_or(slug);

        // Render markdown to HTML
        let opts =
            Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH | Options::ENABLE_TASKLISTS;
        let parser = Parser::new_ext(&md, opts);
        let mut html_output = String::new();
        html::push_html(&mut html_output, parser);

        // Rewrite .md links for the docs viewer
        // [text](current.md#section) → [text](#section) (same-doc)
        // [text](other.md#section) → [text](#other) (cross-doc, drops the anchor)
        // [text](docs/other.md) → [text](#other)
        html_output = rewrite_doc_links(&html_output, slug);

        // Give h2/h3/h4 headings GitHub-style ids and collect the h2/h3
        // (slug, text) pairs that form the two-level nav for this doc. The
        // dedupe map is shared across docs: every doc renders on the same
        // page, so heading ids must be unique page-wide.
        let mut headings: Vec<(String, String)> = Vec::new();
        html_output = slugify_headings(&html_output, &mut seen, &mut headings);

        // Escape for Rust string literal
        let escaped = escape_str(&html_output);
        let title_escaped = escape_str(title);

        writeln!(out, "    (\"{slug}\", \"{title_escaped}\", \"{escaped}\", &[").unwrap();
        for (h_slug, h_text) in &headings {
            let escaped_h = escape_str(h_slug);
            let escaped_t = escape_str(h_text);
            writeln!(out, "        (\"{escaped_h}\", \"{escaped_t}\"),").unwrap();
        }
        writeln!(out, "    ]),").unwrap();
    }

    writeln!(out, "];").unwrap();
}

/// Escape a string for embedding in a Rust string literal.
fn escape_str(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "")
}

/// Rewrite markdown-style .md links to docs viewer hash routes.
/// [text](current.md#section) → [text](#section) (same-doc anchor kept)
/// [text](other.md#section) → [text](#other) (cross-doc, drops the anchor:
/// the anchor cannot resolve inside a different doc section)
/// [text](other.md) → [text](#other)
/// [text](docs/other.md) → [text](#other)
fn rewrite_doc_links(html: &str, current_slug: &str) -> String {
    let re = Regex::new(r#"href="(?:docs/)?([a-z0-9_-]+\.md)(?:#([^"]*))?""#).unwrap();
    re.replace_all(html, |caps: &regex::Captures| {
        let slug = caps[1].trim_end_matches(".md");
        match caps.get(2) {
            Some(anchor) if slug == current_slug => format!("href=\"#{}\"", anchor.as_str()),
            _ => format!("href=\"#{}\"", slug),
        }
    })
    .into_owned()
}

/// GitHub-style slug for a heading: lowercase, keep letters/digits/`_`/
/// hyphens, drop all other punctuation, then turn every space into a
/// hyphen. Matches github-slugger so the ids resolve the anchor hrefs the
/// markdown already uses (e.g. `#windows-rdp-server-tuning`).
fn github_slug(text: &str) -> String {
    let mut cleaned = String::new();
    for c in text.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == ' ' {
            cleaned.push(c);
        }
    }
    cleaned.replace(' ', "-").to_lowercase()
}

/// Strip HTML tags and decode the entities pulldown_cmark can emit in
/// heading text, yielding the plain heading text.
fn heading_text(html: &str) -> String {
    let mut text = String::new();
    let mut in_tag = false;
    for c in html.chars() {
        if c == '<' {
            in_tag = true;
        } else if c == '>' {
            in_tag = false;
        } else if !in_tag {
            text.push(c);
        }
    }
    text.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&#x27;", "'")
}

/// Assign GitHub-style ids to h2/h3/h4 headings in the rendered HTML and
/// collect the h2/h3 (slug, text) pairs for the docs nav, in document
/// order. `seen` is shared across all docs so ids stay unique on the
/// single rendered page; colliding slugs get -2/-3 suffixes. h1 (the doc
/// title) gets no id: the section wrapper already anchors it.
fn slugify_headings(
    html: &str,
    seen: &mut HashMap<String, usize>,
    nav: &mut Vec<(String, String)>,
) -> String {
    let re = Regex::new(r"(?s)<h([234])>(.*?)</h\1>").unwrap();
    re.replace_all(html, |caps: &regex::Captures| {
        let level: u8 = caps[1].parse().unwrap();
        let inner = caps.get(2).unwrap().as_str();
        let text = heading_text(inner);
        let base = github_slug(&text);
        let id = if base.is_empty() {
            String::new()
        } else {
            let count = seen.entry(base.clone()).or_insert(0);
            *count += 1;
            if *count == 1 {
                base
            } else {
                format!("{base}-{count}")
            }
        };
        if level <= 3 && !id.is_empty() {
            nav.push((id.clone(), text));
        }
        if id.is_empty() {
            format!("<h{level}>{inner}</h{level}>")
        } else {
            format!("<h{level} id=\"{id}\">{inner}</h{level}>")
        }
    })
    .into_owned()
}
