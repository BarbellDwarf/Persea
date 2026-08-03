# UI Redesign Research: htmx + Askama + Tailwind CSS

## 1. htmx + Askama Patterns

### Template Hierarchy

Askama supports **template inheritance** via `{% extends "base.html" %}` and `{% block content %}`. Combined with htmx, you create a layered architecture:

```
templates/
  base.html          ← Full HTML shell (head, sidebar, scripts)
  layouts/
    app.html          ← extends base.html, adds sidebar + header
    minimal.html      ← extends base.html, for login/guac client
  pages/
    connections.html  ← extends app.html, fills block "content"
    sessions.html
    admin.html
  partials/
    sidebar.html      ← included in app.html
    table_rows.html   ← returned by htmx for partial swaps
    status_badge.html
    pagination.html
```

**Key pattern: full page vs. htmx fragment.** Check `HX-Request` header on the server side:

```rust
// In axum handler
async fn connections_page(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let is_htmx = headers.get("hx-request").is_some();
    let html = ConnectionsTemplate { /* data */ }.render().unwrap();
    
    if is_htmx {
        // Return just the content fragment (no sidebar, no head)
        Html(html)
    } else {
        // Return full page with layout
        let full = AppTemplate { content: html, /* ... */ }.render().unwrap();
        Html(full)
    }
}
```

**Askama template example — base layout:**

```jinja
{# templates/base.html #}
<!DOCTYPE html>
<html lang="en" class="{{ theme_class }}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ title }} - persea</title>
    <link rel="stylesheet" href="/css/tailwind.min.css">
    <script src="/js/htmx.min.js"></script>
    <script src="/js/htmx-response-targets.js"></script>
</head>
<body class="bg-gray-950 text-gray-100">
    {% block body %}{% endblock %}
</body>
</html>
```

**Askama template example — app layout with sidebar:**

```jinja
{# templates/layouts/app.html #}
{% extends "base.html" %}

{% block body %}
<div class="flex h-screen">
    {# Sidebar #}
    {% include "partials/sidebar.html" %}
    
    {# Main content area #}
    <div class="flex-1 flex flex-col overflow-hidden">
        {# Header bar #}
        <header class="h-16 border-b border-gray-800 flex items-center px-6">
            <button hx-get="/sidebar/toggle" hx-target="#sidebar" hx-swap="outerHTML"
                    class="lg:hidden mr-4 text-gray-400">
                <svg><!-- hamburger icon --></svg>
            </button>
            <h1 class="text-lg font-semibold">{{ page_title }}</h1>
            <div class="ml-auto flex items-center gap-4">
                {% block header_right %}{% endblock %}
            </div>
        </header>
        
        {# Page content #}
        <main id="page-content" class="flex-1 overflow-auto p-6">
            {% block content %}{% endblock %}
        </main>
    </div>
</div>
{% endblock %}
```

### htmx Partial Update Pattern

**Server returns HTML fragments, not JSON.** The handler renders a template and returns it directly:

```rust
async fn sessions_list(...) -> Html<String> {
    let sessions = get_active_sessions(&state);
    let html = SessionRowsTemplate { sessions }.render().unwrap();
    Html(html)
}
```

**Client triggers partial updates:**

```html
{# In page template #}
<table>
    <thead><tr><th>Name</th><th>Status</th><th>Actions</th></tr></thead>
    <tbody id="sessions-body"
           hx-get="/api/sessions"
           hx-trigger="load, every 5s"
           hx-swap="innerHTML">
        {# Server returns <tr> rows directly #}
    </tbody>
</table>
```

### OOB (Out-of-Band) Swaps

Update sidebar badge count when a session ends, without touching the sidebar:

```rust
// Server response includes OOB swap
// Main response goes to #sessions-body
// OOB element updates #session-count badge
```

```html
{# Response from server #}
<div id="session-count" hx-swap-oob="true">3</div>
<tr><td>Server-A</td><td>Connected</td></tr>
<tr><td>Server-B</td><td>Idle</td></tr>
```

### hx-boost for SPA-like Navigation

Enable `hx-boost` on the sidebar to convert all links into AJAX requests targeting the main content area:

```html
<nav hx-boost="true" hx-target="#page-content" hx-swap="innerHTML">
    <a href="/connections" class="nav-item">Connections</a>
    <a href="/sessions" class="nav-item">Active Sessions</a>
    <a href="/admin" class="nav-item">Admin</a>
</nav>
```

This makes every link an AJAX GET that swaps into `#page-content`, giving SPA-like behavior with zero JavaScript.

### History Support

Add `hx-push-url="true"` to links so the browser URL bar updates:

```html
<a href="/connections" hx-boost="true" hx-target="#page-content" 
   hx-push-url="true">Connections</a>
```

---

## 2. Tailwind CSS Setup with Askama

### Build Approach

Two options:

**Option A: Pre-built CSS (recommended for simplicity)**
- Run `npx tailwindcss -i ./input.css -o ./static/css/tailwind.min.css --minify` at build time
- Ship the pre-built CSS file alongside the binary
- No runtime CSS processing needed

**Option B: Tailwind CLI in build.rs**
- Run Tailwind CLI from `build.rs` to generate CSS during `cargo build`
- Keeps everything in one build step

**Recommended: Option A** — simpler, faster dev iteration, no Rust build system coupling.

### Cargo.toml additions

```toml
[dependencies]
askama = "0.14"
askama_axum = "0.5"  # For IntoResponse impl

[dev-dependencies]
# For template testing
```

### Directory structure

```
persea/
  templates/           ← Askama looks here by default
    base.html
    layouts/
    pages/
    partials/
  static/
    css/
      tailwind.min.css ← pre-built
    js/
      htmx.min.js
      htmx-response-targets.js
      theme.js
  src/
    templates.rs       ← template structs (askama derives)
```

### Tailwind Configuration (tailwind.config.js)

```js
module.exports = {
  content: [
    "./templates/**/*.html",
    "./static/**/*.html",  // any legacy pages
  ],
  darkMode: "class",      // class-based dark mode
  theme: {
    extend: {
      colors: {
        brand: {
          50:  '#eef2ff',
          100: '#e0e7ff',
          200: '#c7d2fe',
          300: '#a5b4fc',
          400: '#818cf8',
          500: '#6366f1',  // indigo-500 as primary
          600: '#4f46e5',
          700: '#4338ca',
          800: '#3730a3',
          900: '#312e81',
          950: '#1e1b4b',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
    },
  },
  plugins: [],
}
```

### Professional Color Palette (dark theme)

Based on Grafana/Portainer design language:

```
Background:     gray-950 (#030712) — near-black, not pure black
Surface:        gray-900 (#111827) — cards, panels
Surface-raised: gray-800 (#1f2937) — elevated elements
Border:         gray-800 (#1f2937) — subtle borders
Border-light:   gray-700 (#374151) — hover states
Text:           gray-100 (#f3f4f6) — primary text
Text-secondary: gray-400 (#9ca3af) — secondary info
Accent:         brand-500 (#6366f1) — links, buttons, active states
Success:        emerald-500 (#10b981) — connected, online
Warning:        amber-500 (#f59e0b) — idle, warning
Danger:         red-500 (#ef4444) — error, disconnected
Info:           sky-500 (#0ea5e9) — informational
```

### CSS Input File

```css
/* input.css */
@import "tailwindcss";

/* Custom base layer */
@layer base {
  :root {
    --color-brand: theme('colors.brand.500');
    --color-brand-hover: theme('colors.brand.600');
  }
  
  /* Scrollbar styling */
  * {
    scrollbar-width: thin;
    scrollbar-color: theme('colors.gray.700') transparent;
  }
  
  /* Smooth transitions */
  * {
    transition-property: background-color, border-color, color, fill, stroke;
    transition-timing-function: cubic-bezier(0.4, 0, 0.2, 1);
    transition-duration: 150ms;
  }
}
```

---

## 3. Sidebar Navigation

### Expandable Sections with htmx

The sidebar has two approaches: **server-rendered state** vs. **client-side toggle**.

**Recommended: Server-rendered active state, client-side expand/collapse.**

```jinja
{# templates/partials/sidebar.html #}
<aside id="sidebar" class="w-64 bg-gray-900 border-r border-gray-800 flex flex-col h-full">
    {# Logo #}
    <div class="h-16 flex items-center px-6 border-b border-gray-800">
        <span class="text-xl font-bold text-brand-400">persea</span>
    </div>
    
    {# Navigation #}
    <nav class="flex-1 overflow-y-auto py-4 px-3 space-y-1" hx-boost="true" hx-target="#page-content" hx-swap="innerHTML">
        
        {# User Section #}
        <div class="mb-4">
            <h3 class="px-3 mb-2 text-xs font-semibold text-gray-500 uppercase tracking-wider">Connections</h3>
            
            <a href="/connections"
               class="flex items-center gap-3 px-3 py-2 rounded-lg text-sm
                      {% if active_page == "connections" %}
                          bg-brand-500/10 text-brand-400
                      {% else %}
                          text-gray-300 hover:bg-gray-800 hover:text-white
                      {% endif %}">
                <svg class="w-5 h-5"><!-- server icon --></svg>
                Servers
            </a>
            
            <a href="/sessions"
               class="flex items-center gap-3 px-3 py-2 rounded-lg text-sm
                      {% if active_page == "sessions" %}
                          bg-brand-500/10 text-brand-400
                      {% else %}
                          text-gray-300 hover:bg-gray-800 hover:text-white
                      {% endif %}">
                <svg class="w-5 h-5"><!-- monitor icon --></svg>
                Active Sessions
                {% if session_count > 0 %}
                <span class="ml-auto bg-brand-500/20 text-brand-400 text-xs px-2 py-0.5 rounded-full">{{ session_count }}</span>
                {% endif %}
            </a>
            
            <a href="/quick-connect"
               class="flex items-center gap-3 px-3 py-2 rounded-lg text-sm
                      {% if active_page == "quick_connect" %}
                          bg-brand-500/10 text-brand-400
                      {% else %}
                          text-gray-300 hover:bg-gray-800 hover:text-white
                      {% endif %}">
                <svg class="w-5 h-5"><!-- zap icon --></svg>
                Quick Connect
            </a>
        </div>
        
        {# Admin Section (expandable) #}
        <div class="mb-4">
            <button hx-get="/sidebar/admin-section" hx-target="#admin-section" hx-swap="innerHTML"
                    class="flex items-center gap-3 px-3 py-2 rounded-lg text-sm w-full
                           text-gray-300 hover:bg-gray-800 hover:text-white">
                <svg class="w-5 h-5"><!-- cog icon --></svg>
                Administration
                <svg class="w-4 h-4 ml-auto chevron transition-transform" id="admin-chevron"><!-- chevron --></svg>
            </button>
            
            <div id="admin-section" class="hidden ml-3 mt-1 space-y-1">
                {# Admin items loaded on demand via htmx #}
            </div>
        </div>
        
        {# Account Section #}
        <div class="mb-4">
            <a href="/profile" class="nav-item ...">Profile</a>
            <a href="/tokens" class="nav-item ...">API Keys</a>
            <a href="/sessions/history" class="nav-item ...">Session History</a>
        </div>
    </nav>
    
    {# Footer #}
    <div class="border-t border-gray-800 p-4">
        <div class="flex items-center gap-3">
            <div class="w-8 h-8 rounded-full bg-brand-500/20 flex items-center justify-center text-brand-400 text-sm font-medium">
                {{ user_initials }}
            </div>
            <div class="flex-1 min-w-0">
                <p class="text-sm font-medium truncate">{{ username }}</p>
                <p class="text-xs text-gray-500">{{ role }}</p>
            </div>
            <button hx-post="/logout" hx-confirm="Sign out?" class="text-gray-400 hover:text-white">
                <svg class="w-5 h-5"><!-- logout icon --></svg>
            </button>
        </div>
    </div>
</aside>
```

### Sidebar Expand/Collapse with htmx

**Admin section loads only when clicked:**

```rust
async fn admin_section() -> Html<String> {
    let html = AdminSectionTemplate {}.render().unwrap();
    Html(html)
}
```

```jinja
{# templates/partials/admin_section.html — returned by htmx #}
<a href="/admin/users" class="nav-subitem">Users</a>
<a href="/admin/groups" class="nav-subitem">Groups</a>
<a href="/admin/roles" class="nav-subitem">Roles</a>
<a href="/admin/oidc" class="nav-subitem">Auth Settings</a>
<a href="/admin/audit" class="nav-subitem">Audit Logs</a>
<a href="/admin/reports" class="nav-subitem">Reports</a>
<a href="/admin/config" class="nav-subitem">System Config</a>
<a href="/docs" class="nav-subitem">Documentation</a>
```

### Active State from Server

The `active_page` variable is set by each handler:

```rust
struct PageContext {
    active_page: String,
    user: User,
    // ...
}
```

Each template uses the `{% if active_page == "..." %}` conditional to apply the active style class. This means the server always knows which page is active — no client-side state needed for this.

### Icons

Use **Heroicons** (by Tailwind Labs, MIT licensed). Include as inline SVGs or use a helper:

```rust
// templates/icons.rs or as Askama filters
fn icon_server() -> &'static str {
    r#"<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="w-5 h-5">
        <path stroke-linecap="round" stroke-linejoin="round" d="M5.25 14.25h13.5m-13.5 0a3 3 0 01-3-3m3 3a3 3 0 100 6h13.5a3 3 0 100-6m-16.5-3a3 3 0 013-3h13.5a3 3 0 013 3m-19.5 0a4.5 4.5 0 01.9-2.7L5.737 5.1a3.375 3.375 0 012.7-1.35h7.126c1.062 0 2.062.5 2.7 1.35l2.587 3.45a4.5 4.5 0 01.9 2.7m0 0a3 3 0 01-3 3m0 3h.008v.008h-.008v-.008zm0-6h.008v.008h-.008v-.008zm-3 6h.008v.008h-.008v-.008zm0-6h.008v.008h-.008v-.008z" />
    </svg>"#
}
```

---

## 4. Data Tables with htmx

### Server-Side Sort, Filter, Pagination

```rust
#[derive(Deserialize)]
struct TableParams {
    page: Option<u32>,
    per_page: Option<u32>,
    sort: Option<String>,
    order: Option<String>,
    search: Option<String>,
}

async fn connections_table(
    State(state): State<AppState>,
    Query(params): Query<TableParams>,
) -> Html<String> {
    let page = params.page.unwrap_or(1);
    let per_page = params.per_page.unwrap_or(20);
    let sort = params.sort.as_deref().unwrap_or("name");
    let order = params.order.as_deref().unwrap_or("asc");
    let search = params.search.as_deref().unwrap_or("");
    
    let entries = vault.list_connections(search, sort, order, page, per_page).await;
    let total = vault.count_connections(search).await;
    
    let html = ConnectionRowsTemplate {
        entries: &entries,
        page,
        per_page,
        total_pages: (total as f32 / per_page as f32).ceil() as u32,
        sort: sort.to_string(),
        order: order.to_string(),
    }.render().unwrap();
    
    Html(html)
}
```

### Client-Side Table with htmx

```html
{# templates/pages/connections.html #}
{% extends "layouts/app.html" %}

{% block content %}
<div class="space-y-4">
    {# Search bar #}
    <div class="flex items-center gap-4">
        <div class="relative flex-1 max-w-md">
            <input type="search" name="search" placeholder="Search connections..."
                   hx-get="/api/connections/table"
                   hx-trigger="input changed delay:300ms, search"
                   hx-target="#table-body"
                   hx-include="[name='sort'],[name='order']"
                   class="w-full bg-gray-900 border border-gray-700 rounded-lg px-4 py-2 pl-10 text-sm
                          focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none">
            <svg class="absolute left-3 top-2.5 w-5 h-5 text-gray-500"><!-- search icon --></svg>
        </div>
    </div>
    
    {# Table #}
    <div class="bg-gray-900 rounded-lg border border-gray-800 overflow-hidden">
        <table class="w-full text-sm">
            <thead class="bg-gray-800/50">
                <tr>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                        <button hx-get="/api/connections/table"
                                hx-vals='{"sort":"name","order":"{% if sort == "name" and order == "asc" %}desc{% else %}asc{% endif %}"}'
                                hx-target="#table-body" hx-include="[name='search']">
                            Name {% if sort == "name" %}{% if order == "asc" %}↑{% else %}↓{% endif %}{% endif %}
                        </button>
                    </th>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Type</th>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Status</th>
                    <th class="px-4 py-3 text-right text-xs font-medium text-gray-400 uppercase tracking-wider">Actions</th>
                </tr>
            </thead>
            <tbody id="table-body"
                   hx-get="/api/connections/table"
                   hx-trigger="load"
                   hx-swap="innerHTML"
                   class="divide-y divide-gray-800">
                {# Server returns <tr> rows #}
            </tbody>
        </table>
        
        {# Pagination #}
        <div id="pagination" class="border-t border-gray-800 px-4 py-3 flex items-center justify-between">
        </div>
    </div>
</div>
{% endblock %}
```

### Server-Rendered Table Rows

```jinja
{# templates/partials/connection_rows.html #}
{% for entry in entries %}
<tr class="hover:bg-gray-800/50">
    <td class="px-4 py-3">
        <div class="font-medium">{{ entry.name }}</div>
        <div class="text-xs text-gray-500">{{ entry.host }}</div>
    </td>
    <td class="px-4 py-3">
        <span class="inline-flex items-center gap-1 text-xs font-medium
            {% if entry.protocol == "ssh" %}text-emerald-400
            {% elif entry.protocol == "rdp" %}text-sky-400
            {% elif entry.protocol == "vnc" %}text-amber-400
            {% endif %}">
            <span class="w-1.5 h-1.5 rounded-full bg-current"></span>
            {{ entry.protocol | upper }}
        </span>
    </td>
    <td class="px-4 py-3">
        {% if entry.status == "connected" %}
        <span class="inline-flex items-center gap-1 text-xs text-emerald-400">
            <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
            Connected
        </span>
        {% elif entry.status == "idle" %}
        <span class="text-xs text-gray-500">Idle</span>
        {% else %}
        <span class="text-xs text-gray-600">Offline</span>
        {% endif %}
    </td>
    <td class="px-4 py-3 text-right">
        <a href="/connect/{{ entry.id }}" class="text-brand-400 hover:text-brand-300 text-sm">Connect</a>
    </td>
</tr>
{% endfor %}
```

### Pagination Component

```rust
async fn pagination(
    Query(params): Query<TableParams>,
) -> Html<String> {
    let page = params.page.unwrap_or(1);
    let total_pages = calculate_total_pages(&params).await;
    
    let html = PaginationTemplate { page, total_pages, sort: params.sort.clone(), order: params.order.clone() }
        .render().unwrap();
    Html(html)
}
```

```jinja
{# templates/partials/pagination.html #}
<span class="text-sm text-gray-400">
    Page {{ page }} of {{ total_pages }}
</span>
<div class="flex gap-1">
    {% if page > 1 %}
    <button hx-get="/api/connections/pagination"
            hx-vals='{"page":{{ page - 1 }},"sort":"{{ sort }}","order":"{{ order }}"}'
            hx-target="#pagination" hx-swap="outerHTML"
            class="px-3 py-1 rounded bg-gray-800 text-gray-300 hover:bg-gray-700">
        ← Prev
    </button>
    {% endif %}
    {% if page < total_pages %}
    <button hx-get="/api/connections/pagination"
            hx-vals='{"page":{{ page + 1 }},"sort":"{{ sort }}","order":"{{ order }}"}'
            hx-target="#pagination" hx-swap="outerHTML"
            class="px-3 py-1 rounded bg-gray-800 text-gray-300 hover:bg-gray-700">
        Next →
    </button>
    {% endif %}
</div>
```

---

## 5. Guacamole Client Integration

### Current State

The existing `static/client.html` loads the Guacamole JS client and connects via WebSocket. It takes a session ID as a URL parameter.

### Recommended: Embed in iframe with layout wrapper

```rust
async fn connect_page(
    Path(session_id): Path<String>,
) -> Html<String> {
    let html = ConnectTemplate { session_id }.render().unwrap();
    Html(html)
}
```

```jinja
{# templates/pages/connect.html #}
{% extends "layouts/app.html" %}

{% block content %}
<div class="h-full flex flex-col">
    {# Toolbar #}
    <div class="h-12 bg-gray-900 border-b border-gray-800 flex items-center px-4 gap-3 shrink-0">
        <a href="/sessions" class="text-gray-400 hover:text-white">
            <svg class="w-5 h-5"><!-- arrow-left icon --></svg>
        </a>
        <span class="text-sm font-medium">{{ session_name }}</span>
        <span class="text-xs text-gray-500">{{ protocol | upper }}</span>
        
        <div class="ml-auto flex items-center gap-2">
            {# Clipboard, keyboard shortcuts, disconnect buttons #}
            <button class="px-3 py-1 text-xs rounded bg-gray-800 text-gray-300 hover:bg-gray-700">
                Clipboard
            </button>
            <button hx-post="/api/sessions/{{ session_id }}/disconnect"
                    hx-confirm="Disconnect session?"
                    class="px-3 py-1 text-xs rounded bg-red-500/10 text-red-400 hover:bg-red-500/20">
                Disconnect
            </button>
        </div>
    </div>
    
    {# Guacamole client in iframe #}
    <div id="guac-container" class="flex-1 bg-black relative">
        <iframe src="/guac/client.html?session={{ session_id }}"
                class="w-full h-full border-0"
                allow="clipboard-read; clipboard-write">
        </iframe>
    </div>
</div>
{% endblock %}
```

### Why iframe (not WebSocket proxy)

- **Separation of concerns**: Guacamole JS client is complex, self-contained
- **No Rust dependencies**: The JS client handles protocol directly via WebSocket
- **Existing code works**: `static/guac/` already has the working client
- **Cleaner architecture**: Main app handles UI, iframe handles remote desktop

### Session ID Passing

URL parameter pattern: `/guac/client.html?session={session_id}`

The session ID is already generated and stored. The iframe loads the existing Guacamole JS client which connects via WebSocket using that session ID.

### Alternative: Dedicated route with embedded client

If you want full control, you could serve the Guacamole client HTML from a Rust handler that injects the session ID:

```rust
async fn guac_client(
    Path(session_id): Path<String>,
) -> Html<String> {
    let html = GuacClientTemplate { session_id }.render().unwrap();
    Html(html)
}
```

But the iframe approach is simpler and keeps the Guacamole JS code isolated.

---

## 6. Design References

### What Makes Grafana/Portainer Look Professional

1. **Consistent spacing system** — 4px/8px grid. Tailwind's default scale is already this.
2. **Muted backgrounds** — Near-black (`gray-950`) with subtle elevation via `gray-900` surfaces.
3. **One accent color** — Used sparingly for CTAs and active states. Everything else is neutral.
4. **Monospace for data** — Connection IDs, timestamps, IPs use `font-mono`.
5. **Status indicators** — Small colored dots (green/amber/red) with pulse animation for active states.
6. **Compact data density** — Tables are dense but readable. Small font sizes (`text-sm`, `text-xs`).
7. **Subtle borders** — 1px borders in `gray-800`, never `gray-600` or lighter.
8. **No shadows** — Borders instead of box-shadows for depth (Portainer pattern).
9. **Icon + label pattern** — Every nav item has a small icon (20px) + text.
10. **Header bar is minimal** — Just breadcrumbs/title + user menu. No heavy header.

### Color Palette Comparison

| Element | Grafana | Portainer | persea |
|---------|---------|-----------|----------|
| Background | `#0b0e11` | `#1a1d21` | `gray-950` |
| Surface | `#181b1f` | `#2c3136` | `gray-900` |
| Border | `#2c3136` | `#3d4450` | `gray-800` |
| Text | `#d8dee9` | `#fff` | `gray-100` |
| Accent | `#ff6600` | `#3b82f6` | `brand-500` |
| Success | `#73bf69` | `#23a55a` | `emerald-500` |

---

## 7. Dark/Light Theme

### System Preference Detection + Manual Toggle

```javascript
// static/js/theme.js
(function() {
    const STORAGE_KEY = 'theme';
    
    function getTheme() {
        const stored = localStorage.getItem(STORAGE_KEY);
        if (stored) return stored;
        return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }
    
    function setTheme(theme) {
        document.documentElement.classList.toggle('dark', theme === 'dark');
        document.documentElement.classList.toggle('light', theme === 'light');
        localStorage.setItem(STORAGE_KEY, theme);
    }
    
    // Apply on load (inline in <head> to avoid FOUC)
    setTheme(getTheme());
    
    // Listen for OS changes
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
        if (!localStorage.getItem(STORAGE_KEY)) {
            setTheme(e.matches ? 'dark' : 'light');
        }
    });
    
    // Expose toggle function
    window.toggleTheme = function() {
        const current = document.documentElement.classList.contains('dark') ? 'dark' : 'light';
        setTheme(current === 'dark' ? 'light' : 'dark');
    };
    
    window.setThemeMode = function(mode) {
        if (mode === 'system') {
            localStorage.removeItem(STORAGE_KEY);
            setTheme(getTheme());
        } else {
            setTheme(mode);
        }
    };
})();
```

### Inline script in base.html (avoid FOUC)

```html
{# templates/base.html — inside <head> #}
<script>
    (function(){
        var t=localStorage.getItem('theme');
        var d=t||(matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light');
        document.documentElement.classList.add(d);
    })();
</script>
```

### Three-way toggle in header

```html
{# templates/partials/theme-toggle.html #}
<div class="relative" x-data="{ open: false }">
    <button @click="open = !open" class="p-2 rounded-lg text-gray-400 hover:text-white hover:bg-gray-800">
        <svg id="theme-icon-dark" class="w-5 h-5 hidden dark:block"><!-- sun icon --></svg>
        <svg id="theme-icon-light" class="w-5 h-5 dark:hidden"><!-- moon icon --></svg>
    </button>
    
    <div x-show="open" @click.away="open = false"
         class="absolute right-0 mt-2 w-36 bg-gray-800 border border-gray-700 rounded-lg shadow-xl py-1 z-50">
        <button onclick="setThemeMode('light')" class="w-full px-4 py-2 text-sm text-left hover:bg-gray-700">Light</button>
        <button onclick="setThemeMode('dark')" class="w-full px-4 py-2 text-sm text-left hover:bg-gray-700">Dark</button>
        <button onclick="setThemeMode('system')" class="w-full px-4 py-2 text-sm text-left hover:bg-gray-700">System</button>
    </div>
</div>
```

Note: Use Alpine.js (13KB) for the dropdown, or implement with pure htmx + hyperscript if you want zero JS dependencies.

### Tailwind Dark Mode Setup

```css
/* input.css */
@import "tailwindcss";

@custom-variant dark (&:where(.dark, .dark *));
```

All `dark:` prefixed utilities now apply when `<html class="dark">` is set.

---

## 8. Responsive Design

### Desktop-First (Recommended for Remote Access)

Remote access tools are used primarily on desktops. But the admin UI should be usable on tablets for monitoring.

```html
{# Sidebar responsive behavior #}
<div class="flex h-screen">
    {# Sidebar: hidden on mobile, toggle with hamburger #}
    <aside id="sidebar"
           class="w-64 bg-gray-900 border-r border-gray-800 
                  lg:relative lg:translate-x-0
                  fixed inset-y-0 left-0 z-40 transform -translate-x-full transition-transform">
        {# ... sidebar content ... #}
    </aside>
    
    {# Overlay on mobile #}
    <div id="sidebar-overlay" class="fixed inset-0 bg-black/50 z-30 hidden lg:hidden"
         onclick="document.getElementById('sidebar').classList.add('-translate-x-full'); this.classList.add('hidden');">
    </div>
    
    {# Main content #}
    <div class="flex-1 flex flex-col min-w-0">
        {# Header with hamburger for mobile #}
        <header class="h-16 border-b border-gray-800 flex items-center px-4 lg:px-6">
            <button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full'); document.getElementById('sidebar-overlay').classList.toggle('hidden');"
                    class="lg:hidden mr-4 p-2 rounded-lg text-gray-400 hover:text-white hover:bg-gray-800">
                <svg class="w-5 h-5"><!-- menu icon --></svg>
            </button>
            {# ... rest of header ... #}
        </header>
    </div>
</div>
```

### Breakpoints

- `lg:` (1024px) — Full sidebar visible
- `md:` (768px) — Sidebar can be toggled
- `sm:` (640px) — Compact table mode, stacked layout
- Below 640px — Mobile: sidebar as overlay, stacked content

---

## 9. Component Patterns

### Status Badge

```jinja
{# templates/partials/status_badge.html #}
{% macro status_badge(status) %}
<span class="inline-flex items-center gap-1.5 text-xs font-medium
    {% if status == "connected" %}text-emerald-400
    {% elif status == "connecting" %}text-amber-400
    {% elif status == "error" %}text-red-400
    {% else %}text-gray-500{% endif %}">
    <span class="w-1.5 h-1.5 rounded-full bg-current
        {% if status == "connected" %}animate-pulse{% endif %}"></span>
    {{ status | capitalize }}
</span>
{% endmacro %}
```

### Card Layout

```html
<div class="bg-gray-900 border border-gray-800 rounded-lg p-6">
    <h3 class="text-lg font-semibold mb-4">Quick Connect</h3>
    <form hx-post="/api/quick-connect" hx-target="#quick-result">
        <input name="target" placeholder="user@host:port" 
               class="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-sm
                      focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none mb-3">
        <button type="submit" class="w-full bg-brand-500 hover:bg-brand-600 text-white font-medium py-2 px-4 rounded-lg text-sm">
            Connect
        </button>
    </form>
    <div id="quick-result" class="mt-4"></div>
</div>
```

### Modal Dialog

```html
{# Trigger #}
<button hx-get="/admin/users/new" hx-target="#modal-container" hx-swap="innerHTML">
    Add User
</button>

{# Modal container (in base layout) #}
<div id="modal-container"></div>

{# Server returns this fragment #}
<div class="fixed inset-0 z-50 flex items-center justify-center">
    <div class="fixed inset-0 bg-black/60" hx-get="/api/modal/close" hx-target="#modal-container" hx-swap="innerHTML"></div>
    <div class="relative bg-gray-900 border border-gray-800 rounded-xl shadow-2xl w-full max-w-md p-6 mx-4">
        <h2 class="text-lg font-semibold mb-4">Add User</h2>
        <form hx-post="/api/admin/users" hx-target="#page-content" hx-swap="innerHTML">
            {# form fields #}
        </form>
    </div>
</div>
```

### Empty State

```html
<div class="text-center py-12">
    <svg class="mx-auto h-12 w-12 text-gray-600"><!-- icon --></svg>
    <h3 class="mt-2 text-sm font-medium text-gray-300">No connections</h3>
    <p class="mt-1 text-sm text-gray-500">Get started by adding your first connection.</p>
    <div class="mt-6">
        <button class="bg-brand-500 hover:bg-brand-600 text-white px-4 py-2 rounded-lg text-sm">
            Add Connection
        </button>
    </div>
</div>
```

---

## 10. Migration Strategy

### Phase 1: Foundation (no feature changes)
1. Add `askama` + `askama_axum` dependencies
2. Set up Tailwind CSS build pipeline
3. Create base template with sidebar layout
4. Migrate one page (e.g., connections) to prove the pattern
5. Set up htmx + theme.js

### Phase 2: Core pages
6. Migrate sessions, admin, tokens pages
7. Add htmx partial updates for live data
8. Implement data tables with sort/filter/pagination

### Phase 3: Polish
9. Dark/light theme toggle
10. Responsive sidebar
11. Loading indicators, error states
12. Accessibility (ARIA labels, keyboard nav)

### Key Architectural Decision: Hybrid Approach

Keep existing `static/` HTML files for backward compatibility during migration. New pages go into `templates/`. The router serves both:

```rust
// Existing: serve static files
.nest_service("/static", ServeDir::new("static"))

// New: Askama templates
.route("/connections", get(connections_page))
.route("/sessions", get(sessions_page))

// API endpoints remain the same, just return HTML instead of JSON
.route("/api/connections/table", get(connections_table))
```

---

## Summary: Recommended Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| Templating | Askama 0.14 | Compile-time type safety, Jinja syntax, template inheritance |
| Interactivity | htmx 2.x | Server-driven, zero JS framework, SPA-like UX |
| Styling | Tailwind CSS 4.x | Utility-first, dark mode, consistent spacing |
| Icons | Heroicons (inline SVG) | By Tailwind Labs, MIT, consistent style |
| Dropdowns | Alpine.js (optional) | 13KB, for theme toggle, dropdowns if needed |
| Remote client | Existing Guacamole JS | iframe embed, no Rust changes needed |
| Theme | Class-based dark mode | localStorage + system preference detection |
