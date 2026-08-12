function _deriveCard(hex) {
    var r = parseInt(hex.slice(1, 3), 16);
    var g = parseInt(hex.slice(3, 5), 16);
    var b = parseInt(hex.slice(5, 7), 16);
    var brightness = (r * 299 + g * 587 + b * 114) / 1000;
    var shift = brightness < 128 ? 16 : 8;
    r = Math.min(255, r + shift);
    g = Math.min(255, g + shift);
    b = Math.min(255, b + shift);
    return '#' + ((1 << 24) + (r << 16) + (g << 8) + b).toString(16).slice(1);
}
function applyThemeColors(colors) {
    var r = document.documentElement.style;
    for (var k in colors) r.setProperty('--' + k.replace(/_/g, '-'), colors[k]);
    if (colors.bg) { r.setProperty('--bg-primary', colors.bg); r.setProperty('--bg-card', colors.card || _deriveCard(colors.bg)); }
    if (colors.surface) r.setProperty('--bg-secondary', colors.surface);
    if (colors.input) r.setProperty('--bg-input', colors.input);
    if (colors.bg && colors.surface) r.setProperty('--bg-hover', colors.surface);
    if (colors.text) r.setProperty('--text-primary', colors.text);
    if (colors.text_dim) r.setProperty('--text-secondary', colors.text_dim);
    if (colors.accent) r.setProperty('--border-focus', colors.accent);
    if (colors.accent_hover) r.setProperty('--accent-hover', colors.accent_hover);
    var s = document.getElementById('bg-pattern-style');
    if (!s) { s = document.createElement('style'); s.id = 'bg-pattern-style'; document.head.appendChild(s); }
    s.textContent = colors.bg_pattern && colors.bg_pattern !== 'none' ? 'body{background-image:' + colors.bg_pattern + ';background-attachment:fixed}' : '';
    _lastAppliedColors = colors;
    localStorage.setItem('persea_theme_colors', JSON.stringify(colors));
}
var _themePresets = {}, _adminPreset = 'aurora', _adminColors = null, _lastAppliedColors = null;
var _themeDescriptions = { dark: 'Red & teal on navy', light: 'Blue & teal on white', 'high-contrast': 'High-contrast red & green on black', terminal: 'Amber & green on near-black', nord: 'Arctic ice blue & sage', corporate: 'Blue & orange on slate', aurora: 'Blue & cyan on midnight', jaguar: 'Gold & emerald on dark green' };

// Deep-compare two color maps (both produced by serde_json, so key sets are
// identical for palettes of the same theme set).
function _sameColors(a, b) {
    if (!a || !b) return false;
    var ka = Object.keys(a);
    if (ka.length !== Object.keys(b).length) return false;
    for (var i = 0; i < ka.length; i++) {
        var k = ka[i];
        if (a[k] !== b[k]) return false;
    }
    return true;
}

// The settings UI exposes a single "primary color". When the admin customized
// the primary (and didn't separately configure the accent), drive the accent
// from it too, so buttons, the active nav state and focus rings pick up the
// brand color — those render with --accent/--border-focus in app.css.
function _applyAdminAccent(colors, presetName, presets) {
    var c = {};
    for (var k in colors) c[k] = colors[k];
    var base = presets[presetName];
    if (base && c.primary && c.primary !== base.primary &&
        (!c.accent || c.accent === base.accent)) {
        c.accent = c.primary;
        if (c.primary_hover) c.accent_hover = c.primary_hover;
    }
    return c;
}

// Resolve the effective mode the user is in (stored choice, or the OS
// preference when set to auto). Shared by initTheme and toggleTheme so both
// adapt palettes identically.
function _resolvedMode() {
    var stored = localStorage.getItem('theme') || 'auto';
    if (stored === 'auto') {
        return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }
    return stored;
}

// Adapt a palette to the user's current mode. Light mode swaps the background
// family to whites while keeping the theme's accent colors; dark/auto keep the
// palette as authored. Same math as toggleTheme's per-mode branches.
function _adaptToMode(colors) {
    if (!colors || _resolvedMode() !== 'light') return colors;
    var light = {};
    for (var k in colors) light[k] = colors[k];
    light.bg = '#f8fafc'; light.bg_pattern = 'none';
    light.surface = '#fff'; light.input = '#f1f5f9';
    light.text = '#1e293b'; light.text_muted = '#64748b';
    light.text_dim = '#94a3b8'; light.border = '#e2e8f0';
    light.text_on_primary = '#fff'; light.btn_disabled = '#cbd5e1';
    return light;
}

// Re-apply the persisted color palette — but only when nothing fresh has been
// applied yet. initTheme calls this after its own applyThemeColors, so a
// just-computed (mode-adapted, current-branding) palette always wins over the
// persisted one; the persisted palette only fills in for pages where
// initTheme had nothing to apply (login, or no preset and no admin branding).
function _restorePersistedColors() {
    var saved = localStorage.getItem('persea_theme_colors');
    if (!saved || _lastAppliedColors) return;
    try { applyThemeColors(JSON.parse(saved)); } catch (e) {}
}

function initTheme(t) {
    if (!t) return;
    _themePresets = t.presets || {};
    _adminPreset = t.admin_preset || 'aurora';
    var userTheme = localStorage.getItem('persea_theme');
    var active = userTheme && _themePresets[userTheme] ? userTheme : null;
    if (active) {
        // Explicit user choice always wins over admin branding. Adapt it to
        // the current mode so a refresh doesn't re-apply the raw (dark)
        // palette on top of a persisted light-mode adaptation.
        applyThemeColors(_adaptToMode(_themePresets[active]));
        _adminColors = null;
    } else if (t.admin_colors) {
        // Admin branding applies when the user never picked a preset. Only
        // when the admin actually configured something, though — the resolved
        // default (aurora) must not override the app.css green look.
        var base = _themePresets[_adminPreset];
        var customized = _adminPreset !== 'aurora' || !base || !_sameColors(t.admin_colors, base);
        if (customized) {
            _adminColors = _applyAdminAccent(t.admin_colors, _adminPreset, _themePresets);
            applyThemeColors(_adaptToMode(_adminColors));
        } else {
            _adminColors = null;
        }
    }
    if (t.logo_url) { var l = document.getElementById('site-logo'); if (l) { if (l.src !== t.logo_url && !l.src.endsWith(t.logo_url)) l.src = t.logo_url; l.style.display = ''; } }
    var menu = document.getElementById('um-theme-list');
    if (menu) {
        menu.innerHTML = '';
        // "Default" option — clears preset, restores CSS green defaults
        // (or the admin branding when one is configured)
        var defItem = document.createElement('div');
        defItem.className = 'um-item' + (!active ? ' active' : '');
        var defSw = document.createElement('span');
        defSw.className = 'um-swatch';
        defSw.style.background = 'linear-gradient(135deg, #059669 50%, #10b981 50%)';
        defItem.appendChild(defSw);
        var defInfo = document.createElement('div');
        defInfo.className = 'um-theme-info';
        var defNm = document.createElement('span');
        defNm.className = 'um-theme-name';
        defNm.textContent = 'default';
        defInfo.appendChild(defNm);
        var defDesc = document.createElement('span');
        defDesc.className = 'um-theme-desc';
        defDesc.textContent = _adminColors ? 'Admin branding — colors from settings' : 'Persea green — the original';
        defInfo.appendChild(defDesc);
        defItem.appendChild(defInfo);
        defItem.addEventListener('click', function() {
            localStorage.removeItem('persea_theme');
            localStorage.removeItem('persea_theme_colors');
            document.documentElement.style.cssText = '';
            if (_adminColors) applyThemeColors(_adaptToMode(_adminColors));
            menu.querySelectorAll('.um-item').forEach(function(el) { el.classList.remove('active'); });
            defItem.classList.add('active');
            document.getElementById('user-menu').style.display = 'none';
        });
        menu.appendChild(defItem);
        Object.keys(_themePresets).forEach(function(name) {
            var item = document.createElement('div');
            item.className = 'um-item' + (name === active ? ' active' : '');
            var sw = document.createElement('span');
            sw.className = 'um-swatch';
            var p = _themePresets[name];
            sw.style.background = 'linear-gradient(135deg,' + p.primary + ' 50%,' + p.accent + ' 50%)';
            item.appendChild(sw);
            var info = document.createElement('div');
            info.className = 'um-theme-info';
            var nm = document.createElement('span');
            nm.className = 'um-theme-name';
            nm.textContent = name;
            info.appendChild(nm);
            var desc = document.createElement('span');
            desc.className = 'um-theme-desc';
            desc.textContent = _themeDescriptions[name] || '';
            info.appendChild(desc);
            item.appendChild(info);
            item.addEventListener('click', function() {
                localStorage.setItem('persea_theme', name);
                applyThemeColors(_adaptToMode(_themePresets[name]));
                _adminColors = null;
                menu.querySelectorAll('.um-item').forEach(function(el) { el.classList.remove('active'); });
                item.classList.add('active');
                document.getElementById('user-menu').style.display = 'none';
            });
            menu.appendChild(item);
        });
    }
    // Runs after every applyThemeColors above: a fresh mode-adapted palette is
    // already in place (and wins), the persisted one only fills in when
    // initTheme had nothing to apply.
    _restorePersistedColors();
}
var _ub = document.getElementById('user-menu-btn');
if (_ub) _ub.addEventListener('click', function(e) { e.stopPropagation(); var m = document.getElementById('user-menu'); m.style.display = m.style.display === 'block' ? 'none' : 'block'; });
document.addEventListener('click', function() { var m = document.getElementById('user-menu'); if (m) m.style.display = 'none'; });

// ── Dark / Light / Auto toggle ──────────────────────────────
(function() {
    var root = document.documentElement;
    var mq = window.matchMedia('(prefers-color-scheme: dark)');
    var stored = localStorage.getItem('theme');
    var theme = stored || 'auto';

    function applyClass(mode) {
        root.classList.remove('dark', 'light');
        if (mode === 'auto') {
            root.classList.add(mq.matches ? 'dark' : 'light');
        } else {
            root.classList.add(mode);
        }
        updateToggleLabel();
    }

    var _svgMonitor = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>';
    var _svgSun = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.93 4.93l1.41 1.41m11.32 11.32l1.41 1.41M2 12h2m16 0h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/></svg>';
    var _svgMoon = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg>';

    function updateToggleLabel() {
        var btn = document.getElementById('theme-toggle');
        if (!btn) return;
        var labels = { dark: 'Dark', light: 'Light', auto: 'Auto' };
        var svgs = { dark: _svgMoon, light: _svgSun, auto: _svgMonitor };
        var current = localStorage.getItem('theme') || 'auto';
        btn.title = 'Theme: ' + (labels[current] || current) + ' (click to cycle)';
        var icon = btn.querySelector('.theme-icon');
        if (icon) {
            icon.innerHTML = svgs[current] || _svgMonitor;
        } else {
            var s = document.createElement('span');
            s.className = 'theme-icon';
            s.innerHTML = svgs[current] || _svgMonitor;
            btn.appendChild(s);
        }
    }

    applyClass(theme);

    // Restore the persisted palette (mode-adapted from the user's last
    // interaction). initTheme, when it runs, re-applies a fresh mode-adapted
    // palette right after this — and calls _restorePersistedColors again — so
    // stale or wrong-mode colors never survive a page that has theme data.
    _restorePersistedColors();

    if (stored === 'auto' || !stored) {
        mq.addEventListener('change', function() {
            if ((localStorage.getItem('theme') || 'auto') === 'auto') {
                applyClass('auto');
            }
        });
    }

    window.toggleTheme = function() {
        var current = localStorage.getItem('theme') || 'auto';
        var next = current === 'dark' ? 'light' : current === 'light' ? 'auto' : 'dark';
        localStorage.setItem('theme', next);
        applyClass(next);
        var userPreset = localStorage.getItem('persea_theme');
        var preset = (userPreset && _themePresets[userPreset]) ? _themePresets[userPreset] : null;
        if (preset && preset.bg) {
            // Preset wins over admin branding; adapt it to the chosen mode.
            applyThemeColors(_adaptToMode(preset));
        } else if (_adminColors) {
            // No preset — admin branding still applies; adapt it to the
            // chosen mode like the preset branch above does.
            applyThemeColors(_adaptToMode(_adminColors));
        } else {
            // Clear stale color overrides so CSS rules handle it
            localStorage.removeItem('persea_theme_colors');
            document.documentElement.style.cssText = '';
            // No user preset — apply built-in dark/light palette so toggle has visual effect
            if (!localStorage.getItem('persea_theme')) {
                var darkPalette = {
                    bg: '#0a0f1a', surface: '#111827', input: '#1e293b',
                    text: '#f1f5f9', text_muted: '#94a3b8', text_dim: '#64748b',
                    border: '#2a3548', accent: '#10b981', accent_hover: '#059669',
                    primary: '#10b981', primary_hover: '#059669',
                    bg_pattern: 'none'
                };
                var lightPalette = {
                    bg: '#f8fafc', surface: '#ffffff', input: '#f1f5f9',
                    text: '#1e293b', text_muted: '#64748b', text_dim: '#94a3b8',
                    border: '#e2e8f0', accent: '#10b981', accent_hover: '#059669',
                    primary: '#10b981', primary_hover: '#059669',
                    bg_pattern: 'none'
                };
                applyThemeColors(_resolvedMode() === 'dark' ? darkPalette : lightPalette);
            }
        }
    };
})();
