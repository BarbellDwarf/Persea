function applyThemeColors(colors) {
    var r = document.documentElement.style;
    for (var k in colors) r.setProperty('--' + k.replace(/_/g, '-'), colors[k]);
    if (colors.bg) { r.setProperty('--bg-primary', colors.bg); r.setProperty('--bg-card', colors.bg); }
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
    localStorage.setItem('persea_theme_colors', JSON.stringify(colors));
}
var _themePresets = {}, _adminPreset = 'aurora';
var _themeDescriptions = { dark: 'Navy & cyan \u2014 the default', light: 'Clean white & blue', 'high-contrast': 'Maximum readability', terminal: 'Retro green-on-black', nord: 'Arctic, muted blues', corporate: 'Slate & steel blue', aurora: 'Midnight blue with ambient glow', jaguar: 'Racing green & gold' };
function initTheme(t) {
    if (!t) return;
    _themePresets = t.presets || {};
    _adminPreset = t.admin_preset || 'aurora';
    var userTheme = localStorage.getItem('persea_theme');
    var active = userTheme && _themePresets[userTheme] ? userTheme : null;
    if (active) applyThemeColors(_themePresets[active]);
    if (t.logo_url) { var l = document.getElementById('site-logo'); if (l) { if (l.src !== t.logo_url && !l.src.endsWith(t.logo_url)) l.src = t.logo_url; l.style.display = ''; } }
    var menu = document.getElementById('um-theme-list');
    if (menu) {
        menu.innerHTML = '';
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
                applyThemeColors(_themePresets[name]);
                menu.querySelectorAll('.um-item').forEach(function(el) { el.classList.remove('active'); });
                item.classList.add('active');
                document.getElementById('user-menu').style.display = 'none';
            });
            menu.appendChild(item);
        });
    }
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

    function updateToggleLabel() {
        var btn = document.getElementById('theme-toggle');
        if (!btn) return;
        var labels = { dark: 'Dark', light: 'Light', auto: 'Auto' };
        var icons = { dark: '☾', light: '☀', auto: '🖥' };
        var current = localStorage.getItem('theme') || 'auto';
        btn.title = 'Theme: ' + (labels[current] || current) + ' (click to cycle)';
        var svg = btn.querySelector('svg');
        if (svg) svg.style.display = 'none';
        var span = btn.querySelector('.theme-label');
        if (span) {
            span.textContent = icons[current] || '🖥';
        } else {
            var s = document.createElement('span');
            s.className = 'theme-label';
            s.textContent = icons[current] || '🖥';
            btn.appendChild(s);
        }
    }

    applyClass(theme);

    // Restore color overrides only if the user has an active preset
    var userPreset = localStorage.getItem('persea_theme');
    if (userPreset) {
        var savedColors = localStorage.getItem('persea_theme_colors');
        if (savedColors) {
            try {
                applyThemeColors(JSON.parse(savedColors));
            } catch(e) {}
        }
    }

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
            if (next === 'dark' || next === 'auto') {
                applyThemeColors(preset);
            } else if (next === 'light') {
                var light = {};
                for (var k in preset) light[k] = preset[k];
                light.bg = '#f8fafc'; light.bg_pattern = 'none';
                light.surface = '#fff'; light.input = '#f1f5f9';
                light.text = '#1e293b'; light.text_muted = '#64748b';
                light.text_dim = '#94a3b8'; light.border = '#e2e8f0';
                light.text_on_primary = '#fff'; light.btn_disabled = '#cbd5e1';
                applyThemeColors(light);
            }
        } else {
            // No preset — clear stale color overrides so CSS rules handle it
            localStorage.removeItem('persea_theme_colors');
            document.documentElement.style.cssText = '';
        }
    };
})();
