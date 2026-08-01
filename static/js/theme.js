function applyThemeColors(colors) {
    var r = document.documentElement.style;
    for (var k in colors) r.setProperty('--' + k.replace(/_/g, '-'), colors[k]);
    var s = document.getElementById('bg-pattern-style');
    if (!s) { s = document.createElement('style'); s.id = 'bg-pattern-style'; document.head.appendChild(s); }
    s.textContent = colors.bg_pattern && colors.bg_pattern !== 'none' ? 'body{background-image:' + colors.bg_pattern + ';background-attachment:fixed}' : '';
    localStorage.setItem('rustguac_theme_colors', JSON.stringify(colors));
}
var _themePresets = {}, _adminPreset = 'aurora';
var _themeDescriptions = { dark: 'Navy & cyan \u2014 the default', light: 'Clean white & blue', 'high-contrast': 'Maximum readability', terminal: 'Retro green-on-black', nord: 'Arctic, muted blues', corporate: 'Slate & steel blue', aurora: 'Midnight blue with ambient glow', jaguar: 'Racing green & gold' };
function initTheme(t) {
    if (!t) return;
    _themePresets = t.presets || {};
    _adminPreset = t.admin_preset || 'aurora';
    var u = localStorage.getItem('rustguac_theme'), active = u && _themePresets[u] ? u : _adminPreset, colors = (active === _adminPreset) ? t.admin_colors : _themePresets[active];
    if (colors) applyThemeColors(colors);
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
                localStorage.setItem('rustguac_theme', name);
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
