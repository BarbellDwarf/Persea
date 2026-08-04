function readCookie(name) {
    var parts = document.cookie.split(';');
    for (var i = 0; i < parts.length; i++) {
        var part = parts[i].trim();
        if (part.indexOf(name + '=') === 0) {
            return decodeURIComponent(part.substring(name.length + 1));
        }
    }
    return null;
}

function apiHeaders(extra) {
    var h = { 'Content-Type': 'application/json' };
    var key = sessionStorage.getItem('persea_api_key');
    if (key) h['Authorization'] = 'Bearer ' + key;
    var csrf = readCookie('csrf_token');
    if (csrf) h['X-CSRF-Token'] = csrf;
    if (extra) { for (var k in extra) h[k] = extra[k]; }
    return h;
}
