function apiHeaders(extra) {
    var h = { 'Content-Type': 'application/json' };
    var key = sessionStorage.getItem('persea_api_key');
    if (key) h['Authorization'] = 'Bearer ' + key;
    if (extra) { for (var k in extra) h[k] = extra[k]; }
    return h;
}
