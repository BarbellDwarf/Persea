function apiHeaders(extra) {
    var h = {};
    if (apiKey) h['Authorization'] = 'Bearer ' + apiKey;
    if (extra) { for (var k in extra) h[k] = extra[k]; }
    return h;
}
