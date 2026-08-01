function escapeHtml(s) {
    var d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
}
function escapeAttr(s) {
    return s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/'/g, '&#39;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
function h(tag, text, attrs) {
    var el = document.createElement(tag);
    if (text != null) el.textContent = text;
    if (attrs) for (var k in attrs) el.setAttribute(k, attrs[k]);
    return el;
}
function togglePw(btn) {
    var inp = btn.previousElementSibling;
    if (inp.type === 'password') { inp.type = 'text'; btn.textContent = '\u25CB'; }
    else { inp.type = 'password'; btn.textContent = '\u25CF'; }
}
