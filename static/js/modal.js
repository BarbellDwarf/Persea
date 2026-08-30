// Modal open/close helpers + focus trap and keyboard handling

function openModal(id) {
    var el = document.getElementById(id);
    el.classList.remove('hidden');
    el.setAttribute('aria-hidden', 'false');
    var focusTarget = el.querySelector('input:not([type="hidden"]), select, textarea, button');
    if (focusTarget) focusTarget.focus();
}

function closeModal(id) {
    var el = document.getElementById(id);
    el.classList.add('hidden');
    el.setAttribute('aria-hidden', 'true');
}

(function() {
  document.addEventListener('keydown', function(e) {
    var modal = document.querySelector('[role="dialog"]:not([aria-hidden="true"])');
    if (!modal) return;

    if (e.key === 'Escape') {
      var closeBtn = modal.querySelector('[data-close], .modal-cancel, .btn-cancel');
      if (closeBtn) closeBtn.click();
      return;
    }

    if (e.key === 'Tab') {
      var focusable = modal.querySelectorAll('input, select, textarea, button, a[href], [tabindex]:not([tabindex="-1"])');
      if (focusable.length === 0) return;
      var first = focusable[0];
      var last = focusable[focusable.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    }
  });
})();
