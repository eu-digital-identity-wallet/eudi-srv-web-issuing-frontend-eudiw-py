// Button actions of the pages, in place of inline event handlers (which the
// Content-Security-Policy blocks): data-action="back" goes back in history,
// data-action="home" opens this frontend's start page.
document.addEventListener('click', function (event) {
    var target = event.target.closest('[data-action]');
    if (!target) {
        return;
    }
    if (target.dataset.action === 'back') {
        window.history.back();
    } else if (target.dataset.action === 'home') {
        window.location.href = '/';
    }
});
