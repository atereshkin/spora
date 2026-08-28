// A small brand link back to the site, injected next to the menu buttons so
// no handlebars template needs forking (which would pin us to one mdBook
// version).
(function () {
    var left = document.querySelector('.left-buttons');
    if (!left || document.querySelector('.spora-home-link')) return;
    var a = document.createElement('a');
    a.className = 'spora-home-link';
    a.href = 'https://spora.to/';
    a.textContent = 'spora.to';
    left.appendChild(a);
})();
