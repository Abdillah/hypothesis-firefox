(async function() {
    window.hypothesisConfig = function() {
        return {
            showHighlights: true,
            appType: 'bookmarklet'
        };
    };

    var results = await browser.storage.local.get('hypothesisHash');
    var d = document,
        s = d.createElement('script');
    s.setAttribute('src', 'https://hypothes.is/embed.js');
    s.setAttribute('hash', results['hypothesisHash']);
    d.body.appendChild(s)
})();
