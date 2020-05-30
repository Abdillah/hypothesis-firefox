(function() {
    window.hypothesisConfig = function() {
        return {
            showHighlights: true,
            appType: 'bookmarklet'
        };
    };
    var d = document,
        s = d.createElement('script');
    s.setAttribute('src', 'https://hypothes.is/embed.js');
    d.body.appendChild(s)
})();
