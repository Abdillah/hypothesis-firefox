var hypothesis;

(async function() {
    if (window.document.querySelector('hypothesis-sidebar')) {
        var config = await browser.storage.local.get('activeSites');
        if (typeof config.activeSites === 'undefined') {
            config.activeSites = {};
        }
        config.activeSites[window.location.href] = true;
        await browser.storage.local.set({
            activeSites: config.activeSites
        });
    }

    hypothesis = {
        enable: async function () {
            if (window.document.querySelector('hypothesis-sidebar')) {
                window.document.querySelector('hypothesis-sidebar').style.opacity = 1;
                window.document.querySelector('hypothesis-adder').style.opacity = 1;
                return;
            }

            // Initial config
            var hypothesisConfig = {
                openSidebar: false,
                showHighlights: true,
                appType: 'bookmarklet'
            };

            var results = await browser.storage.local.get('hypothesisHash');
            var d = window.document;

            var c = d.createElement('script');
            c.setAttribute('type', 'application/javascript');
            c.setAttribute('nonce', 'w9s09t');
            c.textContent = `window.hypothesisConfig = function () {
                return ${JSON.stringify(hypothesisConfig)};
            };`;
            d.body.appendChild(c);

            var s = d.createElement('script');
            s.setAttribute('src', 'https://hypothes.is/embed.js');
            s.setAttribute('hash', results['hypothesisHash']);
            d.body.appendChild(s);
        },

        disable: function () {
            if (window.document.querySelector('hypothesis-sidebar')) {
                window.document.querySelector('hypothesis-adder').style.opacity = 0;
                window.document.querySelector('hypothesis-sidebar').style.opacity = 0;
            }
        },
    };
})();
