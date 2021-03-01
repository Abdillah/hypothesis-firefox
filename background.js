async function sha256(message) {
    // encode as UTF-8
    const msgBuffer = new TextEncoder('utf-8').encode(message);

    // hash the message
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);

    // convert ArrayBuffer to Array
    const hashArray = Array.from(new Uint8Array(hashBuffer));

    // convert bytes to hex string
    const hashHex = hashArray.map(b => ('00' + b.toString(16)).slice(-2)).join('');
    return hashHex;
}

async function onHeaderPassed(details) {
    // Filter only response from document URL to patch
    if (details.url.length <= 0 || typeof details.documentUrl !== 'undefined') {
        return {};
    }

    let cspIdx = details.responseHeaders.findIndex(function (headeritem) {
        return headeritem.name.toLowerCase() == "content-security-policy" && headeritem.value.indexOf('script-src ') !== -1;
    });
    if (cspIdx != -1) {
        var results = await browser.storage.local.get('hypothesisHash');
        var csp = details.responseHeaders[cspIdx];
        var patchedCsp = csp.value
        .replace(/default-src ([^;]+);/, "default-src hypothes.is $1;")
        .replace(/frame-src ([^;]+);/, "frame-src hypothes.is $1;")
        .replace(/script-src ([^;]+);/, "script-src cdn.hypothes.is $1 'sha256-" + results['hypothesisHash'] + "';")
        .replace(/style-src ([^;]+);/, "style-src cdn.hypothes.is 'unsafe-inline' $1;");

        details.responseHeaders[cspIdx].value = patchedCsp;
    }

    return {
        responseHeaders: details.responseHeaders
    };
}

async function onPageActionClicked() {
    var config = await browser.storage.local.get('activeSites');
    var isEnabled = (config.activeSites && config.activeSites[currentTab.url]) || false;

    console.log("Before toggle", config);
    let hasDisabled = toggleHypothesis(!isEnabled);
    togglePgActionIcon(!hasDisabled);
}

async function togglePgActionIcon(toActive) {
    if (!toActive) {
        // Mark as disabled
        browser.pageAction.setIcon({
            tabId: currentTab.id,
            path: {
                19: "icons/hypothesis-19.png",
                38: "icons/hypothesis-38.png",
            }
        });
        browser.pageAction.setTitle({
            tabId: currentTab.id,
            title: "Show Hypothes.is",
        });
    } else {
        // Mark as active
        browser.pageAction.setIcon({
            tabId: currentTab.id,
            path: {
                19: "icons/hypothesis-active-19.png",
                38: "icons/hypothesis-active-38.png",
            }
        });
        browser.pageAction.setTitle({
            tabId: currentTab.id,
            title: "Hide Hypothes.is",
        });
    }
}

async function toggleHypothesis(toActive) {
    var command = toActive ? "hypothesis.enable()" : "hypothesis.disable()"
    console.log("Execute: " + command, toActive);
    // Dispatch update
    console.log("- Result: ", await browser.tabs.executeScript(currentTab.id, {
        code: command,
    }));

    // Save toggle
    var config = await browser.storage.local.get('activeSites');
    if (typeof config.activeSites === 'undefined') {
        config.activeSites = {};
    }
    config.activeSites[currentTab.url] = toActive;
    console.log("After edit::",  config);
    browser.storage.local.set({
        activeSites: config['activeSites']
    });

    var config = await browser.storage.local.get();
    console.log("After toggle", config);

    return toActive;
}

async function setupPageAction() {
    console.log("Current tab:", currentTab);
    browser.pageAction.show(currentTab.id);

    var config = await browser.storage.local.get('activeSites');
    var isEnabled = (config.activeSites && config.activeSites[currentTab.url]) || false;
    return togglePgActionIcon(isEnabled);
}

/*
 * Switches currentTab and currentBookmark to reflect the currently active tab
 */
function updateActiveTab() {
    function updateTab(tabs) {
        if (tabs[0]) {
            currentTab = tabs[0];
        }
    }

    var gettingActiveTab = browser.tabs.query({ active: true, currentWindow: true });
    return gettingActiveTab.then(updateTab);
}

/** ----------------- *
 *  Event Listeners
 * ----------------- */

// listen to tab URL changes
browser.tabs.onUpdated.addListener(updateActiveTab);

// listen to tab switching
browser.tabs.onActivated.addListener(updateActiveTab);

// listen for window switching
browser.windows.onFocusChanged.addListener(updateActiveTab);

// listen for page action toggled
browser.pageAction.onClicked.addListener(onPageActionClicked);

/* ----- *
 *  Main
 * ----- */

console.log("hypothesis: Hello!");

var currentTab;

// update when the extension loads initially
updateActiveTab()
.then(setupPageAction);

// Setting up CSP
fetch('https://hypothes.is/embed.js')
.then(response => response.text())
.then(async function (script) {
    var hypothesisHash = await sha256(script);
    browser.storage.local.set({ hypothesisHash: hypothesisHash });

    browser.webRequest.onHeadersReceived.addListener(
        onHeaderPassed,
        { urls: [ "<all_urls>" ] },
        [ "blocking", "responseHeaders" ]
    );
});

// Toggle hypothesis
browser.storage.local.get('activeSites')
.then( function(activeSites) {
    isEnabled = activeSites[currentTab.url] || false;
    toggleHypothesis(!isEnabled);
});
