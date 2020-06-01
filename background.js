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

async function listener(details) {
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

/* ----- *
*  Main
* ----- */

fetch('https://hypothes.is/embed.js')
.then(response => response.text())
.then(async function (script) {
    var hypothesisHash = await sha256(script);
    browser.storage.local.set({ hypothesisHash: hypothesisHash });

    browser.webRequest.onHeadersReceived.addListener(
        listener,
        { urls: [ "<all_urls>" ] },
        [ "blocking", "responseHeaders" ]
    );
});