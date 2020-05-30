function listener(details) {
    let cspIdx = details.responseHeaders.findIndex(function (headeritem) {
        return headeritem.name.toLowerCase() == "content-security-policy" && headeritem.value.indexOf('script-src ') !== -1;
    });
    if (cspIdx != -1) {
        var csp = details.responseHeaders[cspIdx];
        var patchedCsp = csp.value
        .replace(/frame-src ([^;]+);/, "frame-src $1 hypothes.is;")
        .replace(/script-src ([^;]+);/, "script-src $1 cdn.hypothes.is;")
        .replace(/style-src ([^;]+);/, "style-src $1 cdn.hypothes.is;");

        details.responseHeaders[cspIdx].value = patchedCsp;
    }

    return {
        responseHeaders: details.responseHeaders
    };
}

browser.webRequest.onHeadersReceived.addListener(
    listener,
    { urls: [ "<all_urls>" ] },
    [ "blocking", "responseHeaders" ]
);