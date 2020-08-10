const parse = require('./parser');
const unparse = require('./unparser');

class CSPPatcher {
    constructor(cspstr) {
        this.cspstr = cspstr;
    }

    static create(cspstr) {
        return new CSPPatcher(cspstr);
    }

    /**
     * Whitelist @param{host} on specific CSP @param{to} rule
     *
     * This script may tweak the resulting CSP as to allow this host
     * with minimal security hole implication.
     */
    addHost(to, host) {
        if ([ 'default-src', 'base-uri', 'frame-src', 'script-src', 'style-src' ].indexOf(to) == -1) {
            throw "CSPPatcher#addHost 'to' only support one of 'frame-src', 'script-src', 'style-src'";
        }

        // Sanitize host
        host = host.replace(/[^A-z0-9\.-]/g, '');

        var ocsp = parse(this.cspstr);
        var dest = ocsp[to];

        // Check for 'self'
        var iself = 0;
        if ((iself = dest.indexOf("'self'")) != -1) {
            dest.splice(iself + 1, 0, host)
        } else {
            dest.unshift(host)
        }
        ocsp[to] = dest;

        return new CSPPatcher(unparse(ocsp));
    }

    // addUrl(to, url) {}

    // addHash(to, hash) {}

    toString() {
        return this.cspstr.replace(/;?$/, ';');
    }
}

module.exports = CSPPatcher;
