import { parse } from './parser.js';
import { unparse } from './unparser.js';

class UnapplicablePatch extends Error {
    constructor(message) {
        super(message);
        this.message = message;
    }
}

export class CspPatcher {
    constructor(cspstr) {
        this.cspstr = cspstr;
    }

    static create(cspstr) {
        return new CspPatcher(cspstr);
    }

    /**
     * Detect hash rule exists in @param{part}
     */
    hasHashRule(part) {
        var hashpat = "'(sha256|sha384|sha512)-([a-z0-9]+)'";
        var matched = this.cspstr.match(new RegExp(`${part} [^;]+;`));
        var partrule = matched? matched[0] : this.cspstr;
        return partrule.length? (new RegExp(hashpat)).test(partrule) : false;
    }

    /**
     * Detect hash rule exists in @param{part}
     */
    hasNonceRule(part) {
        var noncepat = "'nonce-([a-z0-9]+)'";
        var matched = this.cspstr.match(new RegExp(`${part} [^;]+;`));
        var partrule = matched? matched[0] : this.cspstr;
        return partrule.length? (new RegExp(noncepat)).test(partrule) : false;
    }

    /**
     * Whitelist @param{host} on specific CSP @param{to} rule
     *
     * This script may tweak the resulting CSP as to allow this host
     * with minimal security hole implication.
     */
    addHost(to, host) {
        if ([ 'default-src', 'base-uri', 'frame-src', 'script-src', 'style-src' ].indexOf(to) == -1) {
            throw "CspPatcher#addHost 'to' only support one of 'frame-src', 'script-src', 'style-src'";
        }

        // Sanitize host
        host = host.replace(/[^A-z0-9\.-]/g, '');

        // Check for nonce & hash
        if ((to == 'script-src' || to == 'style-src') && (this.hasHashRule(to) || this.hasNonceRule(to))) {
            throw new UnapplicablePatch("Added host will not take effect when hash & nonce rule exists.");
        }

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

        return new CspPatcher(unparse(ocsp));
    }

    // addUrl(to, url) {}

    // addHash(to, hash) {}

    toString() {
        return this.cspstr.replace(/;?$/, ';');
    }
}
