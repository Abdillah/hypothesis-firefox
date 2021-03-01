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
        this.ocsp = parse(cspstr);
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
        host = host.replace(';', '').trim();

        var dest = this.ocsp[to];

        // Check for 'self'
        var hasAdded = (dest.indexOf(host) !== -1);
        var iself = 0;
        if (!hasAdded && (iself = dest.indexOf("'self'")) !== -1) {
            dest.splice(iself + 1, 0, host)
        } else if (!hasAdded) {
            dest.unshift(host)
        }
        this.ocsp[to] = dest;

        return new CspPatcher(unparse(this.ocsp));
    }

    // addUrl(to, url) {}

    // addHash(to, hash) {}

    toString() {
        return unparse(this.ocsp).trimEnd(';') + ';';
    }
}
