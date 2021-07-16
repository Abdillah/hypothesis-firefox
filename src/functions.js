import { CspPatcher } from './csp/patcher.js';

export function patchCspForHypothesis(cspstr) {
    var patcher = CspPatcher.create(cspstr);
    patcher = patcher
        .addHost('default-src', "https://hypothes.is")
        .addHost('frame-src', "https://hypothes.is")
        .addHost('script-src', "https://cdn.hypothes.is")
        .addHost('style-src', "https://cdn.hypothes.is")
        .addHost('style-src', "'unsafe-inline'")
    ;

    // When only default-src available, we must add CDN URL to it
    if (!patcher.hasRule('script-src') || !patcher.hasRule('style-src')) {
        patcher = patcher
        .addHost('default-src', "https://cdn.hypothes.is")
    }

    if (patcher.hasHashRule('script-src') || patcher.hasNonceRule('script-src')) {
        patcher = patcher
        // Hash of inline hypothesisConfig textContent
        .addHost('script-src', "'nonce-w9s09t'")
        .addHost('script-src', `'sha256-${results['hypothesisHash']}'`)
    }

    return patcher.toString();
}
