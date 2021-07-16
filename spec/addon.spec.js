import * as Assert from 'assert';
import { patchCspForHypothesis } from '../src/functions.js';

describe('Hypothes.is Content Security Policy (CSP) Bypass', function () {
    describe('Real World CSP Patching', function () {
        it('should add host to duckduckgo.com', function () {
            var csp = "content-security-policy: default-src 'none' ; connect-src  https://duckduckgo.com https://*.duckduckgo.com https://3g2upl4pq6kufc4m.onion/ ; manifest-src  https://duckduckgo.com https://*.duckduckgo.com https://3g2upl4pq6kufc4m.onion/ ; media-src  https://duckduckgo.com https://*.duckduckgo.com https://3g2upl4pq6kufc4m.onion/ ; script-src blob:  https://duckduckgo.com https://*.duckduckgo.com https://3g2upl4pq6kufc4m.onion/ 'unsafe-inline' 'unsafe-eval' ; font-src data:  https://duckduckgo.com https://*.duckduckgo.com https://3g2upl4pq6kufc4m.onion/ ; img-src data:  https://duckduckgo.com https://*.duckduckgo.com https://3g2upl4pq6kufc4m.onion/ ; style-src  https://duckduckgo.com https://*.duckduckgo.com https://3g2upl4pq6kufc4m.onion/ 'unsafe-inline' ; object-src 'none' ; worker-src blob: ; child-src blob:  https://duckduckgo.com https://*.duckduckgo.com https://3g2upl4pq6kufc4m.onion/ ; frame-src blob:  https://duckduckgo.com https://*.duckduckgo.com https://3g2upl4pq6kufc4m.onion/ ; form-action  https://duckduckgo.com https://*.duckduckgo.com https://3g2upl4pq6kufc4m.onion/ https://duck.co ; frame-ancestors 'self' ; base-uri 'self' ; block-all-mixed-content ;";
            var patchedCsp = patchCspForHypothesis(csp);

            // No empty entries
            Assert.ok(patchedCsp.indexOf('  ') === -1);
        });

        it('should add host to github.com', function () {
            var csp = "content-security-policy: default-src 'none'; base-uri 'self'; block-all-mixed-content; connect-src 'self' uploads.github.com www.githubstatus.com collector.githubapp.com api.github.com github-cloud.s3.amazonaws.com github-production-repository-file-5c1aeb.s3.amazonaws.com github-production-upload-manifest-file-7fdce7.s3.amazonaws.com github-production-user-asset-6210df.s3.amazonaws.com cdn.optimizely.com logx.optimizely.com/v1/events wss://alive.github.com github.githubassets.com; font-src github.githubassets.com; form-action 'self' github.com gist.github.com; frame-ancestors 'none'; frame-src render.githubusercontent.com; img-src 'self' data: github.githubassets.com identicons.github.com collector.githubapp.com github-cloud.s3.amazonaws.com user-images.githubusercontent.com/ *.githubusercontent.com customer-stories-feed.github.com spotlights-feed.github.com; manifest-src 'self'; media-src github.githubassets.com; script-src github.githubassets.com; style-src 'unsafe-inline' github.githubassets.com; worker-src github.com/socket-worker-5029ae85.js gist.github.com/socket-worker-5029ae85.js";
            var patchedCsp = patchCspForHypothesis(csp);

            // No empty entries
            Assert.ok(patchedCsp.indexOf('  ') === -1);
        })

        it('should add host to yerinalexey.srht.site', function () {
            var csp = "content-security-policy: default-src 'self' 'unsafe-eval' 'unsafe-inline' data:; sandbox allow-forms allow-orientation-lock allow-pointer-lock allow-presentation allow-same-origin allow-scripts;";
            var patchedCsp = patchCspForHypothesis(csp);

            // No empty entries
            Assert.ok(patchedCsp.indexOf('  ') === -1);
        })
    })
});
