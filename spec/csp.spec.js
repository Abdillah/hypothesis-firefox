import * as Assert from 'assert';
import { CspPatcher } from '../src/csp/patcher.js';

import { parse } from '../src/csp/parser.js';
import { unparse } from '../src/csp/unparser.js';

describe('Content Security Policy (CSP) Parser / Unparser', function () {
    it('should retain none, self, unsafe-inline, etc', function () {
        var fixtures = [
            [
                "default-src 'none'; base-uri 'self'; connect-src 'self'",
                {
                    'default-src': [ "'none'" ],
                    'base-uri': [ "'self'" ],
                    'connect-src': [ "'self'" ],
                },
            ],
        ];

        for (var f of fixtures) {
            Assert.deepStrictEqual(parse(f[0]), f[1]);
            Assert.deepStrictEqual(unparse(f[1]), f[0]);
        }
    });

    it('should retain order due to the CSP priority nature', function () {
        var fixtures = [
            [
                "default-src 'none'; base-uri 'self' hypothes.is abc.xyz xifroon.space; connect-src 'self'",
                {
                    'default-src': [ "'none'" ],
                    'base-uri': [ "'self'", "hypothes.is", "abc.xyz", "xifroon.space" ],
                    'connect-src': [ "'self'" ],
                },
            ],
        ];

        for (var f of fixtures) {
            Assert.deepStrictEqual(parse(f[0]), f[1]);
            Assert.deepStrictEqual(unparse(f[1]), f[0]);
        }
    });
});


describe('Content Security Policy (CSP) Patcher', function () {
    const minimalcsp = "Content-Security-Policy: default-src 'none'; base-uri 'self';";

    describe('#addHost', function () {
        var test1;
        it('should add hypothes.is into minimal CSP', test1 = function () {
            Assert.strictEqual(
                'Content-Security-Policy: ' + CspPatcher.create(minimalcsp).addHost('default-src', 'hypothes.is').toString(),
                "Content-Security-Policy: default-src hypothes.is 'none'; base-uri 'self';"
            );
        });

        it("should add hypothes.is before 'none'", function () {
            test1();

            const csp = "Content-Security-Policy: default-src 'none'; base-uri 'self' 'none';";
            Assert.strictEqual(
                'Content-Security-Policy: ' + CspPatcher.create(csp).addHost('base-uri', 'hypothes.is').toString(),
                "Content-Security-Policy: default-src 'none'; base-uri 'self' hypothes.is 'none';"
            );
        });

        it("should add hypothes.is after 'self'", function () {
            Assert.strictEqual(
                'Content-Security-Policy: ' + CspPatcher.create(minimalcsp).addHost('base-uri', 'hypothes.is').toString(),
                "Content-Security-Policy: default-src 'none'; base-uri 'self' hypothes.is;"
            );

            const csp = "Content-Security-Policy: default-src 'none'; base-uri 'self' cdn.bootstrap.com;";
            Assert.strictEqual(
                'Content-Security-Policy: ' + CspPatcher.create(csp).addHost('base-uri', 'hypothes.is').toString(),
                "Content-Security-Policy: default-src 'none'; base-uri 'self' hypothes.is cdn.bootstrap.com;"
            );
        });

        // it("should throws when 'nonce-*' and hash rule exists", function () {
        //     const csp = "Content-Security-Policy: default-src 'none'; base-uri 'self'; script-src 'self' cdn.bootstrap.com 'sha256-edeaaff3f1774ad2888673770c6d64097e391bc362d7d6fb34982ddf0efd18cb';";
        //     Assert.throws(function () {
        //         return CspPatcher.create(csp).addHost('script-src', 'hypothes.is').toString();
        //     });
        // });
    });

    describe('#hasHashRule and #hasNonceRule', function () {
        it('should not detect when no nonce/hash rule exist', function () {
            Assert.ok(false === CspPatcher.create(minimalcsp).hasNonceRule());
            Assert.ok(false === CspPatcher.create(minimalcsp).hasNonceRule('base-uri'));
            Assert.ok(false === CspPatcher.create(minimalcsp).hasHashRule());
            Assert.ok(false === CspPatcher.create(minimalcsp).hasHashRule('base-uri'));
        });

        it('should detect various nonce/hash type rule', function () {
            Assert.ok(true === CspPatcher.create("Content-Security-Policy: default-src 'none'; base-uri 'self' 'nonce-64097e3';").hasNonceRule());
            Assert.ok(true === CspPatcher.create("Content-Security-Policy: default-src 'none'; base-uri 'self' 'nonce-64097e3';").hasNonceRule('base-uri'));
            Assert.ok(true === CspPatcher.create("Content-Security-Policy: default-src 'none'; base-uri 'self' 'sha256-edeaaff3f1774ad2888673770c6d64097e391bc362d7d6fb34982ddf0efd18cb';").hasHashRule());
            Assert.ok(true === CspPatcher.create("Content-Security-Policy: default-src 'none'; base-uri 'self' 'sha256-edeaaff3f1774ad2888673770c6d64097e391bc362d7d6fb34982ddf0efd18cb';").hasHashRule('base-uri'));
        });
    });

    describe('Real World CSP Patching', function () {
        beforeEach(function () {
            this.patch = function(cspstr) {
                return CspPatcher.create(cspstr)
                .addHost('default-src', "https://hypothes.is")
                .addHost('frame-src', "https://hypothes.is")
                .addHost('script-src', "https://cdn.hypothes.is")
                .addHost('script-src', `'sha256-a89st89sra8t'`)
                .addHost('style-src', "https://cdn.hypothes.is")
                .addHost('style-src', "'unsafe-inline'")
                .toString()
            };
        })
        it('should add host to duckduckgo.com', function () {
            var csp = "content-security-policy: default-src 'none' ; connect-src  https://duckduckgo.com https://*.duckduckgo.com https://3g2upl4pq6kufc4m.onion/ ; manifest-src  https://duckduckgo.com https://*.duckduckgo.com https://3g2upl4pq6kufc4m.onion/ ; media-src  https://duckduckgo.com https://*.duckduckgo.com https://3g2upl4pq6kufc4m.onion/ ; script-src blob:  https://duckduckgo.com https://*.duckduckgo.com https://3g2upl4pq6kufc4m.onion/ 'unsafe-inline' 'unsafe-eval' ; font-src data:  https://duckduckgo.com https://*.duckduckgo.com https://3g2upl4pq6kufc4m.onion/ ; img-src data:  https://duckduckgo.com https://*.duckduckgo.com https://3g2upl4pq6kufc4m.onion/ ; style-src  https://duckduckgo.com https://*.duckduckgo.com https://3g2upl4pq6kufc4m.onion/ 'unsafe-inline' ; object-src 'none' ; worker-src blob: ; child-src blob:  https://duckduckgo.com https://*.duckduckgo.com https://3g2upl4pq6kufc4m.onion/ ; frame-src blob:  https://duckduckgo.com https://*.duckduckgo.com https://3g2upl4pq6kufc4m.onion/ ; form-action  https://duckduckgo.com https://*.duckduckgo.com https://3g2upl4pq6kufc4m.onion/ https://duck.co ; frame-ancestors 'self' ; base-uri 'self' ; block-all-mixed-content ;";
            var patchedCsp = this.patch(csp);

            // No empty entries
            Assert.ok(patchedCsp.indexOf('  ') === -1);
        });

        it('should add host to github.com', function () {
            var csp = "content-security-policy: default-src 'none'; base-uri 'self'; block-all-mixed-content; connect-src 'self' uploads.github.com www.githubstatus.com collector.githubapp.com api.github.com github-cloud.s3.amazonaws.com github-production-repository-file-5c1aeb.s3.amazonaws.com github-production-upload-manifest-file-7fdce7.s3.amazonaws.com github-production-user-asset-6210df.s3.amazonaws.com cdn.optimizely.com logx.optimizely.com/v1/events wss://alive.github.com github.githubassets.com; font-src github.githubassets.com; form-action 'self' github.com gist.github.com; frame-ancestors 'none'; frame-src render.githubusercontent.com; img-src 'self' data: github.githubassets.com identicons.github.com collector.githubapp.com github-cloud.s3.amazonaws.com user-images.githubusercontent.com/ *.githubusercontent.com customer-stories-feed.github.com spotlights-feed.github.com; manifest-src 'self'; media-src github.githubassets.com; script-src github.githubassets.com; style-src 'unsafe-inline' github.githubassets.com; worker-src github.com/socket-worker-5029ae85.js gist.github.com/socket-worker-5029ae85.js";
            var patchedCsp = this.patch(csp);

            // No empty entries
            Assert.ok(patchedCsp.indexOf('  ') === -1);
        })

        it('should add host to yerinalexey.srht.site', function () {
            var csp = "content-security-policy: default-src 'self' 'unsafe-eval' 'unsafe-inline' data:; sandbox allow-forms allow-orientation-lock allow-pointer-lock allow-presentation allow-same-origin allow-scripts;";
            var patchedCsp = this.patch(csp);

            // No empty entries
            Assert.ok(patchedCsp.indexOf('  ') === -1);
        })
    })
});
