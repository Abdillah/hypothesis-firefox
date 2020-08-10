const Assert = require('assert');

describe('Content Security Policy (CSP) Parser / Unparser', function () {
    const parse = require('../src/csp/parser');
    const unparse = require('../src/csp/unparser');

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
            Assert.deepEqual(parse(f[0]), f[1]);
            Assert.deepEqual(unparse(f[1]), f[0]);
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
            Assert.deepEqual(parse(f[0]), f[1]);
            Assert.deepEqual(unparse(f[1]), f[0]);
        }
    });
});


describe('Content Security Policy (CSP) Patcher', function () {
    const CSPPatcher = require('../src/csp/patcher');

    const minimalcsp = "Content-Security-Policy: default-src 'none'; base-uri 'self';";

    describe('#addHost', function () {
        it('should add hypothes.is into minimal CSP', test1 = function () {
            Assert.equal(
                'Content-Security-Policy: ' + CSPPatcher.create(minimalcsp).addHost('default-src', 'hypothes.is').toString(),
                "Content-Security-Policy: default-src hypothes.is 'none'; base-uri 'self';"
            );
        });

        it("should add hypothes.is before 'none'", function () {
            test1();

            const csp = "Content-Security-Policy: default-src 'none'; base-uri 'self' 'none';";
            Assert.equal(
                'Content-Security-Policy: ' + CSPPatcher.create(csp).addHost('base-uri', 'hypothes.is').toString(),
                "Content-Security-Policy: default-src 'none'; base-uri 'self' hypothes.is 'none';"
            );
        });

        it("should add hypothes.is after 'self'", function () {
            Assert.equal(
                'Content-Security-Policy: ' + CSPPatcher.create(minimalcsp).addHost('base-uri', 'hypothes.is').toString(),
                "Content-Security-Policy: default-src 'none'; base-uri 'self' hypothes.is;"
            );

            const csp = "Content-Security-Policy: default-src 'none'; base-uri 'self' cdn.bootstrap.com;";
            Assert.equal(
                'Content-Security-Policy: ' + CSPPatcher.create(csp).addHost('base-uri', 'hypothes.is').toString(),
                "Content-Security-Policy: default-src 'none'; base-uri 'self' hypothes.is cdn.bootstrap.com;"
            );
        });

        // it("should throw when 'nonce-*' and hash rule exists", function () {
        //     const csp = "Content-Security-Policy: default-src 'none'; base-uri 'self' 'sha256-edeaaff3f1774ad2888673770c6d64097e391bc362d7d6fb34982ddf0efd18cb';";
        //     Assert.throws(function () {
        //         return CSPPatcher.create(csp).addHost('base-uri', 'hypothes.is').toString();
        //     });
        // });
    });

    describe('#hasHashRule and #hasNonceRule', function () {
        it('should not detect when no nonce/hash rule exist', function () {
            Assert.ok(false === CSPPatcher.create(minimalcsp).hasNonceRule());
            Assert.ok(false === CSPPatcher.create(minimalcsp).hasNonceRule('base-uri'));
            Assert.ok(false === CSPPatcher.create(minimalcsp).hasHashRule());
            Assert.ok(false === CSPPatcher.create(minimalcsp).hasHashRule('base-uri'));
        });

        it('should detect various nonce/hash type rule', function () {
            Assert.ok(true === CSPPatcher.create("Content-Security-Policy: default-src 'none'; base-uri 'self' 'nonce-64097e3';").hasNonceRule());
            Assert.ok(true === CSPPatcher.create("Content-Security-Policy: default-src 'none'; base-uri 'self' 'nonce-64097e3';").hasNonceRule('base-uri'));
            Assert.ok(true === CSPPatcher.create("Content-Security-Policy: default-src 'none'; base-uri 'self' 'sha256-edeaaff3f1774ad2888673770c6d64097e391bc362d7d6fb34982ddf0efd18cb';").hasHashRule());
            Assert.ok(true === CSPPatcher.create("Content-Security-Policy: default-src 'none'; base-uri 'self' 'sha256-edeaaff3f1774ad2888673770c6d64097e391bc362d7d6fb34982ddf0efd18cb';").hasHashRule('base-uri'));
        });
    });
});
