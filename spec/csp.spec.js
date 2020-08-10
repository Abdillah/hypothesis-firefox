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