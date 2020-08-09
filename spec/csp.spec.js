const assert = require('assert');

describe('Content Security Policy (CSP) Parser', function () {
    const cspparser = require('../src/csp/parser');

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
            assert.deepEqual(cspparser(f[0]), f[1]);
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
            assert.deepEqual(cspparser(f[0]), f[1]);
        }
    });
});