function parseValueToArr(val) {
    // var definedtokens = [
    //     "'self'", "'none'", "*",
    // ];
    return val.trim().split(' ');
};

export function unparse(ocsp) {
    var csparr = [];
    for (var k in ocsp) {
        csparr.push([ k ].concat(ocsp[k].join(' ')).join(' '));
    }
    return csparr.join('; ');
}
