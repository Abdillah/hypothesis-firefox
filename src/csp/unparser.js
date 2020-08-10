function parseValueToArr(val) {
    // var definedtokens = [
    //     "'self'", "'none'", "*",
    // ];
    return val.trim().split(' ');
};

module.exports = function (ocsp) {
    var csparr = [];
    for (var k in ocsp) {
        csparr.push([ k ].concat(ocsp[k].join(' ')).join(' '));
    }
    return csparr.join('; ');
}
