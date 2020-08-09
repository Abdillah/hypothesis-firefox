function parseValueToArr(val) {
    // var definedtokens = [
    //     "'self'", "'none'", "*",
    // ];
    return val.trim().split(' ');
};

module.exports = function (cspstr) {
    // Remove header key
    if (cspstr.toLowerCase().indexOf('content-security-policy:') != -1) {
        cspstr = cspstr.split(':', 2)[1];
    }
    var o = cspstr.split(';').reduce((sum, section) => {
        var section = section.trim();
        var spacepos = section.trim().indexOf(' ');
        var key = section.substr(0, spacepos);
        var val = section.substr(spacepos + 1, section.length);
        sum[key] = parseValueToArr(val);
        return sum;
    }, {});

    return o;
}