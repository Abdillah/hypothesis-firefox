function parseValueToArr(val) {
    // var definedtokens = [
    //     "'self'", "'none'", "*",
    // ];
    return val.trim().split(' ').filter(o => o && o.length);
};

export function parse(cspstr) {
    // Remove header key
    if (cspstr.toLowerCase().indexOf('content-security-policy:') != -1) {
        cspstr = cspstr.slice(cspstr.indexOf(':') + 1, cspstr.length);
    }
    var o = cspstr.split(';').reduce((sum, section) => {
        var section = section.trim();
        var spacepos = section.trim().indexOf(' ');
        var key = section.substr(0, spacepos);
        var val = section.substr(spacepos + 1, section.length);
        if (key == '') {
            return sum
        }

        sum[key] = parseValueToArr(val);
        return sum;
    }, {});

    return o;
}
