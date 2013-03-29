var jwt        = require('..').jwt;
var util       = require('util');
var ALGORITHMS = jwt.ALGORITHMS;
var JWT        = jwt.JWT;
var base64url  = require('base64url');
var config     = require('./config/config');

module.exports['Check Setup'] = function(test) {
    test.expect(2);
    test.ok(config.key.length > 0);
    test.ok(config.secret.length > 0);
    test.done();
}

module.exports['Check ALGORITHMS'] = function(test) {
    test.expect(4);
    test.equal(Object.keys(ALGORITHMS).length, 11);
    test.equal(Object.keys(ALGORITHMS).join(','), "NONE,header,HS256,HS384,HS512,RS256,RS384,RS512,ES256,ES384,ES512");
    test.equal(ALGORITHMS.header("NONEx"), undefined);

    test.deepEqual(ALGORITHMS.header("NONE"), { typ: 'JWT', cty: 'JWT', alg: 'NONE' });
    test.done();
}

