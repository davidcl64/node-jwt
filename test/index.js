var jwt        = require('..').jwt;
var util       = require('util');
var ALGORITHMS = jwt.ALGORITHMS;
var JWT        = jwt.JWT;
var base64url  = require('base64url');
var config     = require('./config/config');

JWT.build({
    expiration: 60 * 60,
    delay:      0,
    claims:     {
        iss:    'MyClientID',
        aud:    'https://accounts.localhost.com/o/oauth2/token'
    },
    scope:      ['auth', 'userinfo']
},  function(error, result) {
    if(error) {
        console.log("build error: \r\n" + util.inspect(error));
    } else {
        console.log("build result: \r\n" + util.inspect(result));
        
        JWT.encode({
            alg: ALGORITHMS.NONE,
            //key: require('fs').readFileSync(path.join(__dirname, '/test.pem'), 'utf8'),
            payload: result,
            /*
            refresh: {
                token: refreshToken,
                claimIds: [],
                //key: require('fs').readFileSync(path.join(__dirname, '/test.pem'), 'utf8'),
                dummy: undefined        // so we don't have to worry about the ending comma
            },
            */
            dummy: undefined  // so we don't have to worry about the ending comma

        }, function(error, result) {
            if(error) {
                console.log("Encode error: \r\n" + util.inspect(error));
            } else {
                console.log("Encode result: \r\n" + util.inspect(result));
                
                var sanity = result.split('.');
                console.log(util.inspect(sanity));
                
                sanity.forEach(function(val) {
                    console.log(base64url.decode(val));
                });

                JWT.decode({ token: result }, function(error, result) {
                    if(error) {
                        console.log("Decode error: \r\n" + util.inspect(error));
                    } else {
                        console.log("Decode result: \r\n" + util.inspect(result));
                    } 
                });
            }
        });
    }
});

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

