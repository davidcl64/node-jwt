module.exports = require('./lib');


// Tests
var util       = require('util');
var ALGORITHMS = module.exports.jwt.ALGORITHMS;
var JWT        = module.exports.jwt.JWT;
var base64url  = require('base64url');

console.log(JSON.stringify(ALGORITHMS,null,2)); // MAP of all algorithms
console.log(ALGORITHMS.header("NONEx"));        // Should be undefined
console.log(ALGORITHMS.header("NONE"));         // Should be { alg: 'NONE' }

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

