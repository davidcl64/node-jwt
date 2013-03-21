var jwt        = require('..').jwt;
var util       = require('util');
var ALGORITHMS = jwt.ALGORITHMS;
var JWT        = jwt.JWT;
var base64url  = require('base64url');

var key        = require('fs').readFileSync(require('path').join(__dirname, '../test.pem'), 'utf8');
var secret     = "I know what you did last summer.";


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
    test.ok(key.length > 0);
    test.ok(secret.length > 0);
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

module.exports['JWT.build'] = function(test) {
    /*
     * options: {
     *     expiration: expiration time in seconds,
     *     delay:      time in seconds before this token can be used.  Used to generate the nbf claim,
     *     claims: {
     *        // Any claims passed here will be processed as is.  If scope is provided here, it *MUST*
     *        // be specified as an array of strings.
     *     },
     *     scope:  [Array of valid scopes for this token, no spaces allowed],
     *     scopeSep:  Override the default space seperator if you really must
     * }        
     */
    var opts = {
        expiration: 60 * 60,
        delay:      0,
        claims:     {
            iss:    'MyClientID',
            aud:    'https://accounts.localhost.com/o/oauth2/token'
        },
        scope:      ['auth', 'userinfo']
    };
    var tests    = [];
    var numTests = 0;
    var _now     = Date.now;
    var _getTime = Date.prototype.getTime;
    
    Date.now = function() { return 0; };
    Date.prototype.getTime = Date.now;
    
    var runTests = function() {
        var curTest = tests.shift();
        
        if(curTest) {
            JWT.build(curTest.opts, curTest.unit);
        } else {
            Date.now = _now;
            Date.prototype.getTime = _getTime;
            test.done();
        }
    };
    
    (function() {
        var copy = JSON.parse(JSON.stringify(opts));

        tests.push({
            'opts': copy,
            'unit': function(error,result) {
                test.equal(error,null);
                test.ok(result !== null);
                //console.log(util.inspect(copy));
                process.nextTick(runTests);
            }
        });
    
        numTests += 2;
        test.expect(numTests);
    })();
    
    (function() {
        var copy = JSON.parse(JSON.stringify(opts));
        copy.delay = 300;

        tests.push({
            'opts': copy,
            'unit': function(error,result) {
                //console.log(util.inspect(copy));
                //console.log(util.inspect(result));
                test.equal(error,null);
                test.ok(result !== null);
                test.ok(result.exp === copy.expiration + copy.delay);
                test.ok(result.nbf === copy.delay);
                process.nextTick(runTests);
            }
        });
    
        numTests += 4;
        test.expect(numTests);
    })();
    
    (function() {
        var copy = JSON.parse(JSON.stringify(opts));
        copy.scope = "This is a test";

        tests.push({
            'opts': copy,
            'unit': function(error,result) {
                //console.log(util.inspect(copy));
                //console.log(util.inspect(result));
                test.equal(error,null);
                test.ok(result.scope.length === 4, "Comparing: " + JSON.stringify(result.scope) + " to " + copy.scope);
                process.nextTick(runTests);
            }
        });
    
        numTests += 2;
        test.expect(numTests);
    })();
    
    process.nextTick(runTests);
}
