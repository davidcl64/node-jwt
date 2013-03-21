var jwt        = require('..').jwt;
var util       = require('util');
var ALGORITHMS = jwt.ALGORITHMS;
var JWT        = jwt.JWT;
var base64url  = require('base64url');
var helper     = require('./config/config');

var scopes     = {
    'scope[]':      [],
    'scope[1]':     ['1'],
    'scope[1,3,5]': ['1','3','5'],
    'scope[1..5]':  ['1','2','3','4','5']
};
var scopes2     = {
    '':           [],
    '1':          ['1'],
    '1,3,5':      ['1','3','5'],
    '1,2,3,4,5':  ['1','2','3','4','5']
};

var refreshTokens = {};


/*
 *  testcase: pass in this from your test function
 *  config: {
 *      build: {
 *          opts: {},   // Claims to be added to JWT.build request
 *          cb:   fn,   // Callback function - passed (error, result), 
 *                      // optional: can return opts to pass to encode
 *      },
 *      encode: {
 *          opts: {},   // Claims to be added to the encode request
 *          cb:   fn,   // Callback function - passed (error, result, detail)
 *                      // where detail is { parts:  result.split('.'), result is null, [''] is returned
 *                                           dparts: base64 decoded parts
 *                                           json:   JSON parsed part or {} if non-existant }
 *      }
 *  }
 *  testComplete: callback to be called after runTests completes.
 */
function runTests(testcase, config, testComplete) {
    var opts = testcase.opts;
    
    if(config.build && config.build.opts) {
        for(var key in config.build.opts) {
            opts[key] = config.build.opts[key];
        }
    }
    
    JWT.build(opts, function(error,result) {
        var optsForEncode = config.encode && config.encode.opts ? config.encode.opts : {};
        
        if(config.build && config.build.cb) {
            optsForEncode = config.build.cb(error, result) || optsForEncode;
        }
        
        JWT.encode(optsForEncode, function(error, result) {
            if(config.encode && config.encode.cb) {
                var parts  = (result || "").split('.');
                var dparts = [];
                var json   = [];
                var decodedPart;
                
                for(var i = 0; i < parts.length - 1; i++) {
                    decodedPart = base64url.decode(parts[i] || '');
                    
                    dparts.push(decodedPart);
                    json.push(JSON.parse(decodedPart || '{}'))
                }
                
                config.encode.cb(error, result, {
                    'parts': parts,
                    'dparts': dparts,
                    'json':  json
                });
            }
            
            if(testComplete) {
                testComplete();
            }
        });
    });  
}

/*
 * Helper function go get build config
 */
function buildConfig(test, retValfn) {
    return function(error, result) {
        test.equal(error,null); 
        test.ok(result !== null); 
        
        return retValfn ? retValfn(result) : undefined;
    }
}

module.exports = {
    setUp: function(cb) {
        this.opts = {
            expiration: 60 * 60,
            delay:      0,
            claims:     {
                iss:    'MyClientID',
                aud:    'https://accounts.localhost.com/o/oauth2/token'
            },
            scope:      scopes['scope[1,3,5]']
        };
        
        this._now     = Date.now;
        this._getTime = Date.prototype.getTime;
        
        Date.now = helper.now;
        Date.prototype.getTime = helper.now;
        cb();
    },
    
    tearDown: function(cb   ) {
        Date.now = this._now;
        Date.prototype.getTime = this._getTime;       
        cb();
    },

    "JWT.encode ==> Should FAIL     ==> missing header": function(test) {
        var self = this;
        var config = {
            build:  { cb: buildConfig(test, function(result) { return { payload: result } }) },
            encode: {
                cb: function(error, result, detail) {
                    test.ok(error, "Expected an error, didn't get one, got this instead: " + result);
                }
            }
        };
        
        test.expect(3);
        runTests(this, config, function() { test.done(); });
    },
    
    "JWT.encode ==> Should FAIL     ==> missing payload": function(test) {
        var self = this;
        var config = {
            build:  { cb: buildConfig(test, function(result) { return { header: ALGORITHMS.header(ALGORITHMS.NONE) } }) },
            encode: {
                cb: function(error, result, detail) {
                    test.ok(error, "Expected an error, didn't get one, got this instead: " + result);
                }
            }
        };
        
        test.expect(3);
        runTests(this, config, function() { test.done(); });
    },

    "JWT.encode ==> Should SUCCEED  ==> no refresh, no secret": function(test) {
        var self = this;
        var config = {
            build:  { cb: buildConfig(test, function(result) { return { header: ALGORITHMS.header(ALGORITHMS.NONE), payload: result } }) },
            encode: {
                cb: function(error, result, detail) {
                    test.equal(error,null,error);
                
                    test.equal(detail.parts.length, 3, "Encoded token should contain 3 parts not: " + detail.parts.length);
                    test.equal('', detail.parts[2], "Expected signature to be of zero length not: '" + detail.parts[2] + "'");
                
                    test.deepEqual(detail.json[0], { typ: 'JWT', cty: 'JWT', alg: 'NONE' }, "Unexpected header value: '" + detail.dparts[0] + "'");
                
                    test.deepEqual(detail.json[1], 
                                   { iss: 'MyClientID',
                                     aud: 'https://accounts.localhost.com/o/oauth2/token',
                                     iat: -60,
                                     exp: 3600,
                                     scope: [ '1', '3', '5' ] }, 
                                   "Unexpected payload value: '" + detail.dparts[1] + "'");
                               }
            }
        };
        
        test.expect(7);
        runTests(this, config, function() { test.done(); });
    },
    
    "JWT.encode ==> Should FAIL     ==> no refresh, unexpected secret": function(test) {
        var self = this;
        var config = {
            build:  { cb: buildConfig(test, function(result) { return { header: ALGORITHMS.header(ALGORITHMS.NONE), payload: result, secret: "Shhhhhhh" } }) },
            encode: {
                cb: function(error, result, detail) {
                    test.ok(error, "Expected an error, didn't get one.  Got this instead: " + result);
                }
            }
        };
        
        test.expect(3);
        runTests(this, config, function() { test.done(); });
    },
    
    "JWT.encode ==> Should FAIL     ==> no refresh, unexpected privateKey": function(test) {
        var self = this;
        var config = {
            build:  { cb: buildConfig(test, function(result) { return { header: ALGORITHMS.header(ALGORITHMS.NONE), payload: result, privateKey: helper.key } }) },
            encode: {
                cb: function(error, result, detail) {
                    test.ok(error, "Expected an error, didn't get one.  Got this instead: " + result);
                }
            }
        };
        
        test.expect(3);
        runTests(this, config, function() { test.done(); });
    },
    
    "JWT.encode ==> Should SUCCEED  ==> no refresh, with secret & HS+bits": function(test) {
        var self = this;
        var config = {
            build:  { cb: buildConfig(test, function(result) { return { header: ALGORITHMS.header(ALGORITHMS.HS256), payload: result, secret: helper.secret } }) },
            encode: {
                cb: function(error, result, detail) {
                    test.equal(error,null,error);
                
                    test.equal(detail.parts.length, 3, "Encoded token should contain 3 parts not: " + detail.parts.length);
                    test.ok((detail.parts[2] || '').length > 0, "Expected signature to be > zero: '" + detail.parts[2] + "'");
                
                    test.deepEqual(detail.json[0], { typ: 'JWT', cty: 'JWT', alg: 'HS256' }, "Unexpected header value: '" + detail.dparts[0] + "'");
                
                    test.deepEqual(detail.json[1], 
                                   { iss: 'MyClientID',
                                     aud: 'https://accounts.localhost.com/o/oauth2/token',
                                     iat: -60,
                                     exp: 3600,
                                     scope: [ '1', '3', '5' ] }, 
                                   "Unexpected payload value: '" + detail.dparts[1] + "'");
                               }
            }
        };
        
        test.expect(7);
        runTests(this, config, function() { test.done(); });
    },

    "JWT.encode ==> Should FAIL     ==> no refresh, with secret & RS+bits": function(test) {
        var self = this;
        var config = {
            build:  { cb: buildConfig(test, function(result) { return { header: ALGORITHMS.header(ALGORITHMS.RS256), payload: result, secret: helper.secret } }) },
            encode: {
                cb: function(error, result, detail) {
                    test.ok(error, "Expected error, instead got: " + result);
                }
            }
        };
        
        test.expect(3);
        runTests(this, config, function() { test.done(); });
    },

    "JWT.encode ==> Should FAIL     ==> no refresh, with secret & ES+bits": function(test) {
        var self = this;
        var config = {
            build:  { cb: buildConfig(test, function(result) { return { header: ALGORITHMS.header(ALGORITHMS.ES256), payload: result, secret: helper.secret } }) },
            encode: {
                cb: function(error, result, detail) {
                    test.ok(error, "Expected error, instead got: " + result);
                }
            }
        };
        
        test.expect(3);
        runTests(this, config, function() { test.done(); });
    },

    "JWT.encode ==> Should FAIL     ==> no refresh, with privateKey & HS+bits": function(test) {
        var self = this;
        var config = {
            build:  { cb: buildConfig(test, function(result) { return { header: ALGORITHMS.header(ALGORITHMS.HS256), payload: result, privateKey: helper.key } }) },
            encode: {
                cb: function(error, result, detail) {
                    test.ok(error, "Expected error, instead got: " + result);
                }
            }
        };
        
        test.expect(3);
        runTests(this, config, function() { test.done(); });
    },
     
    "JWT.encode ==> Should SUCCEED  ==> no refresh, with privateKey & RS+bits": function(test) {
        var self = this;
        var config = {
            build:  { cb: buildConfig(test, function(result) { return { header: ALGORITHMS.header(ALGORITHMS.RS256), payload: result, privateKey: helper.key } }) },
            encode: {
                cb: function(error, result, detail) {
                    test.equal(error,null,error);
                
                    test.equal(detail.parts.length, 3, "Encoded token should contain 3 parts not: " + detail.parts.length);
                    test.ok((detail.parts[2] || '').length > 0, "Expected signature to be > zero: '" + detail.parts[2] + "'");
                
                    test.deepEqual(detail.json[0], { typ: 'JWT', cty: 'JWT', alg: 'RS256' }, "Unexpected header value: '" + detail.dparts[0] + "'");
                
                    test.deepEqual(detail.json[1], 
                                   { iss: 'MyClientID',
                                     aud: 'https://accounts.localhost.com/o/oauth2/token',
                                     iat: -60,
                                     exp: 3600,
                                     scope: [ '1', '3', '5' ] }, 
                                   "Unexpected payload value: '" + detail.dparts[1] + "'");
                               }
            }
        };
        
        test.expect(7);
        runTests(this, config, function() { test.done(); });
    },
    
    "JWT.encode ==> Should SUCCEED  ==> no refresh, with privateKey & ES+bits": function(test) {
        var self = this;
        var config = {
            build:  { cb: buildConfig(test, function(result) { return { header: ALGORITHMS.header(ALGORITHMS.ES256), payload: result, privateKey: helper.key } }) },
            encode: {
                cb: function(error, result, detail) {
                    test.equal(error,null,error);
                
                    test.equal(detail.parts.length, 3, "Encoded token should contain 3 parts not: " + detail.parts.length);
                    test.ok((detail.parts[2] || '').length > 0, "Expected signature to be > zero: '" + detail.parts[2] + "'");
                
                    test.deepEqual(detail.json[0], { typ: 'JWT', cty: 'JWT', alg: 'ES256' }, "Unexpected header value: '" + detail.dparts[0] + "'");
                
                    test.deepEqual(detail.json[1], 
                                   { iss: 'MyClientID',
                                     aud: 'https://accounts.localhost.com/o/oauth2/token',
                                     iat: -60,
                                     exp: 3600,
                                     scope: [ '1', '3', '5' ] }, 
                                   "Unexpected payload value: '" + detail.dparts[1] + "'");
                               }
            }
        };
        
        test.expect(7);
        runTests(this, config, function() { test.done(); });
    },

}