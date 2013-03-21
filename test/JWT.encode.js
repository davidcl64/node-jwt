var jwt        = require('..').jwt;
var util       = require('util');
var ALGORITHMS = jwt.ALGORITHMS;
var JWT        = jwt.JWT;
var base64url  = require('base64url');
var config     = require('./config/config');

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
 *  config: {
 *      build: {
 *          opts: {},   // Claims to be added to JWT.build request
 *          cb:   fn,   // Callback function - passed (error, result)
 *      },
 *      encode: {
 *          opts: {},   // Claims to be added to the encode request
 *          cb:   fn,   // Callback function - passed (error, result, detail)
 *                      // where detail is { parts: result.split('.'),
 *                                           json:  JSON parsed part or {} if non-existant }
 *      }
 *  }
 */
function runTests(config) {
    
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
        
        Date.now = config.now;
        Date.prototype.getTime = config.now;
        cb();
    },
    
    tearDown: function(cb   ) {
        Date.now = this._now;
        Date.prototype.getTime = this._getTime;       
        cb();
    },
    
    "JWT.encode ==> no refresh, no secret": function(test) {
        var self = this;
        test.expect(7);
        JWT.build(self.opts, function(error,result) {
            var opts = {};
            
            test.equal(error,null);
            test.ok(result !== null);
            
            opts.header  = ALGORITHMS.header(ALGORITHMS.NONE);
            opts.payload = result;
            
            JWT.encode(opts, function(error, result) {
                test.equal(error,null,error);
                
                var parts = (result || "").split('.');
                
                test.equal(parts.length, 3, "Encoded token should contain 3 parts not: " + parts.length);
                test.equal('', parts[2], "Expected signature to be of zero length not: '" + parts[2] + "'");
                
                var decodedPart = base64url.decode(parts[0]);
                var part = JSON.parse(decodedPart || '{}');
                
                test.deepEqual(part, { typ: 'JWT', cty: 'JWT', alg: 'NONE' }, "Unexpected header value: '" + decodedPart + "'");
                
                decodedPart = base64url.decode(parts[1] || '');
                part        = JSON.parse(decodedPart || '{}');
                
                test.deepEqual(part, { iss: 'MyClientID',
                                       aud: 'https://accounts.localhost.com/o/oauth2/token',
                                       iat: -60,
                                       exp: 3600,
                                       scope: [ '1', '3', '5' ] }, "Unexpected payload value: '" + decodedPart + "'");
                
                test.done();
            });
        });
    }
}