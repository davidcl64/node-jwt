var jwt        = require('..').jwt;
var util       = require('util');
var ALGORITHMS = jwt.ALGORITHMS;
var JWT        = jwt.JWT;
var base64url  = require('base64url');
var config     = require('./config/config');

module.exports = {
    setUp: function(cb) {
        this.opts = {
            expiration: 60 * 60,
            delay:      0,
            claims:     {
                iss:    'MyClientID',
                aud:    'https://accounts.localhost.com/o/oauth2/token'
            },
            scope:      ['auth', 'userinfo']
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
    
    "Basic JWT.build": function(test) {
        var self = this;
        test.expect(2);
        JWT.build(self.opts, function(error,result) {
            test.equal(error,null);
            test.ok(result !== null);
            test.done();
        });
    },
    
    "JWT.build with Delay": function(test) {
        var self = this;
        
        test.expect(4);
        self.opts.delay = 300;
        
        JWT.build(self.opts, function(error,result) {
            test.equal(error,null);
            test.ok(result !== null);
            test.ok(result.exp === self.opts.expiration + self.opts.delay);
            test.ok(result.nbf === self.opts.delay);
            test.done();
        });
    },
    
    "JWT.build with String Scope": function(test) {
        var self = this;
        test.expect(2);
        self.opts.scope = "This is a test";
        
        JWT.build(self.opts, function(error,result) {
            test.equal(error,null);
            test.ok(result.scope.length === 4, "Comparing: " + JSON.stringify(result.scope) + " to " + self.opts.scope);
            test.done();
        });
    },

    "JWT.build with String Scope & delimeter": function(test) {
        var self = this;
        test.expect(2);
        self.opts.scope = "This,is,a,test";
        self.opts.scopeSep = ',';
        
        JWT.build(self.opts, function(error,result) {
            test.equal(error,null, "Unexpected error received.");
            test.ok(result.scope.length === 4, "Comparing: " + JSON.stringify(result.scope) + " to " + self.opts.scope);
            test.done();
        });
    }
};