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
    }
}