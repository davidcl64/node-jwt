var EventEmitter = require('events').EventEmitter;
var jws = require('jws');
const base64url = require('base64url');

// Build a MAP of algorithms and helper function to return an appropriate
// JWA compliant algorithm header.
var ALGORITHMS = (function() {
    var retVal = {
        "NONE": "NONE",
        "header": function header(alg) {
            return alg in this ? { "typ": "JWT", "cty": "JWT", "alg": alg } : undefined;
        }
    }
    
    jws.ALGORITHMS.forEach(function(val) {
        retVal[val] = val;
    });
    
    return retVal;
})();

/*
 * A simple helper to assist in building a compliant 
 * JSON WEB Token.
 *
 * Used to generate values for the claims: exp, iat and nbf
 *
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
function buildToken(options, cb) {
    // ~~ is a (slightly) faster version of Math.floor
    var exp, nbf;
    var iat = ~~((new Date().getTime() / 1000) - 60);
    var claims = options.claims || {};
    var delay  = options.delay || 0;
    var scopeSep = options.scopeSep || ' ';
    
    claims.iat = iat;
    
    // If we have been provided an expiration, we will use it along with delay if necessary
    if(options.expiration) {
        var now = ~~(new Date().getTime() / 1000);
        
        claims.exp = now + options.expiration + delay;
        if(delay) {
            claims.nbf = now + delay;
        }
    }
    
    // If scope was passed in as a string, convert to an array to store it.
    if(options.scope) {
        if(Array.isArray(options.scope)) {
            claims.scope = options.scope;
        } else {
            claims.scope = options.scope.split(scopeSep);
        }
    }
    
    cb(null, claims);
}

/*
 * Call to encode a JSON WEB Token.  
 *
 * RefreshToken validation can be triggered by providing one/both of the refresh option values.  A
 * 
 * If provided, a refresh token will be decoded and its claims will be used to validate the requested
 * claims for the incoming token.  An optional refresh token validation callback can be provided to give
 * the application the opportunity to do domain specific validation.
 *
 * options: {
 *    header:       a JWT header generated with one of jwt.ALGORITHMS,
 *    privateKey:   security key used to encode this token.
 *    payload:      JSON WEB Token (JWT) compliant object,
 *    scopeSep:     scope separator if other than ' ',
 *    refresh: {
 *        token:    If provided, the refresh token will be decoded and used to help validate the data provided,
 *        claimIds: Array of claim ID's to check against the accessToken request.  If not provided checks will be
 *                  performed against ['aud', 'sub', 'iss', 'scope'].  This validation can be skipped by providing
 *                  an empty array (not recommended).  If so, it is strongly recommended that the caller provide
 *                  their own claim validation logic.
 *       
 *                  Array based claims (e.g.: aud & scope) will ensure all values requested for the access token are 
 *                  available in the refreshToken.
 *
 *                  String based clames (e.g.: sub & iss) will be checked for strict equality.
 *
 *        validate: validation function - if provided, will be called to assist in validating the refresh token.
 *                  This would usually involve checking to see if the refresh token hasn't been revoked and whatever
 *                  else your security requires.
 *
 *                  It *MUST* take a callback as its last param with the signature:  callback(error, success)
 *
 *        privateKey: security key used to decode this token. Required if token was signed.
 *    }
 * }
 * 
 * callback: function callback(error, result)
 * where result is { token, expires_in } All validation is successful and the token was successfully encoded
 */
function encode(options, cb) {
    // Briefly sanity check parameters
    if(!options.header) {
        cb(new Error('Invalid Params: Missing required header.  You *MUST* provide this explicitly.'));
        return;
    }
    else if( options.header.alg === ALGORITHMS.NONE && (options.privateKey || options.secret) ) {
        cb(new Error('Invalid Params: passed in a security key but asked for no encryption - which is it?'));
        return;
    } else if( options.payload === undefined ) {
        cb(new Error('Invalid Params: Missing payload, kinda makes this request pointless...'));
        return;
    } else if( options.header.alg !== ALGORITHMS.NONE && !(options.privateKey || options.secret) ) {
        cb(new Error('Invalid Params: You asked for ' + options.header.alg + ' but did not provide a privateKey/secret'));
        return;
    } else if( options.header.alg.charAt(0) === 'H' && !options.secret ) {
        cb(new Error('Invalid Params: You cannot use ' + options.header.alg + ' with a privateKey'));
        return;
    } else if( (options.header.alg.charAt(0) === 'R' || options.header.alg.charAt(0) === 'E') && !options.privateKey ) {
        cb(new Error('Invalid Params: You cannot use ' + options.header.alg + ' with a secret'));
        return;
    }
    
    // The fun begins if we were passed a refresh token.  Lots'o'validation to be done now...
    //
    // This *ASSUMES* (yes I know there's a three letter word in there) that the refresh token is somewhat symmetrical with
    // the access token.  IE: both are JWT based, both (or neither) has scope, etc...
    if(options.refresh) {
        refreshTokenInfo(options.refresh, function(error, result){
            var claimIds      = options.refresh.claimIds || ['aud', 'sub', 'iss', 'scope'];
            var refreshClaims = result.rawToken.payload;
            var accessClaims  = options.payload;
            var claimsOK;
            var claimResult   = [];
            
            if(error) {
                cb(error);
                return;
            }
            
            // This loop will reduce the claim checks to a set of errors.  Once finished, if the
            // claim result is not empty, one or more errors has occurred.
            claimResult = claimIds.reduce(function(prevTop, currTop, index, arr) {
                if(Array.isArray(refreshClaims[currTop])) {
                    return (accessClaims[currTop] || []).reduce(function(prevInner, currInner, indexInner, arrInner) {
                        if(refreshClaims[currTop].indexOf(currInner) < 0) {
                            prevInner.push("ERROR: Requested access exceeds refresh grant (" + currInner + ") is not in: " + refreshClaims[currTop].join(' '));
                        }
                        
                        return prevInner;
                    }, prevTop)
                } else {
                    if(refreshClaims[currTop] !== accessClaims[currTop]) {
                        prevTop.push("ERROR: Equality check failed (" + currTop + "): " + refreshClaims[currTop]  + " !== " + accessClaims[currTop])
                    }
                }
                
                return prevTop;
            }, claimResult);
            
            if(claimResult.length > 0) {
                err = new Error("Claims Mismatch: One or more of the requested claims are not available in the refreshToken");
                err.refreshClaims = refreshClaims;
                err.accessClaims  = accessClaims;
                err.failures      = claimResult;
                
                cb(err);
                return;                
            }
            
            /*
            // The claimsOK check utilizes Array.every to validate all requested claims in the claimIDs filter.
            // If at any time a comparison is false, the check is stopped.
            claimsOK = claimIds.every(function(claimId) {
                if(Array.isArray(refreshClaims)) {
                    return (accessClaims[claimId] || []).every(function(claimVal) {
                        return (refreshClaims.indexOf(claimVal) >= 0);
                    })
                } else {
                    return refreshClaims[claimId] === accessClaims[claimId];
                }
                
            });
            
            if(!claimsOK) {
                err = new Error("Claims Mismatch: One or more of the requested claims are not available in the refreshToken");
                err.refreshClaims = refreshClaims;
                err.accessClaims  = accessClaims;
                
                cb(err);
                return;
            }
            */
            genToken();
            
        })
    } else {
        genToken();
    }
    
    function genToken() {
        var input  = { header:      options.header, 
                       payload:     options.payload, 
                       privateKey:  options.privateKey, 
                       secret:      options.secret };
        var sig = jws.sign(input);    
         
        if((input.privateKey || input.secret) && sig.split('.').length != 3) {
            var error = new Error("Expected a signature, but got nothing.");
            error.input = input;
            error.output = sig;
            cb(error);
            return;
        }
        
        cb(null, sig);   
    }
}

/*
 * Validate the provided signature
 *
 * options: {
 *     signature: signature to be validated
 *     key:   used to valid teh signature
 * }
 */
function validateSignature(options, cb) {
    var valid  = false;
    
    if(options.signature.length > 0) {
        valid = jts.verify(options.signature, options.privateKey || options.secret);
    } else {
        valid = true;
    }
    
    if(!valid) {
        cb(new Error('Invalid Signature: Unable to validate signature against provided key.'));
        return;
    } 
    
    cb(null, true);
}

/*
 * Decode the provided token and validate its signature
 *
 * options: {
 *     token: token to be decoded
 *     key:   used to valid the signature
 * }
 */
function decode(options, cb) {
    var decodedToken = jws.decode(options.token);
    
    if(!decodedToken) {
        cb(new Error('Invalid Token: Missing or invalid signature and/or header.'));
        return;
    }
    
    validateSignature({signature: decodedToken.signature, privateKey: options.privateKey, secret: options.secret}, function(error, result) {
        if(error) {
            cb(error);
            return;
        }
        
        cb(null, decodedToken);
    })   
}

/*
 * Helper function to return more detail about the refresh token and do some 
 * preliminary validation.
 *
 * Retrieving the refreshToken information will in turn decode and validate the signature
 * ensuring that, on a successful result the refresh token can be trusted.
 *
 * options: {
 *    token: the refreshToken in question
 *    key:   the key to decoded the refresh token (if necessary)
 * }
 */
function refreshTokenInfo(options, cb) {
    var retVal = {original: options.token};
    var valid = false;
    
    if(!options.token) {
        cb(new Error('Invalid Params: Unable to obtain refreshToken information if you provide a token'));
        return;
    }
    
    decode(options, function(error, result) {
        if(error) {
            cb(error);
            return;
        }
        
        retVal.rawToken = result;
        if(options.validate) {
            options.validate(options, function(error, result) {
                if(error) {
                    cb(error);
                    return;
                }
                
                // Need to validate exp(iration) and nbf (not before)
                
                cb(null, retVal);
            });
        } else {
            cb(null, retVal);
        }
    });
}


module.exports.ALGORITHMS = ALGORITHMS;
module.exports.JWT = {
    'build':    buildToken,
    'encode':   encode,
    'validate': validateSignature,
    'decode':   decode
}

