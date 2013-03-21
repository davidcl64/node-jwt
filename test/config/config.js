exports.key    = require('fs').readFileSync(require('path').join(__dirname, './test.pem'), 'utf8');
exports.secret = "I know what you did last summer.";

// Used in test to start with a zero based date/time.
exports.now         = function() { return 0; }

// Sets up a time function that will return the offset specified converted to millis
exports.getOffsetFunc  = function(offsetInSecs) { return function() { return offsetInSecs * 1000; } }

