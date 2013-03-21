exports.key    = require('fs').readFileSync(require('path').join(__dirname, './test.pem'), 'utf8');
exports.secret = "I know what you did last summer.";
