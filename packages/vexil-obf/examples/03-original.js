// Example 3: License checker with control flow
var VALID_KEYS = ['PRO-XXXX-1234-ABCDE', 'ENT-YYYY-5678-EFGHI'];
var PRODUCT = 'MyApp Pro';
var VERSION = '3.1.4';

function checkLicense(key) {
  if (!key) {
    return { valid: false, reason: 'no key provided' };
  } else if (key.length !== 19) {
    return { valid: false, reason: 'invalid key format' };
  } else if (VALID_KEYS.indexOf(key) === -1) {
    return { valid: false, reason: 'key not recognized' };
  } else {
    return { valid: true, reason: 'ok', product: PRODUCT, version: VERSION };
  }
}

console.log(checkLicense('PRO-XXXX-1234-ABCDE'));
console.log(checkLicense('FAKE-KEY'));
