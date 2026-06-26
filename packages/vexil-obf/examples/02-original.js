// Example 2: API client script (standalone, no exports)
var API_KEY = 'sk-live-abc123xyz789-prod';
var BASE_URL = 'https://api.myservice.com/v2';

function callEndpoint(path, method) {
  if (method === 'GET') {
    return BASE_URL + path + '?key=' + API_KEY;
  } else if (method === 'POST') {
    return BASE_URL + path;
  } else {
    return 'unsupported method: ' + method;
  }
}

var endpoints = ['users', 'orders', 'payments'];
for (var i = 0; i < endpoints.length; i++) {
  console.log(callEndpoint('/' + endpoints[i], 'GET'));
}
