// Example 4: Real-world class with methods, destructuring, template literals
const { createHash } = require('crypto');

class ApiClient {
  constructor(baseUrl, apiKey) {
    this.baseUrl = baseUrl;
    this.apiKey = apiKey;
    this.headers = { 'Content-Type': 'application/json', 'X-API-Key': apiKey };
  }

  sign(payload) {
    const hash = createHash('sha256');
    hash.update(this.apiKey + JSON.stringify(payload));
    return hash.digest('hex');
  }
}

const ENDPOINTS = { users: '/api/v1/users', orders: '/api/v1/orders' };

function buildQuery(params) {
  return Object.entries(params)
    .filter(([k, v]) => v !== null && v !== undefined)
    .map(([k, v]) => `${k}=${encodeURIComponent(v)}`)
    .join('&');
}

// Test it
const client = new ApiClient('https://api.example.com', 'my-secret');
console.log('sign:', client.sign({ action: 'login' }));
console.log('query:', buildQuery({ name: 'alice', age: 30, tag: null }));
console.log('endpoints:', ENDPOINTS);

module.exports = { ApiClient, buildQuery, ENDPOINTS };
