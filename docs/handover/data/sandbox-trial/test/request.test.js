const test = require('node:test');
const assert = require('node:assert');

test('request library loads', () => {
  const request = require('request');
  assert.strictEqual(typeof request.get, 'function');
});
