const test = require('node:test');
const assert = require('node:assert');
const { summarize } = require('../app');

test('summarize computes count, sum and mean', () => {
  assert.deepStrictEqual(summarize([1, 2, 3, 4]), { count: 4, sum: 10, mean: 2.5 });
});
