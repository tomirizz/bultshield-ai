const _ = require('lodash');

function summarize(numbers) {
  return {
    count: numbers.length,
    sum: _.sum(numbers),
    mean: _.mean(numbers),
  };
}

module.exports = { summarize };
