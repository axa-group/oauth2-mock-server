'use strict';

const fs = require('fs');
const path = require('path');

function get(filename) {
  const filePath = path.join(__dirname, filename);
  let key = fs.readFileSync(filePath, 'utf8');

  if (filename.endsWith('.json')) {
    key = JSON.parse(key);
  }

  return key;
}

module.exports = {
  get,
};
