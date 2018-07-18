'use strict';

let fs = require('fs');
let path = require('path');

function get(filename) {
  let filePath = path.join(__dirname, filename);
  let key = fs.readFileSync(filePath, 'utf8');

  if (filename.endsWith('.json')) {
    key = JSON.parse(key);
  }

  return  key;
}

module.exports = {
  get
};
