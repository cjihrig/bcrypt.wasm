'use strict';
const Crypto = require('crypto');
// Hack to work around issue related to loading from other directories.
// See https://github.com/kripken/emscripten/issues/4542
const cwd = process.cwd();
process.chdir(__dirname);
const Wasm = require('./bcrypt');
process.chdir(cwd);
// End hack


function compareSync (data, hash) {
  if (typeof data !== 'string') {
    throw new TypeError('data must be a string');
  }

  if (typeof hash !== 'string') {
    throw new TypeError('hash must be a string');
  }

  return Wasm.CompareSync(data, hash);
}


function genSaltSync (rounds = 10) {
  if (!Number.isInteger(rounds) || rounds < 0) {
    throw new TypeError('rounds must be a number');
  }

  return Wasm.GenerateSaltSync(rounds, Crypto.randomBytes(16));
}


function getRounds (hash) {
  if (typeof hash !== 'string') {
    throw new Error('hash must be a string');
  }

  return Wasm.GetRounds(hash);
}


function hashSync (data, salt) {
  if (typeof data !== 'string') {
    throw new TypeError('data must be a string');
  }

  if (typeof salt === 'number') {
    salt = genSaltSync(salt);
  } else if (typeof salt !== 'string') {
    throw new TypeError('salt must be a salt string or a number of rounds');
  }

  return Wasm.EncryptSync(data, salt);
}


module.exports = { compareSync, genSaltSync, getRounds, hashSync };
