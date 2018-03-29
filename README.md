# bcrypt.wasm

[![Current Version](https://img.shields.io/npm/v/bcrypt.wasm.svg)](https://www.npmjs.org/package/bcrypt.wasm)
[![Build Status via Travis CI](https://travis-ci.org/cjihrig/bcrypt.wasm.svg?branch=master)](https://travis-ci.org/cjihrig/bcrypt.wasm)
![Dependencies](http://img.shields.io/david/cjihrig/bcrypt.wasm.svg)
[![belly-button-style](https://img.shields.io/badge/eslint-bellybutton-4B32C3.svg)](https://github.com/cjihrig/belly-button)

WebAssembly implementation of bcrypt. This module began life as a quasi-fork of the [bcrypt](https://www.npmjs.com/package/bcrypt) module. Currently, only the synchronous APIs are available.

## Basic Usage

```javascript
'use strict';
const Bcrypt = require('bcrypt.wasm');
const data = 'password';
const salt = Bcrypt.genSaltSync();
const hash = Bcrypt.hashSync(data, salt);

Bcrypt.compareSync(data, hash); // equals true
Bcrypt.compareSync(data + 'x', hash); // equals false
```

## API

`bcrypt.wasm` exports the following methods.

### `compareSync(data, hash)`

  - Arguments
    - `data` (string) - Cleartext data to compare against an encrypted hash.
    - `hash` (string) - An encrypted hash to compare against cleartext input.
  - Returns
    - `match` (boolean) - `true` if the comparison succeeds, and `false` otherwise.

### `genSaltSync(rounds)`

  - Arguments
    - `rounds` (number) - The cost of generating a salt. Optional. Defaults to `10`.
  - Returns
    - `salt` (string) - The generated salt.

### `getRounds(hash)`

  - Arguments
    - `hash` (string) - An encrypted hash.
  - Returns
    - `rounds` (number) - The number of rounds used to encrypt `hash`.

### `hashSync(data, salt)`

  - Arguments
    - `data` (string) - Cleartext data to encrypt.
    - `salt` (number or string) - The salt used to hash `data`. If `salt` is a number, it is passed to `genSaltSync()` to generate a salt string.
  - Returns
    - `hash` (string) - The encrypted hash of `data` using `salt`.
