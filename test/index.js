'use strict';
const Code = require('code');
const Lab = require('lab');
const Bcrypt = require('../lib');

// Test shortcuts
const lab = exports.lab = Lab.script();
const { describe, it } = lab;
const { expect } = Code;


describe('Bcrypt', () => {
  it('tests salt length', () => {
    const salt = Bcrypt.genSaltSync(10);
    expect(salt.length).to.equal(29);
    const split = salt.split('$');
    expect(split[1]).to.equal('2b');
    expect(split[2]).to.equal('10');
  });

  it('tests salt with no arguments', () => {
    const salt = Bcrypt.genSaltSync();
    expect(salt.length).to.equal(29);
    const split = salt.split('$');
    expect(split[1]).to.equal('2b');
    expect(split[2]).to.equal('10');
  });

  it('tests salt with minimum rounds', () => {
    const salt = Bcrypt.genSaltSync(1);
    expect(salt.length).to.equal(29);
    const split = salt.split('$');
    expect(split[1]).to.equal('2b');
    expect(split[2]).to.equal('04');
  });

  it('tests salt with maximum rounds', () => {
    const salt = Bcrypt.genSaltSync(100);
    expect(salt.length).to.equal(29);
    const split = salt.split('$');
    expect(split[1]).to.equal('2b');
    expect(split[2]).to.equal('31');
  });

  it('throws if salt length is not a non-negative integer', () => {
    function fail (value) {
      expect(() => {
        Bcrypt.genSaltSync(value);
      }).to.throw(TypeError, 'rounds must be a number');
    }

    [-5, 3.14, '10', NaN, Infinity, '', null, {}].forEach(fail);
  });

  it('tests hashing', () => {
    const salt = Bcrypt.genSaltSync(10);
    const hash = Bcrypt.hashSync('password', salt);

    expect(hash).to.be.a.string();
  });

  it('tests getting the number of rounds', () => {
    const hash = Bcrypt.hashSync('password', 8);
    const rounds = Bcrypt.getRounds(hash);

    expect(rounds).to.equal(8);
  });

  it('getRounds() throws if hash is not a string', () => {
    expect(() => {
      Bcrypt.getRounds(1);
    }).to.throw(Error, 'hash must be a string');
  });

  it('getRounds() throws if an invalid hash is passed', () => {
    expect(() => {
      Bcrypt.getRounds('foo');
    }).to.throw(Error, 'invalid hash provided');
  });

  it('tests hashing with empty strings', () => {
    const errMessage = 'salt must be of the form: $Vers$log2(NumRounds)$saltvalue';

    expect(Bcrypt.hashSync('', 10)).to.be.a.string();

    expect(() => {
      Bcrypt.hashSync('password', '');
    }).to.throw(Error, errMessage);

    expect(() => {
      Bcrypt.hashSync('', '');
    }).to.throw(Error, errMessage);
  });

  it('hash throws if data is not a string', () => {
    expect(() => {
      Bcrypt.hashSync(1, 10);
    }).to.throw(TypeError, 'data must be a string');
  });

  it('hash throws if salt is not a string or number', () => {
    expect(() => {
      Bcrypt.hashSync('foo');
    }).to.throw(TypeError, 'salt must be a salt string or a number of rounds');
  });

  it('tests that hash salt is a valid salt', () => {
    expect(Bcrypt.hashSync('password', '$2a$10$somesaltyvaluertsetrse')).to.be.a.string();
    expect(() => {
      Bcrypt.hashSync('password', 'some$value');
    }).to.throw(Error, 'salt must be of the form: $Vers$log2(NumRounds)$saltvalue');
  });

  it('compares the correct value with a hash', () => {
    const data = 'password';
    const salt = Bcrypt.genSaltSync();
    const hash = Bcrypt.hashSync(data, salt);

    expect(Bcrypt.compareSync(data, hash)).to.equal(true);
  });

  it('compares the wrong value with a hash', () => {
    const data = 'password';
    const salt = Bcrypt.genSaltSync();
    const hash = Bcrypt.hashSync(data, salt);

    expect(Bcrypt.compareSync(data + 'x', hash)).to.equal(false);
  });

  it('compare throws if data is not a string', () => {
    expect(() => {
      Bcrypt.compareSync(10);
    }).to.throw(TypeError, 'data must be a string');
  });

  it('compare throws if hash is not a string', () => {
    expect(() => {
      Bcrypt.compareSync('password', 10);
    }).to.throw(TypeError, 'hash must be a string');
  });

  it('compare returns false for the empty string and empty hash', () => {
    expect(Bcrypt.compareSync('', '')).to.equal(false);
  });
});
