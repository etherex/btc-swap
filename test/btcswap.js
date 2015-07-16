const btcswap = require('../src/btcswap.js'),
  assert = require('assert');

var btcSwap;

before(function() {
  init();
});

describe('lookupTicket', function() {
  it('simple', function(done) {
    btcSwap.lookupTicket(2, function(result) {
      assert.equal(result.id, 2);
      assert.equal(result.price, 0.0017);
      // TODO result.amount
      // assert.equal(result.address, 'mvBWJFv8Uc84YEyZKBm8HZQ7qrvmBiH7zR');
      assert.equal(result.expiry, 1);
      assert.equal(result.claimer, '');
      assert.equal(result.txhash, '');
      done();
    });
  });
});

function init() {
  console.log('init')

  const host = 'http://localhost:8549';
  const address = '0xc214fd7067d32ffd79cfa7b425317f7194fc5546';  // Olympic with PoW disabled
  const btcTestnet = true;
  btcSwap = new btcswap({
    host: host,
    address: address,
    btcTestnet: btcTestnet
  });
}
