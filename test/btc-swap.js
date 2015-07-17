const BtcSwap = require('../lib/btc-swap.js');
var assert = require('assert');

var btcSwap;

function init() {
  console.log('init');

  const host = 'localhost:8545';
  const address = '0xc214fd7067d32ffd79cfa7b425317f7194fc5546';  // Olympic with PoW disabled
  const btcTestnet = true;
  btcSwap = new BtcSwap({
    host: host,
    address: address,
    btcTestnet: btcTestnet
  });
}

before(function() {
  init();
});

describe('lookupTicket', function() {
  it('looks up a ticket', function(done) {
    btcSwap.lookupTicket(1, function(result) {
      assert.strictEqual(result.id, 1);
      assert.strictEqual(result.amount, '170000000000000000');
      assert.strictEqual(result.price, '0.01');
      assert.strictEqual(result.total, '0.0017');
      assert.strictEqual(result.address, 'mvBWJFv8Uc84YEyZKBm8HZQ7qrvmBiH7zR');
      assert.strictEqual(result.expiry, 1);
      assert.strictEqual(result.claimer, '');
      assert.strictEqual(result.txHash, '');
      done();
    });
  });
});
