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
    , debug: true
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


describe('reserveTicket', function() {
  it.skip('reserves a ticket', function(done) {
    var ticketId = 1;
    var txHash = 'dd5a8f13c97c8b8d47329fa7bd487df24b7d3b7e855a65eb7fd51e8f94f7e482';
    var junkNonce = -2;
    btcSwap.reserveTicket(1, txHash, junkNonce,
      function success(result) {
        assert.strictEqual(result.id, ticketId);
      },

      function completed(result) {
        console.log(result)
        assert.strictEqual(result, ticketId);
        // assert.strictEqual(result.id, 1);
        // assert.strictEqual(result.amount, '170000000000000000');
        // assert.strictEqual(result.price, '0.01');
        // assert.strictEqual(result.total, '0.0017');
        // assert.strictEqual(result.address, 'mvBWJFv8Uc84YEyZKBm8HZQ7qrvmBiH7zR');
        // assert.strictEqual(result.expiry, 1);
        // assert.strictEqual(result.claimer, '');
        // assert.strictEqual(result.txHash, '');
        done();
    });
  });
});
