const BtcSwap = require('../lib/btc-swap.js');
var assert = require('assert');

var btcSwap;
var ticketId;

function init() {
  const host = 'localhost:8545';
  // const address = '0x75160a6ac8c53e80be0f586b7c78bd24a18b89db';  // Olympic with very easy PoW
  const address = '0x73b1c6d725eafb2b9514e2af092f9f61fd005088';  // Private with same easy PoW
  const sender = '0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826';
  const btcTestnet = true;

  btcSwap = new BtcSwap({
    host: host,
    address: address,
    from: sender,
    btcTestnet: btcTestnet,
    debug: false
  });
}

before(function() {
  init();
});

describe('lookupTicket', function() {
  it('looks up a ticket', function(done) {
    btcSwap.lookupTicket(1, function(result) {
      assert.strictEqual(result.id, 1);
      assert.strictEqual(result.amount, '17000000000000000');
      assert.strictEqual(result.price, '0.1');
      assert.strictEqual(result.total, '0.0017');
      assert.strictEqual(result.address, 'mvBWJFv8Uc84YEyZKBm8HZQ7qrvmBiH7zR');
      assert.strictEqual(result.expiry, 1);
      assert.strictEqual(result.claimer, '');
      assert.strictEqual(result.txHash, '');
      assert.strictEqual(result.owner, '0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826');
      done();
    });
  });
});

describe('createTicket', function() {
  this.timeout(0);

  it('creates a ticket', function(done) {
    var btcAddr = 'mvBWJFv8Uc84YEyZKBm8HZQ7qrvmBiH7zR';
    var numEther = '0.017';
    var total = '0.0017';

    btcSwap.createTicket(btcAddr, numEther, total,
      function success(tx) {
        // TODO validate txHash
        console.log("txHash:", tx);
      },
      function completed(tx, result) {
        // console.log('createTicket ticket: ', result);
        ticketId = result.id;
        assert.strictEqual(result.amount, '17000000000000000');
        assert.strictEqual(result.price, '0.1');
        assert.strictEqual(result.total, total);
        assert.strictEqual(result.address, btcAddr);
        assert.strictEqual(result.expiry, 1);
        assert.strictEqual(result.claimer, '');
        assert.strictEqual(result.txHash, '');
        done();
      },
      function failure(error) {
        console.error(error);
      }
    );
  });
});

describe('reserveTicket', function() {
  this.timeout(0);

  it('reserves a ticket', function(done) {
    var txHash = 'dd5a8f13c97c8b8d47329fa7bd487df24b7d3b7e855a65eb7fd51e8f94f7e482';
    var junkNonce = 122;
    btcSwap.reserveTicket(ticketId, txHash, junkNonce,
      function success(result) {
        assert.strictEqual(result.id, ticketId);
      },
      function completed(result) {
        // console.log(result);
        assert.strictEqual(result.id, ticketId);
        assert.strictEqual(result.amount, '17000000000000000');
        assert.strictEqual(result.price, '0.1');
        assert.strictEqual(result.total, '0.0017');
        assert.strictEqual(result.address, 'mvBWJFv8Uc84YEyZKBm8HZQ7qrvmBiH7zR');
        assert.strictEqual(result.expiry, 1);
        assert.strictEqual(result.claimer, '');
        assert.strictEqual(result.txHash, '');
        done();
      },
      function failure(error) {
        console.error(error);
        done();
      }
    );
  });
});
