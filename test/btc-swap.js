const BtcSwap = require('../src/btc-swap.js');
var assert = require('assert');

var btcSwap;
var ticketId;

function init() {
  const host = 'localhost:8545';
  const address = '0xc214fd7067d32ffd79cfa7b425317f7194fc5546';  // Olympic with PoW disabled
  // const address = '0x73b1c6d725eafb2b9514e2af092f9f61fd005088';  // private with PoW disabled
  const from = '0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826';
  const btcTestnet = true;

  btcSwap = new BtcSwap({
    host: host,
    address: address,
    from: from,
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
      assert.strictEqual(result.amount, '170000000000000000');
      assert.strictEqual(result.price, '0.01');
      assert.strictEqual(result.total, '0.0017');
      assert.strictEqual(result.address, 'mvBWJFv8Uc84YEyZKBm8HZQ7qrvmBiH7zR');
      assert.strictEqual(result.expiry, 1437173408);
      assert.strictEqual(result.claimer, '29d33c02a200937995e632c4597b4dca8e503978');
      assert.strictEqual(result.txHash, 'dd5a8f13c97c8b8d47329fa7bd487df24b7d3b7e855a65eb7fd51e8f94f7e482');
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
    var junkNonce = -2;
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
      }
    );
  });
});
