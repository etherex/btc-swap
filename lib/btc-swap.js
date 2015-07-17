'use strict';

var BigNumber = require('bignumber.js');
var bitcoin = require('bitcoinjs-lib');
var btcproof = require('bitcoin-proof');
var web3 = require('web3');
var abi = require('./abi');
var debugAbi = require('./debugAbi');

var ku = require('./keccak.js');
var bnTarget = new BigNumber(2).pow(234);
var kecc = new ku.Keccak();

var TWO_POW_256 = new BigNumber(2).pow(256);

var WEI_PER_ETHER = new BigNumber(10).pow(18);
var SATOSHI_PER_BTC = new BigNumber(10).pow(8);

var TICKET_FIELDS = 7;

var RESERVE_FAIL_UNRESERVABLE = -10;
var RESERVE_FAIL_POW = -11;

var CLAIM_FAIL_INVALID_TICKET = -20;
var CLAIM_FAIL_UNRESERVED = -21;
var CLAIM_FAIL_CLAIMER = -22;
var CLAIM_FAIL_TX_HASH = -23;
var CLAIM_FAIL_INSUFFICIENT_SATOSHI = -24;
var CLAIM_FAIL_PROOF = -25;
var CLAIM_FAIL_WRONG_BTC_ADDR = -26;
var CLAIM_FAIL_TX_ENCODING = -27;

var btcSwap = function btcSwap(params) {
  // Check parameters
  if (!params.host) {
    throw new Error('Web3 host missing');
  }
  if (!params.address) {
    throw new Error('BtcSwap address missing');
  }
  if (typeof params.btcTestnet === 'undefined') this.btcTestnet = true;else this.btcTestnet = params.btcTestnet;

  // Set web3 provider
  web3.setProvider(new web3.providers.HttpProvider('http://' + params.host));

  // Check contract is available
  web3.eth.getCode(params.address, function (err, result) {
    if (err) {
      throw err;
    }
    if (result === '0x') {
      throw new Error('BtcSwap contract not found');
    }
  });

  // Set defaultAccount for transactions
  web3.eth.defaultAccount = params.from;

  // Set debug flag
  this.debug = params.debug;

  // Load contract instance
  this.contract = web3.eth.contract(abi).at(params.address);

  if (this.debug) console.log('BTCswap contract:', this.contract);

  this.versionAddr = this.btcTestnet ? 111 : 0;

  this.createTicket = function (btcAddress, numEther, btcTotal, success, completed, failure) {
    var addrHex;
    try {
      addrHex = '0x' + bitcoin.Address.fromBase58Check(btcAddress).hash.toString('hex');
      if (this.debug) console.log('BTC address hex:', addrHex);
    } catch (err) {
      failure(new Error(btcAddress + ' is an invalid Bitcoin address: ' + err.message));
      return;
    }
    var numWei = web3.toWei(numEther, 'ether');
    var weiPerSatoshi = new BigNumber(numWei).div(SATOSHI_PER_BTC.mul(btcTotal)).round(0).toString(10);

    var objParam = { value: numWei, gas: 500000 };

    var startTime = Date.now();

    this.contract.createTicket.call(addrHex, numWei, weiPerSatoshi, objParam, (function (error, result) {

      var endTime = Date.now();
      var durationSec = (endTime - startTime) / 1000;
      if (this.debug) console.log('Call result:', result, 'duration:', durationSec);

      var rval = result.toNumber();
      if (rval <= 0) {
        if (this.debug) console.log('Return value:', rval);
        var msg = 'Invalid ticket, it will not be created.';
        failure(msg);
        return;
      }

      this.contract.createTicket.sendTransaction(addrHex, numWei, weiPerSatoshi, objParam, (function (err, res) {
        if (this.debug) console.log('createTicket result:', res);

        if (err) {
          failure(err);
          console.log('createTicket sendTx error:', err);
          return;
        }

        success(res);

        this.watchCreateTicket(addrHex, numWei, weiPerSatoshi, res, completed, failure);
      }).bind(this));
    }).bind(this));
  };

  this.watchCreateTicket = function (addrHex, numWei, weiPerSatoshi, pendingHash, completed, failure) {
    var createFilter = this.contract.ticketEvent({ ticketId: 0 }, { fromBlock: 'latest', toBlock: 'latest' });

    createFilter.watch((function (err, res) {
      try {
        if (err) {
          failure(err);
          if (this.debug) console.log('createFilter error:', err);
          return;
        }

        if (this.debug) console.log('createFilter result:', res);

        var eventArgs = res.args;
        var ticketId = eventArgs.rval.toNumber();
        if (ticketId > 0) {
          setTimeout((function () {
            this.lookupTicket(ticketId, function (ticket) {
              completed(pendingHash, ticket);
            }, function (error) {
              failure('Could not lookup created ticket: ' + error);
            });
          }).bind(this), 1000);
        } else {
          failure('Ticket could not be created.');
        }
      } finally {
        if (this.debug) console.log('createFilter.stopWatching()...');
        createFilter.stopWatching();
      }
    }).bind(this));
  };

  this.claimTicket = function (ticketId, txHex, txHash, txIndex, merkleSibling, txBlockHash, success, completed, failure) {
    var objParam = { gas: 3000000 };

    var startTime = Date.now();

    this.contract.claimTicket.call(ticketId, txHex, txHash, txIndex, merkleSibling, txBlockHash, objParam, (function (error, result) {
      if (error) {
        failure(error);
        return;
      }

      var endTime = Date.now();
      var durationSec = (endTime - startTime) / 1000;
      if (this.debug) console.log('claimTicket call:', result, ' duration:', durationSec);

      var rval = result.toNumber();
      switch (rval) {
        case ticketId:
          if (this.debug) console.log('claimTicket call looks good, now sending transaction...');
          break; // the only result that does not return;
        case CLAIM_FAIL_INVALID_TICKET:
          // one way to get here is Claim, mine, then Claim without refreshing the UI
          failure('Invalid Ticket ID' + ' Ticket does not exist or already claimed');
          return;
        case CLAIM_FAIL_UNRESERVED:
          // one way to get here is Reserve, let it expire, then Claim without refreshing the UI
          failure('Ticket is unreserved' + ' Reserve the ticket and try again');
          return;
        case CLAIM_FAIL_CLAIMER:
          // one way to get here is change web3.eth.defaultAccount
          failure('Someone else has reserved the ticket' + ' You can only claim tickets that you have reserved');
          return;
        case CLAIM_FAIL_TX_HASH:
          // should not happen since UI prevents it
          failure('You need to use the transaction used in the reservation', '');
          return;
        case CLAIM_FAIL_INSUFFICIENT_SATOSHI:
          // should not happen since UI prevents it
          failure('Bitcoin transaction did not send enough bitcoins' + ' Number of bitcoins must meet ticket\'s total price');
          return;
        case CLAIM_FAIL_PROOF:
          failure('Bitcoin transaction needs at least 6 confirmations' + ' Wait and try again');
          return;
        case CLAIM_FAIL_WRONG_BTC_ADDR:
          // should not happen since UI prevents it
          failure('Bitcoin transaction paid wrong BTC address' + ' Bitcoins must be sent to the address specified by the ticket');
          return;
        case CLAIM_FAIL_TX_ENCODING:
          failure('Bitcoin transaction incorrectly constructed' + ' Use btcToEther tool to construct bitcoin transaction');
          return;
        default:
          failure('Unexpected error ' + rval);
          return;
      }

      // callback(null, 'claimTicket eth_call succeeded'); return // for testing only

      // at this point, the eth_call succeeded

      // dbgVerifyTx();

      var claimFilter = this.contract.ticketEvent({ ticketId: ticketId });
      claimFilter.watch((function (err, res) {
        try {
          if (err) {
            if (this.debug) console.log('claimFilter error: ', err);
            failure(err);
            return;
          }

          console.log('claimFilter result:', res);

          var eventArgs = res.args;
          if (eventArgs.rval.toNumber() === ticketId) {
            if (this.debug) console.log('Ticket claimed:', ticketId);
            completed(res);
          } else {
            failure('Claim ticket error: ' + rval);
          }
        } finally {
          if (this.debug) console.log('claimFilter.stopWatching()...');
          claimFilter.stopWatching();
        }
      }).bind(this));

      this.contract.claimTicket.sendTransaction(ticketId, txHex, txHash, txIndex, merkleSibling, txBlockHash, objParam, (function (err, res) {
        if (this.debug) console.log('claimTicket result: ', res);
        if (err) {
          failure(err);
          if (this.debug) console.log('claimTicket sendTx error: ', err);
          return;
        }
        success(res);
      }).bind(this));
    }).bind(this));
  };

  this.reserveTicket = function (ticketId, txHash, powNonce, success, completed, failure) {
    var objParam = { gas: 500000 };

    var startTime = Date.now();

    this.contract.reserveTicket.call(ticketId, txHash, powNonce, objParam, (function (error, result) {
      if (error) {
        failure(error);
        return;
      }

      var endTime = Date.now();
      var durationSec = (endTime - startTime) / 1000;
      if (this.debug) console.log('reserveTicket call:', result.toNumber(), ' duration:', durationSec);

      var rval = result.toNumber();
      switch (rval) {
        case ticketId:
          if (this.debug) console.log('reserveTicket call looks good, now sending transaction...');
          break; // the only result that does not return
        case RESERVE_FAIL_UNRESERVABLE:
          failure('Ticket already reserved');
          return;
        case RESERVE_FAIL_POW:
          failure('Proof of Work is invalid');
          return;
        default:
          if (this.debug) console.log('Unexpected error:', rval);
          failure('Unexpected error: ' + rval);
          return;
      }

      // at this point, the eth_call succeeded
      // if (this.debug)
      //   return;

      var reserveFilter = this.contract.ticketEvent({ ticketId: ticketId });
      reserveFilter.watch((function (err, res) {
        try {
          if (err) {
            if (this.debug) console.log('reserveFilter error:', err);
            failure(err);
            return;
          }

          if (this.debug) console.log('reserveFilter result:', res);

          var eventArgs = res.args;
          if (eventArgs.rval.toNumber() === ticketId) {
            if (this.debug) console.log('Ticket reserved:', ticketId);
            this.lookupTicket(ticketId, function (ticket) {
              completed(ticket);
            }, function (lookupError) {
              failure('Could not lookup reserved ticket: ' + lookupError);
            });
          } else {
            failure('Reserve ticket error: ' + rval);
          }
        } finally {
          if (this.debug) console.log('reserveFilter.stopWatching()...');
          reserveFilter.stopWatching();
        }
      }).bind(this));

      this.contract.reserveTicket.sendTransaction(ticketId, txHash, powNonce, objParam, (function (err, res) {
        if (this.debug) console.log('reserveTicket result:', res);
        if (err) {
          failure(err);
          if (this.debug) console.log('reserveTicket sendTx error:', err);
          return;
        }
        success({
          id: ticketId,
          hash: res
        });
      }).bind(this));
    }).bind(this));
  };

  // returns tickets with keys ticketId, btcAddr, numEther, btcTotal, numClaimExpiry
  this.getOpenTickets = function (start, end, success, failure) {
    this.contract.getOpenTickets.call(start, end, (function (error, results) {
      if (error) {
        failure(error);
        return;
      }

      var tickets = [];

      for (var i = 0; i < results.length; i += TICKET_FIELDS) {

        var bnWei = results[i + 2];
        var bnWeiPerSatoshi = results[i + 3];

        tickets.push({
          id: results[i + 0].toNumber(),
          address: this.toBtcAddr(results[i + 1]),
          amount: bnWei.toString(),
          price: this.toBtcPrice(bnWeiPerSatoshi),
          total: this.toBtcTotal(bnWei, bnWeiPerSatoshi),
          expiry: results[i + 4].toNumber(),
          claimer: this.toHash(results[i + 5]),
          txHash: this.toHash(results[i + 6])
        });
      }

      success(tickets);

      // TODO
      // for (var i = 0; i < results.length; i += 1) {
      //   var ticketId = results[i][0];
      //   if (!ticketId)
      //     break;

      //   var bnWei = results[i][2];
      //   var bnWeiPerSatoshi = results[i][3];

      //   tickets.push({
      //     ticketId: ticketId.toNumber(),
      //     btcAddr: this.toBtcAddr(results[i][1]),
      //     numWei: bnWei.toString(),
      //     btcTotal: this.toBtcTotal(bnWei, bnWeiPerSatoshi),
      //     numClaimExpiry: results[i][4].toNumber()
      //     // bnClaimer: ticketArr[i + 5].toString(10),
      //     // bnClaimTxHash: ticketArr[i + 6].toString(10)
      //   });
      // }
      // success(tickets);
    }).bind(this));
  };

  this.lookupTicket = function (id, success, failure) {
    this.contract.lookupTicket.call(id, (function (error, result) {
      if (error) {
        failure('Error loading ticket ' + id + ': ' + String(error));
        return;
      }

      if (this.debug) console.log('LOOKUP', result);

      if (!result || !result[0] || !result[0].toNumber()) {
        success(false);
        return;
      }

      var bnWei = result[1];
      var bnWeiPerSatoshi = result[2];

      var ticket = {
        id: id,
        address: this.toBtcAddr(result[0]), // toBtcAddr(arr[0], this.versionAddr),
        amount: bnWei.toString(), // toEther(bnWei),
        price: this.toBtcPrice(bnWeiPerSatoshi),
        total: this.toBtcTotal(bnWei, bnWeiPerSatoshi),
        expiry: result[3].toNumber(),
        claimer: this.toHash(result[4]),
        txHash: this.toHash(result[5])
      };

      success(ticket);
    }).bind(this));
  };

  this.verifyPoWClicked = function (ticketId, txHash, nonce, success, failure) {
    var hexTicketId = new BigNumber(ticketId).toString(16);
    var padLen = 16 - hexTicketId.length;
    var leadZerosForTicketId = Array(padLen + 1).join('0');

    var hexNonce = new BigNumber(nonce).toString(16);
    padLen = 16 - hexNonce.length;
    var leadZerosForNonce = Array(padLen + 1).join('0');

    var bnSrc = new BigNumber('0x' + txHash + leadZerosForTicketId + hexTicketId + leadZerosForNonce + hexNonce);
    var src;
    var bnHash;
    var strHash;

    if (this.debug) console.log('@@@ bnSrc: ', bnSrc.toString(16));

    src = ku.hexStringToBytes(bnSrc.toString(16));
    src = new Uint32Array(src.buffer);
    var srcLen = src.length;
    var dst = new Uint32Array(8);
    kecc.digestWords(dst, 0, 8, src, 0, srcLen);

    strHash = ku.wordsToHexString(dst);
    bnHash = new BigNumber('0x' + strHash);

    var isPowValid = bnHash.lt(bnTarget);
    if (this.debug) console.log('@@@ isPowValid: ', isPowValid, ' pow: ', bnHash.toString(16), ' target: ', bnTarget.toString(16));

    if (isPowValid) {
      success('Proof of Work valid');
    } else {
      failure('Proof of Work invalid');
    }
  };

  this.computePoW = function (ticketId, btcTxHash, success, failure) {
    try {
      // var powPromise = new Promise(function(resolve, reject) {
      if (this.debug) console.log('@@@ computePow txhash: ', btcTxHash);

      var hexTicketId = new BigNumber(ticketId).toString(16);
      var padLen = 8 - hexTicketId.length;
      var leadZerosForTicketId = Array(padLen + 1).join('0');

      var bnSrc = new BigNumber('0x' + btcTxHash + leadZerosForTicketId + hexTicketId + '0000000000000000');
      var src;
      var bnHash;
      var strHash;

      if (this.debug) console.log('@@@ bnSrc: ', bnSrc.toString(16));

      src = ku.hexStringToBytes(bnSrc.toString(16));
      src = new Uint32Array(src.buffer);
      var srcLen = src.length;
      var dst = new Uint32Array(8);
      kecc.digestWords(dst, 0, 8, src, 0, srcLen);

      strHash = ku.wordsToHexString(dst);
      bnHash = new BigNumber('0x' + strHash);

      var startTime = new Date().getTime();
      if (this.debug) console.log('startTime: ', startTime);

      var start = 0;
      var tryPoW = (function (i) {
        bnSrc = bnSrc.add(1);

        src = ku.hexStringToBytes(bnSrc.toString(16));
        src = new Uint32Array(src.buffer);
        kecc.digestWords(dst, 0, 8, src, 0, srcLen);

        strHash = ku.wordsToHexString(dst);
        bnHash = new BigNumber('0x' + strHash);
        if (this.debug) console.log('PASS', i, strHash, 'DIFF', bnTarget.minus(bnHash).toString());

        if (i >= 1000) failure('PoW failed.');
        // reject("PoW failed.");

        i += 1;
        if (bnHash.gte(bnTarget) && i < 1000) setTimeout(tryPoW, 10, i);else {
          success(i);

          if (this.debug) {
            console.log('endTime: ', new Date().getTime());
            console.log('duration: ', (new Date().getTime() - startTime) / 1000.0);

            console.log('@@@@ nonce: ', i);
            console.log('@@@ strHash: ', strHash);
          }
        }
        // resolve(i);
      }).bind(this);

      tryPoW(start);

      // var i = 0;
      // while (bnHash.gte(bnTarget) && i < 100000000) {
      //   setTimeout(tryPoW(i), 1);
      //   i += 1;
      // }

      // if (i === 100000000)
      //   reject("PoW failed.");

      // resolve(i);
      // }.bind(this));

      // powPromise.then(function (nonce) {
      //     success(nonce);
      // }, function (e) {
      //     failure(String(e));
      // });
    } catch (e) {
      failure(e);
    }
  };

  this.merkleProof = function (tx, index) {
    return btcproof.getProof(tx, index);
  };

  this.debugVerifyTx = function () {
    // TODO don't forget to update the ABI
    var dbgAddress = '0x90439a6495ee8e7d86a4acd2cbe649ed21e2ef6e';
    var dbgContract = web3.eth.contract(debugAbi).at(dbgAddress);

    var txHash = '0x558231b40b5fdddb132f9fcc8dd82c32f124b6139ecf839656f4575a29dca012';
    var dbgEvent = dbgContract.dbgEvent({ txHash: txHash });

    var txhEvent = dbgContract.txhEvent({ txHash: txHash });

    dbgEvent.watch(function (err, res) {
      if (err) {
        console.log('@@@ dbgEvent err: ', err);
        return;
      }

      console.log('@@@ dbgEvent res: ', res);
    });

    txhEvent.watch(function (err, res) {
      if (err) {
        console.log('@@@ txhEvent err: ', err);
        return;
      }

      console.log('@@@ txhEvent res: ', res);
    });
  };

  this.toBtcPrice = function (bnWeiPerSatoshi) {
    return new BigNumber(1).div(bnWeiPerSatoshi.div(WEI_PER_ETHER).mul(SATOSHI_PER_BTC)).toString();
  };

  this.toBtcTotal = function (bnWei, bnWeiPerSatoshi) {
    return bnWei.div(bnWeiPerSatoshi).div(SATOSHI_PER_BTC).round(8).toString(10);
  };

  this.toBtcAddr = function (bignum) {
    var hexAddress = web3.fromDecimal(bignum).substr(2);
    if (this.debug) console.log('hexAddress:', hexAddress, 'versionByte: ', this.versionAddr);
    return new bitcoin.Address(new Buffer(hexAddress, 'hex'), this.versionAddr).toString();
  };

  // needed for handling negative bignums
  // http://stackoverflow.com/questions/3417183/modulo-of-negative-numbers/3417242#3417242
  this.bignumToHex = function (bn) {
    return bn.mod(TWO_POW_256).lt(0) ? bn.add(TWO_POW_256).toString(16) : bn.toString(16);

    // return bn.mod(TWO_POW_256).add(TWO_POW_256).mod(TWO_POW_256).toString(16);
  };

  this.toHash = function (bignum) {
    var hash = this.bignumToHex(bignum);
    return hash === '0' ? '' : hash;
  };

  // var toEther = function(bnWei) {
  //   return web3.fromWei(bnWei, 'ether').toString(10);
  // };
};

module.exports = btcSwap;
//# sourceMappingURL=btc-swap.js.map
