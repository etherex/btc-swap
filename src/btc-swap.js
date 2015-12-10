var BigNumber = require('bignumber.js');
var bitcoin = require('bitcoinjs-lib');
var btcproof = require('bitcoin-proof');
var Blockchain = require('cb-blockr');
var https = require('https');
var Web3 = require('web3');
var web3 = new Web3();
var abi = require('./abi/btc-swap');
var relayAbi = require('./abi/btcrelay');

var ku = require('./keccak.js');
var bnTarget = new BigNumber(2).pow(245);
var kecc = new ku.Keccak();

var RELAY_TESTNET = "0xd34e752661c770ee2eb078326ed7a2a09acff135";
var TWO_POW_256 = new BigNumber(2).pow(256);

var WEI_PER_ETHER = new BigNumber(10).pow(18);
var SATOSHI_PER_BTC = new BigNumber(10).pow(8);
var SATOSHIFEE = 30000;

// var TICKET_FIELDS = 7;

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

var btcSwap = function(params) {
  // Check parameters
  if (!params.host) {
    throw new Error('web3 host missing');
  }
  if (!params.address) {
    throw new Error('btc-swap address missing');
  }
  if (!params.from) {
    throw new Error('fromAccount missing');
  }
  if (typeof params.testnet === 'undefined')
    this.testnet = true;
  else
    this.testnet = params.testnet;

  // Use the environment's web3 provider or fallback
  if (global.web3 && global.web3.currentProvider) {
    web3.setProvider(global.web3.currentProvider);
  } else {
    web3.setProvider(new web3.providers.HttpProvider('//' + params.host));
  }

  // Check contract is available
  web3.eth.getCode(params.address, function(err, result) {
    if (err) {
      throw err;
    }
    if (result === '0x') {
      // throw new Error('btc-swap contract not found');
      console.error('btc-swap contract not found');
    }
  });

  // Set defaultAccount for transactions
  web3.eth.defaultAccount = params.from;

  // Set debug flag
  this.debug = params.debug;

  // Load contract instance
  this.contract = web3.eth.contract(abi).at(params.address);

  // Load btcrelay contract
  try {
    var relayAddr = web3.eth.namereg.addr('btcrelay');
  }
  catch(e) {
    this.testnet = true;
  }
  // var relayAddrTestnet = web3.eth.namereg.addr('btcrelayTestnet'); // TODO namereg btcrelay for BTC testnet
  var relayAddress = this.testnet ? RELAY_TESTNET : relayAddr;
  this.relay = web3.eth.contract(relayAbi).at(relayAddress);

  // if (this.debug)
  //   console.log('btc-swap contract:', this.contract);

  this.versionAddr = this.testnet ? 111 : 0;
  if (this.debug)
    console.log('BTC network:', this.testnet ? "TESTNET" : "LIVE");


  this.reset = function() {
    try {
      web3.reset();
    }
    catch (e) {
      console.error(e);
    }
  };

  this.lookupTicket = function(id, success, failure) {
    this.contract.lookupTicket.call(id, function(error, result) {
      if (error) {
        failure("Error loading ticket " + id + ": " + String(error));
        return;
      }

      if (!result || !result[0] || !result[0].toNumber()) {
        success(false);
        return;
      }

      var bnWei = result[2];
      var bnWeiPerSatoshi = result[3];
      var total = this.toBtcTotal(bnWei, bnWeiPerSatoshi);
      var claimer = this.toHash(result[5]);
      var txHash = this.toHash(result[6]);

      var ticket = {
        id: result[0].toNumber(),
        address: this.toBtcAddr(result[1]),
        amount: bnWei.toString(),
        price: this.toBtcPrice(bnWeiPerSatoshi),
        total: total,
        totalWithFee: new BigNumber(total).add(SATOSHIFEE / SATOSHI_PER_BTC).round(8, BigNumber.ROUND_UP).toString(),
        weiPerSatoshi: bnWeiPerSatoshi.toString(),
        expiry: result[4].toNumber(),
        claimer: claimer ? this.padLeft(claimer, 40) : null,
        txHash: txHash ? this.padLeft(txHash, 64) : null,
        owner: web3.toHex(result[7])
      };

      // if (this.debug)
      //   console.log("LOOKUP", ticket);

      success(ticket);
    }.bind(this));
  };

  this.createTicket = function(btcAddress, numEther, btcTotal, success, completed, failure) {
    var addrHex;
    try {
      addrHex = '0x' + bitcoin.Address.fromBase58Check(btcAddress).hash.toString('hex');
      if (this.debug)
        console.log("BTC address hex:", addrHex);
    }
    catch (err) {
      failure(btcAddress + ' is an invalid Bitcoin address: ' + err.message);
      return;
    }
    var numWei = web3.toWei(numEther, 'ether');
    var weiPerSatoshi = new BigNumber(numWei).div(SATOSHI_PER_BTC.mul(btcTotal)).round(0).toString(10);

    var objParam = {value: numWei, gas: 500000};

    var startTime = Date.now();

    this.contract.createTicket.call(addrHex, numWei, weiPerSatoshi, objParam, function(error, result) {

      var endTime = Date.now();
      var durationSec = (endTime - startTime) / 1000;
      if (this.debug)
        console.log('Call result:', result, 'duration:', durationSec);

      var rval = result.toNumber();
      if (rval <= 0) {
        if (this.debug)
          console.log('Return value:', rval);
        failure('Invalid ticket, it will not be created.');
        return;
      }

      this.contract.createTicket.sendTransaction(addrHex, numWei, weiPerSatoshi, objParam, function(err, res) {
        if (this.debug)
          console.log("createTicket result:", res);

        if (err) {
          failure(err.message);
          if (this.debug)
            console.error('createTicket sendTx error:', err);
          return;
        }

        success(res);

        this.watchCreateTicket(res, completed, failure);
      }.bind(this));
    }.bind(this));
  };

  this.watchCreateTicket = function(pendingHash, completed, failure) {
    var createFilter = this.contract.ticketEvent({ ticketId: 0 }, { fromBlock: 'latest', toBlock: 'latest'});

    if (this.debug)
      console.log('watching for createTicket');

    createFilter.watch(function(err, res) {
      try {
        if (err) {
          failure(err.message);
          if (this.debug)
            console.error('createFilter error:', err);
          return;
        }

        if (this.debug)
          console.log('createFilter result:', res);

        var eventArgs = res.args;
        var ticketId = eventArgs.rval.toNumber();

        if (this.debug)
          console.log('id of "created" ticket: ', ticketId);

        if (ticketId > 0) {
          setTimeout( function() {
            this.lookupTicket(ticketId, function(ticket) {
              if (this.debug)
                console.log('lookup of created ticket: ', ticket);

              completed(pendingHash, ticket);
            }.bind(this), function(error) {
              if (this.debug)
                console.log('error lookup for created ticket:', error);

              failure('Could not lookup created ticket: ' + error);
            }.bind(this));
          }.bind(this), 1000);
        }
        else {
          if (this.debug)
            console.log('return value from failed create ticket: ', ticketId);

          failure('Ticket could not be created.');
        }
      }
      finally {
        if (this.debug)
          console.log('createFilter.stopWatching()...');
        createFilter.stopWatching();
      }
    }.bind(this));
  };

  this.reserveTicket = function(ticketId, txHash, powNonce, success, completed, failure) {
    txHash = '0x' + txHash;

    var objParam = {gas: 500000};

    var startTime = Date.now();

    this.contract.reserveTicket.call(ticketId, txHash, powNonce, objParam, function(error, result) {
      if (error) {
        failure(error);
        return;
      }

      var endTime = Date.now();
      var durationSec = (endTime - startTime) / 1000;
      if (this.debug)
        console.log('reserveTicket call:', result.toNumber(), ' duration:', durationSec);

      var rval = result.toNumber();
      switch (rval) {
        case ticketId:
          if (this.debug)
            console.log('reserveTicket call looks good, now sending transaction...');
          break;  // the only result that does not return
        case RESERVE_FAIL_UNRESERVABLE:
          failure('Ticket already reserved.');
          return;
        case RESERVE_FAIL_POW:
          failure('Proof of Work is invalid.');
          return;
        default:
          if (this.debug)
            console.log('Unexpected error:', rval);
          failure('Unexpected error: ' + rval);
          return;
      }

      // at this point, the eth_call succeeded
      // if (this.debug)
      //   return;

      var reserveFilter = this.contract.ticketEvent({ ticketId: ticketId });
      reserveFilter.watch(function(err, res) {
        try {
          if (err) {
            if (this.debug)
              console.error('reserveFilter error:', err);
            failure(err.message);
            return;
          }

          if (this.debug)
            console.log('reserveFilter result:', res);

          rval = res.args.rval.toNumber();
          if (rval === ticketId) {
            if (this.debug)
              console.log('Ticket reserved:', ticketId);
            setTimeout( function() {
              this.lookupTicket(ticketId, function(ticket) {
                completed(ticket);
              }, function(lookupError) {
                failure('Could not lookup reserved ticket: ' + lookupError);
              });
            }.bind(this), 1000);
          }
          else {
            if (this.debug)
              console.log('Reserve ticket error: ' + rval);
            failure('Reserve ticket error: ' + rval);
          }
        }
        finally {
          if (this.debug)
            console.log('reserveFilter.stopWatching()...');
          reserveFilter.stopWatching();
        }
      }.bind(this));

      this.contract.reserveTicket.sendTransaction(ticketId, txHash, powNonce, objParam, function(err, res) {
        if (this.debug)
          console.log('reserveTicket result:', res);
        if (err) {
          failure(err.message);
          if (this.debug)
            console.error('reserveTicket sendTx error:', err);
          return;
        }
        success({
          id: ticketId,
          hash: res
        });
      }.bind(this));
    }.bind(this));
  };

  this.claimTicket = function(ticketId, txHex, txHash, txIndex, merkleSibling, txBlockHash, feeWei, success, completed, failure) {
    txHash = '0x' + txHash;
    txBlockHash = '0x' + txBlockHash;
    merkleSibling = merkleSibling.map(function(sib) {
      return '0x' + sib;
    });

    var objParam = {
      gas: 3000000,
      value: feeWei
    };

    var startTime = Date.now();

    this.contract.claimTicket.call(ticketId, txHex, txHash, txIndex, merkleSibling, txBlockHash, objParam, function(error, result) {
      if (error) {
        failure(error);
        return;
      }

      var endTime = Date.now();
      var durationSec = (endTime - startTime) / 1000;
      if (this.debug)
        console.log('claimTicket call:', result, ' duration:', durationSec);

      var rval = result.toNumber();
      switch (rval) {
        case ticketId:
          if (this.debug)
            console.log('claimTicket call looks good, now sending transaction...');
          break;  // the only result that does not return;
        case CLAIM_FAIL_INVALID_TICKET:  // one way to get here is Claim, mine, then Claim without refreshing the UI
          failure('Invalid Ticket ID. Ticket does not exist or is already claimed.');
          return;
        case CLAIM_FAIL_UNRESERVED:  // one way to get here is Reserve, let it expire, then Claim without refreshing the UI
          failure('Ticket is unreserved.  Reserve the ticket and try again');
          return;
        case CLAIM_FAIL_CLAIMER:  // one way to get here is change web3.eth.defaultAccount
          failure('Someone else has reserved the ticket. You can only claim tickets that you have reserved');
          return;
        case CLAIM_FAIL_TX_HASH:  // should not happen since UI prevents it
          failure('You need to use the transaction used in the reservation', '');
          return;
        case CLAIM_FAIL_INSUFFICIENT_SATOSHI:  // should not happen since UI prevents it
          failure('Bitcoin transaction did not send enough bitcoins. The amount of bitcoins must meet the ticket\'s total.');
          return;
        case CLAIM_FAIL_PROOF:
          failure('Bitcoin transaction needs at least 6 confirmations. Wait and try again later.');
          return;
        case CLAIM_FAIL_WRONG_BTC_ADDR:  // should not happen since UI prevents it
          failure('Bitcoin transaction paid wrong BTC address. Bitcoins must be sent to the address specified by the ticket.');
          return;
        case CLAIM_FAIL_TX_ENCODING:
          failure('Bitcoin transaction incorrectly constructed. Use btcToEther tool to construct bitcoin transaction.');
          return;
        default:
          failure('Unexpected error: ' + String(rval));
          return;
      }

      var claimFilter = this.contract.ticketEvent({ ticketId: ticketId });
      claimFilter.watch(function(err, res) {
        try {
          if (err) {
            if (this.debug)
              console.error('claimFilter error: ', err);
            failure(err.message);
            return;
          }

          console.log('claimFilter result:', res);

          var eventArgs = res.args;
          if (eventArgs.rval.toNumber() === 0) {
            if (this.debug)
              console.log('Ticket claimed:', ticketId);
            completed(ticketId);
          }
          else {
            failure('Claim ticket error: ' + ticketId);
          }
        }
        finally {
          if (this.debug)
            console.log('claimFilter.stopWatching()...');
          claimFilter.stopWatching();
        }
      }.bind(this));

      this.contract.claimTicket.sendTransaction(ticketId, txHex, txHash, txIndex, merkleSibling, txBlockHash, objParam, function(err, res) {
          if (this.debug)
            console.log("claimTicket result: ", res);
          if (err) {
            failure(err.message);
            if (this.debug)
              console.error('claimTicket sendTx error: ', err);
            return;
          }
          success(res);
      }.bind(this));
    }.bind(this));
  };

  this.cancelTicket = function(ticketId, success, completed, failure) {
    this.contract.cancelTicket.call(ticketId, function(error, result) {
      if (error) {
        failure("Error canceling ticket " + ticketId + ": " + String(error));
        return;
      }

      if (this.debug)
        console.log("CANCEL", result.toNumber());

      if (!result || !result.toNumber() || result.toNumber() !== ticketId) {
        failure("Error canceling ticket # " + ticketId);
        return;
      }

      var cancelFilter = this.contract.ticketEvent({ ticketId: ticketId });

      cancelFilter.watch(function(err, res) {
        try {
          if (err) {
            if (this.debug)
              console.error('cancelFilter error: ', err);
            failure(err.message);
            return;
          }

          console.log('cancelFilter result:', res);

          var eventArgs = res.args;
          if (eventArgs.rval.toNumber() === 0) {
            if (this.debug)
              console.log('Ticket canceled:', ticketId);
            completed(ticketId);
          }
          else {
            failure('Cancel ticket error: ' + ticketId);
          }
        }
        finally {
          if (this.debug)
            console.log('cancelFilter.stopWatching()...');
          cancelFilter.stopWatching();
        }
      }.bind(this));

      this.contract.cancelTicket.sendTransaction(ticketId, function(err, res) {
          if (this.debug)
            console.log("cancelTicket result: ", res);
          if (err) {
            failure(err.message);
            if (this.debug)
              console.error('cancelTicket sendTx error: ', err);
            return;
          }
          success(ticketId, res);
      }.bind(this));
    }.bind(this));
  };

  // Global ticket watcher
  this.watchTickets = function(ticketEvent, failure) {
    // Prevent the filter from being set multiple times
    if (this.ticketFilter)
      this.ticketFilter.stopWatching();

    this.ticketFilter = this.contract.ticketEvent({ ticketId: null });

    this.ticketFilter.watch(function(err, res) {
      try {
        if (err) {
          if (this.debug)
            console.error('ticketFilter error: ', err);
          failure(err.message);
          return;
        }

        if (this.debug)
          console.log('ticketFilter result:', res);

        var eventArgs = res.args;
        var ticketId = eventArgs.ticketId.toNumber();
        var rval = eventArgs.rval.toNumber();

        // New ticket
        if (ticketId === 0 && rval > 0) {
          if (this.debug)
            console.log('New ticket:', rval);
          ticketEvent("new", rval);
        }
        // Ticket reserved
        else if (ticketId > 0 && ticketId === rval) {
          if (this.debug)
            console.log('Ticket reserved:', rval);
          ticketEvent("reserved", rval);
        }
        // Ticket claimed or canceled
        else if (ticketId > 0 && rval === 0) {
          if (this.debug)
            console.log('Ticket removed:', ticketId);
          ticketEvent("removed", ticketId);
        }
        // else {
        //   failure('Ticket event for # ' + ticketId + ': ' + rval);
        // }
      }
      catch(e) {
        if (this.debug)
          console.error('ticketFilter error, should maybe stopWatching()...');
        // this.ticketFilter.stopWatching();
        failure('Ticket filter error: ' + e.message);
      }
    }.bind(this));
  };

  // Returns open ticket IDs
  this.getTicketIDs = function(success, failure) {
    this.contract.getTicketIDs.call(function(error, results) {
      if (error) {
        failure(error);
        return;
      }

      var ticketIDs = results.map(function(ticketId) {
        return ticketId.toNumber();
      });

      success(ticketIDs);
    });
  };

  /*
   * PoW nonce generation, verification and merkleProof
   */
  this.computePoW = function(ticketId, btcTxHash, success, failure) {
    try {
      if (this.debug)
        console.log('computePow txhash: ', btcTxHash);

      var hexTicketId = new BigNumber(ticketId).toString(16);
      var bnSrc = new BigNumber('0x' + btcTxHash + this.padLeft(hexTicketId, 16) + "0000000000000000");
      var src;
      var bnHash;
      var strHash;

      var powSrc = this.padLeft(bnSrc.toString(16), 96);

      if (this.debug)
        console.log('PoW source: ', powSrc);

      src = ku.hexStringToBytes(powSrc);
      src = new Uint32Array(src.buffer);
      var srcLen = src.length;
      var dst = new Uint32Array(8);
      kecc.digestWords(dst, 0, 8, src, 0, srcLen);

      strHash = ku.wordsToHexString(dst);
      bnHash = new BigNumber('0x' + strHash);

      var startTime = new Date().getTime();
      if (this.debug)
        console.log("startTime: ", startTime);

      var start = 0;

      var tryPoW = function(i) {
        bnSrc = bnSrc.add(1);
        powSrc = this.padLeft(bnSrc.toString(16), 96);

        src = ku.hexStringToBytes(powSrc);
        src = new Uint32Array(src.buffer);
        kecc.digestWords(dst, 0, 8, src, 0, srcLen);

        strHash = ku.wordsToHexString(dst);
        bnHash = new BigNumber('0x' + strHash);
        if (this.debug)
          console.log("PASS", i, bnHash.toNumber(), bnTarget.toNumber(), "DIFF", bnHash.minus(bnTarget).toNumber());

        if (i >= 10000 - 1) {
          failure("PoW failed.");
          return;
        }

        i += 1;
        if (bnHash.gte(bnTarget) && i < 10000)
          setTimeout(tryPoW, 10, i);
        else {
          success(i);

          if (this.debug) {
            console.log("endTime: ", new Date().getTime());
            console.log("duration: ", (new Date().getTime() - startTime) / 1000.0);

            console.log('nonce: ', i);
            console.log('strHash: ', strHash);
          }
        }
      }.bind(this);

      tryPoW(start);
    }
    catch(e) {
      failure(e);
    }
  };

  this.verifyPoW = function(ticketId, txHash, nonce, success, failure) {
    var hexTicketId = new BigNumber(ticketId).toString(16);
    var hexNonce = new BigNumber(nonce).toString(16);

    var src;
    var bnHash;
    var strHash;
    var bnSrc = new BigNumber('0x' + txHash + this.padLeft(hexTicketId, 16) + this.padLeft(hexNonce, 16));
    var powSrc = this.padLeft(bnSrc.toString(16), 96);

    if (this.debug)
      console.log('PoW source: ', powSrc);

    src = ku.hexStringToBytes(powSrc);
    src = new Uint32Array(src.buffer);
    var srcLen = src.length;
    var dst = new Uint32Array(8);
    kecc.digestWords(dst, 0, 8, src, 0, srcLen);

    strHash = ku.wordsToHexString(dst);
    bnHash = new BigNumber('0x' + strHash);

    var isPowValid = bnHash.lt(bnTarget);
    if (this.debug)
      console.log('isPowValid: ', isPowValid, ' pow: ', bnHash.toString(16), ' target: ', bnTarget.toString(16));

    if (isPowValid) {
      success('Proof of Work valid.');
    }
    else {
      failure('Proof of Work invalid.');
    }
  };

  this.merkleProof = function(tx, index) {
    return btcproof.getProof(tx, index);
  };


  /*
   * Utility functions
   */
  this.padLeft = function (string, chars, sign) {
    return new Array(chars - string.length + 1).join(sign ? sign : "0") + string;
  };

  this.padRight = function (string, chars, sign) {
    return string + (new Array(chars - string.length + 1).join(sign ? sign : "0"));
  };

  this.toBtcPrice = function(bnWeiPerSatoshi) {
    return new BigNumber(1).div(bnWeiPerSatoshi.div(WEI_PER_ETHER).mul(SATOSHI_PER_BTC)).round(8, BigNumber.ROUND_UP).toString();
  };

  this.toBtcTotal = function(bnWei, bnWeiPerSatoshi) {
    return bnWei.div(bnWeiPerSatoshi).div(SATOSHI_PER_BTC).round(8, BigNumber.ROUND_UP).toString(10);
  };

  this.toBtcAddr = function(bignum) {
    var hexAddress = web3.fromDecimal(bignum).substr(2);
    // if (this.debug)
    //   console.log('hexAddress:', hexAddress, 'versionByte: ', this.versionAddr);
    return new bitcoin.Address(new Buffer(hexAddress, 'hex'), this.versionAddr).toString();
  };

  // needed for handling negative bignums
  // http://stackoverflow.com/questions/3417183/modulo-of-negative-numbers/3417242#3417242
  this.bignumToHex = function(bn) {
    return bn.mod(TWO_POW_256).lt(0) ? bn.add(TWO_POW_256).toString(16) : bn.toString(16);

    // return bn.mod(TWO_POW_256).add(TWO_POW_256).mod(TWO_POW_256).toString(16);
  };

  this.toHash = function(bignum) {
    var hash = this.bignumToHex(bignum);
    return hash === '0' ? '' : hash;
  };


  /**
   * BTC intermediate wallet
   */
  this.generateWallet = function(success, failure) {
    var network = this.testnet ? bitcoin.networks.testnet : bitcoin.networks.bitcoin;

    try {
      var key = bitcoin.ECKey.makeRandom();

      var wallet = {
        key: key.toWIF(network),
        address: key.pub.getAddress(network).toString()
      };

      success(wallet);
    }
    catch(e) {
      if (this.debug)
        console.error(e);
      failure(e.message);
    }
  };

  this.importWallet = function(wif, success, failure) {
    var network = this.testnet ? bitcoin.networks.testnet : bitcoin.networks.bitcoin;

    try {
      var key = bitcoin.ECKey.fromWIF(wif);

      var wallet = {
        key: key.toWIF(network),
        address: key.pub.getAddress(network).toString()
      };

      success(wallet);
    }
    catch(e) {
      if (this.debug)
        console.error(e);
      failure(e.message);
    }
  };

  this.createTransaction = function(wallet, recipient, amountBtc, etherFee, etherAddress, success, failure) {
    var blockchain = new Blockchain(this.testnet ? 'testnet' : 'bitcoin');

    var amount = Math.floor(amountBtc * SATOSHI_PER_BTC);
    var minimum = amount + SATOSHIFEE;

    if (this.debug)
      console.log("CREATE_TRANSACTION", wallet, recipient, amount, amountBtc, etherAddress, etherFee);

    // Get unspent outputs
    var error;
    blockchain.addresses.unspents(wallet.address, function(err, unspents) {
      if (err) {
        failure("Error retrieving unspent outputs.");
        return;
      }

      if (this.debug)
        console.log("UNSPENTS", unspents);

      if (!unspents) {
        error = "Error: not enough unspent outputs in BTC address.";
        failure(error);
        return;
      }

      // Calculate balance, fee and gather inputs
      var balanceBtc = 0;
      var inputs = [];
      for (var i = 0; i < unspents.length; i++) {
        if (unspents[i].confirmations >= 3) {
          balanceBtc += parseFloat(unspents[i].value);
          var out = {
            hash: unspents[i].txId,
            index: unspents[i].vout
          };
          inputs.push(out);
        }
        else {
          failure("Not enough confirmations at your intermediate wallet. Please wait for at least 3 confirmation.");
          return;
        }
      }
      if (this.debug)
        console.log("INPUTS", inputs);

      var balance = Math.floor(balanceBtc * SATOSHI_PER_BTC);
      var fee = balance - amount;

      // Check balance
      if (this.debug)
        console.log("BALANCE", balance, "MINIMUM", minimum);

      if (balance < minimum) {
        var minimumBtc = minimum / SATOSHI_PER_BTC;
        var feeBtc = SATOSHIFEE / SATOSHI_PER_BTC;
        if (fee > 0)
          feeBtc = fee / SATOSHI_PER_BTC;
        failure(`Insufficient funds. Total needed is ${minimumBtc} BTC (includes ${feeBtc} BTC miner fee). Intermediate address has ${balanceBtc} BTC.`);
        return;
      }

      var tx = new bitcoin.TransactionBuilder();

      // Add inputs
      for (var o = 0; o < inputs.length; o++)
        tx.addInput(inputs[o].hash, inputs[o].index);

      // Add output
      tx.addOutput(recipient, amount);

      // Add output script
      var ethAddressBtc = new bitcoin.Address(new Buffer(etherAddress, 'hex'), this.versionAddr).toString();
      var ethFeeValue = parseInt('1' + ('0000' + parseFloat(etherFee).toFixed(2).replace('.', '')).slice(-4));
      tx.addOutput(ethAddressBtc, ethFeeValue);

      // Make private key from WIF
      var key = bitcoin.ECKey.fromWIF(wallet.key);

      // Sign inputs with key
      for (var s = 0; s < inputs.length; s++)
        tx.sign(s, key);

      // Build transaction
      try {
        tx = tx.build();
      }
      catch(e) {
        error = "Error building BTC transaction: ";
        if (this.debug)
          console.error(error, e);
        failure(error + e.message);
        return;
      }

      var signedTx = {
        fee: fee,
        hash: tx.getId(),
        hex: tx.toHex()
      };

      if (this.debug)
        console.log(signedTx);

      // Return signed transaction
      success(signedTx);

    }.bind(this));
  };

  this.propagateTransaction = function(txHex, success, failure) {
    var blockchain = new Blockchain(this.testnet ? 'testnet' : 'bitcoin');

    if (!bitcoin.Transaction.fromHex(txHex)) {
      failure("Invalid raw transaction.");
      return;
    }

    blockchain.transactions.propagate(txHex, function(err, res) {
      if (err) {
        if (this.debug)
          console.error(err);
        failure("Error propagating transaction: " + err.message);
        return;
      }

      if (!res) {
        failure("No result from propagating transaction.");
        return;
      }

      success(res);
    }.bind(this));
  };


  /**
   * BTC relay
   */
  this.getBlockchainHead = function(success, failure) {
    this.relay.getBlockchainHead.call(function(err, res) {
      if (err) {
        var error = "Error retrieving BTC chain head:";
        if (this.debug)
          console.error(error, err);
        failure(error + ' ' + err.message);
        return;
      }

      var hash = res.toString(16);
      var formattedHash = Array(64 - hash.length + 1).join('0') + hash;

      success(formattedHash);
    }.bind(this));
  };

  this.getLastBlockHeight = function(success, failure) {
    this.relay.getLastBlockHeight.call(function(err, res) {
      if (err) {
        var error = "Error retrieving BTC block height:";
        if (this.debug)
          console.error(error, err);
        failure(error + ' ' + err.message);
        return;
      }

      var height = res.toString();

      success(height);
    }.bind(this));
  };

  this.getFeeAmount = function(blockHash, success, failure) {
    this.relay.getFeeAmount.call(blockHash, function(err, res) {
      if (err) {
        var error = "Error retrieving fee amount:";
        if (this.debug)
          console.error(error, err);
        failure(error + ' ' + err.message);
        return;
      }

      var feeAmount = res.toString();

      success(feeAmount);
    }.bind(this));
  };

  this.storeBlockWithFee = function(blockHash, feeWei, success, failure) {
    var options = {gas: 300000};

    var reqOptions = {
      hostname: (this.testnet ? 't' : '') + 'btc.blockr.io',
      port: 443,
      path: '/api/v1/block/raw/' + blockHash,
      method: 'GET',
      withCredentials: false
    };

    var errorMsg;
    var req = https.request(reqOptions, function(res) {
      if (!res || res.statusCode !== 200) {
        errorMsg = "Error retrieving BTC block.";
        if (this.debug)
          console.error(errorMsg, res);
        failure(errorMsg);
        return;
      }

      res.on('data', function(data) {
        var json = JSON.parse(data);

        if (json.status !== 'success') {
          errorMsg = "Error retrieving BTC block data.";
          if (this.debug)
            console.error(errorMsg, json);
          failure(errorMsg);
          return;
        }

        data = json.data;
        if (!data || !data.tx) {
          errorMsg = "Not enough data in BTC block.";
          if (this.debug)
            console.error(errorMsg, data);
          failure(errorMsg);
          return;
        }

        var block = new bitcoin.Block();
        block.version = data.version;
        block.prevHash = bitcoin.bufferutils.reverse(new Buffer(data.previousblockhash, 'hex'));
        block.merkleRoot = bitcoin.bufferutils.reverse(new Buffer(data.merkleroot, 'hex'));
        block.timestamp = data.time;
        block.bits = parseInt(data.bits, 16);
        block.nonce = data.nonce;

        var blockHeader = web3.toAscii(block.toHex(true));

        if (this.debug) {
          console.log("BTC_BLOCK", block, block.toHex(true));
          console.log("BTC_BLOCK_BYTES", blockHeader, web3.toHex(blockHeader));
        }

        errorMsg = "Block header is invalid.";

        this.relay.storeBlockWithFee.call(blockHeader, feeWei, options, function(err, result) {
          if (err) {
            if (this.debug)
              console.error(errorMsg, err);
            failure(errorMsg + ' ' + err.message);
            return;
          }

          var blockNumber = result.toNumber();

          if (this.debug)
            console.log("STORE_BLOCK_HEADER", blockNumber, blockHash, blockHeader);

          if (blockNumber) {
            this.relay.storeBlockWithFee.sendTransaction(blockHeader, feeWei, options, function(error, txHash) {
              if (error) {
                if (this.debug)
                  console.error(errorMsg, error);
                failure(errorMsg + ' Sending transaction failed: ' + String(error));
                return;
              }

              if (txHash) {
                var txFilter = web3.eth.filter('latest');
                txFilter.watch( function(filterError, newBlockHash) {
                  if (filterError) {
                    if (this.debug)
                      console.error(errorMsg, filterError);
                    failure(errorMsg + ' Filter failed: ' + String(filterError));
                    return;
                  }
                  if (!newBlockHash)
                    return;

                  var tx = web3.eth.getTransactionReceipt(txHash);
                  if (tx && tx.blockNumber) {
                    success(blockNumber); // Return the BTC blockNumber
                    txFilter.stopWatching();
                  }
                });
              }
              else
                failure(errorMsg);
            });
          }
          else
            failure(errorMsg);
        }.bind(this));
      }.bind(this));
    }.bind(this));

    req.end();
    req.on('error', function(e) {
      errorMsg = "Request error:";
      if (this.debug)
        console.error(errorMsg, e);
      failure(errorMsg + " " + e.message);
    });
  };
};

module.exports = btcSwap;
