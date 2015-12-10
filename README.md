# Ethereum BTC Swap
[![Build Status](https://travis-ci.org/etherex/btc-swap.svg)](https://travis-ci.org/etherex/btc-swap)
[![Dependency Status](https://david-dm.org/etherex/btc-swap.svg)](https://david-dm.org/etherex/btc-swap)
[![devDependency Status](https://david-dm.org/etherex/btc-swap/dev-status.svg)](https://david-dm.org/etherex/btc-swap#info=devDependencies)

## Installation
```
npm install --save etherex/btc-swap
```

## Usage
```
var BtcSwap = require('btc-swap');
var client = new BtcSwap({
  address: "0x4491959fe1772faa7332464b0e7f1aa9aa2d8446", // Address of the BtcSwap contract
  host: "localhost:8545", // Ethereum node
  from: "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826", // Ethereum account
  testnet: true, // Use BTC testnet, defaults to true
  debug: true
});
```

## Methods
For any method with a `failure` callback, any error will fire that callback
before aborting the execution of that method.

#### `lookupTicket(ticketId, success, failure)`
Returns a ticket object specified by `ticketId` to the `success` callback.

#### `createTicket(btcAddress, numEther, btcTotal, success, completed, failure)`
Create a ticket for `btcAddress` of `numEther` for `btcTotal`. The `success`
callback gets fired when the Ethereum transaction is sent and returns the
transaction hash. The `completed` callback gets fired when the transaction
is mined, returns the same transaction hash as first parameter and the created
ticket object as second parameter.

#### `reserveTicket(ticketId, txHash, powNonce, success, completed, failure)`
Reserve a ticket with ID `ticketId`, with the BTC transaction hash `txHash`
and computed nonce `powNonce` (see `computePoW()`). The `success` callback
gets fired when the Ethereum transaction is sent, returns the ticket ID as
first parameter and the Ethereum transaction hash as second parameter. The
`completed` callback gets fired when the transaction is mined and returns the
reserved ticket object.

#### `claimTicket(ticketId, txHex, txHash, txIndex, merkleSibling, txBlockHash,
  feeWei, success, completed, failure)`
Claim a ticket with ID `ticketId`, with the signed BTC transaction hex `txHex`,
the BTC transaction hash `txHash`, BTC transaction index `txIndex`, BTC merkle
siblings `merkleSibling` and BTC block hash `txBlockHash`. `feeWei` can be
obtained by calling `getFeeAmount(txBlockHash)` and will be the transaction's
value if it's above zero. The `success` callback gets fired when the Ethereum
transaction is sent and returns the Ethereum transaction hash. The `completed`
callback gets fired when the transaction is mined and returns the ticket ID.

#### `cancelTicket(ticketId, success, failure)`
Cancel a ticket with `ticketId`, if the ticket is still reservable and by
the creator of that ticket only. The `success` callback gets fired when the
Ethereum transaction is sent and returns the ticket ID as first parameter and
the Ethereum transaction hash as second parameter. The `completed` callback gets
fired when the transaction is mined and returns the ticket ID that was just
canceled.

## Ticket ID list
#### `getTicketIDs(success, failure)`
Returns open ticket IDs. Use with `lookupTicket()` to load all currently open
tickets.

## Watch filter
#### `watchTickets(ticketEvent, failure)`
Sets a global watch filter for all ticket events, which calls `ticketEvent` that
returns `new`, `reserved` or `removed` as first parameter, and the ticket ID
as second parameter. Use this to watch tickets created, reserved, claimed or
canceled by other users. Take note that this filter will also trigger on the
same events as the other methods' `completed` callbacks.

## Proof of Work nonce
#### `computePoW(ticketId, btcTxHash, success, failure)`
Compute a nonce for a ticket with ID `ticketId`, with the BTC transaction hash
`txHash`. The `success` callback gets fired when a nonce is found.

#### `verifyPoW(ticketId, txHash, nonce, success, failure)`
Verify a nonce for a ticket with ID `ticketId`, with the BTC transaction hash
`txHash` and previously computed `nonce`. The `success` callback gets fired
when the nonce is found to be valid with a success message, same with the
`failure` callback when the nonce is invalid.

## Intermediate wallet methods
#### `generateWallet(success, failure)`
Generate an intermediate wallet to be used for reserving and claiming a ticket.
The `success` callback gets fired when the wallet is successfully generated and
returns a wallet object with the address and WIF key.

#### `importWallet(wif, success, failure)`
Import a previously generated wallet using the WIF key from `wif`. The success
callback gets fired on successful importation of the wallet and returns a
wallet object with the address and the same WIF key.

#### `createTransaction(wallet, recipient, amountBtc, etherFee, etherAddress, success, failure)`
Create a signed BTC transaction to get a transaction hash for `reserveTicket()`
to be later broadcast with `propagateTransaction()` (see below), using a
wallet object `wallet` (as returned by `generateWallet()`), paid to the BTC
address `recipient` for the amount of `amountBtc`, including an ether fee of
`etherFee` for a third-party claimer, and from the Ethereum address
`etherAddress`. The `success` callback gets fired when the transaction is
successfully created and returns an object with `fee` for the actual BTC miner
fee after the `etherAddress` and `etherFee` have been encoded into the
transaction, the `hash` of the BTC transaction and `hex` of the raw transaction.

#### `propagateTransaction(txHex, success, failure)`
Broadcast a previously signed raw transaction `txHex` to the Bitcoin network.
The `success` callback gets fired when the transaction is successfully broadcast
and returns the BTC transaction hash.

## BTC relay methods
#### `getBlockchainHead(success, failure)`
Query the [btcrelay](https://github.com/ethereum/btcrelay) contract for its last
stored BTC block hash. The `success` callback gets fired on a successful call
and returns the hash of the latest block.

#### `getLastBlockHeight(success, failure)`
Query the [btcrelay](https://github.com/ethereum/btcrelay) contract for its last
stored BTC block number. The `success` callback gets fired on a successful call
and returns the block number of the latest block.

#### `getFeeAmount(blockHash, success, failure)`
Get the fee from [btcrelay](https://github.com/ethereum/btcrelay) to validate a
transaction in a given `blockHash`. The `success` callback gets fired on a
successful call and returns the fee amount in wei.

#### `storeBlockWithFee(blockHash, feeWei, success, failure)`
Query the [blockr](https://blockr.io) API for the raw block data of a block
with hash `blockHash`, generate the BTC block header from that data, call the
`storeBlockWithFee` method of [btcrelay](https://github.com/ethereum/btcrelay)
and send an Ethereum transaction for that same method if successful, effectively
storing the block header. The `success` callback gets fired when the transaction
is mined and returns the BTC block number for which the block header was stored.
