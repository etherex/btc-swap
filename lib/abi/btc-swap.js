"use strict";

module.exports = [{
    "constant": false,
    "type": "function",
    "name": "cancelTicket(int256)",
    "outputs": [{
        "type": "int256",
        "name": "out"
    }],
    "inputs": [{
        "type": "int256",
        "name": "ticketId"
    }]
}, {
    "constant": false,
    "type": "function",
    "name": "claimTicket(int256,bytes,int256,int256,int256[],int256)",
    "outputs": [{
        "type": "int256",
        "name": "out"
    }],
    "inputs": [{
        "type": "int256",
        "name": "ticketId"
    }, {
        "type": "bytes",
        "name": "txStr"
    }, {
        "type": "int256",
        "name": "txHash"
    }, {
        "type": "int256",
        "name": "txIndex"
    }, {
        "type": "int256[]",
        "name": "sibling"
    }, {
        "type": "int256",
        "name": "txBlockHash"
    }]
}, {
    "constant": false,
    "type": "function",
    "name": "createTicket(int256,int256,int256)",
    "outputs": [{
        "type": "int256",
        "name": "out"
    }],
    "inputs": [{
        "type": "int256",
        "name": "btcAddr"
    }, {
        "type": "int256",
        "name": "numWei"
    }, {
        "type": "int256",
        "name": "weiPerSatoshi"
    }]
}, {
    "constant": false,
    "type": "function",
    "name": "getFirst2Outputs(bytes)",
    "outputs": [{
        "type": "int256[]",
        "name": "out"
    }],
    "inputs": [{
        "type": "bytes",
        "name": "txStr"
    }]
}, {
    "constant": false,
    "type": "function",
    "name": "getLastTicketId()",
    "outputs": [{
        "type": "int256",
        "name": "out"
    }],
    "inputs": []
}, {
    "constant": false,
    "type": "function",
    "name": "getTicketIDs()",
    "outputs": [{
        "type": "int256[]",
        "name": "out"
    }],
    "inputs": []
}, {
    "constant": false,
    "type": "function",
    "name": "getUnsignedBitsLE(bytes,int256,int256)",
    "outputs": [{
        "type": "int256[]",
        "name": "out"
    }],
    "inputs": [{
        "type": "bytes",
        "name": "txStr"
    }, {
        "type": "int256",
        "name": "pos"
    }, {
        "type": "int256",
        "name": "bits"
    }]
}, {
    "constant": false,
    "type": "function",
    "name": "lookupTicket(int256)",
    "outputs": [{
        "type": "int256[]",
        "name": "out"
    }],
    "inputs": [{
        "type": "int256",
        "name": "ticketId"
    }]
}, {
    "constant": false,
    "type": "function",
    "name": "reserveTicket(int256,int256,int256)",
    "outputs": [{
        "type": "int256",
        "name": "out"
    }],
    "inputs": [{
        "type": "int256",
        "name": "ticketId"
    }, {
        "type": "int256",
        "name": "txHash"
    }, {
        "type": "int256",
        "name": "nonce"
    }]
}, {
    "constant": false,
    "type": "function",
    "name": "setTrustedBtcRelay(int256)",
    "outputs": [{
        "type": "int256",
        "name": "out"
    }],
    "inputs": [{
        "type": "int256",
        "name": "trustedRelayContract"
    }]
}, {
    "inputs": [{
        "indexed": false,
        "type": "int256",
        "name": "btcAddr"
    }, {
        "indexed": false,
        "type": "int256",
        "name": "numSatoshi"
    }, {
        "indexed": false,
        "type": "int256",
        "name": "ethAddr"
    }, {
        "indexed": false,
        "type": "int256",
        "name": "satoshiIn2ndOutput"
    }],
    "type": "event",
    "name": "claimSuccess(int256,int256,int256,int256)"
}, {
    "inputs": [{
        "indexed": true,
        "type": "int256",
        "name": "ticketId"
    }, {
        "indexed": false,
        "type": "int256",
        "name": "rval"
    }],
    "type": "event",
    "name": "ticketEvent(int256,int256)"
}];
//# sourceMappingURL=btc-swap.js.map
