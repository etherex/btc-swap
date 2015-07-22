module.exports = [{
    "name": "claimTicket(int256,bytes,int256,int256,int256[],int256)",
    "type": "function",
    "inputs": [{ "name": "ticketId", "type": "int256" }, { "name": "txStr", "type": "bytes" }, { "name": "txHash", "type": "int256" }, { "name": "txIndex", "type": "int256" }, { "name": "sibling", "type": "int256[]" }, { "name": "txBlockHash", "type": "int256" }],
    "outputs": [{ "name": "out", "type": "int256" }]
},
{
    "name": "createTicket(int256,int256,int256)",
    "type": "function",
    "inputs": [{ "name": "btcAddr", "type": "int256" }, { "name": "numWei", "type": "int256" }, { "name": "weiPerSatoshi", "type": "int256" }],
    "outputs": [{ "name": "out", "type": "int256" }]
},
{
    "name": "getFirst2Outputs(bytes)",
    "type": "function",
    "inputs": [{ "name": "txStr", "type": "bytes" }],
    "outputs": [{ "name": "out", "type": "int256[]" }]
},
{
    "name": "getOpenTickets(int256,int256)",
    "type": "function",
    "inputs": [{ "name": "startTicketId", "type": "int256" }, { "name": "endTicketId", "type": "int256" }],
    "outputs": [{ "name": "out", "type": "int256[]" }]
},
{
    "name": "getUnsignedBitsLE(bytes,int256,int256)",
    "type": "function",
    "inputs": [{ "name": "txStr", "type": "bytes" }, { "name": "pos", "type": "int256" }, { "name": "bits", "type": "int256" }],
    "outputs": [{ "name": "out", "type": "int256[]" }]
},
{
    "name": "lookupTicket(int256)",
    "type": "function",
    "inputs": [{ "name": "ticketId", "type": "int256" }],
    "outputs": [{ "name": "out", "type": "int256[]" }]
},
{
    "name": "reserveTicket(int256,int256,int256)",
    "type": "function",
    "inputs": [{ "name": "ticketId", "type": "int256" }, { "name": "txHash", "type": "int256" }, { "name": "nonce", "type": "int256" }],
    "outputs": [{ "name": "out", "type": "int256" }]
},
{
    "name": "setTrustedBtcRelay(int256)",
    "type": "function",
    "inputs": [{ "name": "trustedRelayContract", "type": "int256" }],
    "outputs": [{ "name": "out", "type": "int256" }]
},
{
    "name": "testingOnlyClaimTicketLatestTicket(bytes,int256,int256,int256[],int256)",
    "type": "function",
    "inputs": [{ "name": "txStr", "type": "bytes" }, { "name": "txHash", "type": "int256" }, { "name": "txIndex", "type": "int256" }, { "name": "sibling", "type": "int256[]" }, { "name": "txBlockHash", "type": "int256" }],
    "outputs": [{ "name": "out", "type": "int256" }]
},
{
    "name": "testingOnlyReserveLatestTicket(int256)",
    "type": "function",
    "inputs": [{ "name": "txHash", "type": "int256" }],
    "outputs": [{ "name": "out", "type": "int256" }]
},
{
    "name": "ttClaimHash()",
    "type": "function",
    "inputs": [],
    "outputs": [{ "name": "out", "type": "int256" }]
},
{
    "name": "ttLastTid()",
    "type": "function",
    "inputs": [],
    "outputs": [{ "name": "out", "type": "int256" }]
},
{
    "name": "claimSuccess(int256,int256,int256,int256)",
    "type": "event",
    "inputs": [{ "name": "btcAddr", "type": "int256", "indexed": false }, { "name": "numSatoshi", "type": "int256", "indexed": false }, { "name": "ethAddr", "type": "int256", "indexed": false }, { "name": "satoshiIn2ndOutput", "type": "int256", "indexed": false }]
},
{
    "name": "ticketEvent(int256,int256)",
    "type": "event",
    "inputs": [{ "name": "ticketId", "type": "int256", "indexed": true }, { "name": "rval", "type": "int256", "indexed": false }]
}];
