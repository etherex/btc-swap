module.exports = [{
    "name": "computeMerkle(int256,int256,int256[])",
    "type": "function",
    "inputs": [{ "name": "txHash", "type": "int256" }, { "name": "txIndex", "type": "int256" }, { "name": "sibling", "type": "int256[]" }],
    "outputs": [{ "name": "out", "type": "int256" }]
},
{
    "name": "verifyTx(int256,int256,int256[],int256)",
    "type": "function",
    "inputs": [{ "name": "txHash", "type": "int256" }, { "name": "txIndex", "type": "int256" }, { "name": "sibling", "type": "int256[]" }, { "name": "txBlockHash", "type": "int256" }],
    "outputs": [{ "name": "out", "type": "int256" }]
},
{
    "name": "dbgEvent(int256,int256,int256[],int256)",
    "type": "event",
    "inputs": [{ "name": "txHash", "type": "int256", "indexed": true }, { "name": "txIndex", "type": "int256", "indexed": false }, { "name": "sibling", "type": "int256[]", "indexed": false }, { "name": "txBlockHash", "type": "int256", "indexed": false }]
},
{
    "name": "txhEvent(int256,int256)",
    "type": "event",
    "inputs": [{ "name": "txHash", "type": "int256", "indexed": true }, { "name": "val", "type": "int256", "indexed": false }]
}];
