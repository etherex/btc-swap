#!/usr/bin/env python

# Requires btcrelay in a sibling folder

import json
from serpent import mk_full_signature

contracts = {
    'btcrelay': '../btcrelay/btcrelay.se',
    'btc-swap': 'contracts/btc-swap.se'
}

for c in contracts:
    sig = mk_full_signature(contracts[c])
    # print sig

    abi = json.dumps(sig, indent=4, separators=(',', ': '))
    # print abi

    with open('src/abi/%s.js' % c, 'w') as out:
        out.write("module.exports = %s;\n" % abi)
