from ethereum import tester
import logging

from bitcoin import *  # NOQA

import pytest
slow = pytest.mark.slow

logging.getLogger('eth.pb').setLevel('INFO')
logging.getLogger('eth.pb.msg').setLevel('INFO')
logging.getLogger('eth.pb.msg.state').setLevel('INFO')
logging.getLogger('eth.pb.tx').setLevel('INFO')
logging.getLogger('eth.vm').setLevel('INFO')
logging.getLogger('eth.vm.op').setLevel('INFO')
logging.getLogger('eth.vm.exit').setLevel('INFO')
logging.getLogger('eth.chain.tx').setLevel('INFO')
logging.getLogger('transactions.py').setLevel('INFO')
logging.getLogger('eth.msg').setLevel('INFO')


class TestEthBtcSwap(object):

    CONTRACT_DEBUG = 'tests/btc-swap_testing.se'

    ETHER = 10 ** 18

    ONLY_RESERVER_CLAIM_SECS = 3600 * 2
    ANYONE_CLAIM_SECS = 3600 * 2
    TOTAL_RESERVED_SECS = ONLY_RESERVER_CLAIM_SECS + ANYONE_CLAIM_SECS

    RESERVE_FAIL_UNRESERVABLE = -10
    RESERVE_FAIL_POW = -11

    CLAIM_FAIL_INVALID_TICKET = -20
    CLAIM_FAIL_UNRESERVED = -21
    CLAIM_FAIL_CLAIMER = -22
    CLAIM_FAIL_TX_HASH = -23
    CLAIM_FAIL_INSUFFICIENT_SATOSHI = -24
    CLAIM_FAIL_PROOF = -25
    CLAIM_FAIL_WRONG_BTC_ADDR = -26  # untested
    CLAIM_FAIL_TX_ENCODING = -27  # untested

    def setup_class(cls):
        tester.gas_limit = int(2.8e6)  # 2.5e6 should be ok if testingOnly methods are commented out
        cls.s = tester.state()
        cls.c = cls.s.abi_contract(cls.CONTRACT_DEBUG, gas=3000000)
        cls.snapshot = cls.s.snapshot()
        cls.seed = tester.seed

    def setup_method(self, method):
        self.s.revert(self.snapshot)
        tester.seed = self.seed

    # same as testClaimerFee, except the sender is the coinbase, so exact assertions
    # on balances can be made
    def testFlowSameSender(self):
        # block 300k
        txBlockHash = 0x000000000000000082ccf8f1557c5d40b21edabb18d2d691cfbf87118bac7254
        txStr = ('0100000002a0419f78a1ef9441b1d91a5cb3e198d4a1ef8b382cd942de98a58a5f968d073f000000006a473044022032a0332c1afb753afc1bb44555c9ccefa83709ca5e1e62a'
                 '608024b9cf4c087c002201a506f2c8442c390590769d5cdefc6e4e0e1f8517a060365ec527cc9b749068c012102caa12ebb756b4a3a90c8779d2ec75d7082f9c2897f07159898'
                 '40f16bf3aa7adfffffffff55ad24bbc9541d9848ad64546ab4a6f4b96cb15043ddeea52fbeb3cc70987340000000008a47304402203d4cb993d6e73979c3aae2d1c4752f6b4c5'
                 '01c4b64fc19f212efaa54a7ba199f02204ba50d8764532c2157f7438cf2eee6e975853975eb3803823f9de4a1c1f230e30141040a424c356d3adfdc6ba29cf41474105434d01a'
                 '7ad5be3ae6938f8af92da215bdb0e21bd2ad6301f43be02f1ce796229a8c00873356e11a056c8c65f731304a7fffffffff0280ba8c01000000001976a914956bfc5575c0a7134'
                 'c7effef268e51d887ba701588ac4a480f00000000001976a914587488c119f40666b4a0c807b0d7a1acfe3b691788ac00000000')
        txHash = 0x141e4ea2fa3c9bf9984d03ff081d21555f8ccc7a528326cea96221ca6d476566
        nonce = 2089206
        txIndex = 190
        sibling = [0x09636b32593267f1aec7cf7ac36b6a51b8ef158f5648d1d27882492b7908ca2e,
                   0xe081237dd6f75f2a0b174ac8a8f138fffd4c05ad05c0c12cc1c69a203eec79ae,
                   0x0c23978510ed856b5e17cba4b4feba7e8596581d604cce84f50b6ea180fd91a4,
                   0x1f4deef9f140251f6dc011d3b9db88586a2a313de813f803626dcdac4e1e3127,
                   0x266f31fc4cdca488ecf0f9cbf56e4b25aa5e49154ae192bc6982fc28827cc62b,
                   0xd394350ece3e0cb705c99c1db14f29d1db0e1a3dcbd3094baf695e297bea0f6b,
                   0x3a2e3e81c6ef3a3ff65ec6e62ead8eb5c2f8bb950ba2422038fa573a6d638812,
                   0xaec0b4d49d190f9ac61d0e32443ade724274de466eed4acb0498207664832d84]
        satoshiOutputOne = int(0.26e8)
        satoshiOutputTwo = int(0.01001546e8)

        btcAddr = 0x956bfc5575c0a7134c7effef268e51d887ba7015
        numWei = self.ETHER
        weiPerSatoshi = 38461538462  # ceiling of numWei / satoshiOutputOne
        ethAddr = 0x587488c119f40666b4a0c807b0d7a1acfe3b6917

        MOCK_VERIFY_TX_ONE = self.s.abi_contract('./tests/mock_verifyTxReturnsOne.se')
        self.c.setTrustedBtcRelay(MOCK_VERIFY_TX_ONE.address)

        ticketId = self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei)
        assert ticketId == 1

        # claimer = tester.k0
        addrClaimer = tester.a0
        claimerBalPreReserve = self.s.block.get_balance(addrClaimer)
        res = self.c.reserveTicket(ticketId, txHash, nonce, profiling=True)
        # print('GAS: '+str(res['gas']))
        assert res['output'] == 1

        balPreClaim = self.s.block.get_balance(addrClaimer)
        assert balPreClaim == claimerBalPreReserve

        eventArr = []
        self.s.block.log_listeners.append(lambda x: eventArr.append(self.c._translator.listen(x)))
        balPreClaim = self.s.block.get_balance(addrClaimer)
        claimRes = self.c.claimTicket(ticketId, txStr, txHash, txIndex, sibling, txBlockHash, profiling=True)
        # print('GAS claimTicket() ', claimRes['gas'])
        assert claimRes['output'] == ticketId

        claimerFeePercent = (satoshiOutputTwo % 10000) / 10000.0
        feeToClaimer = int(claimerFeePercent * numWei)  # int() is needed
        endClaimerBal = self.s.block.get_balance(addrClaimer)
        assert endClaimerBal == balPreClaim + feeToClaimer

        indexOfBtcAddr = txStr.find(format(btcAddr, 'x'))
        ethAddrBin = txStr[indexOfBtcAddr + 68:indexOfBtcAddr + 108].decode('hex')  # assumes ether addr is after btcAddr
        buyerEthBalance = self.s.block.get_balance(ethAddrBin)
        assert buyerEthBalance == (1 - claimerFeePercent) * numWei

        self.assertClaimSuccessLogs(eventArr, satoshiOutputOne, btcAddr, ethAddr, satoshiOutputTwo, ticketId)

        # re-claim is not allowed
        claimRes = self.c.claimTicket(ticketId, txStr, txHash, txIndex, sibling, txBlockHash, profiling=True)
        # print('GAS claimTicket() ', claimRes['gas'])
        assert claimRes['output'] == self.CLAIM_FAIL_INVALID_TICKET

        assert eventArr == [{
            '_event_type': 'ticketEvent',
            'ticketId': ticketId,
            'rval': self.CLAIM_FAIL_INVALID_TICKET  # a claimed ticket no longer exists
        }]
        eventArr.pop()

    # same as testFlowSameSender but ticket is claimed by a different address than the reserver
    def testClaimerDifferentThanReserver(self):
        # block 300k
        txBlockHash = 0x000000000000000082ccf8f1557c5d40b21edabb18d2d691cfbf87118bac7254
        txStr = ('0100000002a0419f78a1ef9441b1d91a5cb3e198d4a1ef8b382cd942de98a58a5f968d073f000000006a473044022032a0332c1afb753afc1bb44555c9ccefa83709ca5e1e62a'
                 '608024b9cf4c087c002201a506f2c8442c390590769d5cdefc6e4e0e1f8517a060365ec527cc9b749068c012102caa12ebb756b4a3a90c8779d2ec75d7082f9c2897f07159898'
                 '40f16bf3aa7adfffffffff55ad24bbc9541d9848ad64546ab4a6f4b96cb15043ddeea52fbeb3cc70987340000000008a47304402203d4cb993d6e73979c3aae2d1c4752f6b4c5'
                 '01c4b64fc19f212efaa54a7ba199f02204ba50d8764532c2157f7438cf2eee6e975853975eb3803823f9de4a1c1f230e30141040a424c356d3adfdc6ba29cf41474105434d01a'
                 '7ad5be3ae6938f8af92da215bdb0e21bd2ad6301f43be02f1ce796229a8c00873356e11a056c8c65f731304a7fffffffff0280ba8c01000000001976a914956bfc5575c0a7134'
                 'c7effef268e51d887ba701588ac4a480f00000000001976a914587488c119f40666b4a0c807b0d7a1acfe3b691788ac00000000')
        txHash = 0x141e4ea2fa3c9bf9984d03ff081d21555f8ccc7a528326cea96221ca6d476566
        nonce = 2089206
        txIndex = 190
        sibling = [0x09636b32593267f1aec7cf7ac36b6a51b8ef158f5648d1d27882492b7908ca2e,
                   0xe081237dd6f75f2a0b174ac8a8f138fffd4c05ad05c0c12cc1c69a203eec79ae,
                   0x0c23978510ed856b5e17cba4b4feba7e8596581d604cce84f50b6ea180fd91a4,
                   0x1f4deef9f140251f6dc011d3b9db88586a2a313de813f803626dcdac4e1e3127,
                   0x266f31fc4cdca488ecf0f9cbf56e4b25aa5e49154ae192bc6982fc28827cc62b,
                   0xd394350ece3e0cb705c99c1db14f29d1db0e1a3dcbd3094baf695e297bea0f6b,
                   0x3a2e3e81c6ef3a3ff65ec6e62ead8eb5c2f8bb950ba2422038fa573a6d638812,
                   0xaec0b4d49d190f9ac61d0e32443ade724274de466eed4acb0498207664832d84]
        satoshiOutputOne = int(0.26e8)
        satoshiOutputTwo = int(0.01001546e8)

        btcAddr = 0x956bfc5575c0a7134c7effef268e51d887ba7015
        numWei = self.ETHER
        weiPerSatoshi = 38461538462  # ceiling of numWei / satoshiOutputOne
        ethAddr = 0x587488c119f40666b4a0c807b0d7a1acfe3b6917

        MOCK_VERIFY_TX_ONE = self.s.abi_contract('./tests/mock_verifyTxReturnsOne.se')
        self.c.setTrustedBtcRelay(MOCK_VERIFY_TX_ONE.address)

        # k2 creates ticket
        ticketId = self.c.createTicket(btcAddr, numWei, weiPerSatoshi, sender=tester.k2, value=numWei)
        assert ticketId == 1

        # k1 is the reserver
        res = self.c.reserveTicket(ticketId, txHash, nonce, sender=tester.k1, profiling=True)
        # print('GAS: '+str(res['gas']))
        assert res['output'] == 1

        # claimer = tester.k0
        addrClaimer = tester.a0

        eventArr = []
        self.s.block.log_listeners.append(lambda x: eventArr.append(self.c._translator.listen(x)))

        balPreClaim = self.s.block.get_balance(addrClaimer)
        claimRes = self.c.claimTicket(ticketId, txStr, txHash, txIndex, sibling, txBlockHash, profiling=True)
        # print('GAS claimTicket() ', claimRes['gas'])
        assert claimRes['output'] == self.CLAIM_FAIL_CLAIMER
        assert self.s.block.get_balance(addrClaimer) == balPreClaim
        assert eventArr == [{
            '_event_type': 'ticketEvent',
            'ticketId': ticketId,
            'rval': self.CLAIM_FAIL_CLAIMER
        }]
        eventArr.pop()

        # ticket can only still be claimed by the reserver
        self.s.block.timestamp += self.ONLY_RESERVER_CLAIM_SECS

        balPreClaim = self.s.block.get_balance(addrClaimer)
        claimRes = self.c.claimTicket(ticketId, txStr, txHash, txIndex, sibling, txBlockHash, profiling=True)
        # print('GAS claimTicket() ', claimRes['gas'])
        assert claimRes['output'] == self.CLAIM_FAIL_CLAIMER
        assert self.s.block.get_balance(addrClaimer) == balPreClaim
        assert eventArr == [{
            '_event_type': 'ticketEvent',
            'ticketId': ticketId,
            'rval': self.CLAIM_FAIL_CLAIMER
        }]
        eventArr.pop()

        #
        # 1 second later, the ticket should be claimable by anyone
        # and the claimer gets the fee
        #
        self.s.block.timestamp += 1

        balPreClaim = self.s.block.get_balance(addrClaimer)
        claimRes = self.c.claimTicket(ticketId, txStr, txHash, txIndex, sibling, txBlockHash, profiling=True)

        assert claimRes['output'] == ticketId

        claimerFeePercent = (satoshiOutputTwo % 10000) / 10000.0
        feeToClaimer = int(claimerFeePercent * numWei)  # int() is needed

        endClaimerBal = self.s.block.get_balance(addrClaimer)
        assert endClaimerBal == balPreClaim + feeToClaimer

        indexOfBtcAddr = txStr.find(format(btcAddr, 'x'))
        ethAddrBin = txStr[indexOfBtcAddr + 68:indexOfBtcAddr + 108].decode('hex')  # assumes ether addr is after btcAddr
        buyerEthBalance = self.s.block.get_balance(ethAddrBin)

        assert buyerEthBalance == (1 - claimerFeePercent) * numWei

        self.assertClaimSuccessLogs(eventArr, satoshiOutputOne, btcAddr, ethAddr, satoshiOutputTwo, ticketId)

        # re-claim is not allowed
        claimRes = self.c.claimTicket(ticketId, txStr, txHash, txIndex, sibling, txBlockHash, profiling=True)
        # print('GAS claimTicket() ', claimRes['gas'])
        assert claimRes['output'] == self.CLAIM_FAIL_INVALID_TICKET

        assert eventArr == [{
            '_event_type': 'ticketEvent',
            'ticketId': ticketId,
            'rval': self.CLAIM_FAIL_INVALID_TICKET  # a claimed ticket no longer exists
        }]
        eventArr.pop()

    # claimer is different from reserver, but claim only succeeds if tx is valid
    def testClaimerCannotOverwriteTrustedBtcRelay(self):
        # block 300k
        txBlockHash = 0x000000000000000082ccf8f1557c5d40b21edabb18d2d691cfbf87118bac7254
        txStr = ('0100000002a0419f78a1ef9441b1d91a5cb3e198d4a1ef8b382cd942de98a58a5f968d073f000000006a473044022032a0332c1afb753afc1bb44555c9ccefa83709ca5e1e62a'
                 '608024b9cf4c087c002201a506f2c8442c390590769d5cdefc6e4e0e1f8517a060365ec527cc9b749068c012102caa12ebb756b4a3a90c8779d2ec75d7082f9c2897f07159898'
                 '40f16bf3aa7adfffffffff55ad24bbc9541d9848ad64546ab4a6f4b96cb15043ddeea52fbeb3cc70987340000000008a47304402203d4cb993d6e73979c3aae2d1c4752f6b4c5'
                 '01c4b64fc19f212efaa54a7ba199f02204ba50d8764532c2157f7438cf2eee6e975853975eb3803823f9de4a1c1f230e30141040a424c356d3adfdc6ba29cf41474105434d01a'
                 '7ad5be3ae6938f8af92da215bdb0e21bd2ad6301f43be02f1ce796229a8c00873356e11a056c8c65f731304a7fffffffff0280ba8c01000000001976a914956bfc5575c0a7134'
                 'c7effef268e51d887ba701588ac4a480f00000000001976a914587488c119f40666b4a0c807b0d7a1acfe3b691788ac00000000')
        txHash = 0x141e4ea2fa3c9bf9984d03ff081d21555f8ccc7a528326cea96221ca6d476566
        nonce = [None, 2089206, 680495]
        txIndex = 190
        sibling = [0x09636b32593267f1aec7cf7ac36b6a51b8ef158f5648d1d27882492b7908ca2e,
                   0xe081237dd6f75f2a0b174ac8a8f138fffd4c05ad05c0c12cc1c69a203eec79ae,
                   0x0c23978510ed856b5e17cba4b4feba7e8596581d604cce84f50b6ea180fd91a4,
                   0x1f4deef9f140251f6dc011d3b9db88586a2a313de813f803626dcdac4e1e3127,
                   0x266f31fc4cdca488ecf0f9cbf56e4b25aa5e49154ae192bc6982fc28827cc62b,
                   0xd394350ece3e0cb705c99c1db14f29d1db0e1a3dcbd3094baf695e297bea0f6b,
                   0x3a2e3e81c6ef3a3ff65ec6e62ead8eb5c2f8bb950ba2422038fa573a6d638812,
                   0xaec0b4d49d190f9ac61d0e32443ade724274de466eed4acb0498207664832d84]
        # satoshiOutputOne = int(0.26e8)
        # satoshiOutputTwo = int(0.01001546e8)

        btcAddr = 0x956bfc5575c0a7134c7effef268e51d887ba7015
        numWei = self.ETHER
        weiPerSatoshi = 38461538462  # ceiling of numWei / satoshiOutputOne
        # ethAddr = 0x587488c119f40666b4a0c807b0d7a1acfe3b6917

        # fail transactions
        MOCK_VERIFY_TX_ZERO = self.s.abi_contract('./tests/mock_verifyTxReturnsZero.se')
        self.c.setTrustedBtcRelay(MOCK_VERIFY_TX_ZERO.address)

        # k2 creates ticket
        ticketId = self.c.createTicket(btcAddr, numWei, weiPerSatoshi, sender=tester.k2, value=numWei)
        assert ticketId == 1
        assert 2 == self.c.createTicket(btcAddr, numWei, weiPerSatoshi, sender=tester.k2, value=numWei)

        # k1 is the reserver
        res = self.c.reserveTicket(ticketId, txHash, nonce[ticketId], sender=tester.k1, profiling=True)
        # print('GAS: '+str(res['gas']))
        assert res['output'] == 1
        res = self.c.reserveTicket(2, txHash, nonce[2], sender=tester.k1, profiling=True)
        assert res['output'] == 2

        # claimer = tester.k0
        addrClaimer = tester.a0

        eventArr = []
        self.s.block.log_listeners.append(lambda x: eventArr.append(self.c._translator.listen(x)))

        # anyone can claim
        self.s.block.timestamp += self.ONLY_RESERVER_CLAIM_SECS + 1

        balPreClaim = self.s.block.get_balance(addrClaimer)
        claimRes = self.c.claimTicket(ticketId, txStr, txHash, txIndex, sibling, txBlockHash, profiling=True)
        # print('GAS claimTicket() ', claimRes['gas'])
        assert claimRes['output'] == self.CLAIM_FAIL_PROOF
        assert self.s.block.get_balance(addrClaimer) == balPreClaim
        assert eventArr == [{
            '_event_type': 'ticketEvent',
            'ticketId': ticketId,
            'rval': self.CLAIM_FAIL_PROOF
        }]
        eventArr.pop()

        # try to make transactions pass validation, but cannot overwrite trustedBtcRelay
        MOCK_VERIFY_TX_ONE = self.s.abi_contract('./tests/mock_verifyTxReturnsOne.se')
        self.c.setTrustedBtcRelay(MOCK_VERIFY_TX_ONE.address)

        balPreClaim = self.s.block.get_balance(addrClaimer)
        claimRes = self.c.claimTicket(ticketId, txStr, txHash, txIndex, sibling, txBlockHash, profiling=True)

        assert claimRes['output'] == self.CLAIM_FAIL_PROOF
        assert self.s.block.get_balance(addrClaimer) == balPreClaim
        assert eventArr == [{
            '_event_type': 'ticketEvent',
            'ticketId': ticketId,
            'rval': self.CLAIM_FAIL_PROOF
        }]
        eventArr.pop()

    # claimer is different from reserver, but claim only succeeds if tx is valid
    def testAnyClaimMustStillBeValidTx(self):
        # block 300k
        txBlockHash = 0x000000000000000082ccf8f1557c5d40b21edabb18d2d691cfbf87118bac7254
        txStr = ('0100000002a0419f78a1ef9441b1d91a5cb3e198d4a1ef8b382cd942de98a58a5f968d073f000000006a473044022032a0332c1afb753afc1bb44555c9ccefa83709ca5e1e62a'
                 '608024b9cf4c087c002201a506f2c8442c390590769d5cdefc6e4e0e1f8517a060365ec527cc9b749068c012102caa12ebb756b4a3a90c8779d2ec75d7082f9c2897f07159898'
                 '40f16bf3aa7adfffffffff55ad24bbc9541d9848ad64546ab4a6f4b96cb15043ddeea52fbeb3cc70987340000000008a47304402203d4cb993d6e73979c3aae2d1c4752f6b4c5'
                 '01c4b64fc19f212efaa54a7ba199f02204ba50d8764532c2157f7438cf2eee6e975853975eb3803823f9de4a1c1f230e30141040a424c356d3adfdc6ba29cf41474105434d01a'
                 '7ad5be3ae6938f8af92da215bdb0e21bd2ad6301f43be02f1ce796229a8c00873356e11a056c8c65f731304a7fffffffff0280ba8c01000000001976a914956bfc5575c0a7134'
                 'c7effef268e51d887ba701588ac4a480f00000000001976a914587488c119f40666b4a0c807b0d7a1acfe3b691788ac00000000')
        txHash = 0x141e4ea2fa3c9bf9984d03ff081d21555f8ccc7a528326cea96221ca6d476566
        nonce = [None, 2089206, 680495]
        txIndex = 190
        sibling = [0x09636b32593267f1aec7cf7ac36b6a51b8ef158f5648d1d27882492b7908ca2e,
                   0xe081237dd6f75f2a0b174ac8a8f138fffd4c05ad05c0c12cc1c69a203eec79ae,
                   0x0c23978510ed856b5e17cba4b4feba7e8596581d604cce84f50b6ea180fd91a4,
                   0x1f4deef9f140251f6dc011d3b9db88586a2a313de813f803626dcdac4e1e3127,
                   0x266f31fc4cdca488ecf0f9cbf56e4b25aa5e49154ae192bc6982fc28827cc62b,
                   0xd394350ece3e0cb705c99c1db14f29d1db0e1a3dcbd3094baf695e297bea0f6b,
                   0x3a2e3e81c6ef3a3ff65ec6e62ead8eb5c2f8bb950ba2422038fa573a6d638812,
                   0xaec0b4d49d190f9ac61d0e32443ade724274de466eed4acb0498207664832d84]
        satoshiOutputOne = int(0.26e8)
        satoshiOutputTwo = int(0.01001546e8)

        btcAddr = 0x956bfc5575c0a7134c7effef268e51d887ba7015
        numWei = self.ETHER
        weiPerSatoshi = 38461538462  # ceiling of numWei / satoshiOutputOne
        ethAddr = 0x587488c119f40666b4a0c807b0d7a1acfe3b6917

        # fail transactions
        MOCK_VERIFY_TX_ONE = self.s.abi_contract('./tests/mock_verifyTxReturnsOne.se')
        self.c.setTrustedBtcRelay(MOCK_VERIFY_TX_ONE.address)

        # k2 creates ticket
        ticketId = self.c.createTicket(btcAddr, numWei, weiPerSatoshi, sender=tester.k2, value=numWei)
        assert ticketId == 1
        assert 2 == self.c.createTicket(btcAddr, numWei, weiPerSatoshi, sender=tester.k2, value=numWei)

        # k1 is the reserver
        res = self.c.reserveTicket(ticketId, txHash, nonce[ticketId], sender=tester.k1, profiling=True)
        # print('GAS: '+str(res['gas']))
        assert res['output'] == 1
        res = self.c.reserveTicket(2, txHash, nonce[2], sender=tester.k1, profiling=True)
        assert res['output'] == 2

        # claimer = tester.k0
        addrClaimer = tester.a0

        eventArr = []
        self.s.block.log_listeners.append(lambda x: eventArr.append(self.c._translator.listen(x)))

        # anyone can claim
        self.s.block.timestamp += self.ONLY_RESERVER_CLAIM_SECS + 1

        balPreClaim = self.s.block.get_balance(addrClaimer)
        claimRes = self.c.claimTicket(ticketId, txStr, txHash, txIndex, sibling, txBlockHash, profiling=True)
        # print('GAS claimTicket() ', claimRes['gas'])
        assert claimRes['output'] == ticketId

        self.assertClaimSuccessLogs(eventArr, satoshiOutputOne, btcAddr, ethAddr, satoshiOutputTwo, ticketId)

        claimerFeePercent = (satoshiOutputTwo % 10000) / 10000.0
        feeToClaimer = int(claimerFeePercent * numWei)  # int() is needed

        endClaimerBal = self.s.block.get_balance(addrClaimer)
        assert endClaimerBal == balPreClaim + feeToClaimer

        indexOfBtcAddr = txStr.find(format(btcAddr, 'x'))
        ethAddrBin = txStr[indexOfBtcAddr + 68:indexOfBtcAddr + 108].decode('hex')  # assumes ether addr is after btcAddr
        buyerEthBalance = self.s.block.get_balance(ethAddrBin)

        assert buyerEthBalance == (1 - claimerFeePercent) * numWei

        # re-claim is not allowed
        claimRes = self.c.claimTicket(ticketId, txStr, txHash, txIndex, sibling, txBlockHash, profiling=True)
        # print('GAS claimTicket() ', claimRes['gas'])
        assert claimRes['output'] == self.CLAIM_FAIL_INVALID_TICKET

        assert eventArr == [{
            '_event_type': 'ticketEvent',
            'ticketId': ticketId,
            'rval': self.CLAIM_FAIL_INVALID_TICKET  # a claimed ticket no longer exists
        }]
        eventArr.pop()

    def assertClaimSuccessLogs(self, eventArr, satoshiOutputOne, btcAddr, ethAddr, satoshiOutputTwo, ticketId):
        assert eventArr[1] == {
            '_event_type': 'claimSuccess',
            'numSatoshi': satoshiOutputOne,
            'btcAddr': btcAddr,
            'ethAddr': ethAddr,
            'feeWei': 0,
            'satoshiIn2ndOutput': satoshiOutputTwo
        }
        eventArr.pop()

        assert eventArr == [{
            '_event_type': 'ticketEvent',
            'ticketId': ticketId,
            'rval': 0
        }]
        eventArr.pop()

    def testKeccak(self):
        txHash = 0xdd5a8f13c97c8b8d47329fa7bd487df24b7d3b7e855a65eb7fd51e8f94f7e482
        ticketId = 2
        nonce = 2460830
        expHash = 0x000003cda023979d2888a9542ef2a90a52ae250856b6a559bacdf361191864cc
        assert self.c.funcKeccak(txHash, ticketId, nonce) == expHash

        txHash = 0xdd5a8f13c97c8b8d47329fa7bd487df24b7d3b7e855a65eb7fd51e8f94f7e482
        ticketId = 3
        nonce = 726771
        expHash = 0x0000013fc2168a88d89d68a2ef4d2ba9994d6aaf17ce51355d7c4a926b89f4a0
        assert self.c.funcKeccak(txHash, ticketId, nonce) == expHash

        txHash = 0x141e4ea2fa3c9bf9984d03ff081d21555f8ccc7a528326cea96221ca6d476566
        ticketId = 2
        nonce = 680495
        expHash = 0x00000290c7705248df8fcc6fb0c21b7cf304c5294bace5aa18dd7a4f5c0c6c79
        assert self.c.funcKeccak(txHash, ticketId, nonce) == expHash

        txHash = 0x141e4ea2fa3c9bf9984d03ff081d21555f8ccc7a528326cea96221ca6d476566
        ticketId = 1
        nonce = 2089206
        expHash = 0x0000015263afcfe8ff095e519dba81c2769f6d48c683259368dfa7c8a3afdeba
        assert self.c.funcKeccak(txHash, ticketId, nonce) == expHash

        txHash = 0x141e4ea2fa3c9bf9984d03ff081d21555f8ccc7a528326cea96221ca6d476566
        ticketId = 3
        nonce = 12037620
        expHash = 0x00000184736e7144dc389049cea44ba3b5c6fd28088af94299279070f7b0a861
        assert self.c.funcKeccak(txHash, ticketId, nonce) == expHash

        txHash = 0x141e4ea2fa3c9bf9984d03ff081d21555f8ccc7a528326cea96221ca6d476566
        ticketId = 4
        nonce = 6492745
        expHash = 0x000003a488f958c83be5b4d0a99b4d96deb9c803559f8472ab435214637a757e
        assert self.c.funcKeccak(txHash, ticketId, nonce) == expHash

        txHash = 0x558231b40b5fdddb132f9fcc8dd82c32f124b6139ecf839656f4575a29dca012
        ticketId = 1
        nonce = 1997185
        expHash = 0x0000004e44fd508d602c7faa29a96086166f0e765ded0e1a41476671e72dec9a
        assert self.c.funcKeccak(txHash, ticketId, nonce) == expHash

        txHash = 0xfff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4
        ticketId = 1
        nonce = 4392122
        expHash = 0x0000002d691438f89ced909061a0302c05118412104d54045eb860cf500e10e5
        assert self.c.funcKeccak(txHash, ticketId, nonce) == expHash

        txHash = 0xfff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4
        ticketId = 3
        nonce = 1896566
        expHash = 0x000000c5dabdc3a1ece8b2794a5c973f323fd8a168e3187231d5093ad3d7ae52
        assert self.c.funcKeccak(txHash, ticketId, nonce) == expHash

    def testClaimerFee(self):
        # block 300k
        txBlockHash = 0x000000000000000082ccf8f1557c5d40b21edabb18d2d691cfbf87118bac7254
        txStr = ('0100000002a0419f78a1ef9441b1d91a5cb3e198d4a1ef8b382cd942de98a58a5f968d073f000000006a473044022032a0332c1afb753afc1bb44555c9ccefa83709ca5e1e62a'
                 '608024b9cf4c087c002201a506f2c8442c390590769d5cdefc6e4e0e1f8517a060365ec527cc9b749068c012102caa12ebb756b4a3a90c8779d2ec75d7082f9c2897f07159898'
                 '40f16bf3aa7adfffffffff55ad24bbc9541d9848ad64546ab4a6f4b96cb15043ddeea52fbeb3cc70987340000000008a47304402203d4cb993d6e73979c3aae2d1c4752f6b4c5'
                 '01c4b64fc19f212efaa54a7ba199f02204ba50d8764532c2157f7438cf2eee6e975853975eb3803823f9de4a1c1f230e30141040a424c356d3adfdc6ba29cf41474105434d01a'
                 '7ad5be3ae6938f8af92da215bdb0e21bd2ad6301f43be02f1ce796229a8c00873356e11a056c8c65f731304a7fffffffff0280ba8c01000000001976a914956bfc5575c0a7134'
                 'c7effef268e51d887ba701588ac4a480f00000000001976a914587488c119f40666b4a0c807b0d7a1acfe3b691788ac00000000')
        txHash = 0x141e4ea2fa3c9bf9984d03ff081d21555f8ccc7a528326cea96221ca6d476566
        nonce = 2089206
        txIndex = 190
        sibling = [0x09636b32593267f1aec7cf7ac36b6a51b8ef158f5648d1d27882492b7908ca2e,
                   0xe081237dd6f75f2a0b174ac8a8f138fffd4c05ad05c0c12cc1c69a203eec79ae,
                   0x0c23978510ed856b5e17cba4b4feba7e8596581d604cce84f50b6ea180fd91a4,
                   0x1f4deef9f140251f6dc011d3b9db88586a2a313de813f803626dcdac4e1e3127,
                   0x266f31fc4cdca488ecf0f9cbf56e4b25aa5e49154ae192bc6982fc28827cc62b,
                   0xd394350ece3e0cb705c99c1db14f29d1db0e1a3dcbd3094baf695e297bea0f6b,
                   0x3a2e3e81c6ef3a3ff65ec6e62ead8eb5c2f8bb950ba2422038fa573a6d638812,
                   0xaec0b4d49d190f9ac61d0e32443ade724274de466eed4acb0498207664832d84]
        satoshiOutputOne = int(0.26e8)
        satoshiOutputTwo = int(0.01001546e8)

        btcAddr = 0x956bfc5575c0a7134c7effef268e51d887ba7015
        numWei = self.ETHER
        weiPerSatoshi = 38461538462  # ceiling of numWei / satoshiOutputOne
        ethAddr = 0x587488c119f40666b4a0c807b0d7a1acfe3b6917

        MOCK_VERIFY_TX_ONE = self.s.abi_contract('./tests/mock_verifyTxReturnsOne.se')
        self.c.setTrustedBtcRelay(MOCK_VERIFY_TX_ONE.address)
        assert self.contractBalance() == 0

        ticketId = self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei)
        assert ticketId == 1
        assert self.contractBalance() == numWei

        claimer = tester.k1
        addrClaimer = tester.a1

        claimerBalPreReserve = self.s.block.get_balance(addrClaimer)
        res = self.c.reserveTicket(ticketId, txHash, nonce, sender=claimer, profiling=True)
        # print('GAS: '+str(res['gas']))
        assert res['output'] == 1
        assert self.contractBalance() == numWei

        approxCostOfReserve = res['gas']
        boundedCostOfReserve = int(1.05 * approxCostOfReserve)
        balPreClaim = self.s.block.get_balance(addrClaimer)
        assert balPreClaim < claimerBalPreReserve - approxCostOfReserve
        assert balPreClaim > claimerBalPreReserve - boundedCostOfReserve

        eventArr = []
        self.s.block.log_listeners.append(lambda x: eventArr.append(self.c._translator.listen(x)))

        balPreClaim = self.s.block.get_balance(addrClaimer)
        claimRes = self.c.claimTicket(ticketId, txStr, txHash, txIndex, sibling, txBlockHash, sender=claimer, profiling=True)
        # print('GAS claimTicket() ', claimRes['gas'])
        assert claimRes['output'] == ticketId
        assert self.contractBalance() == 0

        claimerFeePercent = (satoshiOutputTwo % 10000) / 10000.0
        feeToClaimer = int(claimerFeePercent * numWei)  # int() is needed

        # gas from profiling claimTicket() is inaccurate so assert that the
        # balance is within 2.4X of approxCostToClaim
        # TODO why 2.4X ? now up to 2.8...
        approxCostToClaim = claimRes['gas']
        boundedCostToClaim = int(2.8 * approxCostToClaim)

        endClaimerBal = self.s.block.get_balance(addrClaimer)
        assert endClaimerBal < balPreClaim + feeToClaimer - approxCostToClaim
        assert endClaimerBal > balPreClaim + feeToClaimer - boundedCostToClaim

        assert endClaimerBal < claimerBalPreReserve + feeToClaimer - approxCostToClaim - approxCostOfReserve
        assert endClaimerBal > claimerBalPreReserve + feeToClaimer - boundedCostToClaim - boundedCostOfReserve

        indexOfBtcAddr = txStr.find(format(btcAddr, 'x'))
        ethAddrBin = txStr[indexOfBtcAddr + 68:indexOfBtcAddr + 108].decode('hex')  # assumes ether addr is after btcAddr
        buyerEthBalance = self.s.block.get_balance(ethAddrBin)

        assert buyerEthBalance == (1 - claimerFeePercent) * numWei

        self.assertClaimSuccessLogs(eventArr, satoshiOutputOne, btcAddr, ethAddr, satoshiOutputTwo, ticketId)

        # re-claim is not allowed
        claimRes = self.c.claimTicket(ticketId, txStr, txHash, txIndex, sibling, txBlockHash, sender=claimer, profiling=True)
        # print('GAS claimTicket() ', claimRes['gas'])
        assert claimRes['output'] == self.CLAIM_FAIL_INVALID_TICKET

        assert eventArr == [{
            '_event_type': 'ticketEvent',
            'ticketId': ticketId,
            'rval': self.CLAIM_FAIL_INVALID_TICKET  # a claimed ticket no longer exists
        }]
        eventArr.pop()

    # weiPerSatoshi is a round figure 200000000000
    def testClaimRoundPrice(self):
        # block 300k
        txBlockHash = 0x000000000000000082ccf8f1557c5d40b21edabb18d2d691cfbf87118bac7254
        txStr = ('0100000002a0419f78a1ef9441b1d91a5cb3e198d4a1ef8b382cd942de98a58a5f968d073f000000006a473044022032a0332c1afb753afc1bb44555c9ccefa83709ca5e1e62a'
                 '608024b9cf4c087c002201a506f2c8442c390590769d5cdefc6e4e0e1f8517a060365ec527cc9b749068c012102caa12ebb756b4a3a90c8779d2ec75d7082f9c2897f07159898'
                 '40f16bf3aa7adfffffffff55ad24bbc9541d9848ad64546ab4a6f4b96cb15043ddeea52fbeb3cc70987340000000008a47304402203d4cb993d6e73979c3aae2d1c4752f6b4c5'
                 '01c4b64fc19f212efaa54a7ba199f02204ba50d8764532c2157f7438cf2eee6e975853975eb3803823f9de4a1c1f230e30141040a424c356d3adfdc6ba29cf41474105434d01a'
                 '7ad5be3ae6938f8af92da215bdb0e21bd2ad6301f43be02f1ce796229a8c00873356e11a056c8c65f731304a7fffffffff0280ba8c01000000001976a914956bfc5575c0a7134'
                 'c7effef268e51d887ba701588ac4a480f00000000001976a914587488c119f40666b4a0c807b0d7a1acfe3b691788ac00000000')
        txHash = 0x141e4ea2fa3c9bf9984d03ff081d21555f8ccc7a528326cea96221ca6d476566
        nonce = 2089206
        txIndex = 190
        sibling = [0x09636b32593267f1aec7cf7ac36b6a51b8ef158f5648d1d27882492b7908ca2e,
                   0xe081237dd6f75f2a0b174ac8a8f138fffd4c05ad05c0c12cc1c69a203eec79ae,
                   0x0c23978510ed856b5e17cba4b4feba7e8596581d604cce84f50b6ea180fd91a4,
                   0x1f4deef9f140251f6dc011d3b9db88586a2a313de813f803626dcdac4e1e3127,
                   0x266f31fc4cdca488ecf0f9cbf56e4b25aa5e49154ae192bc6982fc28827cc62b,
                   0xd394350ece3e0cb705c99c1db14f29d1db0e1a3dcbd3094baf695e297bea0f6b,
                   0x3a2e3e81c6ef3a3ff65ec6e62ead8eb5c2f8bb950ba2422038fa573a6d638812,
                   0xaec0b4d49d190f9ac61d0e32443ade724274de466eed4acb0498207664832d84]
        satoshiOutputOne = int(0.26e8)
        satoshiOutputTwo = int(0.01001546e8)

        btcAddr = 0x956bfc5575c0a7134c7effef268e51d887ba7015
        numWei = int(5.2 * self.ETHER)
        weiPerSatoshi = 200000000000  # numWei / satoshiOutputOne
        ethAddr = 0x587488c119f40666b4a0c807b0d7a1acfe3b6917

        MOCK_VERIFY_TX_ONE = self.s.abi_contract('./tests/mock_verifyTxReturnsOne.se')
        self.c.setTrustedBtcRelay(MOCK_VERIFY_TX_ONE.address)

        ticketId = self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei)
        assert ticketId == 1

        claimer = tester.k1
        addrClaimer = tester.a1

        claimerBalPreReserve = self.s.block.get_balance(addrClaimer)
        res = self.c.reserveTicket(ticketId, txHash, nonce, sender=claimer, profiling=True)
        # print('GAS: '+str(res['gas']))
        assert res['output'] == 1

        approxCostOfReserve = res['gas']
        boundedCostOfReserve = int(1.05 * approxCostOfReserve)
        balPreClaim = self.s.block.get_balance(addrClaimer)
        assert balPreClaim < claimerBalPreReserve - approxCostOfReserve
        assert balPreClaim > claimerBalPreReserve - boundedCostOfReserve

        eventArr = []
        self.s.block.log_listeners.append(lambda x: eventArr.append(self.c._translator.listen(x)))

        balPreClaim = self.s.block.get_balance(addrClaimer)
        claimRes = self.c.claimTicket(ticketId, txStr, txHash, txIndex, sibling, txBlockHash, sender=claimer, profiling=True)
        # print('GAS claimTicket() ', claimRes['gas'])
        assert claimRes['output'] == ticketId

        claimerFeePercent = (satoshiOutputTwo % 10000) / 10000.0
        feeToClaimer = int(claimerFeePercent * numWei)  # int() is needed

        # gas from profiling claimTicket() is inaccurate so assert that the
        # balance is within 2.4X of approxCostToClaim
        # TODO why 2.4X ? now 2.8...
        approxCostToClaim = claimRes['gas']
        boundedCostToClaim = int(2.8 * approxCostToClaim)

        endClaimerBal = self.s.block.get_balance(addrClaimer)
        assert endClaimerBal < balPreClaim + feeToClaimer - approxCostToClaim
        assert endClaimerBal > balPreClaim + feeToClaimer - boundedCostToClaim

        assert endClaimerBal < claimerBalPreReserve + feeToClaimer - approxCostToClaim - approxCostOfReserve
        assert endClaimerBal > claimerBalPreReserve + feeToClaimer - boundedCostToClaim - boundedCostOfReserve

        indexOfBtcAddr = txStr.find(format(btcAddr, 'x'))
        ethAddrBin = txStr[indexOfBtcAddr + 68:indexOfBtcAddr + 108].decode('hex')  # assumes ether addr is after btcAddr
        buyerEthBalance = self.s.block.get_balance(ethAddrBin)

        assert buyerEthBalance == (1 - claimerFeePercent) * numWei

        self.assertClaimSuccessLogs(eventArr, satoshiOutputOne, btcAddr, ethAddr, satoshiOutputTwo, ticketId)

    # smaller version of testClaimerFee except weiPerSatoshi is 1 less (thus
    # buyer's 0.26 BTC will not be enough to claim the ether)
    def testInsufficientSatoshi(self):
        # block 300k
        txBlockHash = 0x000000000000000082ccf8f1557c5d40b21edabb18d2d691cfbf87118bac7254
        txStr = ('0100000002a0419f78a1ef9441b1d91a5cb3e198d4a1ef8b382cd942de98a58a5f968d073f000000006a473044022032a0332c1afb753afc1bb44555c9ccefa83709ca5e1e62a'
                 '608024b9cf4c087c002201a506f2c8442c390590769d5cdefc6e4e0e1f8517a060365ec527cc9b749068c012102caa12ebb756b4a3a90c8779d2ec75d7082f9c2897f07159898'
                 '40f16bf3aa7adfffffffff55ad24bbc9541d9848ad64546ab4a6f4b96cb15043ddeea52fbeb3cc70987340000000008a47304402203d4cb993d6e73979c3aae2d1c4752f6b4c5'
                 '01c4b64fc19f212efaa54a7ba199f02204ba50d8764532c2157f7438cf2eee6e975853975eb3803823f9de4a1c1f230e30141040a424c356d3adfdc6ba29cf41474105434d01a'
                 '7ad5be3ae6938f8af92da215bdb0e21bd2ad6301f43be02f1ce796229a8c00873356e11a056c8c65f731304a7fffffffff0280ba8c01000000001976a914956bfc5575c0a7134'
                 'c7effef268e51d887ba701588ac4a480f00000000001976a914587488c119f40666b4a0c807b0d7a1acfe3b691788ac00000000')
        txHash = 0x141e4ea2fa3c9bf9984d03ff081d21555f8ccc7a528326cea96221ca6d476566
        nonce = 2089206
        txIndex = 190
        sibling = [0x09636b32593267f1aec7cf7ac36b6a51b8ef158f5648d1d27882492b7908ca2e,
                   0xe081237dd6f75f2a0b174ac8a8f138fffd4c05ad05c0c12cc1c69a203eec79ae,
                   0x0c23978510ed856b5e17cba4b4feba7e8596581d604cce84f50b6ea180fd91a4,
                   0x1f4deef9f140251f6dc011d3b9db88586a2a313de813f803626dcdac4e1e3127,
                   0x266f31fc4cdca488ecf0f9cbf56e4b25aa5e49154ae192bc6982fc28827cc62b,
                   0xd394350ece3e0cb705c99c1db14f29d1db0e1a3dcbd3094baf695e297bea0f6b,
                   0x3a2e3e81c6ef3a3ff65ec6e62ead8eb5c2f8bb950ba2422038fa573a6d638812,
                   0xaec0b4d49d190f9ac61d0e32443ade724274de466eed4acb0498207664832d84]
        # satoshiOutputOne = int(0.26e8)
        # satoshiOutputTwo = int(0.01001546e8)

        btcAddr = 0x956bfc5575c0a7134c7effef268e51d887ba7015
        numWei = self.ETHER
        weiPerSatoshi = 38461538461  # floor of numWei / satoshiOutputOne
        # ethAddr = 0x587488c119f40666b4a0c807b0d7a1acfe3b6917

        MOCK_VERIFY_TX_ONE = self.s.abi_contract('./tests/mock_verifyTxReturnsOne.se')
        self.c.setTrustedBtcRelay(MOCK_VERIFY_TX_ONE.address)

        ticketId = self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei)
        assert ticketId == 1

        claimer = tester.k1
        # addrClaimer = tester.a1

        # claimerBalPreReserve = self.s.block.get_balance(addrClaimer)
        res = self.c.reserveTicket(ticketId, txHash, nonce, sender=claimer, profiling=True)
        # print('GAS: '+str(res['gas']))
        assert res['output'] == 1

        eventArr = []
        self.s.block.log_listeners.append(lambda x: eventArr.append(self.c._translator.listen(x)))

        # balPreClaim = self.s.block.get_balance(addrClaimer)
        claimRes = self.c.claimTicket(ticketId, txStr, txHash, txIndex, sibling, txBlockHash, sender=claimer, profiling=True)
        # print('GAS claimTicket() ', claimRes['gas'])
        assert claimRes['output'] == self.CLAIM_FAIL_INSUFFICIENT_SATOSHI

        assert eventArr == [{
            '_event_type': 'ticketEvent',
            'ticketId': ticketId,
            'rval': self.CLAIM_FAIL_INSUFFICIENT_SATOSHI
        }]
        eventArr.pop()

    def testWrongClaimer(self):
        # block 300k
        txBlockHash = 0x000000000000000082ccf8f1557c5d40b21edabb18d2d691cfbf87118bac7254
        txStr = ('0100000002a0419f78a1ef9441b1d91a5cb3e198d4a1ef8b382cd942de98a58a5f968d073f000000006a473044022032a0332c1afb753afc1bb44555c9ccefa83709ca5e1e62a'
                 '608024b9cf4c087c002201a506f2c8442c390590769d5cdefc6e4e0e1f8517a060365ec527cc9b749068c012102caa12ebb756b4a3a90c8779d2ec75d7082f9c2897f07159898'
                 '40f16bf3aa7adfffffffff55ad24bbc9541d9848ad64546ab4a6f4b96cb15043ddeea52fbeb3cc70987340000000008a47304402203d4cb993d6e73979c3aae2d1c4752f6b4c5'
                 '01c4b64fc19f212efaa54a7ba199f02204ba50d8764532c2157f7438cf2eee6e975853975eb3803823f9de4a1c1f230e30141040a424c356d3adfdc6ba29cf41474105434d01a'
                 '7ad5be3ae6938f8af92da215bdb0e21bd2ad6301f43be02f1ce796229a8c00873356e11a056c8c65f731304a7fffffffff0280ba8c01000000001976a914956bfc5575c0a7134'
                 'c7effef268e51d887ba701588ac4a480f00000000001976a914587488c119f40666b4a0c807b0d7a1acfe3b691788ac00000000')
        txHash = 0x141e4ea2fa3c9bf9984d03ff081d21555f8ccc7a528326cea96221ca6d476566
        nonce = 2089206
        txIndex = 190
        sibling = [0x09636b32593267f1aec7cf7ac36b6a51b8ef158f5648d1d27882492b7908ca2e,
                   0xe081237dd6f75f2a0b174ac8a8f138fffd4c05ad05c0c12cc1c69a203eec79ae,
                   0x0c23978510ed856b5e17cba4b4feba7e8596581d604cce84f50b6ea180fd91a4,
                   0x1f4deef9f140251f6dc011d3b9db88586a2a313de813f803626dcdac4e1e3127,
                   0x266f31fc4cdca488ecf0f9cbf56e4b25aa5e49154ae192bc6982fc28827cc62b,
                   0xd394350ece3e0cb705c99c1db14f29d1db0e1a3dcbd3094baf695e297bea0f6b,
                   0x3a2e3e81c6ef3a3ff65ec6e62ead8eb5c2f8bb950ba2422038fa573a6d638812,
                   0xaec0b4d49d190f9ac61d0e32443ade724274de466eed4acb0498207664832d84]
        satoshiOutputOne = int(0.26e8)
        # satoshiOutputTwo = int(0.01001546e8)

        btcAddr = 0x956bfc5575c0a7134c7effef268e51d887ba7015
        numWei = self.ETHER
        weiPerSatoshi = numWei / satoshiOutputOne
        # ethAddr = 0x587488c119f40666b4a0c807b0d7a1acfe3b6917

        MOCK_VERIFY_TX_ONE = self.s.abi_contract('./tests/mock_verifyTxReturnsOne.se')
        self.c.setTrustedBtcRelay(MOCK_VERIFY_TX_ONE.address)

        ticketId = self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei)
        assert ticketId == 1

        reserver = tester.k1
        claimer = tester.k2

        res = self.c.reserveTicket(ticketId, txHash, nonce, sender=reserver, profiling=True)
        assert res['output'] == 1

        eventArr = []
        self.s.block.log_listeners.append(lambda x: eventArr.append(self.c._translator.listen(x)))

        assert self.CLAIM_FAIL_CLAIMER == self.c.claimTicket(ticketId, txStr, txHash, txIndex, sibling, txBlockHash, sender=claimer)

        assert eventArr == [{
            '_event_type': 'ticketEvent',
            'ticketId': ticketId,
            'rval': self.CLAIM_FAIL_CLAIMER
        }]
        eventArr.pop()

    def testClaimWithWrongTx(self):
        # block 300k
        txBlockHash = 0x000000000000000082ccf8f1557c5d40b21edabb18d2d691cfbf87118bac7254
        txStr = ('0100000002a0419f78a1ef9441b1d91a5cb3e198d4a1ef8b382cd942de98a58a5f968d073f000000006a473044022032a0332c1afb753afc1bb44555c9ccefa83709ca5e1e62a'
                 '608024b9cf4c087c002201a506f2c8442c390590769d5cdefc6e4e0e1f8517a060365ec527cc9b749068c012102caa12ebb756b4a3a90c8779d2ec75d7082f9c2897f07159898'
                 '40f16bf3aa7adfffffffff55ad24bbc9541d9848ad64546ab4a6f4b96cb15043ddeea52fbeb3cc70987340000000008a47304402203d4cb993d6e73979c3aae2d1c4752f6b4c5'
                 '01c4b64fc19f212efaa54a7ba199f02204ba50d8764532c2157f7438cf2eee6e975853975eb3803823f9de4a1c1f230e30141040a424c356d3adfdc6ba29cf41474105434d01a'
                 '7ad5be3ae6938f8af92da215bdb0e21bd2ad6301f43be02f1ce796229a8c00873356e11a056c8c65f731304a7fffffffff0280ba8c01000000001976a914956bfc5575c0a7134'
                 'c7effef268e51d887ba701588ac4a480f00000000001976a914587488c119f40666b4a0c807b0d7a1acfe3b691788ac00000000')
        txHash = 0x141e4ea2fa3c9bf9984d03ff081d21555f8ccc7a528326cea96221ca6d476566
        nonce = 2089206
        txIndex = 190
        sibling = [0x09636b32593267f1aec7cf7ac36b6a51b8ef158f5648d1d27882492b7908ca2e,
                   0xe081237dd6f75f2a0b174ac8a8f138fffd4c05ad05c0c12cc1c69a203eec79ae,
                   0x0c23978510ed856b5e17cba4b4feba7e8596581d604cce84f50b6ea180fd91a4,
                   0x1f4deef9f140251f6dc011d3b9db88586a2a313de813f803626dcdac4e1e3127,
                   0x266f31fc4cdca488ecf0f9cbf56e4b25aa5e49154ae192bc6982fc28827cc62b,
                   0xd394350ece3e0cb705c99c1db14f29d1db0e1a3dcbd3094baf695e297bea0f6b,
                   0x3a2e3e81c6ef3a3ff65ec6e62ead8eb5c2f8bb950ba2422038fa573a6d638812,
                   0xaec0b4d49d190f9ac61d0e32443ade724274de466eed4acb0498207664832d84]
        satoshiOutputOne = int(0.26e8)
        # satoshiOutputTwo = int(0.01001546e8)

        btcAddr = 0x956bfc5575c0a7134c7effef268e51d887ba7015
        numWei = self.ETHER
        weiPerSatoshi = numWei / satoshiOutputOne
        # ethAddr = 0x587488c119f40666b4a0c807b0d7a1acfe3b6917

        MOCK_VERIFY_TX_ONE = self.s.abi_contract('./tests/mock_verifyTxReturnsOne.se')
        self.c.setTrustedBtcRelay(MOCK_VERIFY_TX_ONE.address)

        ticketId = self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei)
        assert ticketId == 1

        reserver = tester.k1

        res = self.c.reserveTicket(ticketId, txHash, nonce, sender=reserver, profiling=True)
        assert res['output'] == 1

        eventArr = []
        self.s.block.log_listeners.append(lambda x: eventArr.append(self.c._translator.listen(x)))

        assert self.CLAIM_FAIL_TX_HASH == self.c.claimTicket(ticketId, txStr, txHash + 1, txIndex, sibling, txBlockHash, sender=reserver)

        assert eventArr == [{
            '_event_type': 'ticketEvent',
            'ticketId': ticketId,
            'rval': self.CLAIM_FAIL_TX_HASH
        }]
        eventArr.pop()

    def testClaimWithoutReserve(self):
        # block 300k
        txBlockHash = 0x000000000000000082ccf8f1557c5d40b21edabb18d2d691cfbf87118bac7254
        txStr = ('0100000002a0419f78a1ef9441b1d91a5cb3e198d4a1ef8b382cd942de98a58a5f968d073f000000006a473044022032a0332c1afb753afc1bb44555c9ccefa83709ca5e1e62a'
                 '608024b9cf4c087c002201a506f2c8442c390590769d5cdefc6e4e0e1f8517a060365ec527cc9b749068c012102caa12ebb756b4a3a90c8779d2ec75d7082f9c2897f07159898'
                 '40f16bf3aa7adfffffffff55ad24bbc9541d9848ad64546ab4a6f4b96cb15043ddeea52fbeb3cc70987340000000008a47304402203d4cb993d6e73979c3aae2d1c4752f6b4c5'
                 '01c4b64fc19f212efaa54a7ba199f02204ba50d8764532c2157f7438cf2eee6e975853975eb3803823f9de4a1c1f230e30141040a424c356d3adfdc6ba29cf41474105434d01a'
                 '7ad5be3ae6938f8af92da215bdb0e21bd2ad6301f43be02f1ce796229a8c00873356e11a056c8c65f731304a7fffffffff0280ba8c01000000001976a914956bfc5575c0a7134'
                 'c7effef268e51d887ba701588ac4a480f00000000001976a914587488c119f40666b4a0c807b0d7a1acfe3b691788ac00000000')
        txHash = 0x141e4ea2fa3c9bf9984d03ff081d21555f8ccc7a528326cea96221ca6d476566
        # nonce = 2089206
        txIndex = 190
        sibling = [0x09636b32593267f1aec7cf7ac36b6a51b8ef158f5648d1d27882492b7908ca2e,
                   0xe081237dd6f75f2a0b174ac8a8f138fffd4c05ad05c0c12cc1c69a203eec79ae,
                   0x0c23978510ed856b5e17cba4b4feba7e8596581d604cce84f50b6ea180fd91a4,
                   0x1f4deef9f140251f6dc011d3b9db88586a2a313de813f803626dcdac4e1e3127,
                   0x266f31fc4cdca488ecf0f9cbf56e4b25aa5e49154ae192bc6982fc28827cc62b,
                   0xd394350ece3e0cb705c99c1db14f29d1db0e1a3dcbd3094baf695e297bea0f6b,
                   0x3a2e3e81c6ef3a3ff65ec6e62ead8eb5c2f8bb950ba2422038fa573a6d638812,
                   0xaec0b4d49d190f9ac61d0e32443ade724274de466eed4acb0498207664832d84]
        satoshiOutputOne = int(0.26e8)
        # satoshiOutputTwo = int(0.01001546e8)

        btcAddr = 0x956bfc5575c0a7134c7effef268e51d887ba7015
        numWei = self.ETHER
        weiPerSatoshi = numWei / satoshiOutputOne
        # ethAddr = 0x587488c119f40666b4a0c807b0d7a1acfe3b6917

        MOCK_VERIFY_TX_ONE = self.s.abi_contract('./tests/mock_verifyTxReturnsOne.se')
        self.c.setTrustedBtcRelay(MOCK_VERIFY_TX_ONE.address)

        ticketId = self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei)
        assert ticketId == 1

        claimer = tester.k1
        # addrClaimer = tester.a1

        eventArr = []
        self.s.block.log_listeners.append(lambda x: eventArr.append(self.c._translator.listen(x)))

        assert self.CLAIM_FAIL_UNRESERVED == self.c.claimTicket(ticketId, txStr, txHash, txIndex, sibling, txBlockHash, sender=claimer)

        assert eventArr == [{
            '_event_type': 'ticketEvent',
            'ticketId': ticketId,
            'rval': self.CLAIM_FAIL_UNRESERVED
        }]
        eventArr.pop()

    def testClaimWithoutSecondReserve(self):
        # block 300k
        txBlockHash = 0x000000000000000082ccf8f1557c5d40b21edabb18d2d691cfbf87118bac7254
        txStr = ('0100000002a0419f78a1ef9441b1d91a5cb3e198d4a1ef8b382cd942de98a58a5f968d073f000000006a473044022032a0332c1afb753afc1bb44555c9ccefa83709ca5e1e62a'
                 '608024b9cf4c087c002201a506f2c8442c390590769d5cdefc6e4e0e1f8517a060365ec527cc9b749068c012102caa12ebb756b4a3a90c8779d2ec75d7082f9c2897f07159898'
                 '40f16bf3aa7adfffffffff55ad24bbc9541d9848ad64546ab4a6f4b96cb15043ddeea52fbeb3cc70987340000000008a47304402203d4cb993d6e73979c3aae2d1c4752f6b4c5'
                 '01c4b64fc19f212efaa54a7ba199f02204ba50d8764532c2157f7438cf2eee6e975853975eb3803823f9de4a1c1f230e30141040a424c356d3adfdc6ba29cf41474105434d01a'
                 '7ad5be3ae6938f8af92da215bdb0e21bd2ad6301f43be02f1ce796229a8c00873356e11a056c8c65f731304a7fffffffff0280ba8c01000000001976a914956bfc5575c0a7134'
                 'c7effef268e51d887ba701588ac4a480f00000000001976a914587488c119f40666b4a0c807b0d7a1acfe3b691788ac00000000')
        txHash = 0x141e4ea2fa3c9bf9984d03ff081d21555f8ccc7a528326cea96221ca6d476566
        nonce = 2089206
        txIndex = 190
        sibling = [0x09636b32593267f1aec7cf7ac36b6a51b8ef158f5648d1d27882492b7908ca2e,
                   0xe081237dd6f75f2a0b174ac8a8f138fffd4c05ad05c0c12cc1c69a203eec79ae,
                   0x0c23978510ed856b5e17cba4b4feba7e8596581d604cce84f50b6ea180fd91a4,
                   0x1f4deef9f140251f6dc011d3b9db88586a2a313de813f803626dcdac4e1e3127,
                   0x266f31fc4cdca488ecf0f9cbf56e4b25aa5e49154ae192bc6982fc28827cc62b,
                   0xd394350ece3e0cb705c99c1db14f29d1db0e1a3dcbd3094baf695e297bea0f6b,
                   0x3a2e3e81c6ef3a3ff65ec6e62ead8eb5c2f8bb950ba2422038fa573a6d638812,
                   0xaec0b4d49d190f9ac61d0e32443ade724274de466eed4acb0498207664832d84]
        satoshiOutputOne = int(0.26e8)
        # satoshiOutputTwo = int(0.01001546e8)

        btcAddr = 0x956bfc5575c0a7134c7effef268e51d887ba7015
        numWei = self.ETHER
        weiPerSatoshi = numWei / satoshiOutputOne
        # ethAddr = 0x587488c119f40666b4a0c807b0d7a1acfe3b6917

        MOCK_VERIFY_TX_ONE = self.s.abi_contract('./tests/mock_verifyTxReturnsOne.se')
        self.c.setTrustedBtcRelay(MOCK_VERIFY_TX_ONE.address)

        ticketId = self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei)
        assert ticketId == 1

        assert ticketId == self.c.reserveTicket(ticketId, txHash, nonce)

        # at the reservation deadline
        self.s.block.timestamp += self.TOTAL_RESERVED_SECS
        assert self.c.funcTicketAvailable(ticketId) == 0

        # 1 second later reservation expires
        self.s.block.timestamp += 1
        assert self.c.funcTicketAvailable(ticketId) == 1

        eventArr = []
        self.s.block.log_listeners.append(lambda x: eventArr.append(self.c._translator.listen(x)))

        # ticket should be unclaimed since it needs to be reserved again
        assert self.CLAIM_FAIL_UNRESERVED == self.c.claimTicket(ticketId, txStr, txHash, txIndex, sibling, txBlockHash)

        assert eventArr == [{
            '_event_type': 'ticketEvent',
            'ticketId': ticketId,
            'rval': self.CLAIM_FAIL_UNRESERVED
        }]
        eventArr.pop()

    def testClaimBadTx(self):
        # block 300k
        txBlockHash = 0x000000000000000082ccf8f1557c5d40b21edabb18d2d691cfbf87118bac7254
        txStr = ('0100000002a0419f78a1ef9441b1d91a5cb3e198d4a1ef8b382cd942de98a58a5f968d073f000000006a473044022032a0332c1afb753afc1bb44555c9ccefa83709ca5e1e62a'
                 '608024b9cf4c087c002201a506f2c8442c390590769d5cdefc6e4e0e1f8517a060365ec527cc9b749068c012102caa12ebb756b4a3a90c8779d2ec75d7082f9c2897f07159898'
                 '40f16bf3aa7adfffffffff55ad24bbc9541d9848ad64546ab4a6f4b96cb15043ddeea52fbeb3cc70987340000000008a47304402203d4cb993d6e73979c3aae2d1c4752f6b4c5'
                 '01c4b64fc19f212efaa54a7ba199f02204ba50d8764532c2157f7438cf2eee6e975853975eb3803823f9de4a1c1f230e30141040a424c356d3adfdc6ba29cf41474105434d01a'
                 '7ad5be3ae6938f8af92da215bdb0e21bd2ad6301f43be02f1ce796229a8c00873356e11a056c8c65f731304a7fffffffff0280ba8c01000000001976a914956bfc5575c0a7134'
                 'c7effef268e51d887ba701588ac4a480f00000000001976a914587488c119f40666b4a0c807b0d7a1acfe3b691788ac00000000')
        txHash = 0x141e4ea2fa3c9bf9984d03ff081d21555f8ccc7a528326cea96221ca6d476566
        nonce = 2089206
        txIndex = 190
        sibling = [0x09636b32593267f1aec7cf7ac36b6a51b8ef158f5648d1d27882492b7908ca2e,
                   0xe081237dd6f75f2a0b174ac8a8f138fffd4c05ad05c0c12cc1c69a203eec79ae,
                   0x0c23978510ed856b5e17cba4b4feba7e8596581d604cce84f50b6ea180fd91a4,
                   0x1f4deef9f140251f6dc011d3b9db88586a2a313de813f803626dcdac4e1e3127,
                   0x266f31fc4cdca488ecf0f9cbf56e4b25aa5e49154ae192bc6982fc28827cc62b,
                   0xd394350ece3e0cb705c99c1db14f29d1db0e1a3dcbd3094baf695e297bea0f6b,
                   0x3a2e3e81c6ef3a3ff65ec6e62ead8eb5c2f8bb950ba2422038fa573a6d638812,
                   0xaec0b4d49d190f9ac61d0e32443ade724274de466eed4acb0498207664832d84]
        # satoshiOutputOne = int(0.26e8)
        # satoshiOutputTwo = int(0.01001546e8)

        btcAddr = 0x956bfc5575c0a7134c7effef268e51d887ba7015
        numWei = self.ETHER
        weiPerSatoshi = 38461538462  # ceiling of numWei / satoshiOutputOne
        # ethAddr = 0x587488c119f40666b4a0c807b0d7a1acfe3b6917

        MOCK_VERIFY_TX_ZERO = self.s.abi_contract('./tests/mock_verifyTxReturnsZero.se')
        self.c.setTrustedBtcRelay(MOCK_VERIFY_TX_ZERO.address)

        ticketId = self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei)
        assert ticketId == 1

        claimer = tester.k1
        addrClaimer = tester.a1

        claimerBalPreReserve = self.s.block.get_balance(addrClaimer)
        res = self.c.reserveTicket(ticketId, txHash, nonce, sender=claimer, profiling=True)
        # print('GAS: '+str(res['gas']))
        assert res['output'] == 1

        approxCostOfReserve = res['gas']
        boundedCostOfReserve = int(1.05 * approxCostOfReserve)
        balPreClaim = self.s.block.get_balance(addrClaimer)
        assert balPreClaim < claimerBalPreReserve - approxCostOfReserve
        assert balPreClaim > claimerBalPreReserve - boundedCostOfReserve

        contractBalance = self.s.block.get_balance(self.c.address)

        eventArr = []
        self.s.block.log_listeners.append(lambda x: eventArr.append(self.c._translator.listen(x)))

        balPreClaim = self.s.block.get_balance(addrClaimer)
        claimRes = self.c.claimTicket(ticketId, txStr, txHash, txIndex, sibling, txBlockHash, sender=claimer, profiling=True)
        # print('GAS claimTicket() ', claimRes['gas'])
        assert claimRes['output'] == self.CLAIM_FAIL_PROOF

        # gas from profiling claimTicket() is inaccurate so assert that the
        # balance is within 2.2X of approxCostToClaim
        # TODO why so high at 2.2X?
        approxCostToClaim = claimRes['gas']
        boundedCostToClaim = int(2.2 * approxCostToClaim)

        endClaimerBal = self.s.block.get_balance(addrClaimer)
        assert endClaimerBal < balPreClaim - approxCostToClaim
        assert endClaimerBal > balPreClaim - boundedCostToClaim

        assert endClaimerBal < claimerBalPreReserve - approxCostToClaim - approxCostOfReserve
        assert endClaimerBal > claimerBalPreReserve - boundedCostToClaim - boundedCostOfReserve

        indexOfBtcAddr = txStr.find(format(btcAddr, 'x'))
        ethAddrBin = txStr[indexOfBtcAddr + 68:indexOfBtcAddr + 108].decode('hex')  # assumes ether addr is after btcAddr
        buyerEthBalance = self.s.block.get_balance(ethAddrBin)

        assert buyerEthBalance == 0
        assert self.s.block.get_balance(self.c.address) == contractBalance

        assert eventArr == [{
            '_event_type': 'ticketEvent',
            'ticketId': ticketId,
            'rval': self.CLAIM_FAIL_PROOF
        }]
        eventArr.pop()

    def testZeroFee(self):
        # tx is fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4
        # from block100K
        txBlockHash = 0x000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506
        txStr = ('0100000001032e38e9c0a84c6046d687d10556dcacc41d275ec55fc00779ac88fdf357a187000000008c493046022100c352d3dd993a981beba4a63ad15c209275ca9470abf'
                 'cd57da93b58e4eb5dce82022100840792bc1f456062819f15d33ee7055cf7b5ee1af1ebcc6028d9cdb1c3af7748014104f46db5e9d61a9dc27b8d64ad23e7383a4e6ca16459'
                 '3c2527c038c0857eb67ee8e825dca65046b82c9331586c82e0fd1f633f25f87c161bc6f8a630121df2b3d3ffffffff0200e32321000000001976a914c398efa9c392ba6013c'
                 '5e04ee729755ef7f58b3288ac000fe208010000001976a914948c765a6914d43f2a7ac177da2c2f6b52de3d7c88ac00000000')
        txHash = int(bin_dbl_sha256(txStr.decode('hex'))[::-1].encode('hex'), 16)
        nonceForTicket3 = 1896566
        txIndex = 1
        sibling = [0x8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87, 0x8e30899078ca1813be036a073bbf80b86cdddde1c96e9e9c99e9e3782df4ae49]
        satoshiOutputOne = int(5.56e8)
        satoshiOutputTwo = int(44.44e8)

        btcAddr = 0xc398efa9c392ba6013c5e04ee729755ef7f58b32
        numWei = self.ETHER
        weiPerSatoshi = 38461538462  # ceiling of numWei / satoshiOutputOne
        ethAddr = 0x948c765a6914d43f2a7ac177da2c2f6b52de3d7c

        MOCK_VERIFY_TX_ONE = self.s.abi_contract('./tests/mock_verifyTxReturnsOne.se')
        self.c.setTrustedBtcRelay(MOCK_VERIFY_TX_ONE.address)

        # let's claim a ticket with ID bigger than 1
        ticketId = self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei)
        assert ticketId == 1
        ticketId = self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei)
        assert ticketId == 2
        ticketId = self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei)
        assert ticketId == 3

        claimer = tester.k1
        addrClaimer = tester.a1

        claimerBalPreReserve = self.s.block.get_balance(addrClaimer)
        # gasPrice = int(10e12)  # 10 szabo
        res = self.c.reserveTicket(ticketId, txHash, nonceForTicket3, sender=claimer, profiling=True)
        # print('GAS: '+str(res['gas']))
        assert res['output'] == ticketId

        # since the gas from profiling seems approximate, assert that the
        # balance is within 5% of approxTxCost
        approxCostOfReserve = res['gas']
        boundedCostOfReserve = int(1.05 * approxCostOfReserve)
        balPreClaim = self.s.block.get_balance(addrClaimer)
        assert balPreClaim < claimerBalPreReserve - approxCostOfReserve
        assert balPreClaim > claimerBalPreReserve - boundedCostOfReserve

        eventArr = []
        self.s.block.log_listeners.append(lambda x: eventArr.append(self.c._translator.listen(x)))

        claimRes = self.c.claimTicket(ticketId, txStr, txHash, txIndex, sibling, txBlockHash, sender=claimer, profiling=True)
        # print('GAS claimTicket() ', claimRes['gas'])
        assert claimRes['output'] == ticketId

        # gas from profiling claimTicket() is inaccurate so assert that the
        # balance is within 1.8X of approxCostToClaim
        # TODO 2X?
        approxCostToClaim = claimRes['gas']
        boundedCostToClaim = int(2 * approxCostToClaim)

        endClaimerBal = self.s.block.get_balance(addrClaimer)
        assert endClaimerBal < balPreClaim - approxCostToClaim
        assert endClaimerBal > balPreClaim - boundedCostToClaim

        assert endClaimerBal < claimerBalPreReserve - approxCostToClaim - approxCostOfReserve
        assert endClaimerBal > claimerBalPreReserve - boundedCostToClaim - boundedCostOfReserve

        indexOfBtcAddr = txStr.find(format(btcAddr, 'x'))
        ethAddrBin = txStr[indexOfBtcAddr + 68:indexOfBtcAddr + 108].decode('hex')  # assumes ether addr is after btcAddr
        buyerEthBalance = self.s.block.get_balance(ethAddrBin)

        assert buyerEthBalance == numWei

        self.assertClaimSuccessLogs(eventArr, satoshiOutputOne, btcAddr, ethAddr, satoshiOutputTwo, ticketId)

    def testClaimInvalidTicket(self):
        txStr = '1'
        txHash = 0xbeef
        txIndex = 1
        sibling = []
        txBlockHash = 0xbeef2
        assert self.c.claimTicket(-1, txStr, txHash, txIndex, sibling, txBlockHash) == self.CLAIM_FAIL_INVALID_TICKET
        assert self.c.claimTicket(0, txStr, txHash, txIndex, sibling, txBlockHash) == self.CLAIM_FAIL_INVALID_TICKET
        assert self.c.claimTicket(1, txStr, txHash, txIndex, sibling, txBlockHash) == self.CLAIM_FAIL_INVALID_TICKET
        assert self.c.claimTicket(1000, txStr, txHash, txIndex, sibling, txBlockHash) == self.CLAIM_FAIL_INVALID_TICKET

        assert self.c.claimTicket(0, txStr, 0, txIndex, sibling, txBlockHash) == self.CLAIM_FAIL_INVALID_TICKET
        assert self.c.claimTicket(0, txStr, 1, txIndex, sibling, txBlockHash) == self.CLAIM_FAIL_INVALID_TICKET
        assert self.c.claimTicket(1, txStr, 1, txIndex, sibling, txBlockHash) == self.CLAIM_FAIL_INVALID_TICKET

    def testReserveInvalidTicket(self):
        txHash = 0x141e4ea2fa3c9bf9984d03ff081d21555f8ccc7a528326cea96221ca6d476566
        nonce = 2089206

        assert self.c.reserveTicket(-1, txHash, nonce) == self.RESERVE_FAIL_UNRESERVABLE
        assert self.c.reserveTicket(0, txHash, nonce) == self.RESERVE_FAIL_UNRESERVABLE
        assert self.c.reserveTicket(1, txHash, nonce) == self.RESERVE_FAIL_UNRESERVABLE
        assert self.c.reserveTicket(1000, txHash, nonce) == self.RESERVE_FAIL_UNRESERVABLE

    def testOpenTickets(self):
        btcAddr = 9
        numWei = self.ETHER
        weiPerSatoshi = 8

        expExpiry = self.s.block.timestamp + self.TOTAL_RESERVED_SECS
        expSender = int(self.s.block.coinbase.encode('hex'), 16)
        txHash = 0x141e4ea2fa3c9bf9984d03ff081d21555f8ccc7a528326cea96221ca6d476566
        nonce = [None, 2089206, 680495, 12037620, 6492745]
        baseTicket = [btcAddr, numWei, weiPerSatoshi, 1, 0, 0, expSender]

        assert self.c.getTicketIDs() == []

        assert 1 == self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei)
        assert 2 == self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei)

        assert self.c.getTicketIDs() == [2, 1]
        assert self.c.lookupTicket(1) == [1] + baseTicket
        assert self.c.lookupTicket(2) == [2] + baseTicket

        assert 3 == self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei)
        assert self.c.getTicketIDs() == [3, 2, 1]
        assert self.c.lookupTicket(3) == [3] + baseTicket

        # timePreReserve = self.s.block.timestamp
        assert 2 == self.c.reserveTicket(2, txHash, nonce[2], sender=tester.k0)
        assert self.c.getTicketIDs() == [3, 2, 1]
        assert self.c.lookupTicket(2) == [2, btcAddr, numWei, weiPerSatoshi, expExpiry, expSender, txHash, expSender]

        self.s.block.timestamp += self.TOTAL_RESERVED_SECS + 1

        assert 4 == self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei)
        assert self.c.getTicketIDs() == [4, 3, 2, 1]
        assert self.c.lookupTicket(4) == [4] + baseTicket

        expiry2 = self.s.block.timestamp + self.TOTAL_RESERVED_SECS

        assert 3 == self.c.reserveTicket(3, txHash, nonce[3], sender=tester.k0)
        assert self.c.getTicketIDs() == [4, 3, 2, 1]
        assert self.c.lookupTicket(3) == [3, btcAddr, numWei, weiPerSatoshi, expiry2, expSender, txHash, expSender]

        assert 1 == self.c.reserveTicket(1, txHash, nonce[1], sender=tester.k0)
        assert self.c.getTicketIDs() == [4, 3, 2, 1]
        assert self.c.lookupTicket(1) == [1, btcAddr, numWei, weiPerSatoshi, expiry2, expSender, txHash, expSender]

        assert 4 == self.c.reserveTicket(4, txHash, nonce[4], sender=tester.k0)
        assert self.c.getTicketIDs() == [4, 3, 2, 1]
        assert self.c.lookupTicket(4) == [4, btcAddr, numWei, weiPerSatoshi, expiry2, expSender, txHash, expSender]

        assert 2 == self.c.reserveTicket(2, txHash, nonce[2], sender=tester.k0)
        assert self.c.getTicketIDs() == [4, 3, 2, 1]
        assert self.c.lookupTicket(2) == [2, btcAddr, numWei, weiPerSatoshi, expiry2, expSender, txHash, expSender]

    def testCancelTicket(self):
        btcAddr = 9
        numWei = self.ETHER
        weiPerSatoshi = 8

        assert self.c.getTicketIDs() == []

        assert 1 == self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei)
        assert 2 == self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei)
        assert 3 == self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei)
        assert 4 == self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei)
        assert 5 == self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei)

        assert self.c.getTicketIDs() == [5, 4, 3, 2, 1]
        assert 5 == self.c.getLastTicketId()

        assert 3 == self.c.cancelTicket(3)
        assert self.c.getTicketIDs() == [5, 4, 2, 1]

        assert 5 == self.c.cancelTicket(5)
        assert self.c.getTicketIDs() == [4, 2, 1]

        assert 1 == self.c.cancelTicket(1)
        assert self.c.getTicketIDs() == [4, 2]

        assert 2 == self.c.cancelTicket(2)
        assert self.c.getTicketIDs() == [4]

        assert 4 == self.c.cancelTicket(4)
        assert self.c.getTicketIDs() == []

        assert 0 == self.c.getLastTicketId()
        assert 1 == self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei)
        assert 2 == self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei)
        assert self.c.getTicketIDs() == [2, 1]

        assert 2 == self.c.cancelTicket(2)
        assert self.c.getTicketIDs() == [1]

        assert 1 == self.c.cancelTicket(1)
        assert self.c.getTicketIDs() == []

        assert 0 == self.c.getLastTicketId()
        assert 1 == self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei)
        assert 2 == self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei)
        assert self.c.getTicketIDs() == [2, 1]

    def testCancelLastTickets(self):
        btcAddr = 9
        numWei = self.ETHER
        weiPerSatoshi = 8

        assert self.c.getTicketIDs() == []

        assert 1 == self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei)
        assert 2 == self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei)
        assert 3 == self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei)
        assert 4 == self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei)
        assert 5 == self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei)

        assert self.c.getTicketIDs() == [5, 4, 3, 2, 1]
        assert 5 == self.c.cancelTicket(5)
        assert self.c.getTicketIDs() == [4, 3, 2, 1]
        assert 4 == self.c.cancelTicket(4)
        assert self.c.getTicketIDs() == [3, 2, 1]
        assert 3 == self.c.cancelTicket(3)
        assert self.c.getTicketIDs() == [2, 1]
        assert 2 == self.c.cancelTicket(2)
        assert self.c.getTicketIDs() == [1]
        assert 1 == self.c.cancelTicket(1)
        assert self.c.getTicketIDs() == []

        assert 0 == self.c.getLastTicketId()
        assert 1 == self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei)
        assert 2 == self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei)
        assert self.c.getTicketIDs() == [2, 1]

    def testCancelFirstTickets(self):
        btcAddr = 9
        numWei = self.ETHER
        weiPerSatoshi = 8

        assert self.c.getTicketIDs() == []

        assert 1 == self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei)
        assert 2 == self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei)
        assert 3 == self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei)
        assert 4 == self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei)
        assert 5 == self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei)

        assert self.c.getTicketIDs() == [5, 4, 3, 2, 1]
        assert 1 == self.c.cancelTicket(1)
        assert self.c.getTicketIDs() == [5, 4, 3, 2]
        assert 2 == self.c.cancelTicket(2)
        assert self.c.getTicketIDs() == [5, 4, 3]
        assert 3 == self.c.cancelTicket(3)
        assert self.c.getTicketIDs() == [5, 4]
        assert 4 == self.c.cancelTicket(4)
        assert self.c.getTicketIDs() == [5]
        assert 5 == self.c.cancelTicket(5)
        assert self.c.getTicketIDs() == []

        assert 0 == self.c.getLastTicketId()
        assert 1 == self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei)
        assert 2 == self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei)
        assert self.c.getTicketIDs() == [2, 1]

    # test Create Lookup Reserve ticket
    #
    # the sender is always the coinbase so that the gas for reserveTicket does not
    # affect calculations of the balance after reserveTicket: using the coinbase
    # seems to be a special case with tester
    def testCLRTicket(self):
        btcAddr = 9
        numWei = self.ETHER
        weiPerSatoshi = 8

        expExpiry = self.s.block.timestamp + self.TOTAL_RESERVED_SECS
        expSender = int(self.s.block.coinbase.encode('hex'), 16)

        # ticket missing value
        preBal = self.coinbaseBalance()
        assert 0 == self.c.createTicket(btcAddr, numWei, weiPerSatoshi)
        postBal = self.coinbaseBalance()
        assert postBal == preBal

        res = self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei, profiling=True)
        print('GAS: ' + str(res['gas']))
        assert res['output'] == 1
        assert numWei == self.s.block.get_balance(self.c.address)

        assert 2 == self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei)
        assert 2 * numWei == self.s.block.get_balance(self.c.address)

        assert self.c.lookupTicket(0) == []
        assert self.c.lookupTicket(1) == [1, btcAddr, numWei, weiPerSatoshi, 1, 0, 0, expSender]
        assert self.c.lookupTicket(2) == [2, btcAddr, numWei, weiPerSatoshi, 1, 0, 0, expSender]
        assert self.c.lookupTicket(3) == []
        assert self.c.lookupTicket(100) == []
        assert self.c.lookupTicket(-1) == []

        # ticket insufficient value sent, value should be refunded
        preBal = self.coinbaseBalance()
        contractBalance = self.s.block.get_balance(self.c.address)
        assert 0 == self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei - 1)
        assert self.s.block.get_balance(self.c.address) == contractBalance
        postBal = self.coinbaseBalance()
        assert postBal == preBal

        txHash = 0x141e4ea2fa3c9bf9984d03ff081d21555f8ccc7a528326cea96221ca6d476566
        nonceForTicket1 = 2089206
        nonceForTicket2 = 680495

        # invalid PoW
        preBal = self.coinbaseBalance()
        assert self.RESERVE_FAIL_POW == self.c.reserveTicket(1, txHash, 0)
        assert self.RESERVE_FAIL_POW == self.c.reserveTicket(2, txHash, 1)
        postBal = self.coinbaseBalance()
        assert postBal == preBal

        # invalid PoW
        preBal = self.coinbaseBalance()
        assert self.RESERVE_FAIL_POW == self.c.reserveTicket(2, txHash, -1)
        postBal = self.coinbaseBalance()
        assert postBal == preBal

        # valid PoW
        preBal = self.s.block.get_balance(self.s.block.coinbase)
        assert 2 == self.c.reserveTicket(2, txHash, nonceForTicket2, sender=tester.k0)
        postBal = self.coinbaseBalance()
        assert postBal == preBal
        assert self.c.lookupTicket(2) == [2, btcAddr, numWei, weiPerSatoshi, expExpiry, expSender, txHash, expSender]

        # valid PoW
        preBal = self.coinbaseBalance()
        assert 1 == self.c.reserveTicket(1, txHash, nonceForTicket1)
        postBal = self.coinbaseBalance()
        assert postBal == preBal
        assert self.c.lookupTicket(1) == [1, btcAddr, numWei, weiPerSatoshi, expExpiry, expSender, txHash, expSender]

        # valid PoW, but ticketId2 still reserved
        preBal = self.coinbaseBalance()
        assert self.RESERVE_FAIL_UNRESERVABLE == self.c.reserveTicket(2, txHash, nonceForTicket2)
        postBal = self.coinbaseBalance()
        assert postBal == preBal
        assert self.c.lookupTicket(2) == [2, btcAddr, numWei, weiPerSatoshi, expExpiry, expSender, txHash, expSender]

        # valid PoW and previous ticketId2 reservation has expired
        preBal = self.coinbaseBalance()
        self.s.block.timestamp += self.TOTAL_RESERVED_SECS + 1
        timePreReserve = self.s.block.timestamp
        assert 2 == self.c.reserveTicket(2, txHash, nonceForTicket2)
        postBal = self.coinbaseBalance()
        assert postBal == preBal
        expExpiry = timePreReserve + self.TOTAL_RESERVED_SECS
        assert self.c.lookupTicket(2) == [2, btcAddr, numWei, weiPerSatoshi, expExpiry, expSender, txHash, expSender]

        # close but not yet expired
        self.s.block.timestamp += self.TOTAL_RESERVED_SECS
        preBal = self.coinbaseBalance()
        assert self.RESERVE_FAIL_UNRESERVABLE == self.c.reserveTicket(2, txHash, nonceForTicket2)
        postBal = self.coinbaseBalance()
        assert postBal == preBal
        assert self.c.lookupTicket(2) == [2, btcAddr, numWei, weiPerSatoshi, expExpiry, expSender, txHash, expSender]

        # expired reservation can now be reserved
        self.s.block.timestamp += 100
        timePreReserve = self.s.block.timestamp
        preBal = self.coinbaseBalance()
        assert 2 == self.c.reserveTicket(2, txHash, nonceForTicket2)
        postBal = self.coinbaseBalance()
        assert postBal == preBal
        expExpiry = timePreReserve + self.TOTAL_RESERVED_SECS
        assert self.c.lookupTicket(2) == [2, btcAddr, numWei, weiPerSatoshi, expExpiry, expSender, txHash, expSender]

    # offer is 1.7 ETH for 0.0017 BTC; buyer states zero fee
    def testBalances(self):
        # testnet block 447771
        txBlockHash = 0x000000007971768c5a88699e5cf20cad19d2404d16bbd6d3305824b131f6b3f5
        txStr = ('0100000001c6e4ac5a14c1fa273d1511248d504522afc04b6af805c8c8732c9a26c3ee6c54010000008c493046022100b1a346052813d4e141c92d5f60107a61a24134205876'
                 'b88d86917cac4f423732022100dda77724092d1ed746f583c80315e316fd5081805b35a83d88a394bd1f8eafc4014104858527cb6bf730cbd1bcf636bc7e77bbaf0784b9428e'
                 'c5cca2d8378a0adc75f5ca893d14d9db2034cbb7e637aacf28088a68db311ff6f1ebe6d00a62fed9951effffffff0210980200000000001976a914a0dc485fc3ade71be5e1b6'
                 '8397abded386c0adb788ac10270000000000001976a914cd2a3d9f938e13cd947ec05abc7fe734df8dd82688ac00000000')
        txHash = 0x558231b40b5fdddb132f9fcc8dd82c32f124b6139ecf839656f4575a29dca012
        nonce = 1997185
        txIndex = 8
        sibling = [0x6155584c5555baf187ac6e409a3278de39a02a1020871ec034044c13f27dc3cd]
        satoshiOutputOne = 170000
        satoshiOutputTwo = 10000

        btcAddr = 0xa0dc485fc3ade71be5e1b68397abded386c0adb7
        numWei = 1700000000000000000
        weiPerSatoshi = 10000000000000
        ethAddrStr = 'cd2a3d9f938e13cd947ec05abc7fe734df8dd826'

        MOCK_VERIFY_TX_ONE = self.s.abi_contract('./tests/mock_verifyTxReturnsOne.se')
        self.c.setTrustedBtcRelay(MOCK_VERIFY_TX_ONE.address)
        assert self.contractBalance() == 0

        ticketId = self.c.createTicket(btcAddr, numWei, weiPerSatoshi, value=numWei, sender=tester.k2)
        assert ticketId == 1
        assert self.contractBalance() == numWei

        claimer = tester.k1
        addrClaimer = tester.a1

        claimerBalPreReserve = self.s.block.get_balance(addrClaimer)
        res = self.c.reserveTicket(ticketId, txHash, nonce, sender=claimer, profiling=True)
        # print('GAS: '+str(res['gas']))
        assert res['output'] == 1
        assert self.contractBalance() == numWei
        assert self.s.block.get_balance(ethAddrStr.decode('hex')) == 0

        approxCostOfReserve = res['gas']
        boundedCostOfReserve = int(1.05 * approxCostOfReserve)
        balPreClaim = self.s.block.get_balance(addrClaimer)
        assert balPreClaim < claimerBalPreReserve - approxCostOfReserve
        assert balPreClaim > claimerBalPreReserve - boundedCostOfReserve

        eventArr = []
        self.s.block.log_listeners.append(lambda x: eventArr.append(self.c._translator.listen(x)))

        balPreClaim = self.s.block.get_balance(addrClaimer)
        claimRes = self.c.claimTicket(ticketId, txStr, txHash, txIndex, sibling, txBlockHash, sender=claimer, profiling=True)
        # print('GAS claimTicket() ', claimRes['gas'])
        assert claimRes['output'] == ticketId
        assert self.contractBalance() == 0

        claimerFeePercent = (satoshiOutputTwo % 10000) / 10000.0
        assert claimerFeePercent == 0
        feeToClaimer = int(claimerFeePercent * numWei)  # int() is needed

        # gas from profiling claimTicket() is inaccurate so assert that the
        # balance is within 2.4X of approxCostToClaim
        # TODO why 2.4X ?
        approxCostToClaim = claimRes['gas']
        boundedCostToClaim = int(2.4 * approxCostToClaim)

        endClaimerBal = self.s.block.get_balance(addrClaimer)
        assert endClaimerBal < balPreClaim + feeToClaimer - approxCostToClaim
        assert endClaimerBal > balPreClaim + feeToClaimer - boundedCostToClaim

        assert endClaimerBal < claimerBalPreReserve + feeToClaimer - approxCostToClaim - approxCostOfReserve
        assert endClaimerBal > claimerBalPreReserve + feeToClaimer - boundedCostToClaim - boundedCostOfReserve

        indexOfBtcAddr = txStr.find(format(btcAddr, 'x'))
        ethAddrBin = txStr[indexOfBtcAddr + 68:indexOfBtcAddr + 108].decode('hex')  # assumes ether addr is after btcAddr
        assert ethAddrStr.decode('hex') == ethAddrBin
        buyerEthBalance = self.s.block.get_balance(ethAddrBin)

        assert buyerEthBalance == (1 - claimerFeePercent) * numWei

        self.assertClaimSuccessLogs(eventArr, satoshiOutputOne, btcAddr, int(ethAddrStr, 16), satoshiOutputTwo, ticketId)

        # re-claim is not allowed
        claimRes = self.c.claimTicket(ticketId, txStr, txHash, txIndex, sibling, txBlockHash, sender=claimer, profiling=True)
        # print('GAS claimTicket() ', claimRes['gas'])
        assert claimRes['output'] == self.CLAIM_FAIL_INVALID_TICKET

        assert eventArr == [{
            '_event_type': 'ticketEvent',
            'ticketId': ticketId,
            'rval': self.CLAIM_FAIL_INVALID_TICKET  # a claimed ticket no longer exists
        }]
        eventArr.pop()

    # actor/user/claimer balance (as opposed to contract's balance)
    def coinbaseBalance(self):
        return self.s.block.get_balance(self.s.block.coinbase)

    def contractBalance(self):
        return self.s.block.get_balance(self.c.address)
