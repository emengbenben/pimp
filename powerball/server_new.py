from Homepage import Homepage 

from packets import RequestTransferToClient, RequestAdmission, ProofOfPayment, PaymentResult
from packets import RequestGame, GameRequest, GameResponse

import asyncio, os, pickle
import sys, getpass, os, playground

from playground.common.CipherUtil import loadCertFromFile, RSA_SIGNATURE_MAC
from BankCore import LedgerLineStorage, LedgerLine
from OnlineBankConfig import OnlineBankConfig

from OnlineBank import BankClientProtocol
from playground.network.packet import PacketType


class PaymentProcessing:
    def __init__(self):
        self._bankconfig = OnlineBankConfig()       
        # TODO: This is hard coded. It needs to be changed to be part of the ini
        certPath = os.path.join(self._bankconfig.path(), "bank.cert")
        
        self._cert = loadCertFromFile(certPath)
        self._account = None
        self._price   = None
        self._total   = 0
        self._tokens  = {}
        
    def configure(self, account, price):
        self._account = account
        self._price   = price
        
    def createAdmissionRequest(self, amount):
        if self._account == None:
            raise Exception("Not properly configured.")
        token = int.from_bytes(os.urandom(4), byteorder="big")
        req_admission = RequestAdmission(
            account=self._account,
            amount = amount,
            token  = token
        )
        self._tokens[ token ] = "WAITING"
        return req_admission
        
    def _verifyReceiptSignature(self, receipt, signature):
        verifier = RSA_SIGNATURE_MAC(self._cert.public_key())
        return verifier.verify(receipt, signature)
        
    def _verifyReceipt(self, receipt, expected_token):
        ledger_line = LedgerLineStorage.deserialize(receipt)
        memo = ledger_line.memo(self._account)
        if str(memo) != str(expected_token):
            return "Mismatching token in memo (expected {} got {})".format(
                expected_token,
                memo)
        amount = ledger_line.getTransactionAmount(self._account)
        if amount != self._price:
            return "Mismatching amount (expected {} got {})".format(
                self._price,
                amount)
        return "Verified"
        
        
    def process(self, token, receipt, signature):
        if token in self._tokens:
            del self._tokens[token]
            if not self._verifyReceiptSignature(receipt, signature):
                return "Signature failed"
            return self._verifyReceipt(receipt, token)
        return "Unknown Token"

    def set_src_account(self, src_account):
        """This is not async. should be called before loop starts or in executor"""
        self._login_name = input("Enter bank login name for account {}: ".format(src_account))
        self._password   = getpass.getpass("Password: ")
        self._src_account = src_account

    async def make_payment(self, dst_account, amount, memo):
        loop = asyncio.get_event_loop()
        bank_addr = self._bankconfig.get_parameter("CLIENT","bank_addr")
        bank_port = int(self._bankconfig.get_parameter("CLIENT","bank_port"))

        print("Connect to bank {}:{} for payment.".format(bank_addr, bank_port))

        transport, protocol = await playground.create_connection(
            lambda: BankClientProtocol(self._cert, self._login_name, self._password),
            bank_addr,
            bank_port)

        try:
            result = await protocol.loginToServer()
        except Exception as e:
            print("Could not log in because", e)
            self.transport.close()
            return None
        try:
            result = await protocol.switchAccount(self._src_account)
            result = await protocol.transfer(dst_account, amount, memo)
        except Exception as e:
            result = None
            print("Could not transfer funds because", e)
        try:
            protocol.close()
        except Exception as e:
            print ("Warning, could not close bank connection because", e)
        return result

global_payment_processor = PaymentProcessing()

class HomepageServerProtocol(asyncio.Protocol):
    def __init__(self):
        self._buffer = PacketType.Deserializer()
        self._token = None
        
    def connection_made(self, transport):
        print("Server connected")
        self.transport = transport

    def data_received(self, data):
        self._buffer.update(data)
        for packet in self._buffer.nextPackets():
            print("Server got", packet)

            if isinstance(packet, RequestGame):
                self.homepage = Homepage()
                self.homepage.start()
                #req = global_payment_processor.createAdmissionRequest(5)
                #self.transport.write(req.__serialize__())

            elif isinstance(packet, RequestAdmission):
                """
                if self._token != None:
                    self.transport.close()
                    raise Exception("Already paid!")
                else:
                """
                self._token = packet.token
                make_payment_coro = self.pay_for_admission(
                    packet.account,
                    packet.amount,
                    packet.token)
                asyncio.ensure_future(make_payment_coro)

            elif isinstance(packet, ProofOfPayment):
                payment_status = global_payment_processor.process(
                    packet.token,
                    packet.receipt, 
                    packet.signature)
                if payment_status == "Verified":
                    self._token = packet.token


                    #self.homepage = Homepage()
                    #self.homepage.start()

                    response = PaymentResult(
                        token=   self._token,
                        accepted=True,
                        message= payment_status)
                    self.transport.write(response.__serialize__())
                else:
                    response = PaymentResult(
                        token=   packet.token,
                        accepted=False,
                        message= payment_status)
                    self.transport.write(response.__serialize__())
                    self.transport.close()

            elif isinstance(packet, PaymentResult):
                if not packet.accepted:
                    print("Payment rejected: ", packet.accepted)
                else:
                    print("Payment accepted.")
                self.transport.close()

            elif isinstance(packet, GameRequest):
                if packet.token != self._token:
                    self.transport.close()
                else:
                    if self.homepage.getSign() == False:
                        response = self.homepage.welcome_narratives()
                        self.homepage.setSign()
                    else:
                        response = self.homepage.input(packet.command)

                    status   = self.homepage.getstatus()
                    game_response = GameResponse(
                        response=response,
                        status  =status)
                    self.transport.write(game_response.__serialize__())
                    if status == "6":
                        if(self.homepage.getcurrency() >= 0):
                            response = "The amount of Bitpoints u earn is " + str(self.homepage.getcurrency())
                            request_transfer = RequestTransferToClient(
                            amount = self.homepage.getcurrency()
                            )
                        else:
                            response = "The amount of Bitpoints u must pay is " + str(0 - self.homepage.getcurrency())
                            #request_transfer = RequestTransferToServer(
                            #amount = 0 - self.homepage.getcurrency())

                        status   = self.homepage.getstatus()
                        game_response = GameResponse(
                            response = response,
                            status = status)
                        self.transport.write(game_response.__serialize__())

                        if(self.homepage.getcurrency() >= 0):
                            self.transport.write(request_transfer.__serialize__())
                            print("Request transfer sent")
                        else:
                            req = global_payment_processor.createAdmissionRequest(0 - self.homepage.getcurrency())
                            self.transport.write(req.__serialize__())

                        
                        #self.transport.close()

    async def pay_for_admission(self, dst_account, amount, token):
        
        result = await global_payment_processor.make_payment(dst_account, amount, token)
        if result == None:
            self.transport.close()
            return False
        
        proof = ProofOfPayment(
            token    = self._token,
            receipt  = result.Receipt, 
            signature= result.ReceiptSignature)
        
        self.transport.write(proof.__serialize__())
        return True
              


if __name__=="__main__":
    import sys, argparse
    #from playground.common.logging import EnablePresetLogging, PRESET_DEBUG
    #EnablePresetLogging(PRESET_DEBUG)
    
    parser = argparse.ArgumentParser()
    parser.add_argument("account")
    parser.add_argument("-p", "--port", default=5679)
    parser.add_argument("--price", default = 5)
    
    args = parser.parse_args(sys.argv[1:])
    global_payment_processor.configure(args.account, int(args.price))
    global_payment_processor.set_src_account(args.account)
    
    loop = asyncio.get_event_loop()
    coro = playground.create_server(HomepageServerProtocol, host='20191.2.10.1', port=args.port)
    server = loop.run_until_complete(coro)

    
    # Serve requests until Ctrl+C is pressed
    print('Serving on {}'.format(server.sockets[0].getsockname()))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    # Close the server
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
