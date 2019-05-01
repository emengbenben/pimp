import random
import asyncio
import sys

from packets import RequestTransferToClient, RequestAdmission, ProofOfPayment, PaymentResult,RequestGameResult
from packets import RequestGame, GameRequest, GameResponse
import getpass, os, playground
from OnlineBank import BankClientProtocol
from OnlineBankConfig import OnlineBankConfig
from playground.network.packet import PacketType
from playground.common.CipherUtil import loadCertFromFile, RSA_SIGNATURE_MAC
from BankCore import LedgerLineStorage, LedgerLine

input_queue = []
output_queue = []

class PaymentProcessing:
    def __init__(self):
        self._bankconfig = OnlineBankConfig()
        # TODO: This is hard coded. It needs to be changed to be part of the ini
        bank_certPath = os.path.join(self._bankconfig.path(), "bank.cert")
        self._bank_cert = loadCertFromFile(bank_certPath)
        self._tokens  = {}
        
    def set_src_account(self, src_account):
        """This is not async. should be called before loop starts or in executor"""
        self._login_name = input("Enter bank login name for account {}: ".format(src_account))
        self._password   = getpass.getpass("Password: ")
        self._src_account = src_account

    def createAdmissionRequest(self, amount):
        if self._src_account == None :
            raise Exception("Not properly configured.")
        token = int.from_bytes(os.urandom(4), byteorder="big")
        req_admission = RequestAdmission(
            account= self._src_account,
            amount = amount,
            token  = token
        )
        self._tokens[ token ] = "WAITING"
        return req_admission

    def _verifyReceiptSignature(self, receipt, signature):
        verifier = RSA_SIGNATURE_MAC(self._bank_cert.public_key())
        return verifier.verify(receipt, signature)
        
    def _verifyReceipt(self, receipt, expected_token):
        ledger_line = LedgerLineStorage.deserialize(receipt)
        memo = ledger_line.memo(self._src_account)
        if str(memo) != str(expected_token):
            return "Mismatching token in memo (expected {} got {})".format(
                expected_token,
                memo)
        amount = ledger_line.getTransactionAmount(self._src_account)
        """
        if amount != self._price:
            return "Mismatching amount (expected {} got {})".format(
                self._price,
                amount)
        """
        return "Verified"
        
        
    def process(self, token, receipt, signature):
        if token in self._tokens:
            del self._tokens[token]
            if not self._verifyReceiptSignature(receipt, signature):
                return "Signature failed"
            return self._verifyReceipt(receipt, token)
        return "Unknown Token"
        
    async def make_payment(self, dst_account, amount, memo):
        loop = asyncio.get_event_loop()
        bank_addr = self._bankconfig.get_parameter("CLIENT","bank_addr")
        bank_port = int(self._bankconfig.get_parameter("CLIENT","bank_port"))
        print("Connect to bank {}:{} for payment.".format(bank_addr, bank_port))
        transport, protocol = await playground.create_connection(
            lambda: BankClientProtocol(self._bank_cert, self._login_name, self._password),
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

async def async_get_input(prompt):
    print(prompt, end="")
    sys.stdout.flush()
    while len(input_queue) == 0:
        await asyncio.sleep(.1)
    return input_queue.pop(0)

def stdin_reader():
    line_in = sys.stdin.readline()
    input_queue.append(line_in[:-1])
    
class HomepageClientProtocol(asyncio.Protocol):
    def __init__(self):
        self._buffer = PacketType.Deserializer()
        self._token = None
        #self.message = message
        #self.loop = loop
        
    def connection_made(self, transport):
        #transport.write(self.message.encode())
        self.transport = transport
        self.transport.write(RequestGame().__serialize__())
        print("request game sent")
        
    def connection_lost(self, transport):
        loop = asyncio.get_event_loop()
        # 1 second to shut everything down.
        loop.call_later(1, loop.stop)
        
    def data_received(self, data):

        self._buffer.update(data)
        for packet in self._buffer.nextPackets():
            print("Client got", packet)

            if isinstance(packet, RequestTransferToClient):
                req = global_payment_processor.createAdmissionRequest(packet.amount)
                self.transport.write(req.__serialize__())

            elif isinstance(packet, RequestGameResult):
                print("Starting game.")
                asyncio.ensure_future(self.get_gncasino_input())

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

                    response = PaymentResult(
                        token=   packet.token,
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
                    #print("Starting game.")
                    #asyncio.ensure_future(self.get_gncasino_input())
            elif isinstance(packet, GameResponse):
                print(packet.response)
                if packet.status != "6":
                    asyncio.ensure_future(self.get_gncasino_input())
                else: 
                    print("Quit!")

    async def pay_for_admission(self, dst_account, amount, token):
        
        result = await global_payment_processor.make_payment(dst_account, amount, token)
        if result == None:
            self.transport.close()
            return False
        
        proof = ProofOfPayment(
            token    =self._token,
            receipt  =result.Receipt, 
            signature=result.ReceiptSignature)
        
        self.transport.write(proof.__serialize__())
        return True
    
    async def response(self):
        while not self.server_response:
            await asyncio.sleep(.1)
        r = self.server_response
        self.server_response = None
        return r
    
    async def get_gncasino_input(self):
        command = await async_get_input(">> ")
        cmd = GameRequest(command=command)
        self.transport.write(cmd.__serialize__())
        
if __name__=="__main__":
    import sys, argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("account")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("-p", "--port", default=5657)
    args = parser.parse_args(sys.argv[1:])
    host, port = args.host, args.port
    port = int(port) 
    # this will ask for login name and password for bank for this account
    # but it doesn't actually log in yet.
    global_payment_processor.set_src_account(args.account)
    loop = asyncio.get_event_loop()
    coro = playground.create_connection(HomepageClientProtocol, host=host, port=port)
    transport, protocol = loop.run_until_complete(coro)
    print("connected",protocol,transport)
    loop.add_reader(sys.stdin, stdin_reader)
    loop.run_forever()
    loop.close()
