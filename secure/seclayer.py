from playground.network.common import StackingProtocol, StackingTransport, StackingProtocolFactory
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, STRING, BUFFER, BOOL, LIST
from playground.network.packet.fieldtypes.attributes import Optional
import os, hashlib, logging, asyncio, random
from . import cert_factory

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM 

#from OpenSSL import crypto


logger = logging.getLogger('playground.__connector__.' + __name__)

class PLSPacket(PacketType):
    DEFINITION_IDENTIFIER = 'PLS.Packet'
    DEFINITION_VERSION = '1.0'
    FIELDS = [
     ('Type', STRING), # type can be Hello, KeyTransport, Finished, Data and Close.
     ('Premaster_Secret', BUFFER({Optional:True})),
     ('Random', BUFFER({Optional:True})),
     ('Certificate', LIST(BUFFER, {Optional:True})),
     ('Encrypted_Data', BUFFER)
     ]

    @classmethod
    def HelloPacket(cls, random, mychain):
        pkt = cls()
        pkt.Type = "Hello"
        pkt.Random = random 
        pkt.Certificate = mychain 
        pkt.Encrypted_Data = b""
        print("<><><><> SENT Hello Packet <><><><>")
        return pkt


    @classmethod
    def KeyPacket(cls, random):
      pkt = cls()
      pkt.Type = "KeyTransport"
      pkt.Premaster_Secret = random # need to sort it out
      #pkt.Random = random #This too
      #pkt.Certificate = PLSCertificate #Should send a list
      pkt.Encrypted_Data = b""

      print("<><><><> SENT Key Packet <><><><>")
      return pkt


    @classmethod
    def FinPacket(cls):
        pkt = cls()
        pkt.Type = "Finished"
        #pkt.Premaster_Secret = "" # need to sort it out
        #pkt.Random = "" #This too
        #pkt.Certificate = "" #Should send a list
        pkt.Encrypted_Data = b""
        print("<><><><> SENT Finished Packet <><><><>")
        return pkt

    @classmethod
    def ClosePacket(cls):
        pkt = cls()
        pkt.Type = "Close"
        #pkt.Premaster_Secret = "" # need to sort it out
        #pkt.Random = 0 #This too
        #pkt.Certificate = "" #Should send a list
        pkt.Encrypted_Data = b""
        print("<><><><> SENT Close Packet <><><><>")
        return pkt

    @classmethod
    def DataPacket(cls, encrypted_data):
        pkt = cls()
        pkt.Type = "Data"
        #pkt.Premaster_Secret = "" # need to sort it out
        #pkt.Random = 0 #This too
        #pkt.Certificate = "" #Should send a list
        pkt.Encrypted_Data = encrypted_data
        print("<><><><> SENT Data Packet <><><><>")
        return pkt

class PLSTransport(StackingTransport):
    def __init__(self, protocol, lower_transport):
        super().__init__(lower_transport)
        self.protocol = protocol
        self.closed = False

    def write(self, data):
        self.protocol.sendEncData(data)
        pass


    def close(self):   # Closing the connection check
        if self.closed:
            return
        self.closed = True
        self.protocol.higherProtocol().connection_lost(None)
        self.protocol.close()

class PLSProtocol(StackingProtocol):

  def connection_made(self, transport):
    self.transport = transport
    self.plspacket = PLSPacket()
    self.deserializer = self.plspacket.Deserializer()

    self.sent_rand = b'0' #random.getrandbits(32)
    self.recv_rand = b'0'
    self.pmk = 0
    self.recv_pmk = 0
    self.state = None
    self.pubkey = None
    self.recv_cert = None
    self.masterkey = None
    self.mychain = []
    self.mykey = None
    self.peername = None
    self.count = 0

    self.SER_LISTEN = 100
    self.SER_HELLO_SENT = 102
    self.SER_PMK_SENT = 103
    self.SER_EST = 104

    self.CLI_HELLO_SENT = 202
    self.CLI_PMK_SENT = 203
    self.CLI_FIN_SENT = 204
    self.CLI_EST = 205

  def sendEncData(self,data):
    counter = self.getcounter()
    
    if "2" in str(self.state):
      aesgcm = AESGCM(self.client_write_key)
      nonce = self.client_iv
      nonce = nonce + counter
      enc_data = aesgcm.encrypt(nonce, data, None)
      
      pkt = PLSPacket.DataPacket(enc_data)
      self.transport.write(pkt.__serialize__())

    else:
      aesgcm = AESGCM(self.server_write_key)
      nonce = self.server_iv
      nonce = nonce + counter
      enc_data = aesgcm.encrypt(nonce, data, None)
      
      pkt = PLSPacket.DataPacket(enc_data)
      self.transport.write(pkt.__serialize__())

  def recvEncData(self,data):
    
    counter = self.getcounter()
    
    if "2" in str(self.state):
      aesgcm = AESGCM(self.server_write_key)
      nonce = self.server_iv
      nonce = nonce + counter
      data = aesgcm.decrypt(nonce, data, None)
      
      return data
      

    else:
      aesgcm = AESGCM(self.client_write_key)
      nonce = self.client_iv
      nonce = nonce + counter
      data = aesgcm.decrypt(nonce, data, None)
      
      return data
      

  def sendHello(self):
    rand = self.GenRandom()
    self.sent_rand = rand
    

    if self.state == self.SER_LISTEN:
      #path = "/home/nits/trusted_certs/bank_cert.cert"

      pkt = PLSPacket.HelloPacket(self.sent_rand, self.mychain)
      self.transport.write(pkt.__serialize__())
      self.state = self.SER_HELLO_SENT

    else:
      pkt = PLSPacket.HelloPacket(self.sent_rand, self.mychain)
      self.transport.write(pkt.__serialize__())
      self.state = self.CLI_HELLO_SENT

  def mycert(self,mykey,mychain,peername):
    self.mykey = mykey
    self.mychain = mychain
    self.peername = peername


  def sendPmk(self, pmk = 0):
    if pmk == 0:
      self.pmk = self.Genpmk()
      
    else:
      self.pmk = pmk
    
    encrypt_pmk = self.pubkey.encrypt(self.pmk, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    print(encrypt_pmk)
    if self.state == self.CLI_HELLO_SENT:
      pkt = PLSPacket.KeyPacket(encrypt_pmk)
      
      self.transport.write(pkt.__serialize__())

      self.state = self.CLI_PMK_SENT
    else:
      pkt = PLSPacket.KeyPacket(encrypt_pmk)
      
      self.transport.write(pkt.__serialize__())
      self.state = self.SER_PMK_SENT

  def sendFin(self):
    if "2" in str(self.state):
      """data = 
      aesgcm = AESGCM(self.client_write_key)
      nounce = self.client_iv
      enc_data = aesgcm.encrypt(nonce, data, aad)
      return enc_data"""
      pkt = PLSPacket.FinPacket()
      self.transport.write(pkt.__serialize__())
      self.state = self.CLI_FIN_SENT

    else:
      """data = 
      aesgcm = AESGCM(self.server_write_key)
      nounce = self.server_iv
      enc_data = aesgcm.encrypt(nonce, data, aad)
      return enc_data"""
     
      pkt = PLSPacket.FinPacket()
      self.transport.write(pkt.__serialize__())


  def recvPmk(self, encrypt_pmk):
    if self.state == self.SER_HELLO_SENT:
      private_key = self.mykey
      print(encrypt_pmk)
      self.recv_pmk = private_key.decrypt(encrypt_pmk, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
      print(str(self.recv_pmk))
      self.sendPmk(self.recv_pmk)
      self.KDF()

    else:
      private_key = self.mykey
      self.recv_pmk = private_key.decrypt(encrypt_pmk, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),label=None))

      if self.pmk == self.recv_pmk:
        self.KDF()


  def GenRandom(self):
    self.rand = str(random.getrandbits(32))
    return self.rand.encode()

  def Genpmk(self):
    pmk = str(random.getrandbits(32))
    return pmk.encode()

  def getcounter(self):
    out = self.count
    #print(self.count)
    out = str(bin(out)[2:])
    while len(out) < 4:
      out = "0" + out
    #print(out)
    
    self.count = self.count + 1
    
    if self.count >=15:
      self.count = 0
    return out.encode()

  def verify_cert(self,buff):
    #return True
    if len(buff) == 3:
      cert_buffer = []
      flag = False
      for cert in buff:
        cert_buffer.append(x509.load_pem_x509_certificate(cert, default_backend()))

      #addr_CN = cert_buffer[0].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
      #if self.peername != addr_CN:
      #  return False

      for i in range(0,1):
        issuer = cert_buffer[i].issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        issuer = issuer.split(".")
        subject = cert_buffer[i+1].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        subject = subject.split(".")

        if issuer == subject:
          flag = True

      if flag == True:
        return True
      else:
        return False
    else:
      return False



  def ProcessCert(self,cert):
    cert = x509.load_pem_x509_certificate(cert, default_backend())
    self.pubkey = cert.public_key()
    self.recv_cert = cert
    self.pubkey = self.recv_cert.public_key()
    

  def KDF(self):
        print (self.sent_rand)
        print (self.recv_rand)
        if "2" in str(self.state):
          print("Client kdf")
          self.masterkey = self.sent_rand
          self.masterkey += self.recv_rand #self.server_rand
        else:
          print("Server kdf")
          self.masterkey = self.recv_rand #self.server_rand
          self.masterkey += self.sent_rand

        #print(self.masterkey)
        self.masterkey += self.pmk
        #print(self.masterkey)
        kdf = HKDF(algorithm = hashes.SHA256(), salt = b'', info=None, length= 48, backend= default_backend())
        gen = kdf.derive(self.masterkey)
        #print("<><><><><><><> "+ str(gen)+ "<><><><><><><><><><>")

        self.client_write_key = gen[0:16]
        self.server_write_key = gen[16:32]
        self.client_iv = gen[32:40]
        self.server_iv = gen[40:48]

        if "2" in str(self.state):
          self.sendFin()
    

  def data_received(self,data):
    self.deserializer.update(data)
    for pkt in self.deserializer.nextPackets():

      if pkt.Type == "Hello" and self.state == self.SER_LISTEN:
        # Call for certificate verification
        cert = pkt.Certificate
        print(str(cert))
        if(self.verify_cert(cert)):
          self.recv_rand = pkt.Random
          
          self.ProcessCert(cert[0])
          self.sendHello()
          #self.state = SER_HELLO_SENT

      elif pkt.Type == "Hello" and self.state == self.CLI_HELLO_SENT:
        # Do something else process the packet and prepare for session key
        cert = pkt.Certificate
        if(self.verify_cert(cert)):
          self.recv_rand = pkt.Random
          self.ProcessCert(cert[0])
          
          self.sendPmk() # Send PMK

      elif pkt.Type == "KeyTransport" and self.state == self.SER_HELLO_SENT:
        encrypt_pmk = pkt.Premaster_Secret
        self.recvPmk(encrypt_pmk) #decrypt the packet
        # store the premaster key
        #send Pmk to client signed with clients public key

      elif pkt.Type == "KeyTransport" and self.state == self.CLI_PMK_SENT:
        encrypt_pmk = pkt.Premaster_Secret
        self.recvPmk(encrypt_pmk)# decrypt with private key
        #check if the session key remained same as sent
        #Prepare tp sent fin

      elif pkt.Type == "Finished" and self.state == self.SER_PMK_SENT:
        self.sendFin()
        self.state = self.SER_EST #Call server connection made of higher protocol
        print("ESTABLISHED")
        self.higherProtocol().connection_made(PLSTransport(self, self.transport))

      elif pkt.Type == "Finished" and self.state == self.CLI_FIN_SENT:
        self.state = self.CLI_EST
        print("ESTABLISHED")
        self.higherProtocol().connection_made(PLSTransport(self, self.transport)) #call client higher protocol

      elif pkt.Type == "Data" and self.state == self.SER_EST:
        print("I AM HERE!!!")
        data = self.recvEncData(pkt.Encrypted_Data)
        print(data)
        self.higherProtocol().data_received(data)

      elif pkt.Type == "Data" and self.state == self.CLI_EST:
        data = self.recvEncData(pkt.Encrypted_Data)
        print(data)
        self.higherProtocol().data_received(data)

  def sendClose(self):
    pass

class PLSClientProtocol(PLSProtocol):

  def connection_made(self, transport):
    super().connection_made(transport)
    address, port = transport.get_extra_info("sockname")
    mykey, mychain = cert_factory.get_credentials(address)
    peeraddress = transport.get_extra_info("peername")[0]
    self.mycert(mykey,mychain,peeraddress)
    self.sendHello()

class PLSServerProtocol(PLSProtocol):

  def connection_made(self, transport):
    super().connection_made(transport)
    address, port = transport.get_extra_info("sockname")
    mykey, mychain = cert_factory.get_credentials(address)
    peeraddress = transport.get_extra_info("peername")[0]
    self.mycert(mykey,mychain,peeraddress)
    self.state = self.SER_LISTEN
    


PLSClientFactory = StackingProtocolFactory.CreateFactoryType(PLSClientProtocol)
PLSServerFactory = StackingProtocolFactory.CreateFactoryType(PLSServerProtocol)
