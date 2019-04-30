from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import BOOL, STRING, UINT16, UINT32, BUFFER

class RequestGame(PacketType):
    DEFINITION_IDENTIFIER = "samples.GNgame.RequestGame"
    DEFINITION_VERSION = "1.0"
    FIELDS = []

class RequestTransferToClient(PacketType):
    DEFINITION_IDENTIFIER = "samples.GNgame.RequestTransferToClient"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("amount",  UINT16)
    ]

class RequestTransferToServer(PacketType):
    DEFINITION_IDENTIFIER = "samples.GNgame.RequestTransferToServer"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("amount",  UINT16)
    ]

class RequestAdmission(PacketType):
    DEFINITION_IDENTIFIER = "samples.GNgame.RequestAdmission"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("account", STRING),
        ("amount",  UINT16),
        ("token",   UINT32)
    ]
    
class ProofOfPayment(PacketType):
    DEFINITION_IDENTIFIER = "samples.GNgame.ProofOfPayment"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("token",     UINT32),
        ("receipt",   BUFFER),
        ("signature", BUFFER)
    ]
    
class PaymentResult(PacketType):
    DEFINITION_IDENTIFIER = "samples.GNgame.PaymentResult"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("token",    UINT32),
        ("accepted", BOOL),
        ("message",  STRING)
        ]
    
class GameRequest(PacketType):
    DEFINITION_IDENTIFIER = "samples.GNgame.GameRequest"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("token",   UINT32),
        ("command", STRING)
    ]
    
class GameResponse(PacketType):
    DEFINITION_IDENTIFIER = "samples.GNgame.GameResponse"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("response", STRING),
        ("status",   STRING)
    ]
