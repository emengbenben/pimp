import playground
from .pimp import PIMPServerFactory, PIMPClientFactory
from .protocol import PLSRoastClient, PLSRoastServer
from playground.network.common import StackingProtocolFactory

pimpConnector = playground.Connector(protocolStack=(PIMPClientFactory(), PIMPServerFactory()))
playground.setConnector("pimp", pimpConnector)
playground.setConnector("lab1_GoldenNuggetNetSec2019", pimpConnector)

pimpConnector = playground.getConnector("pimp")
pimpClientType = pimpConnector.getClientStackFactory()
pimpServerType = pimpConnector.getServerStackFactory()

PlsClientFactory = StackingProtocolFactory.CreateFactoryType(pimpClientType, PLSClientProtocol)
PlsServerFactory = StackingProtocolFactory.CreateFactoryType(pimpServerType, PLSServerProtocol)

plsConnector = playground.Connector(protocolStack=(PlsClientFactory(),PlsServerFactory()))
playground.setConnector("pls_roast", plsConnector)
