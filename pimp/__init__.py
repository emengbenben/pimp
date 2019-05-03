import playground
from .pimp import PIMPServerFactory, PIMPClientFactory

pimpConnector = playground.Connector(protocolStack=(PIMPClientFactory(), PIMPServerFactory()))
playground.setConnector("pimp", pimpConnector)
playground.setConnector("lab1_GoldenNuggetNetSec2019", pimpConnector)
