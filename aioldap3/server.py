import asyncio, ssl, logging
from asyncio.sslproto import SSLProtocol
from .protocol import LDAPProtocol
from .future import FutureSimpleResponse, FutureSearchResponse
import aioldap3.wire.rfc4511 as rfc4511
from asn1crypto.core import _parse_build

from ldap3 import ANONYMOUS, SIMPLE, SASL, NTLM, SUBTREE, DEREF_ALWAYS
from ldap3.core.exceptions import LDAPExtensionError

class ClientProtocol(LDAPProtocol):
    def __init__(self, server=None):
        super().__init__()
        self.server = server

    async def starttls(self):
        future = asyncio.Future()
        self.transport.resume_reading()
        sslcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        sslcontext.load_cert_chain('cert.pem')
        self.tlssession = SSLProtocol( loop=self.transport._loop, app_protocol=self, sslcontext=sslcontext, waiter=future, server_side=True, server_hostname='localhost' )
        self.transport._protocol = self.tlssession
        self.tlssession.connection_made( self.transport )
        await future

    def make_attribute_list(self, *args):
        hr = rfc4511.PartialAttributeList()
        for k,v in args:
            k = rfc4511.AttributeDescription(k)
            v = rfc4511.AttributeValue(v)
            attr = rfc4511.PartialAttribute()
            attr[0] = k
            attr[1] = rfc4511.SetOfAttributeValue(value=[v])
            hr.append( attr )
        return hr

class ServiceClient(ClientProtocol):
    dispatch_table = {
        0: lambda self,msg: self.bind_request_received(msg),
        3: lambda self,msg: self.search_request_received(msg),
       23: lambda self,msg: self.extended_request_received(msg),
    }

    def connection_made(self, transport):
        super().connection_made(transport)
        if self.server:
            self.server.connection_made( self )

    def message_received(self, ldap_message):
        dispatch = self.dispatch_table.get( ldap_message[1].chosen.tag, None )
        if not dispatch:
            logging.warn( 'no dispatcher' )
            return 
        dispatch( self, ldap_message )

    def connection_lost(self, ex):
        if self.server:
            self.server.connection_lost( self, ex )
        super().connection_lost(ex)

from weakref import proxy

class LDAPService:
    def __init__(self, client_class=ServiceClient):
        self.clients = set()
        self.client_class = client_class

    def accept(self):
        return self.client_class(proxy(self))

    def connection_made(self, client):
        logging.debug( 'connexion from {}'.format( client.transport.get_extra_info('peername') ) )
        self.clients.add( client )

    def connection_lost(self, client, ex):
        self.clients.discard( client )


