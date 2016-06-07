import asyncio, ssl
from asyncio.sslproto import SSLProtocol
import logging

from .protocol import LDAPProtocol
from .future import FutureSimpleResponse, FutureSearchResponse
import aioldap3.wire.rfc4511 as rfc4511

from ldap3.core.exceptions import LDAPExtensionError

class LDAPClient(LDAPProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)    
        self._sequence = 0     # FIXME
        self._getters = dict()

    def bind(self, user, password, controls=None):
        msg = self.make_message()
        request = rfc4511.BindRequest()
        request[0] = 3
        request[1] = user.encode('utf8')
        request[2] = rfc4511.AuthenticationChoice('simple', password.encode('utf8'))
        msg[1] = rfc4511.ProtocolOp('bindRequest', request)
        self.send(msg)
        return self.make_future( FutureSimpleResponse, msg )

    def search(self,
        search_base,
        search_filter,
        search_scope=2,     # subtree
        dereference_aliases=3,  # deref-always
        attributes=None,
        size_limit=0,
        time_limit=0,
        types_only=False,
        get_operational_attributes=False,
        controls=None,
        paged_size=None,
        paged_criticality=False
    ):
        msg = self.make_message()
        request = rfc4511.SearchRequest()
        request[0] = search_base.encode('utf8')
        request[1] = search_scope
        request[2] = dereference_aliases
        request[3] = size_limit
        request[4] = time_limit
        request[5] = types_only
        kv = rfc4511.AttributeValueAssertion()
        kv[0], kv[1] = b'cn', b'hugh'
        request[6] = rfc4511.Filter('equalityMatch', kv)
        request[7] = rfc4511.AttributeSelection(value=b'cn givenName sn'.split())
        msg[1] = rfc4511.ProtocolOp('searchRequest', request)
        self.send(msg)
        return self.make_future( FutureSearchResponse, msg )

    def extend(self, request_name, request_value=None, controls=None):
        msg = self.make_message()
        request = rfc4511.ExtendedRequest()
        request[0] = request_name.encode('utf8')
        if request_value is not None:
            request[1] = request_value.encode('utf8')
        msg[1] = rfc4511.ProtocolOp('extendedReq', request)
        self.send(msg)
        return self.make_future( FutureSimpleResponse, msg )

    def make_message(self):
        self._sequence += 1
        msg = rfc4511.LDAPMessage()
        msg[0] = self._sequence
        return msg
   
    def make_future(self, future_factory, ldap_message):
        message_id = int(ldap_message[0])
        future = future_factory( message_id )
        self._getters[ message_id ] = future
        return future

    def message_id_overflowed(self, future, ldap_response):
        self.transport.pause_reading()
        future.set_resume_reading_callback( lambda: self.can_resume_reading(future, ldap_response) )

    def can_resume_reading(self, future, ldap_message):
        future.write_response( ldap_message )
        self.transport.resume_reading()

    def message_received(self, ldap_message):
        message_id = int(ldap_message[0])

        # unsolicited messages
        if message_id == 0:
            logging.warn('unsolicited message {}'.format(ldap_message))
            return

        # route message to getter
        future = self._getters.get( message_id, None )
        if future is None:
            logging.warn('message without getter {}'.format(ldap_message))
            return

        if future.full():
            self.message_id_overflowed( future, ldap_message )
            return

        future.write_response( ldap_message )
        if future.done():
            del self._getters[ future.message_id ]

    async def starttls(self):
        if self._getters:
            raise LDAPExceptionError('cannot start tls while any operations are active.')
        response = await self.extend( '1.3.6.1.4.1.1466.20037' )
        if int(response[1].chosen[0]) != 0:
            raise LDAPExtensionError( response )
        future = asyncio.Future()
        sslcontext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        self.tlssession = SSLProtocol( loop=self.transport._loop, app_protocol=self, sslcontext=sslcontext, waiter=future, server_side=False, server_hostname=None )
        self.transport._protocol = self.tlssession
        self.tlssession.connection_made( self.transport )
        return (await future)


