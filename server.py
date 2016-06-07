#!/usr/bin/env python

import asyncio
import logging
from aioldap3.server import LDAPService, ServiceClient
import aioldap3.wire.rfc4511 as rfc4511

logging.basicConfig(level=logging.DEBUG)

i = 0
class MyServiceClient(ServiceClient):
    def bind_request_received(self, ldap_message):
        logging.info( 'bindRequest' )
        msg = rfc4511.LDAPMessage()
        msg[0] = ldap_message[0]
        response = rfc4511.BindResponse()
        response[0] = rfc4511.ResultCode(0)
        response[1] = ldap_message[1].chosen[1]
        response[2] = b''
        msg[1] = rfc4511.ProtocolOp('bindResponse', response)
        self.send( msg )

    def search_request_received(self, ldap_message):
        global i
        logging.info( 'searchRequest' )
        for i in range(i, i+10):
            msg = rfc4511.LDAPMessage()
            msg[0] = ldap_message[0]
            response = rfc4511.SearchResultEntry()
            response[0] = 'cn={}'.format(i).encode('utf8')
            response[1] = self.make_attribute_list(
                (b'cn',str(i).encode('utf8')), 
                (b'givenName','Jane{}'.format(i).encode('utf8')), 
            )
            msg[1] = rfc4511.ProtocolOp('searchResEntry', response)
            self.send( msg )
        i += 1

        msg = rfc4511.LDAPMessage()
        msg[0] = ldap_message[0]
        response = rfc4511.SearchResultDone()
        response[0] = rfc4511.ResultCode(0)
        response[1] = b''
        response[2] = b''
        msg[1] = rfc4511.ProtocolOp('searchResDone', response)
        self.send( msg )

    def extended_request_received(self, ldap_message):
        logging.info('extendedRequest')

        request = ldap_message[1].chosen
        name, value = request[0].native, request[1].native

        msg = rfc4511.LDAPMessage()
        msg[0] = ldap_message[0]
        response = rfc4511.ExtendedResponse()
        response[1] = b''
        response[2] = b''
        msg[1] = rfc4511.ProtocolOp('extendedResp', response)
        if name == b'1.3.6.1.4.1.1466.20037':
            response[0] = rfc4511.ResultCode(0)
            self.transport.pause_reading()
            self.send( msg )
            self.tlssession = asyncio.ensure_future( self.starttls() )
            return

        response[0] = rfc4511.ResultCode(12)
        self.send( msg )

loop = asyncio.get_event_loop()
loop.set_debug(True)
service = LDAPService(MyServiceClient)
server  = loop.run_until_complete( loop.create_server( lambda: service.accept(), '127.0.0.1', 1389 ) )

try:
    loop.run_forever()
except KeyboardInterrupt:
    pass

server.close()
loop.run_until_complete(server.wait_closed())
loop.close()

