import asyncio
import logging
import aioldap3.wire.rfc4511 as rfc4511
from asn1crypto.core import _parse_build
import pdb

class LDAPProtocol(asyncio.Protocol):
    def __init__(self, version=3):
        self.version = version
        self._buf = bytes()
        self.transport = None
        self.tlssession = None
        self.closed_waiter = None

    def connection_made(self, transport):
        logging.info('connexion made')
        self.transport = transport

    def connection_lost(self, ex):
        if self.closed_waiter:
            self.closed_waiter.set_result(ex)
        if ex:
            raise ex

    def close(self):
        self.transport.close()
        self.closed_waiter = asyncio.Future()

    async def wait_closed(self):
        await self.closed_waiter

    def data_received(self, data):
        buf, p = self._buf + data, 0
        while p < len(buf):
            ldap_message, consumed = _parse_build( buf, pointer=p, spec=rfc4511.LDAPMessage )
            if ldap_message is None:
                break

            self.message_received( ldap_message )
            p += consumed

        if p > 0:
            self._buf = buf[p:]

    def send(self, ldap_message):
        self.transport.write( ldap_message.dump() )

    def message_received(self, ldap_msg):
        raise NotImplementedError

