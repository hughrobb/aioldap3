#!/usr/bin/env python

import asyncio
from aioldap3.client import LDAPClient
import logging, argparse, sys

async def foo(loop, host, port):
  c = LDAPClient()
  await loop.create_connection(lambda:c, host, port)
  result = await c.bind('cn=Hugh,ou=People', 'Silly password')
  logging.info(result.native)
  async for result in c.search('ou=People', '(&(objectClass=person)(cn=*es*))', attributes='cn givenName sn'.split()):
    logging.info(result.native)
  logging.info('search done')
  await c.starttls()
  async for result in c.search('ou=People', '(&(objectClass=person)(cn=*es*))', attributes='cn givenName sn'.split()):
    logging.info(result.native)
  logging.info('closing')
  c.close()
  await c.wait_closed()
  logging.info('done')

logging.basicConfig(level=logging.DEBUG)

parser = argparse.ArgumentParser()
parser.add_argument('host', default='127.0.0.1', nargs='?')
parser.add_argument('port', type=int, default=1389, nargs='?')

args = parser.parse_args()

loop = asyncio.get_event_loop()
loop.set_debug(True)
loop.run_until_complete( foo(loop, args.host, args.port) )
