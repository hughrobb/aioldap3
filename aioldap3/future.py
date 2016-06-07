import asyncio
import pdb

class FutureResponse:
    def __init__(self, message_id):
        self.message_id = message_id

    def write_response(self, ldap_response):
        raise NotImplementedError
    def full(self):
        return False
    def done(self):
        raise NotImplementedError

class FutureSimpleResponse(asyncio.Future, FutureResponse):
    def __init__(self, message_id):
        asyncio.Future.__init__(self)
        FutureResponse.__init__(self, message_id)

    def write_response(self, ldap_response):
        self.set_result(ldap_response)

class FutureStreamingResponse(FutureResponse):
    def __init__(self, message_id, maxsize=0):
        super().__init__(message_id)
        self.queue = asyncio.Queue(maxsize=maxsize)
    def full(self):
        return self.queue.full()
    def write_response(self, ldap_response):
        self.queue.put_nowait( ldap_response )
    async def __aiter__(self):
        return self
    async def __anext__(self):
        return await self.queue.get()

class FutureSearchResponse(FutureStreamingResponse):
    def __init__(self, message_id):
        super().__init__(message_id)
        self.search_done = False

    def done(self):
        return self.search_done

    def write_response(self, ldap_response):
        if ldap_response[1].chosen.tag == 5:
            self.search_done = True
            self.queue.put_nowait( None )
            return
        super().write_response(ldap_response)

    async def __anext__(self):
        if self.search_done and self.queue.empty():
            logging.info('stop-async-iteration')
            raise StopAsyncIteration
        val = await self.queue.get()
        if val is None:
            raise StopAsyncIteration
        return val


