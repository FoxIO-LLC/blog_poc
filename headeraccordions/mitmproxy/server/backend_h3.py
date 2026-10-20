import asyncio

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent


class Handler(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.h3 = H3Connection(self._quic)

    def quic_event_received(self, event: QuicEvent):
        for h3_event in self.h3.handle_event(event):
            if isinstance(h3_event, HeadersReceived):
                self.h3.send_headers(
                    h3_event.stream_id,
                    [(b":status", b"200"), (b"content-length", b"3")],
                )
                self.h3.send_data(h3_event.stream_id, b"OK\n", end_stream=True)
                self.transmit()


async def main():
    config = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
    config.load_cert_chain("/app/certs/cert.pem", "/app/certs/key.pem")
    print("Backend H3 server listening on 0.0.0.0:4443", flush=True)
    await serve("0.0.0.0", 4443, configuration=config, create_protocol=Handler)
    await asyncio.Future()


asyncio.run(main())
