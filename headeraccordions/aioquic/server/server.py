import argparse
import asyncio
import logging
import resource
import sys

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived, H3Event
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated, QuicEvent


def peak_rss_mb():
    usage = resource.getrusage(resource.RUSAGE_SELF)
    if sys.platform == "darwin":
        return usage.ru_maxrss / (1024 * 1024)
    return usage.ru_maxrss / 1024


class Server(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = None
        self._count = 0

    def http_event_received(self, event: H3Event):
        if isinstance(event, HeadersReceived):
            self._count += 1
            logging.warning(
                "request=%d headers=%d peak_rss=%.1fMB",
                self._count,
                len(event.headers),
                peak_rss_mb(),
            )
            self._http.send_headers(
                stream_id=event.stream_id,
                headers=[(b":status", b"200")],
            )
            self._http.send_data(
                stream_id=event.stream_id, data=b"ok\n", end_stream=True
            )
            self.transmit()

    def quic_event_received(self, event: QuicEvent):
        if isinstance(event, ProtocolNegotiated):
            if event.alpn_protocol in H3_ALPN:
                self._http = H3Connection(self._quic)
        if self._http is not None:
            for http_event in self._http.handle_event(event):
                self.http_event_received(http_event)


async def main(host, port, cert, key):
    configuration = QuicConfiguration(
        alpn_protocols=H3_ALPN,
        is_client=False,
        max_datagram_frame_size=65536,
    )
    configuration.load_cert_chain(cert, key)
    await serve(
        host,
        port,
        configuration=configuration,
        create_protocol=Server,
    )
    await asyncio.Future()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=4433)
    parser.add_argument("--cert", default="cert.pem")
    parser.add_argument("--key", default="key.pem")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main(args.host, args.port, args.cert, args.key))
