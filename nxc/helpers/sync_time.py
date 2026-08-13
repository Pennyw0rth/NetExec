from socket import socket, AF_INET, SOCK_DGRAM
from struct import unpack
from datetime import datetime, timezone
from freezegun import freeze_time

from nxc.logger import nxc_logger


def sync_and_spoof(ntp_server: str):
    """
    Tries to fetch the time from ntp_server and uses
    freezegun to set this time as the internal clock
    application wide.

    Just patching impacket.krb5.kerberosv5.sendReceive would be
    cleaner, however, as we would need to freeze each previous and
    future import, each import would have its own ticking clock.
    """
    try:
        nxc_logger.debug(f"Trying to fetch time from {ntp_server}")
        timestamp = get_time_from_ntp_server(server=ntp_server)
    except Exception as e:
        nxc_logger.error(f"Got error while fetchting time: {e}")
        nxc_logger.warning("Could not fetch time, skipping time spoofing")
        return

    nxc_logger.debug(f"Got time {timestamp} from NTP server, setting fake internal clock")
    try:
        freezer = freeze_time(timestamp, tick=True)
        freezer.start()
    except Exception as e:
        nxc_logger.error(f"Got error while setting internal clock using freeze_time: {e}")
        return


def get_time_from_ntp_server(server: str, port=123) -> str:
    """
    Fetches the time from server using just socket

    Based on:
    https://www.mattcrampton.com/blog/query_an_ntp_server_from_python/
    """
    buf = 1024
    address = (server, port)
    msg = "\x1b" + 47 * "\0"

    TIME1970 = 2208988800  # 1970-01-01 00:00:00

    client = socket(AF_INET, SOCK_DGRAM)
    client.sendto(msg.encode("utf-8"), address)
    msg, address = client.recvfrom(buf)
    t = unpack("!12I", msg)[10]
    t -= TIME1970

    return datetime.fromtimestamp(t, tz=timezone.utc).isoformat()
