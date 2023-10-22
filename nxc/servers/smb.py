import threading
from threading import enumerate
from sys import exit
from impacket import smbserver
from nxc.logger import nxc_logger


class NXCSMBServer(threading.Thread):
    def __init__(
        self,
        logger,
        share_name,
        share_path="/tmp/nxc_hosted",
        listen_address="0.0.0.0",
        listen_port=445,
        verbose=False,
    ):
        try:
            threading.Thread.__init__(self)
            self.server = smbserver.SimpleSMBServer(listen_address, listen_port)
            self.server.addShare(share_name.upper(), share_path)
            if verbose:
                self.server.setLogFile("")
            self.server.setSMB2Support(True)
            self.server.setSMBChallenge("")
        except Exception as e:
            errno, message = e.args
            if errno == 98 and message == "Address already in use":
                nxc_logger.error("Error starting SMB server on port 445: the port is already in use")
            else:
                nxc_logger.error(f"Error starting SMB server on port 445: {message}")
                exit(1)

    def run(self):
        try:
            self.server.start()
        except Exception as e:
            nxc_logger.debug(f"Error starting SMB server: {e}")

    def shutdown(self):
        # TODO: should fine the proper way
        # make sure all the threads are killed
        for thread in enumerate():
            if thread.is_alive():
                try:
                    self._stop()
                except Exception as e:
                    nxc_logger.debug(f"Error stopping SMB server: {e}")
