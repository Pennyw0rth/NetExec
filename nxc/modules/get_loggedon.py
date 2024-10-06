from impacket.dcerpc.v5 import transport, wkst

class NXCModule:
	"""
	-------
	Module by @aniqfakhrul
	Query logged on users via NetrWkstaUserEnum (requires admin privileges)
	"""

	name = "get_loggedon"
	description = "Query logged on users"
	supported_protocols = ["smb"]
	opsec_safe = True
	multiple_hosts = True

	def __init__(self, context=None, module_options=None):
		self.context = context
		self.module_options = module_options
		self.method = None

	def options(self, context, module_options):
		pass

	def on_admin_login(self, context, connection):
		host = connection.host
		domain_name = connection.domain
		username = connection.username
		password = getattr(connection, "password", "")
		lmhash = getattr(connection, "lmhash", "")
		nthash = getattr(connection, "nthash", "")

		obj = GetLoggedOn(context)
		target = connection.host if not connection.kerberos else connection.hostname + "." + connection.domain
		dce = obj.connect(
			username=connection.username,
			password=connection.password,
			domain=connection.domain,
			lmhash=connection.lmhash,
			nthash=connection.nthash,
			target=target,
			doKerberos=connection.kerberos,
			dcHost=connection.kdcHost,
			aesKey=connection.aesKey,
			port=445
		)
		users = obj.lookup(dce)
		for user in users:
			context.log.highlight("%s\\%s" % (user[0], user[1]))

class GetLoggedOn:
	KNOWN_PROTOCOLS = {
		139: {'bindstr': r'ncacn_np:%s[\pipe\wkssvc]'},
		445: {'bindstr': r'ncacn_np:%s[\pipe\wkssvc]'},
	}

	
	def __init__(self, context):
		self.context = context

	def connect(self, username, password, domain, lmhash, nthash, aesKey, target, doKerberos, dcHost, port=445):
		stringbinding = self.KNOWN_PROTOCOLS[port]['bindstr'] % target

		rpctransport = transport.DCERPCTransportFactory(stringbinding)
		rpctransport.set_dport(port)

		if hasattr(rpctransport, "set_credentials"):
			rpctransport.set_credentials(
				username=username,
				password=password,
				domain=domain,
				lmhash=lmhash,
				nthash=nthash,
				aesKey=aesKey,
			)

		if doKerberos:
			rpctransport.set_kerberos(doKerberos, kdcHost=dcHost)

		rpctransport.setRemoteHost(target)
		dce = rpctransport.get_dce_rpc()
		try:
			dce.connect()
		except Exception as e:
			self.context.log.debug(f"Something went wrong, check error status => {e!s}")
			return None
		try:
			dce.bind(wkst.MSRPC_UUID_WKST)
		except Exception as e:
			self.context.log.debug(f"Something went wrong, check error status => {e!s}")
			return None
		self.context.log.debug("Successfully bound!")
		return dce

	def lookup(self, dce):
		users = set()
		resp = wkst.hNetrWkstaUserEnum(dce, 1)
		for i in resp['UserInfo']['WkstaUserInfo']['Level1']['Buffer']:
			if i['wkui1_username'][-2] == '$':
				continue
			# Can refer here https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wkst/c37b9606-866f-40ac-9490-57b8334968e2 for structure details
			users.add((
				i['wkui1_logon_domain'][:-1],
				i['wkui1_username'][:-1],
				i['wkui1_oth_domains'][:-1],
				i['wkui1_logon_server'][:-1])
			)
		return users