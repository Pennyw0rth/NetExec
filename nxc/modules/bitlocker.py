import re

class NXCModule:

	name = "bitlocker"
	description = "Enumerating BitLocker Status on target(s) If it is enabled or disabled."
	supported_protocols = ["smb"]
	opsec_safe = True  # only running commands are executed on the remote host for check
	multiple_hosts = True

	def options(self, context, module_options):
		""" """

	def on_admin_login(self, context, connection):
	
		# PowerShell command to check BitLocker volumes status.
		check_bitlocker_command_str = 'powershell.exe "Get-BitLockerVolume | Select-Object MountPoint, ProtectionStatus"'

		try:
			# Executing the PowerShell command to get BitLocker volumes status.
			check_bitlocker_command_str_output = connection.execute(check_bitlocker_command_str, True)
			# Splitting the output into lines.
			lines = check_bitlocker_command_str_output.strip().split("\n")

			# Getting data lines.
			data_lines = lines[2:]

			# Analyzing data lines.
			for line in data_lines:
				parts = re.split(r"\s{2,}", line.strip())  # Stripping spaces and splitting the line.
				MountPoint = parts[0]  # Getting the mount point of the drive.
				protection_status = parts[1]  # Getting the protection status.
				
				# Checking if BitLocker is enabled.
				if protection_status == "On":
					context.log.success(f"BitLocker is enabled on {MountPoint} drive!")
				else:
					context.log.highlight(f"BitLocker is disabled on {MountPoint} drive!")
		except Exception as e:
			context.log.exception(f"Exception occurred: {e}")
