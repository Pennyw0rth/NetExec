from nxc.helpers.misc import CATEGORY
from impacket.examples.secretsdump import RemoteOperations
from impacket.dcerpc.v5 import rrp
import json


class NXCModule:
    """
    Module by @qu35t_tv
    """

    name = "wsus_enum"
    description = "Check the WSUS configuration to determine if it is vulnerable to WSUS spoofing"
    supported_protocols = ["winrm", "smb"]
    category = CATEGORY.ENUMERATION

    def __init__(self):
        self.server = None
        self.results = {
            'WUServer': None,                         # WSUS server URL
            'WUStatusServer': None,                   # Status server URL
            'UseWUServer': None,                      # WSUS enforced by GPO
            'NoAutoUpdate': None,                     # Disable auto update
            'AUOptions': None,                        # Update install mode
            'ScheduledInstallDay': None,              # Planned install day
            'ScheduledInstallTime': None,             # Planned install time
            'RescheduleWaitTime': None,               # Delay before retry
            'DetectionFrequency': None,               # Detection interval
            'DetectionFrequencyEnabled': None,        # Enable detection interval
            'NoAutoRebootWithLoggedOnUsers': None,    # Prevent reboot if user logged
            'LastSuccessTime': None,                  # Last successful update check
            'NextDetectionTime': None,                # Next scheduled detection
        }

    def options(self, context, module_options):
        """No options for now"""
        return {}

    _PS_ENUM_SCRIPT = r"""
    $result = @{}

    $paths = @{
      'Policies'   = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
      'PoliciesAU' = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
      'Client'     = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate'
      'ClientAuto' = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update'
    }

    foreach ($k in $paths.Keys) {
      $p = $paths[$k]
      $obj = @{}
      if (Test-Path $p) {
        try {
          $props = Get-ItemProperty -Path $p -ErrorAction Stop
          foreach ($name in $props.PSObject.Properties.Name) {
            $val = $props.$name
            $obj[$name] = $val
          }
        } catch {
          $obj['error'] = $_.Exception.Message
        }
      } else {
        $obj['present'] = $false
      }
      $result[$k] = $obj
    }

    $json = $result | ConvertTo-Json -Depth 5
    Write-Output $json
    """

    def _rrp_query(self, remote_ops, subkey, value_name):
        try:
            ans = rrp.hOpenLocalMachine(remote_ops._RemoteOperations__rrp)
            hklm = ans['phKey']
            ans = rrp.hBaseRegOpenKey(remote_ops._RemoteOperations__rrp, hklm, subkey)
            key = ans['phkResult']
            _type, data = rrp.hBaseRegQueryValue(remote_ops._RemoteOperations__rrp, key, value_name)
            return data
        except Exception:
            return None

    def _smb_collect(self, context, connection):
        remote_ops = RemoteOperations(connection.conn, False)
        remote_ops.enableRegistry()

        q = lambda subkey, name: self._rrp_query(remote_ops, subkey, name)

        # Policies
        self.results['WUServer'] = q(r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", "WUServer")
        self.results['WUStatusServer'] = q(r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", "WUStatusServer")
        self.results['UseWUServer'] = q(r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "UseWUServer")
        self.results['NoAutoUpdate'] = q(r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate")
        self.results['AUOptions'] = q(r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "AUOptions")
        self.results['ScheduledInstallDay'] = q(r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "ScheduledInstallDay")
        self.results['ScheduledInstallTime'] = q(r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "ScheduledInstallTime")
        self.results['RescheduleWaitTime'] = q(r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "RescheduleWaitTime")
        self.results['DetectionFrequency'] = q(r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "DetectionFrequency")
        self.results['DetectionFrequencyEnabled'] = q(r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "DetectionFrequencyEnabled")
        self.results['NoAutoRebootWithLoggedOnUsers'] = q(r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoRebootWithLoggedOnUsers")
        self.results['LastSuccessTime'] = q(r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update", "LastSuccessTime")
        self.results['NextDetectionTime'] = q(r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update", "NextDetectionTime")

    def _winrm_collect(self, context, connection):
        out = connection.execute(self._PS_ENUM_SCRIPT, get_output=True, shell_type="powershell")
        if not out:
            context.log.debug("PowerShell returned no output")
            return False

        out = out.strip().lstrip("\ufeff")  # strip BOM if present
        try:
            obj = json.loads(out)
        except Exception:
            start = out.find('{')
            if start != -1:
                obj = json.loads(out[start:])
            else:
                context.log.error("Failed to parse PowerShell JSON output")
                return False

        def get_prop(section, name):
            return obj.get(section, {}).get(name)

        self.results.update({
            'WUServer': get_prop('Policies', 'WUServer'),
            'WUStatusServer': get_prop('Policies', 'WUStatusServer'),
            'UseWUServer': get_prop('PoliciesAU', 'UseWUServer'),
            'NoAutoUpdate': get_prop('PoliciesAU', 'NoAutoUpdate'),
            'AUOptions': get_prop('PoliciesAU', 'AUOptions'),
            'ScheduledInstallDay': get_prop('PoliciesAU', 'ScheduledInstallDay'),
            'ScheduledInstallTime': get_prop('PoliciesAU', 'ScheduledInstallTime'),
            'RescheduleWaitTime': get_prop('PoliciesAU', 'RescheduleWaitTime'),
            'DetectionFrequency': get_prop('PoliciesAU', 'DetectionFrequency'),
            'DetectionFrequencyEnabled': get_prop('PoliciesAU', 'DetectionFrequencyEnabled'),
            'NoAutoRebootWithLoggedOnUsers': get_prop('PoliciesAU', 'NoAutoRebootWithLoggedOnUsers'),
            'LastSuccessTime': get_prop('ClientAuto', 'LastSuccessTime'),
            'NextDetectionTime': get_prop('ClientAuto', 'NextDetectionTime'),
        })
        return True

    def _post_assess(self, context):
        def _to_int(v):
            try:
                return int(v)
            except Exception:
                return None

        wus = self.results.get('WUServer')
        use_wus = _to_int(self.results.get('UseWUServer'))

        is_http = isinstance(wus, str) and wus.lower().startswith("http://")
        is_used = (use_wus == 1)

        # Log all results first
        for k, v in self.results.items():
            if v is None:
                context.log.info(f"{k}: <not present>")
            else:
                context.log.success(f"{k}: {v}")

        # Vulnerability banner / reason
        if wus and is_http and is_used:
            context.log.debug("Target is vulnerable to WSUS Spoofing")
            context.log.highlight("VULNERABLE, WSUS Spoofing")
        else:
            if not wus:
                reason = "no custom WSUS configured"
            elif not is_http:
                reason = "WSUS uses HTTPS"
            elif use_wus != 1:
                reason = "WSUS not enforced"
            else:
                reason = "conditions not met"
            context.log.fail(f"Target is not vulnerable to WSUS Spoofing ({reason})")
            return

    def on_login(self, context, connection):
        """
        - If protocol is SMB and admin, use SMB/RemoteRegistry (RRP).
        - If protocol is SMB and NOT admin, stop.
        - If protocol is WinRM, use WinRM/PowerShell.
        """
        if "smb" in context.protocol:
            if connection.admin_privs:
                try:
                    self._smb_collect(context, connection)
                except Exception as e:
                    context.log.error(f"SMB registry read failed: {e}")
                    return
                self._post_assess(context)
                return
            else:
                context.log.fail("Only admin can use this module over SMB")
                return

        if "winrm" in context.protocol:
            try:
                ok = self._winrm_collect(context, connection)
                if not ok:
                    return
            except Exception as e:
                context.log.error(f"WinRM collection failed: {e}")
                return

        self._post_assess(context)
