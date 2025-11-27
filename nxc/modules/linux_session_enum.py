from nxc.helpers.misc import CATEGORY


class NXCModule:
    name = "linux_session_enum"
    description = (
        "Enumerate interactive users currently logged into the remote Linux system"
    )
    supported_protocols = ["ssh"]
    category = CATEGORY.ENUMERATION
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """No module options required."""
        pass

    def on_login(self, context, connection):
        # Execute the script on the remote Linux machine (requires loginctl)
        cmd = r"""
current_user=$(whoami)
loginctl list-sessions --no-legend | while read sid uid seat; do
    user=$(loginctl show-session "$sid" -p Name --value)
    [ "$user" = "$current_user" ] && continue
    uid_val=$(id -u "$user" 2>/dev/null)
    if [ "$uid_val" != "" ] && [ "$uid_val" -ne 0 ] && [ "$uid_val" -lt 1000 ]; then
        continue
    fi
    type=$(loginctl show-session "$sid" -p Type --value)
    ip=$(loginctl show-session "$sid" -p RemoteHost --value)
    if getent passwd "$user" >/dev/null 2>&1; then
        if grep -E "^${user}:" /etc/passwd >/dev/null 2>&1; then
            origin="local"
        else
            origin="domain"
        fi
    else
        origin="unknown"
    fi
    if [ "$(id -u "$user" 2>/dev/null)" -eq 0 ] || \
       id -nG "$user" 2>/dev/null | grep -Eq '\b(sudo|wheel|admin|root)\b'; then
        priv="privileged"
    else
        priv="unprivileged"
    fi
    echo "$user ($type) from ${ip:-local} [$origin] [$priv]"
done
"""

        output = connection.execute(cmd)
        # Display results
        if output is None:
            context.log.error("Command failed or returned no output.")
            return

        if not output.strip():
            context.log.display("No active session found.")
            return

        context.log.success("Active sessions:")
        for line in output.splitlines():
            context.log.highlight(line.strip())
