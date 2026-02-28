# Get current user running the SSH session
current_user=$(whoami)

# Enumerate all sessions
loginctl list-sessions --no-legend | while read sid uid seat; do
    # Extract username associated with the session
    user=$(loginctl show-session "$sid" -p Name --value)
    # Skip our own session
    [ "$user" = "$current_user" ] && continue
    # Skip system/service users (uid < 1000, except root)
    uid_val=$(id -u "$user" 2>/dev/null)
    if [ -n "$uid_val" ] && [ "$uid_val" -ne 0 ] && [ "$uid_val" -lt 1000 ]; then
        continue
    fi
    # Extract session type
    type=$(loginctl show-session "$sid" -p Type --value)
    # Extract remote host (empty = local)
    ip=$(loginctl show-session "$sid" -p RemoteHost --value)
    # Determine account origin (local / domain / unknown)
    if getent passwd "$user" >/dev/null 2>&1; then
        if grep -qE "^${user}:" /etc/passwd; then
            origin="local"
        else
            origin="domain"
        fi
    else
        origin="unknown"
    fi
    # Determine privilege level
    if [ "$(id -u "$user" 2>/dev/null)" -eq 0 ] || \
       id -nG "$user" 2>/dev/null | grep -Eq '\b(sudo|wheel|admin|root)\b'; then
        priv="privileged"
    else
        priv="unprivileged"
    fi
    # Output
    echo "$user ($type) from ${ip:-local} [$origin] [$priv]"
done
