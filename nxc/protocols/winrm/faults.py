"""WS-Management fault matching.

The same fault arrives in two shapes depending on the service version:
WinRM 3.0+ answers with only the SOAP subcode (a:DestinationUnreachable),
WinRM 2.0 (2008 R2 / Windows 7) additionally embeds a WSManFault element
carrying the numeric Code attribute. pypsrp surfaces the numeric code
when present and the SOAP subcode string otherwise, so a fault has to be
matched against both forms.
"""


def is_fault(e, fault):
    """Whether a caught exception is the given fault, in either shape."""
    return getattr(e, "code", None) in fault or any(form in str(getattr(e, "code", "")) for form in fault if isinstance(form, str))


# the resource URI, its selectors or its namespace do not exist on the
# target (a missing WMI namespace or class answers with this)
FAULT_DESTINATION_UNREACHABLE = {"a:DestinationUnreachable", 2150858752}
