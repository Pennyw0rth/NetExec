#!/usr/bin/env python3
import json
import socket
from os import makedirs
from certipy.commands.find import Find
from certipy.lib.target import Target, DnsResolver
from certipy.lib.formatting import pretty_print
from datetime import datetime

from nxc.helpers.misc import CATEGORY
from nxc.paths import NXC_PATH


class NXCModule:
    """Module made by: @NeffIsBack, @gatariee"""
    name = "certipy-find"
    description = "certipy find command with options to export the result to text/csv/json. Default: Show only vulnerable templates"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options(self, context, module_options):
        """
        VULN        Show only vulnerable configurations (Default: True)
        ENABLED     Show only enabled templates

        Export options:
        TEXT        Export results to a plain text file
        CSV         Export results to a CSV file
        JSON        Export results to a JSON file
        """
        self.vuln = True
        self.enabled = False
        self.output_path = f"{NXC_PATH}/modules/certipy-find"
        self.json = False
        self.csv = False
        self.text = False

        if "VULN" in module_options:
            self.vuln = module_options["VULN"].lower() in ["true", "1", "yes"]
        if "ENABLED" in module_options:
            self.enabled = module_options["ENABLED"].lower() in ["true", "1", "yes"]

        # Export options
        if "JSON" in module_options:
            self.json = module_options["JSON"].lower() in ["true", "1", "yes"]
        if "CSV" in module_options:
            self.csv = module_options["CSV"].lower() in ["true", "1", "yes"]
        if "TEXT" in module_options:
            self.text = module_options["TEXT"].lower() in ["true", "1", "yes"]

    def on_login(self, context, connection):
        dns_server = connection.args.dns_server
        if not dns_server:
            try:
                # If connection.host is an IP, use it as DNS
                socket.inet_aton(connection.host)
                dns_server = connection.host
            except Exception:
                # Otherwise let DnsResolver use system resolver (None)
                dns_server = None

        resolv = DnsResolver.create(dns_server)

        # prefer connection.hostname if present, otherwise connection.host
        remote = (connection.hostname or connection.host) or ""
        remote = (f"{remote}.{connection.domain}".lower() if "." not in remote else remote.lower()) if connection.domain else remote.lower()

        target = Target(
            resolver=resolv,
            domain=connection.domain,
            username=connection.username,
            password=connection.password,
            remote_name=connection.remoteName,
            lmhash=connection.lmhash,
            nthash=connection.nthash,
            do_kerberos=connection.kerberos,
            target_ip=connection.host,
            ldap_port=connection.port,
            ldap_scheme="ldaps" if connection.port == 636 else "ldap",
            ldap_signing=connection.signing_required,
            ldap_channel_binding=connection.cbt_status in ["Always", "When Supported"],
        )

        finder = Find(
            target=target,
            json=self.json,
            csv=self.csv,
            text=self.text,
            output_path=self.output_path,
            stdout=True,
            vulnerable=self.vuln,
            enabled=self.enabled,
        )

        # Get templates and CAs
        templates = finder.get_certificate_templates()
        cas = finder.get_certificate_authorities()
        finder._link_cas_and_templates(cas, templates)

        # Get OIDs
        oids = finder.get_issuance_policies()

        # Process information
        finder._link_templates_and_policies(templates, oids)
        finder._process_ca_properties(cas)
        finder._process_template_properties(templates)

        output = finder.get_output_for_text_and_json(templates, cas, oids)
        pretty_print(output, print_func=context.log.highlight)

        # Save to disk if any export option specified
        if self.json or self.csv or self.text:
            makedirs(self.output_path, exist_ok=True)

        filename = f"certipy_{connection.hostname}_{connection.host}_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}".replace(":", "-")
        if self.json:
            with open(f"{self.output_path}/{filename}.json", "w") as f:
                json.dump(
                    output,
                    f,
                    indent=2,
                    default=str,
                )
        if self.csv:
            template_output = finder.get_template_output_for_csv(output)
            ca_output = finder.get_ca_output_for_csv(output)
            with open(f"{self.output_path}/{filename}-templates.csv", "w") as f:
                f.write(template_output)
            with open(f"{self.output_path}/{filename}-cas.csv", "w") as f:
                f.write(ca_output)
        if self.text:
            with open(f"{self.output_path}/{filename}.txt", "w") as f:
                pretty_print(output, print_func=lambda x: f.write(x + "\n"))
