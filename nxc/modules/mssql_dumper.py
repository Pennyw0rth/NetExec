#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# MSSQL Dumper v1 - Created by LTJAX
import json
import os
import datetime
import re

class NXCModule:

    name = 'mssql_dumper'
    description = "Search for Sensitive Data across all the databases"
    supported_protocols = ['mssql']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        '''
        SEARCH       Semicolon-separated regex(es) to search for in **Cell Values**
        LIKE_SEARCH  Comma-separated list of column names to specifically look for
        SAVE         Save the output to sqlite database (default True)
        '''
        regex_input = module_options.get("REGEX", "")
        self.regex_patterns = []
        for pattern in regex_input.split(';'):
            pattern = pattern.strip()
            if pattern:
                try:
                    self.regex_patterns.append(re.compile(pattern))
                except re.error as e:
                    context.log.fail(f"[!] Invalid regex pattern '{pattern}': {e}")
        like_input = module_options.get("LIKE_SEARCH", "")
        self.like_search = [s.strip().lower() for s in like_input.split(',') if s.strip()]
        self.save = module_options.get("SAVE", "true").lower() == "true"
        pass

    def pii(self):
        return [
    'username',
    'user_name',
    'email',
    'first_name',
    'last_name',
    'full_name',
    'dob',
    'date_of_birth',
    'ssn',
    'social_security_number',
    'passport_number',
    'national_id',
    'phone',
    'phone_number',
    'phonenumber',
    'address',
    'city',
    'state',
    'zip',
    'zipcode',
    'password',
    'passwd',
    'passwd_hash',
    'password_hash',
    'password_salt',
    'token',
    'auth_token',
    'session_token',
    'session',
    'api_key',
    'mfa_secret',
    'security_question',
    'credit_card_number',
    'cc_number',
    'card_number',
    'cardholder_name',
    'cvv',
    'cvv2',
    'expiration_date',
    'expiry_date',
    'billing_address',
    'iban',
    'account_number',
    'routing_number',
    'payment_token',
    'medical_record',
    'patient_id',
    'diagnosis',
    'treatment',
    'insurance_number',
    'tax_id',
    'tin',
    'ein',
    'contract_number',
    'salary',
    'compensation',
    'middle_name',
    'nickname',
    'maiden_name',
    'gender',
    'birth_date',
    'ssn_hash',
    'nin',
    'drivers_license',
    'dl_number',
    'street',
    'house_number',
    'apartment',
    'region',
    'country',
    'location',
    'email_address',
    'alt_email',
    'mobile',
    'fax',
    'password_plaintext',
    'old_password',
    'user_pass',
    'user_password',
    'user_token',
    'refresh_token',
    'secret_key',
    'otp_secret',
    'security_pin',
    'security_answer',
    'security_code',
    'creditcard',
    'credit_card',
    'credit_card_hash',
    'credit_card_expiry',
    'cc_exp_month',
    'cc_exp_year',
    'card_exp',
    'debit_card',
    'ccv',
    'bic',
    'bank_account',
    'bank_name',
    'bank_code',
    'bank_id',
    'paypal_email',
    'invoice_id',
    'invoice_total',
    'order_id',
    'order_total',
    'order_amount',
    'payment_status',
    'employee_id',
    'position',
    'job_title',
    'employment_status',
    'income',
    'annual_salary',
    'legal_name',
    'legal_entity',
    'blood_type',
    'allergies',
    'prescriptions',
    'health_id',
    'insurance_id',
    'medication',
    'emergency_contact',
    'pin',
    'pin_code',
    'user_secret',
    'login_token',
    'reset_token',
    'recovery_key',
    'temp_password',
    'user_credential',
    'auth_code',
    'sessionid',
    'access_token'
]


    def on_login(self, context, connection):
        try:
            all_results = []
            hostname = connection.hostname or connection.host
            databases = connection.conn.sql_query("SELECT name FROM master.dbo.sysdatabases")
            for db in databases:
                db_name = db.get('name') or db.get('', '')
                if db_name.lower() in ('master', 'model', 'msdb', 'tempdb'):
                    continue  # skip system DBs

                context.log.display(f"Searching database: {db_name}")
                connection.conn.sql_query(f"USE [{db_name}]")

                # get all user tables in this DB
                tables = connection.conn.sql_query(
                    "SELECT table_name FROM information_schema.tables WHERE table_type = 'BASE TABLE'"
                )

                for table in tables:
                    table_name = table.get('table_name') or table.get('', '')
                    try:
                        columns = connection.conn.sql_query(
                            f"SELECT column_name FROM information_schema.columns WHERE table_name = '{table_name}'"
                        )
                        column_names = [c.get('column_name') or c.get('', '') for c in columns]

                        # find matching columns
                        search_keys = self.pii() + self.like_search
                        matched = [col for col in column_names if any(key in col.lower() for key in search_keys)]
                        if matched:
                            column_str = ', '.join(f'[{c}]' for c in matched)
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
                                                v = v.decode('utf-8', errors='replace')
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
                                        val_str = val.decode('utf-8', 'replace') if isinstance(val, bytes) else str(val)
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
                        return obj.decode('utf-8', 'replace')
                    else:
                        return obj
                cleaned = sanitize(all_results)
                with open(filename, 'w') as f:
                    json.dump(cleaned, f, indent=2)
                    context.log.success(f"Data saved to {filename}")
            except Exception as e:
                context.log.fail(f"Failed to save results to file: {e}")




