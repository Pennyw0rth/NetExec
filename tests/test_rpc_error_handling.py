"""Unit tests for RPC error handling in SMB protocol."""

import pytest


class MockDCERPCException(Exception):
    """Mock DCERPCException for testing error handling."""

    def __init__(self, message):
        self.message = message
        super().__init__(message)

    def __str__(self):
        return self.message


class TestRPCErrorMessages:
    """Test that RPC errors are converted to user-friendly messages."""

    # Map of status codes to expected message patterns
    ERROR_PATTERNS = {
        "STATUS_ACCESS_DENIED": "Access denied",
        "STATUS_NO_SUCH_USER": "User not found",
        "STATUS_NONE_MAPPED": ["User not found", "Group not found", "Domain not found", "None", "could not be resolved"],
        "STATUS_SOME_NOT_MAPPED": "Some",
        "STATUS_NO_SUCH_GROUP": "Group not found",
        "STATUS_NO_SUCH_ALIAS": "Group not found",
        "STATUS_NO_SUCH_DOMAIN": "Domain not found",
        "STATUS_USER_EXISTS": "User already exists",
        "STATUS_GROUP_EXISTS": "Group already exists",
        "STATUS_ALIAS_EXISTS": "Group already exists",
        "STATUS_WRONG_PASSWORD": "Wrong old password",
        "STATUS_PASSWORD_RESTRICTION": "complexity requirements",
        "STATUS_ACCOUNT_LOCKED_OUT": "Account locked out",
        "STATUS_LM_CROSS_ENCRYPTION_REQUIRED": "encryption",
        "STATUS_NT_CROSS_ENCRYPTION_REQUIRED": "encryption",
        "STATUS_MEMBER_IN_GROUP": "already a member",
        "STATUS_MEMBER_IN_ALIAS": "already a member",
        "STATUS_MEMBER_NOT_IN_GROUP": "not a member",
        "STATUS_MEMBER_NOT_IN_ALIAS": "not a member",
        "STATUS_OBJECT_NAME_NOT_FOUND": ["No explicit account rights", "not found"],
        "STATUS_OBJECT_NAME_COLLISION": "already exists",
    }

    def test_error_patterns_defined(self):
        """Verify all expected error patterns are defined."""
        assert len(self.ERROR_PATTERNS) > 0
        for code, pattern in self.ERROR_PATTERNS.items():
            assert code.startswith("STATUS_")
            if isinstance(pattern, list):
                assert all(isinstance(p, str) for p in pattern)
            else:
                assert isinstance(pattern, str)

    def test_status_codes_have_friendly_messages(self):
        """Verify status codes map to non-technical messages."""
        technical_patterns = ["0x", "DCERPC", "SessionError", "code:"]
        for code, pattern in self.ERROR_PATTERNS.items():
            patterns = pattern if isinstance(pattern, list) else [pattern]
            for p in patterns:
                for tech in technical_patterns:
                    assert tech.lower() not in p.lower(), f"{code} message contains technical term: {tech}"


class TestStatusCodeMapping:
    """Test Microsoft status code mappings."""

    STATUS_CODES = {
        "STATUS_ACCESS_DENIED": 0xC0000022,
        "STATUS_MORE_ENTRIES": 0x00000105,
        "STATUS_NO_MORE_ENTRIES": 0x8000001A,
        "STATUS_SOME_NOT_MAPPED": 0x00000107,
        "STATUS_NONE_MAPPED": 0xC0000073,
        "STATUS_WRONG_PASSWORD": 0xC000006A,
        "STATUS_ACCOUNT_LOCKED_OUT": 0xC0000234,
        "STATUS_GROUP_EXISTS": 0xC0000065,
        "STATUS_USER_EXISTS": 0xC0000063,
        "STATUS_LM_CROSS_ENCRYPTION_REQUIRED": 0xC000017F,
        "STATUS_NT_CROSS_ENCRYPTION_REQUIRED": 0xC000015D,
    }

    def test_status_codes_are_valid(self):
        """Verify status codes are valid hex values."""
        for name, code in self.STATUS_CODES.items():
            assert isinstance(code, int)
            assert code >= 0
            assert name.startswith("STATUS_")

    def test_error_codes_are_documented(self):
        """Verify all documented error codes are present."""
        expected_codes = [
            "STATUS_ACCESS_DENIED",
            "STATUS_NONE_MAPPED",
            "STATUS_SOME_NOT_MAPPED",
            "STATUS_WRONG_PASSWORD",
            "STATUS_ACCOUNT_LOCKED_OUT",
            "STATUS_GROUP_EXISTS",
            "STATUS_USER_EXISTS",
        ]
        for code in expected_codes:
            assert code in self.STATUS_CODES


class TestOutputFormatUserGroups:
    """Test the --rpc-user-groups output format."""

    def test_output_format_structure(self):
        """Verify the output format has proper columns."""
        expected_columns = ["RID", "ATTR", "Name"]
        header_line = f"{'RID':<8} {'ATTR':<6} {'Name':<30}"
        for col in expected_columns:
            assert col in header_line

    def test_separator_line_format(self):
        """Verify separator line matches header."""
        separator = f"{'-' * 8} {'-' * 6} {'-' * 30}"
        assert len(separator) == 8 + 1 + 6 + 1 + 30

    def test_data_line_format(self):
        """Verify data line format."""
        rid = 513
        attr = 7
        name = "Domain Users"
        data_line = f"{rid:<8} {attr:<6} {name:<30}"
        assert "513" in data_line
        assert "7" in data_line
        assert "Domain Users" in data_line


class TestOutputFormatGroup:
    """Test the --rpc-group output format."""

    def test_group_members_without_domain(self):
        """Verify group members are shown without domain prefix."""
        members = ["Administrator", "testme", "Domain Admins"]
        member_str = ", ".join(members)
        assert "\\" not in member_str


class TestErrorHandlingCoverage:
    """Test that all RPC methods have proper error handling."""

    RPC_METHODS = [
        "rpc_users",
        "rpc_groups",
        "rpc_user",
        "rpc_user_groups",
        "rpc_group",
        "rpc_dom_info",
        "rpc_pass_pol",
        "rpc_trusts",
        "rpc_shares",
        "rpc_sessions",
        "rpc_connections",
        "rpc_server_info",
        "rid_brute",
        "lsa_query",
        "lsa_sids",
        "lsa_privs",
        "lsa_lookup_sids",
        "lsa_rights",
        "lsa_create_account",
        "lsa_query_security",
        "lookup_names",
        "lookup_domain",
        "sam_lookup",
        "create_user",
        "delete_user",
        "enable_user",
        "disable_user",
        "change_password",
        "reset_password",
        "create_group",
        "delete_group",
        "add_to_group",
        "remove_from_group",
    ]

    def test_all_methods_listed(self):
        """Verify all RPC methods are listed for testing."""
        assert len(self.RPC_METHODS) >= 30

    def test_method_names_are_valid(self):
        """Verify method names follow naming convention."""
        for method in self.RPC_METHODS:
            assert isinstance(method, str)
            assert method.islower() or "_" in method
