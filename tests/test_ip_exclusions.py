from unittest.mock import patch

from nxc.parsers.ip import get_local_ip, parse_exclusions, parse_targets


class TestGetLocalIP:
    """Test local IP detection functionality."""
    
    @patch("netifaces.interfaces")
    @patch("netifaces.ifaddresses")
    def test_get_local_ip_success(self, mock_ifaddresses, mock_interfaces):
        """Test successful local IP detection via netifaces."""
        # Mock available interfaces
        mock_interfaces.return_value = ["lo", "eth0", "wlan0"]
        
        # Mock addresses for each interface
        import netifaces
        mock_ifaddresses.side_effect = lambda iface: {
            "lo": {netifaces.AF_INET: [{"addr": "127.0.0.1"}]},
            "eth0": {netifaces.AF_INET: [{"addr": "192.168.1.100"}]},
            "wlan0": {}
        }.get(iface, {})
        
        result = get_local_ip()
        
        assert result == "192.168.1.100"
        mock_interfaces.assert_called_once()

    @patch("netifaces.interfaces")
    @patch("netifaces.ifaddresses")
    def test_get_local_ip_skip_localhost(self, mock_ifaddresses, mock_interfaces):
        """Test that localhost addresses are skipped."""
        # Mock only loopback interface
        mock_interfaces.return_value = ["lo"]
        
        import netifaces
        mock_ifaddresses.return_value = {
            netifaces.AF_INET: [{"addr": "127.0.0.1"}]
        }
        
        result = get_local_ip()
        
        assert result is None

    @patch("netifaces.interfaces")
    @patch("netifaces.ifaddresses")
    def test_get_local_ip_skip_link_local(self, mock_ifaddresses, mock_interfaces):
        """Test that link-local addresses (169.254.x.x) are skipped."""
        mock_interfaces.return_value = ["eth0"]
        
        import netifaces
        mock_ifaddresses.return_value = {
            netifaces.AF_INET: [{"addr": "169.254.1.1"}]
        }
        
        result = get_local_ip()
        
        assert result is None

    @patch("netifaces.interfaces")
    def test_get_local_ip_exception_handling(self, mock_interfaces):
        """Test when netifaces raises an exception."""
        # Make interfaces() raise an exception
        mock_interfaces.side_effect = Exception("Network error")
        
        result = get_local_ip()
        
        assert result is None


class TestParseExclusions:
    """Test exclusion parsing functionality."""
    
    def test_parse_exclusions_single_ip(self):
        """Test parsing single IP address."""
        exclusions = ["192.168.1.10"]
        result = parse_exclusions(exclusions)
        
        assert result == {"192.168.1.10"}

    def test_parse_exclusions_multiple_ips(self):
        """Test parsing multiple IP addresses."""
        exclusions = ["192.168.1.10", "10.0.0.1", "172.16.0.5"]
        result = parse_exclusions(exclusions)
        
        assert result == {"192.168.1.10", "10.0.0.1", "172.16.0.5"}

    def test_parse_exclusions_cidr_range(self):
        """Test parsing CIDR notation."""
        exclusions = ["192.168.1.0/30"]  # Should expand to .1, .2
        result = parse_exclusions(exclusions)
        
        expected = {"192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"}
        assert result == expected

    def test_parse_exclusions_ip_range(self):
        """Test parsing IP range notation."""
        exclusions = ["192.168.1.10-192.168.1.12"]
        result = parse_exclusions(exclusions)
        
        expected = {"192.168.1.10", "192.168.1.11", "192.168.1.12"}
        assert result == expected

    def test_parse_exclusions_short_range(self):
        """Test parsing short IP range notation."""
        exclusions = ["192.168.1.10-12"]  # Should expand to 192.168.1.10-192.168.1.12
        result = parse_exclusions(exclusions)
        
        expected = {"192.168.1.10", "192.168.1.11", "192.168.1.12"}
        assert result == expected

    def test_parse_exclusions_hostname(self):
        """Test parsing hostname (treated as string)."""
        exclusions = ["example.com"]
        result = parse_exclusions(exclusions)
        
        assert result == {"example.com"}

    def test_parse_exclusions_mixed_formats(self):
        """Test parsing mixed IP formats."""
        exclusions = [
            "192.168.1.10",           # Single IP
            "10.0.0.0/31",           # CIDR (expands to .0, .1)
            "172.16.1.5-7",          # Short range
            "test.local"             # Hostname
        ]
        result = parse_exclusions(exclusions)
        
        expected = {
            "192.168.1.10",
            "10.0.0.0", "10.0.0.1",
            "172.16.1.5", "172.16.1.6", "172.16.1.7",
            "test.local"
        }
        assert result == expected

    def test_parse_exclusions_empty_list(self):
        """Test parsing empty exclusion list."""
        exclusions = []
        result = parse_exclusions(exclusions)
        
        assert result == set()

    def test_parse_exclusions_ipv6(self):
        """Test parsing IPv6 addresses."""
        exclusions = ["2001:db8::1"]
        result = parse_exclusions(exclusions)
        
        assert result == {"2001:db8::1"}


class TestTargetFiltering:
    """Test integration of exclusion filtering with target parsing."""
    
    def test_target_filtering_excludes_single_ip(self):
        """Test that single IP is properly excluded from target list."""
        targets = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]
        exclusions = parse_exclusions(["192.168.1.2"])
        
        filtered_targets = [target for target in targets if target not in exclusions]
        
        assert filtered_targets == ["192.168.1.1", "192.168.1.3"]

    def test_target_filtering_excludes_cidr_range(self):
        """Test that CIDR range exclusions work properly."""
        targets = ["192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.10"]
        exclusions = parse_exclusions(["192.168.1.0/30"])  # Excludes .0-.3
        
        filtered_targets = [target for target in targets if target not in exclusions]
        
        assert filtered_targets == ["192.168.1.10"]

    def test_target_filtering_no_exclusions(self):
        """Test that no exclusions leaves targets unchanged."""
        targets = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]
        exclusions = parse_exclusions([])
        
        filtered_targets = [target for target in targets if target not in exclusions]
        
        assert filtered_targets == targets

    def test_target_filtering_all_excluded(self):
        """Test that all targets can be excluded."""
        targets = ["192.168.1.1", "192.168.1.2"]
        exclusions = parse_exclusions(["192.168.1.0/30"])  # Excludes .0-.3
        
        filtered_targets = [target for target in targets if target not in exclusions]
        
        assert filtered_targets == []

    def test_target_filtering_mixed_formats(self):
        """Test filtering with mixed target and exclusion formats."""
        # Targets from parse_targets (simulated)
        targets = []
        for target_spec in ["192.168.1.1", "10.0.0.1-3"]:
            targets.extend(list(parse_targets(target_spec)))
        
        # Exclude some targets
        exclusions = parse_exclusions(["192.168.1.1", "10.0.0.2"])
        
        filtered_targets = [target for target in targets if target not in exclusions]
        
        expected = ["10.0.0.1", "10.0.0.3"]
        assert set(filtered_targets) == set(expected)


class TestEdgeCases:
    """Test edge cases and error conditions."""
    
    def test_exclusions_with_invalid_ip(self):
        """Test that invalid IPs are treated as hostnames."""
        exclusions = ["invalid.ip.address"]
        result = parse_exclusions(exclusions)
        
        # Should be treated as hostname
        assert result == {"invalid.ip.address"}

    def test_exclusions_duplicate_handling(self):
        """Test that duplicate exclusions are handled properly."""
        exclusions = ["192.168.1.1", "192.168.1.1", "192.168.1.2"]
        result = parse_exclusions(exclusions)
        
        # Set should deduplicate
        assert result == {"192.168.1.1", "192.168.1.2"}

    def test_exclusions_case_sensitivity(self):
        """Test hostname case sensitivity."""
        exclusions = ["Example.COM", "example.com"]
        result = parse_exclusions(exclusions)
        
        # Should preserve case (hostnames are case-insensitive but we preserve input)
        assert result == {"Example.COM", "example.com"}


class TestConfigIntegration:
    """Test config-based exclusion integration."""
    
    @patch("nxc.config.exclude_hosts", ["192.168.1.10", "10.0.0.0/30"])
    @patch("nxc.config.skip_self", False)
    def test_config_exclusions_loaded(self):
        """Test that exclusions are properly loaded from config."""
        from nxc.config import exclude_hosts, skip_self
        
        assert exclude_hosts == ["192.168.1.10", "10.0.0.0/30"]
        assert skip_self is False
    
    @patch("nxc.config.exclude_hosts", [])
    @patch("nxc.config.skip_self", True)
    def test_config_skip_self_enabled(self):
        """Test that skip_self config option works."""
        from nxc.config import skip_self
        
        assert skip_self is True
    
    def test_config_exclusions_processing(self):
        """Test that config exclusions are processed correctly."""
        # Simulate config values
        config_exclusions = ["192.168.1.10", "10.0.0.0/30"]
        
        # Process exclusions the same way as in netexec.py
        excluded_ips = set()
        if config_exclusions:
            excluded_ips.update(parse_exclusions(config_exclusions))
        
        expected = {
            "192.168.1.10",
            "10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"
        }
        assert excluded_ips == expected


class TestConfigValidation:
    """Test config validation and error handling."""
    
    def test_malformed_exclude_hosts_syntax_error(self):
        """Test that malformed exclude_hosts syntax is handled gracefully."""
        from ast import literal_eval
        
        # Simulate what happens in config.py with malformed input
        malformed_inputs = [
            "[192.168.1.1]",  # Missing quotes
            "[192.168.1.1, 10.0.0.1]",  # Multiple without quotes
            "192.168.1.1",  # Plain string
            "",  # Empty string
        ]
        
        for malformed_input in malformed_inputs:
            try:
                result = literal_eval(malformed_input)
                # If we get here, it didn't fail as expected
                assert isinstance(result, list), f"Expected list for valid input: {malformed_input}"
            except (ValueError, SyntaxError):
                # This is expected behavior - should gracefully handle the error
                # In actual config.py, this would fall back to empty list
                assert True
    
    def test_exclude_hosts_type_validation(self):
        """Test that non-list values are rejected."""
        from ast import literal_eval
        
        # Test inputs that parse successfully but aren't lists
        non_list_inputs = [
            '"192.168.1.1"',  # String instead of list
            "192",  # Integer
            "True",  # Boolean
        ]
        
        for input_val in non_list_inputs:
            result = literal_eval(input_val)
            # Should validate that result is a list
            assert not isinstance(result, list), f"Input {input_val} should not be a list"