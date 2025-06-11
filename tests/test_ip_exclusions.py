from unittest.mock import patch, MagicMock

from nxc.parsers.ip import get_local_ip, parse_exclusions, parse_targets


class TestGetLocalIP:
    """Test local IP detection functionality."""
    
    @patch("socket.socket")
    def test_get_local_ip_success(self, mock_socket):
        """Test successful local IP detection via UDP socket."""
        mock_sock = MagicMock()
        mock_sock.getsockname.return_value = ("192.168.1.100", 12345)
        mock_socket.return_value.__enter__.return_value = mock_sock
        
        result = get_local_ip()
        
        assert result == "192.168.1.100"
        mock_sock.connect.assert_called_once_with(("8.8.8.8", 80))
        mock_sock.getsockname.assert_called_once()

    @patch("socket.socket")
    @patch("socket.gethostname")
    @patch("socket.gethostbyname")
    def test_get_local_ip_fallback_success(self, mock_gethostbyname, mock_gethostname, mock_socket):
        """Test fallback method when UDP socket fails."""
        # Make UDP socket fail
        mock_socket.side_effect = Exception("Network unreachable")
        
        # Setup fallback method
        mock_gethostname.return_value = "test-machine"
        mock_gethostbyname.return_value = "10.0.0.50"
        
        result = get_local_ip()
        
        assert result == "10.0.0.50"
        mock_gethostname.assert_called_once()
        mock_gethostbyname.assert_called_once_with("test-machine")

    @patch("socket.socket")
    @patch("socket.gethostname")
    @patch("socket.gethostbyname")
    def test_get_local_ip_fallback_localhost_filtered(self, mock_gethostbyname, mock_gethostname, mock_socket):
        """Test fallback method filters out localhost."""
        # Make UDP socket fail
        mock_socket.side_effect = Exception("Network unreachable")
        
        # Setup fallback to return localhost
        mock_gethostname.return_value = "localhost"
        mock_gethostbyname.return_value = "127.0.0.1"
        
        result = get_local_ip()
        
        assert result is None

    @patch("socket.socket")
    @patch("socket.gethostname")
    def test_get_local_ip_all_methods_fail(self, mock_gethostname, mock_socket):
        """Test when all methods fail to detect local IP."""
        # Make UDP socket fail
        mock_socket.side_effect = Exception("Network unreachable")
        
        # Make hostname resolution fail
        mock_gethostname.side_effect = Exception("Hostname resolution failed")
        
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