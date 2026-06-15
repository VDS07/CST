"""Unit tests for the port scanner module."""

import pytest
from unittest.mock import patch, MagicMock
from modules.port_scanner import scan_port, run


class TestScanPort:
    """Tests for the individual port scanning function."""

    @patch("modules.port_scanner.socket.socket")
    def test_open_port(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket_cls.return_value = mock_sock

        with patch("modules.port_scanner.socket.getservbyport", return_value="http"):
            result = scan_port("127.0.0.1", 80, 0.5)

        assert result is not None
        port, status, service = result
        assert port == 80
        assert status == "OPEN"
        assert service == "http"
        mock_sock.close.assert_called_once()

    @patch("modules.port_scanner.socket.socket")
    def test_closed_port(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 1  # non-zero = closed
        mock_socket_cls.return_value = mock_sock

        result = scan_port("127.0.0.1", 9999, 0.5)

        assert result is None
        mock_sock.close.assert_called_once()

    @patch("modules.port_scanner.socket.socket")
    def test_socket_error(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect_ex.side_effect = OSError("network error")
        mock_socket_cls.return_value = mock_sock

        result = scan_port("127.0.0.1", 80, 0.5)

        assert result is None
        mock_sock.close.assert_called_once()

    @patch("modules.port_scanner.socket.socket")
    def test_unknown_service(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket_cls.return_value = mock_sock

        with patch("modules.port_scanner.socket.getservbyport", side_effect=OSError):
            result = scan_port("127.0.0.1", 54321, 0.5)

        assert result is not None
        _, _, service = result
        assert service == "unknown"


class TestPortScannerRun:
    """Tests for the main scan orchestrator."""

    @patch("modules.port_scanner.scan_port")
    def test_returns_structure(self, mock_scan):
        mock_scan.return_value = None  # all ports closed

        results = run("127.0.0.1", start_port=1, end_port=3)

        assert results["target"] == "127.0.0.1"
        assert results["ports_scanned"] == "1-3"
        assert isinstance(results["open_ports"], list)
        assert "scan_duration_seconds" in results

    @patch("modules.port_scanner.scan_port")
    def test_open_ports_sorted(self, mock_scan):
        # Simulate ports 80 and 22 found open (in reverse order)
        def side_effect(target, port, timeout):
            if port == 80:
                return (80, "OPEN", "http")
            if port == 22:
                return (22, "OPEN", "ssh")
            return None

        mock_scan.side_effect = side_effect

        results = run("127.0.0.1", start_port=1, end_port=100)

        ports = [p["port"] for p in results["open_ports"]]
        assert ports == sorted(ports)

    @patch("modules.port_scanner.scan_port")
    def test_scan_duration_tracked(self, mock_scan):
        mock_scan.return_value = None

        results = run("127.0.0.1", start_port=1, end_port=5)

        assert results["scan_duration_seconds"] >= 0
