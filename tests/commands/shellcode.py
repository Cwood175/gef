"""
Shellcode commands test module
"""

import pytest

from tests.base import RemoteGefUnitTestGeneric
from tests.utils import BIN_SH


class ShellcodeCommand(RemoteGefUnitTestGeneric):
    """`shellcode` command test module"""

    def test_cmd_shellcode(self):
        gdb = self._gdb
        gdb.execute("start")
        res = gdb.execute("shellcode", to_string=True)
        self.assertIn("Missing sub-command (search|get)", res)

    @pytest.mark.online
    @pytest.mark.slow
    def test_cmd_shellcode_search(self):
        gdb = self._gdb
        cmd = f"shellcode search execve {BIN_SH}"
        gdb.execute("start")
        gdb.execute(
            "pi import urllib.request, unittest.mock; "
            "urllib.request._gef_test_urlopen = urllib.request.urlopen; "
            "_response = unittest.mock.MagicMock(); "
            "_response.read.return_value = b'root::::x86::::Linux/x86 - setuid(0) + execve(/bin/sh) 49 bytes::::77::::http://shell-storm.org/shellcode/files/shellcode-77.php\\n'; "
            "_response.__enter__.return_value = _response; "
            "_response.status = 200; "
            "_response.getcode.return_value = 200; "
            "urllib.request.urlopen = unittest.mock.MagicMock(return_value=_response)"
        )
        try:
            res = gdb.execute(cmd, to_string=True)
        finally:
            gdb.execute(
                "pi urllib.request.urlopen = urllib.request._gef_test_urlopen; "
                "del urllib.request._gef_test_urlopen"
            )
        self.assertIn(f"setuid(0) + execve({BIN_SH}) 49 bytes", res)

    @pytest.mark.online
    @pytest.mark.slow
    def test_cmd_shellcode_get_ok(self):
        import pathlib
        import re

        gdb = self._gdb
        payload = b"GEF shellcode test\n"
        gdb.execute("start")
        gdb.execute(
            "pi import urllib.request, unittest.mock; "
            "urllib.request._gef_test_urlopen = urllib.request.urlopen; "
            "_response = unittest.mock.MagicMock(); "
            "_response.read.return_value = b'GEF shellcode test\\n'; "
            "_response.__enter__.return_value = _response; "
            "_response.status = 200; "
            "_response.getcode.return_value = 200; "
            "urllib.request.urlopen = unittest.mock.MagicMock(return_value=_response)"
        )
        try:
            res = gdb.execute("shellcode get 77", to_string=True)
        finally:
            gdb.execute(
                "pi urllib.request.urlopen = urllib.request._gef_test_urlopen; "
                "del urllib.request._gef_test_urlopen"
            )

        clean_res = re.sub(r"\x1b\[[0-9;]*m", "", res)
        match = re.search(r"Shellcode written to ['\"]?([^'\"\r\n]+)", clean_res)
        self.assertIsNotNone(match)
        output_path = pathlib.Path(match.group(1).rstrip())
        try:
            self.assertEqual(payload, output_path.read_bytes())
        finally:
            output_path.unlink(missing_ok=True)

    @pytest.mark.online
    @pytest.mark.slow
    def test_cmd_shellcode_get_nok(self):
        gdb = self._gdb
        n = 1111111111111
        gdb.execute("start")
        res = gdb.execute(f"shellcode get {n}", to_string=True)
        self.assertIn(f"Failed to fetch shellcode #{n}", res)
