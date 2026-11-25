import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pxecred
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class SmokeTest(unittest.TestCase):
    def test_help(self):
        script = Path(__file__).resolve().parents[1] / "pxecred.py"
        result = subprocess.run(
            [sys.executable, str(script), "--help"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("pxecred", result.stdout)
        self.assertIn("--variables", result.stdout)
        self.assertIn("--boot-var", result.stdout)
        self.assertIn("--password", result.stdout)


class MediaVariableDecryptTest(unittest.TestCase):
    def test_decrypts_boot_var(self):
        plaintext = (
            '<?xml version="1.0" encoding="UTF-16"?>'
            '<MediaVarList Version="5.00.9128.1007">'
            '<var name="SMSTSMP">http://192.168.0.41</var>'
            '<var name="_SMSMediaGuid">{24FDDDDE-FA2F-4861-89AB-F3DEFCDE9BFF}</var>'
            '<var name="_SMSTSSiteCode">P01</var>'
            '</MediaVarList>'
        )
        password = "hello"
        key = pxecred.aes_des_key_derivation(password.encode("utf-16-le"))
        data = plaintext.encode("utf-16-le")
        data += b"\x00" * ((-len(data)) % 16)
        encryptor = Cipher(
            algorithms.AES(key[:16]), modes.CBC(b"\x00" * 16)
        ).encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        blob = b"\x00" * 24 + ciphertext + b"\x00" * 8

        with tempfile.TemporaryDirectory() as directory:
            boot_var = Path(directory) / "media.boot.var"
            boot_var.write_bytes(blob)
            text = pxecred.decrypt_media_variables(boot_var, password)
            values = pxecred.load_variables_text(text)
            self.assertEqual(
                values["_SMSMediaGuid"], "{24FDDDDE-FA2F-4861-89AB-F3DEFCDE9BFF}"
            )
            self.assertEqual(values["_SMSTSSiteCode"], "P01")


if __name__ == "__main__":
    unittest.main()
