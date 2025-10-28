import base64
import json
import unittest
from unittest import mock

from barbican.cmd.pkcs11_kek_rewrap import KekRewrap
from barbican.common import utils


class TestKekRewrap(unittest.TestCase):
    def setUp(self):
        # Mock configuration and dependencies
        self.conf = mock.MagicMock()
        self.conf.database = mock.MagicMock()
        self.conf.database.connection = (
            "sqlite:///:memory:"  # Use in-memory SQLite for testing
        )
        self.crypto_plugin = mock.MagicMock()
        self.pkcs11 = mock.MagicMock()
        self.session = mock.MagicMock()
        self.db_session = mock.MagicMock()

        # Mock the crypto plugin and its attributes
        self.crypto_plugin.mkek_label = "new_mkek_label"
        self.crypto_plugin.hmac_label = "new_hmac_label"
        self.crypto_plugin.mkek_key_type = "AES"
        self.crypto_plugin.hmac_key_type = "HMAC"
        self.crypto_plugin._get_master_key.side_effect = (
            lambda key_type, label: f"{key_type}_{label}_key"
        )
        self.crypto_plugin.pkcs11 = self.pkcs11

        # Mock pkcs11 methods
        self.pkcs11.get_key_handle.side_effect = (
            lambda key_type, label, session: f"{key_type}_{label}_handle"
        )
        self.pkcs11.verify_hmac.return_value = None
        self.pkcs11.unwrap_key.return_value = "unwrapped_kek"
        self.pkcs11.wrap_key.return_value = {
            "iv": b"new_iv",
            "wrapped_key": b"new_wrapped_key",
        }
        self.pkcs11.compute_hmac.return_value = b"new_hmac"
        self.pkcs11.destroy_object.return_value = None

        # Mock logging to prevent oslo_log errors
        with mock.patch(
            "barbican.cmd.pkcs11_kek_rewrap.p11_crypto.P11CryptoPlugin",
            return_value=self.crypto_plugin,
        ):
            with mock.patch.object(
                utils, "generate_fullname_for", return_value="plugin_name"
            ):
                self.rewrapper = KekRewrap(self.conf)

        # Override attributes for testing
        self.rewrapper.crypto_plugin = self.crypto_plugin
        self.rewrapper.pkcs11 = self.pkcs11
        self.rewrapper.hsm_session = self.session
        self.rewrapper._session_creator = mock.MagicMock(
            return_value=self.db_session
        )

    def test_rewrap_kek_iv_valid(self):
        """Test normal rewrap_kek functionality."""
        # Mock kek object
        kek = mock.MagicMock()
        kek.plugin_meta = json.dumps(
            {
                "mkek_label": "mkek_label",
                "hmac_label": "hmac_label",
                "iv": base64.b64encode(b"old_iv").decode(),
                "wrapped_key": base64.b64encode(b"old_wrapped_key").decode(),
                "hmac": base64.b64encode(b"hmac").decode(),
                "key_wrap_mechanism": "CKM_AES_KEY_WRAP_PAD",
            }
        )
        kek.id = "kek_id"

        # Mock project
        project = mock.MagicMock()

        # Call the method
        self.rewrapper.rewrap_kek(project, kek)

        # iv is not None,
        # Assert verify_hmac was called with correct arguments 
        self.pkcs11.verify_hmac.assert_called_once_with(
            "HMAC_hmac_label_handle",
            b"hmac",
            b"old_iv" + b"old_wrapped_key",  # kek_data = iv + wrapped_key
            self.session,
        )

        updated_meta = json.loads(kek.plugin_meta)
        self.assertEqual(updated_meta["mkek_label"], "new_mkek_label")
        self.assertEqual(updated_meta["hmac_label"], "new_hmac_label")
        self.assertEqual(
            updated_meta["iv"],
            base64.b64encode(b"new_iv").decode()
        )
        self.assertEqual(
            updated_meta["wrapped_key"],
            base64.b64encode(b"new_wrapped_key").decode()
        )
        self.assertEqual(
            updated_meta["hmac"],
            base64.b64encode(b"new_hmac").decode()
        )

    def test_rewrap_kek_iv_none(self):
        """Test rewrap_kek functionality when IV is None."""
        # Mock kek object
        kek = mock.MagicMock()
        kek.plugin_meta = json.dumps(
            {
                "mkek_label": "mkek_label",
                "hmac_label": "hmac_label",
                "iv": None,
                "wrapped_key": base64.b64encode(b"old_wrapped_key").decode(),
                "hmac": base64.b64encode(b"hmac").decode(),
                "key_wrap_mechanism": "CKM_AES_KEY_WRAP_PAD",
            }
        )
        kek.id = "kek_id"

        # Mock project
        project = mock.MagicMock()

        # Call the method and ensure no TypeError is raised
        try:
            self.rewrapper.rewrap_kek(project, kek)
        except Exception:
            self.fail(
                "Exception was unexpectedly raised when IV is None,because"
                "Softhsm2) allows key rewrapping"
                "when key_wrap_generate_iv is set to false and "
                "key_wrap_mechanism is CKM_AES_KEY_WRAP_PAD."
            )

        # iv is None,
        # verify_hmac should be called with kek_data = wrapped_key
        self.pkcs11.verify_hmac.assert_called_once_with(
            "HMAC_hmac_label_handle",
            b"hmac",
            b"old_wrapped_key",  # kek_data = wrapped_key
            self.session,
        )

        # Check if plugin_meta was updated
        updated_meta = json.loads(kek.plugin_meta)
        self.assertEqual(updated_meta["mkek_label"], "new_mkek_label")
        self.assertEqual(updated_meta["hmac_label"], "new_hmac_label")
        self.assertEqual(
            updated_meta["iv"], base64.b64encode(b"new_iv").decode()
        )  # New IV is generated even if old was None
        self.assertEqual(
            updated_meta["wrapped_key"],
            base64.b64encode(b"new_wrapped_key").decode()
        )
        self.assertEqual(
            updated_meta["hmac"],
            base64.b64encode(b"new_hmac").decode()
        )


if __name__ == "__main__":
    unittest.main()
