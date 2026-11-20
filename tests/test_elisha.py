"""Tests run in dry mode: no radio, no tools, no network needed."""
import json
import os
import shlex
import sys
import tempfile
import unittest
from pathlib import Path

TMP = tempfile.mkdtemp()
os.environ["ELISHA_HOME"] = TMP
os.environ["ELISHA_DRYRUN"] = "1"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import elisha as m  # noqa: E402

m.ensure_dirs()
P = {"port": "/dev/ttyACM0"}


def act(action_name, /, **kw):
    return m.ACTIONS[action_name]({**P, **kw})


class Validation(unittest.TestCase):
    def test_bad_port(self):
        with self.assertRaises(m.Bad):
            m.ACTIONS["mt_info"]({"port": "/dev/ttyACM0; rm -rf /"})

    def test_missing_port(self):
        with self.assertRaises(m.Bad):
            m.ACTIONS["mt_info"]({})

    def test_dash_injection(self):
        with self.assertRaises(m.Bad):
            act("mt_owner", long="--factory-reset", short="x")

    def test_set_value_injection(self):
        with self.assertRaises(m.Bad):
            act("mt_set", field="lora.hop_limit", value="--reboot")

    def test_mc_radio_range(self):
        with self.assertRaises(m.Bad):
            act("mc_radio", freq="2400", bw="62.5", sf="7", cr="5")

    def test_confirmations(self):
        with self.assertRaises(m.Bad):
            act("mt_factory", confirm="no")
        with self.assertRaises(m.Bad):
            act("fw_esp_erase", confirm="no")

    def test_path_traversal(self):
        with self.assertRaises(m.Bad):
            act("mt_import", file="../../etc/passwd")


class Commands(unittest.TestCase):
    def test_owner(self):
        r = act("mt_owner", long="Home Base", short="HB01")
        self.assertEqual(r["cmd"], "meshtastic --port /dev/ttyACM0 --set-owner 'Home Base' --set-owner-short HB01")

    def test_channel_key_hidden(self):
        r = act("mt_channel_set", index="0", name="Home", psk_mode="custom", psk="00112233445566778899aabbccddeeff")
        self.assertIn("--ch-index 0", r["cmd"])
        self.assertNotIn("0011223344", r["cmd"])

    def test_mc_radio(self):
        r = act("mc_radio", freq="910.525", bw="62.5", sf="7", cr="5")
        self.assertTrue(r["cmd"].endswith("set radio 910.525,62.5,7,5"))

    def test_mc_channel_key_hidden(self):
        r = act("mc_channel_set", index="1", name="Squad", key="00112233445566778899aabbccddeeff")
        self.assertNotIn("0011223344", r["cmd"])

    def test_tcp_meshtastic_only(self):
        r = m.ACTIONS["mt_info"]({"port": "tcp:192.168.1.50"})
        self.assertIn("--host 192.168.1.50", r["cmd"])

    def test_psk_forms(self):
        self.assertEqual(m.psk_arg("random", ""), "random")
        self.assertEqual(m.psk_arg("custom", "00" * 16), "0x" + "00" * 16)
        with self.assertRaises(m.Bad):
            m.psk_arg("custom", "abc")

    def test_genkey(self):
        self.assertEqual(len(m.make_key(16)["hex"]), 32)
        self.assertEqual(len(m.make_key(32)["hex"]), 64)


class BackupLogic(unittest.TestCase):
    def setUp(self):
        self._run = m.run
        self._dry = m.DRY
        m.DRY = False

    def tearDown(self):
        m.run = self._run
        m.DRY = self._dry

    def test_mc_backup_script_roundtrip(self):
        info = json.dumps({"name": "Home Base", "radio_freq": 910.525, "radio_bw": 62.5, "radio_sf": 7,
                           "radio_cr": 5, "tx_power": 20, "adv_lat": 29.35, "adv_lon": -98.12}, indent=4)
        out = info + "\n0: Public [8b3387e9c5cdea6ac9e5edbaa115cd72]\n1: #squad [aabbccddeeff00112233445566778899]\n"
        m.run = lambda argv, t=90: (0, out, "")
        r = act("mc_backup", label="home base")
        self.assertTrue(r["ok"], r)
        lines = (m.DIRS["backups"] / r["saved"]).read_text().splitlines()
        parsed = [shlex.split(x) for x in lines if x and not x.startswith("#")]
        self.assertIn(["set", "name", "Home Base"], parsed)
        self.assertIn(["set_channel", "1", "#squad"], parsed)

    def test_mc_failure_detected_even_with_exit_zero(self):
        m.run = lambda argv, t=90: (0, "Error: could not open port\n", "Traceback (most recent call last):")
        self.assertFalse(act("mc_info")["ok"])

    def test_mt_export_requires_file(self):
        m.run = lambda argv, t=90: (0, "ok\n", "")
        self.assertFalse(act("mt_export", label="x")["ok"])


if __name__ == "__main__":
    unittest.main()
