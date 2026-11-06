from forgeverity import keys
from forgeverity.cli import _find_key_file, _key_resolver


def test_keys_in_secrets_root_are_available_for_trust_and_signing(tmp_path):
    private = keys.generate_private()
    record = keys.generate_key_record(private, "receipt", 0, 10000)
    pem = keys.private_pem(private)
    keys.save_key(tmp_path / "secrets" / "receipt.json", record, pem)

    assert _find_key_file(tmp_path, record["id"]) == (record, pem)
    assert keys.private_pem(_key_resolver(tmp_path)(record["id"])) == pem
