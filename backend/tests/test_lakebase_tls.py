import hashlib
import ssl
import sys
from types import SimpleNamespace

import certifi
import pytest

from backend.services.lakebase import _lakebase_ssl_context
from scripts.deploy_lib.lakebase import grant_database_permissions
from scripts.setup_lakebase import _grant_permissions


def test_lakebase_context_verifies_identity_without_affected_root():
    context = _lakebase_ssl_context()
    roots = {
        hashlib.sha256(cert).hexdigest()
        for cert in context.get_ca_certs(binary_form=True)
    }

    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname
    affected_root = "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b"
    assert affected_root not in roots


@pytest.mark.parametrize("grant", [grant_database_permissions, _grant_permissions])
def test_lakebase_installers_verify_identity(monkeypatch, grant):
    params = {}

    class Connection:
        def execute(self, _sql):
            pass

        def close(self):
            pass

    def connect(**kwargs):
        params.update(kwargs)
        return Connection()

    monkeypatch.setitem(sys.modules, "psycopg", SimpleNamespace(connect=connect))
    postgres = SimpleNamespace(
        get_endpoint=lambda **_kw: SimpleNamespace(
            status=SimpleNamespace(hosts=SimpleNamespace(host="ep.example"))
        ),
        generate_database_credential=lambda **_kw: SimpleNamespace(token="unused"),
    )
    client = SimpleNamespace(postgres=postgres, config=SimpleNamespace(client_id="deployer"))

    assert grant(client, "project", "service-principal", endpoint_name="primary")
    assert params["sslmode"] == "verify-full"
    assert params["sslrootcert"] == certifi.where()
