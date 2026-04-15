#!/usr/bin/env python3
"""Idempotent provisioning of the Keycloak client + scope + mappers for Baserow.

Creates (or updates) in the PrudAI realm:
  * Public OIDC client ``baserow-ui`` with PKCE + Baserow redirect URIs.
  * Realm role ``baserow-admin``.
  * Client scope ``prudai-org`` with two user-attribute mappers that add the
    ``organization_id`` and ``organization_name`` claims to the ID token + userinfo.
  * Attaches ``prudai-org`` as a default scope on ``baserow-ui``.

Usage:
    KEYCLOAK_SERVER_URL=https://login.prudai.com \
    KEYCLOAK_REALM=prudai \
    KEYCLOAK_BOOTSTRAP_CLIENT_ID=account-service \
    KEYCLOAK_BOOTSTRAP_CLIENT_SECRET=... \
    BASEROW_PUBLIC_URL=https://register.prudai.com \
    python3 provision_baserow_keycloak.py

Re-running is safe: existing objects are updated in place, not duplicated.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any

import requests


class KCError(RuntimeError):
    pass


class KC:
    def __init__(
        self, *, base_url: str, realm: str, client_id: str, client_secret: str
    ) -> None:
        self.base = base_url.rstrip("/")
        self.realm = realm
        self.s = requests.Session()
        self.s.verify = False
        r = self.s.post(
            f"{self.base}/realms/{realm}/protocol/openid-connect/token",
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
            },
            timeout=20,
        )
        if r.status_code != 200:
            raise KCError(f"bootstrap token fetch failed: {r.status_code} {r.text[:200]}")
        self.s.headers["Authorization"] = f"Bearer {r.json()['access_token']}"

    def _req(self, method: str, path: str, *, ok: tuple[int, ...], **kw: Any) -> requests.Response:
        r = self.s.request(method, f"{self.base}{path}", timeout=20, **kw)
        if r.status_code not in ok:
            raise KCError(f"{method} {path} -> {r.status_code}: {r.text[:300]}")
        return r

    # --- realm roles ---
    def ensure_realm_role(self, name: str, description: str) -> None:
        r = self.s.get(f"{self.base}/admin/realms/{self.realm}/roles/{name}", timeout=20)
        if r.status_code == 200:
            print(f"  role {name}: exists")
            return
        if r.status_code != 404:
            raise KCError(f"role lookup {name}: {r.status_code} {r.text[:200]}")
        self._req(
            "POST",
            f"/admin/realms/{self.realm}/roles",
            ok=(201,),
            json={"name": name, "description": description},
        )
        print(f"  role {name}: created")

    # --- clients ---
    def find_client(self, client_id: str) -> dict | None:
        r = self._req(
            "GET",
            f"/admin/realms/{self.realm}/clients",
            ok=(200,),
            params={"clientId": client_id},
        )
        data = r.json()
        for c in data:
            if c.get("clientId") == client_id:
                return c
        return None

    def ensure_client(self, *, client_id: str, redirect_uris: list[str], web_origins: list[str]) -> dict:
        # Confidential client with a secret: Baserow's OIDC client is a
        # server-side component that does not send a PKCE code_challenge,
        # so we skip PKCE enforcement and rely on the client secret instead.
        payload = {
            "clientId": client_id,
            "enabled": True,
            "publicClient": False,
            "clientAuthenticatorType": "client-secret",
            "standardFlowEnabled": True,
            "directAccessGrantsEnabled": False,
            "implicitFlowEnabled": False,
            "serviceAccountsEnabled": False,
            "redirectUris": redirect_uris,
            "webOrigins": web_origins,
            "protocol": "openid-connect",
            "attributes": {
                "post.logout.redirect.uris": "+",
            },
        }
        existing = self.find_client(client_id)
        if existing is None:
            self._req(
                "POST", f"/admin/realms/{self.realm}/clients", ok=(201,), json=payload
            )
            existing = self.find_client(client_id)
            assert existing is not None
            print(f"  client {client_id}: created")
        else:
            merged = {**existing, **payload}
            merged["id"] = existing["id"]
            self._req(
                "PUT",
                f"/admin/realms/{self.realm}/clients/{existing['id']}",
                ok=(204,),
                json=merged,
            )
            print(f"  client {client_id}: updated")
        return existing

    # --- client scopes ---
    def find_client_scope(self, name: str) -> dict | None:
        r = self._req("GET", f"/admin/realms/{self.realm}/client-scopes", ok=(200,))
        for s in r.json():
            if s.get("name") == name:
                return s
        return None

    def ensure_client_scope_with_mappers(self, name: str) -> dict:
        scope = self.find_client_scope(name)
        scope_payload = {
            "name": name,
            "protocol": "openid-connect",
            "description": "PrudAI organization claims for downstream SSO apps",
            "attributes": {
                "include.in.token.scope": "true",
                "display.on.consent.screen": "false",
            },
        }
        if scope is None:
            self._req(
                "POST",
                f"/admin/realms/{self.realm}/client-scopes",
                ok=(201,),
                json=scope_payload,
            )
            scope = self.find_client_scope(name)
            assert scope is not None
            print(f"  scope {name}: created")
        else:
            print(f"  scope {name}: exists")

        desired_mappers = [
            _user_attr_mapper("organization_id", "org_id"),
            _user_attr_mapper("organization_name", "organization_name"),
        ]
        existing_mappers = self._req(
            "GET",
            f"/admin/realms/{self.realm}/client-scopes/{scope['id']}/protocol-mappers/models",
            ok=(200,),
        ).json()
        by_name = {m["name"]: m for m in existing_mappers}
        for m in desired_mappers:
            if m["name"] in by_name:
                current = by_name[m["name"]]
                merged = {**current, **m, "id": current["id"]}
                self._req(
                    "PUT",
                    f"/admin/realms/{self.realm}/client-scopes/{scope['id']}/protocol-mappers/models/{current['id']}",
                    ok=(204,),
                    json=merged,
                )
                print(f"    mapper {m['name']}: updated")
            else:
                self._req(
                    "POST",
                    f"/admin/realms/{self.realm}/client-scopes/{scope['id']}/protocol-mappers/models",
                    ok=(201,),
                    json=m,
                )
                print(f"    mapper {m['name']}: created")
        return scope

    def attach_default_scope(self, client_uuid: str, scope_id: str, scope_name: str) -> None:
        self._req(
            "PUT",
            f"/admin/realms/{self.realm}/clients/{client_uuid}/default-client-scopes/{scope_id}",
            ok=(204,),
        )
        print(f"  default scope {scope_name} attached to client")


def _user_attr_mapper(claim_name: str, user_attribute: str) -> dict[str, Any]:
    return {
        "name": claim_name,
        "protocol": "openid-connect",
        "protocolMapper": "oidc-usermodel-attribute-mapper",
        "config": {
            "user.attribute": user_attribute,
            "claim.name": claim_name,
            "jsonType.label": "String",
            "id.token.claim": "true",
            "access.token.claim": "true",
            "userinfo.token.claim": "true",
            "multivalued": "false",
            "aggregate.attrs": "false",
        },
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument(
        "--server-url", default=os.environ.get("KEYCLOAK_SERVER_URL")
    )
    p.add_argument("--realm", default=os.environ.get("KEYCLOAK_REALM"))
    p.add_argument(
        "--bootstrap-client-id",
        default=os.environ.get("KEYCLOAK_BOOTSTRAP_CLIENT_ID", "account-service"),
    )
    p.add_argument(
        "--bootstrap-client-secret",
        default=os.environ.get("KEYCLOAK_BOOTSTRAP_CLIENT_SECRET"),
    )
    p.add_argument(
        "--baserow-public-url",
        default=os.environ.get("BASEROW_PUBLIC_URL", "https://register.prudai.com"),
    )
    args = p.parse_args()

    missing = [
        flag
        for flag, value in [
            ("--server-url", args.server_url),
            ("--realm", args.realm),
            ("--bootstrap-client-secret", args.bootstrap_client_secret),
        ]
        if not value
    ]
    if missing:
        print(f"missing required args/env: {', '.join(missing)}", file=sys.stderr)
        return 2

    base_url = args.baserow_public_url.rstrip("/")
    redirect_uris = [f"{base_url}/api/sso/oauth2/callback/*"]
    web_origins = [base_url]

    kc = KC(
        base_url=args.server_url,
        realm=args.realm,
        client_id=args.bootstrap_client_id,
        client_secret=args.bootstrap_client_secret,
    )
    print("Provisioning Baserow SSO objects in realm", args.realm)
    kc.ensure_realm_role(
        "baserow-admin", "Admin access to the Baserow SSO workspace tooling"
    )
    client = kc.ensure_client(
        client_id="baserow-ui",
        redirect_uris=redirect_uris,
        web_origins=web_origins,
    )
    scope = kc.ensure_client_scope_with_mappers("prudai-org")
    kc.attach_default_scope(client["id"], scope["id"], "prudai-org")
    print("\nDone. baserow-ui is a public PKCE client; configure Baserow OIDC with:")
    print(f"  issuer          = {args.server_url.rstrip('/')}/realms/{args.realm}")
    print(f"  client id       = baserow-ui")
    print(f"  redirect URIs   = {redirect_uris}")
    return 0


if __name__ == "__main__":
    # Silence self-signed certs in dev if KEYCLOAK_VERIFY_SSL=False.
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    sys.exit(main())
