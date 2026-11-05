#!/usr/bin/env python3
"""Exercise Bee Panel against a disposable reserved-domain fixture on a test server.

Requires BEE_SMOKE_PASSWORD; defaults to the panel on localhost. Creates resources
under .invalid, validates Nginx behavior, and removes every created resource.
"""
import base64
import http.client
import json
import os
import pwd
import shutil
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

BASE = os.environ.get("BEE_SMOKE_URL", "http://127.0.0.1:8443/api/v2")
USERNAME = os.environ.get("BEE_SMOKE_USERNAME", "admin")
PASSWORD = os.environ.get("BEE_SMOKE_PASSWORD")
if not PASSWORD:
    sys.exit("Set BEE_SMOKE_PASSWORD")


def request(path, method="GET", data=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    payload = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(BASE + "/" + path, data=payload, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"{method} {path}: {error.code} {error.read().decode()}") from error


def http_response(port, host, path="/", authorization=None, secure=False):
    if secure:
        import ssl
        conn = http.client.HTTPSConnection("127.0.0.1", port, context=ssl._create_unverified_context(), timeout=8)
    else:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=8)
    headers = {"Host": host}
    if authorization:
        headers["Authorization"] = "Basic " + base64.b64encode(authorization.encode()).decode()
    conn.request("GET", path, headers=headers)
    response = conn.getresponse()
    result = (response.status, dict(response.getheaders()), response.read().decode(errors="replace"))
    conn.close()
    return result


def wait_response(port, host, expected, path="/", authorization=None, secure=False):
    result = None
    for _ in range(20):
        try:
            result = http_response(port, host, path, authorization, secure)
            if result[0] == expected:
                return result
        except OSError:
            pass
        time.sleep(0.2)
    return result


def free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def main():
    token = request("auth/login", "POST", {"username": USERNAME, "password": PASSWORD})["token"]
    me = request("auth/me", token=token)
    assert me["role"] == "admin", "Smoke test requires admin"
    metrics = request("metrics", token=token)
    assert metrics["nginx_running"], "Nginx is not running"
    for path in ("proxy-hosts", "redirections", "streams", "dead-hosts", "access-lists", "certificates", "users", "audit-logs"):
        assert isinstance(request(path, token=token), list), path
    print("PASS auth, metrics and all eight list endpoints")

    stamp = str(int(time.time()))
    created = []
    created_user_name = None
    tenant_token = None
    domain = "smoke-" + stamp + ".invalid"
    try:
        access = request("access-lists", "POST", {
            "name": "smoke-" + stamp, "items": [{"directive": "allow", "address": "127.0.0.1"}],
            "auth_users": [{"username": "smoke", "password": "temporary-smoke-pass"}],
            "satisfy_any": False, "pass_auth_to_host": False,
        }, token)
        created.append(("access-lists", access["id"]))
        db = sqlite3.connect("/etc/bee-panel/bee-panel.db")
        stored_hash = db.execute("SELECT password_hash FROM access_list_auths WHERE access_list_id = ?", (access["id"],)).fetchone()[0]
        db.close()
        assert stored_hash.startswith("$6$") and "temporary-smoke-pass" not in stored_hash
        print("PASS access list and hashed Basic Auth")

        proxy = request("proxy-hosts", "POST", {
            "domain_names": [domain], "forward_scheme": "http", "forward_host": "127.0.0.1", "forward_port": 8443,
            "access_list_id": access["id"], "caching_enabled": True, "websocket_support": True,
        }, token)
        created.append(("proxy-hosts", proxy["id"]))
        status, headers, body = wait_response(80, domain, 401)
        assert status == 401, (status, headers, body[:200])
        status, headers, body = wait_response(80, domain, 200, authorization="smoke:temporary-smoke-pass")
        assert status == 200, (status, headers, body[:200])
        challenge_token = "smoke-" + stamp
        challenge_path = Path("/var/lib/bee-panel/acme-challenges") / challenge_token
        challenge_path.write_text("challenge-ok")
        try:
            assert wait_response(80, domain, 200, "/.well-known/acme-challenge/" + challenge_token)[2] == "challenge-ok"
            assert wait_response(80, "unmatched-" + domain, 200, "/.well-known/acme-challenge/" + challenge_token)[2] == "challenge-ok"
        finally:
            challenge_path.unlink(missing_ok=True)
        print("PASS proxy, cache zone, Basic Auth and ACME challenge routing")

        redir_domain = "redirect-" + domain
        redir = request("redirections", "POST", {
            "domain_names": [redir_domain], "forward_http_code": 308,
            "forward_scheme": "https", "forward_domain": "example.com", "preserve_path": True,
        }, token)
        created.append(("redirections", redir["id"]))
        status, headers, _ = wait_response(80, redir_domain, 308, "/smoke/path")
        assert status == 308 and headers.get("Location") == "https://example.com/smoke/path", (status, headers)
        print("PASS redirection and path preservation")

        dead_domain = "dead-" + domain
        dead = request("dead-hosts", "POST", {"domain_names": [dead_domain], "status_code": 503, "custom_message": "Smoke maintenance"}, token)
        created.append(("dead-hosts", dead["id"]))
        status, _, body = wait_response(80, dead_domain, 503)
        assert status == 503 and "Smoke maintenance" in body
        print("PASS maintenance host")

        incoming = free_port()
        stream = request("streams", "POST", {"incoming_port": incoming, "forward_host": "127.0.0.1", "forward_port": 8443, "tcp_forwarding": True, "udp_forwarding": False}, token)
        created.append(("streams", stream["id"]))
        assert wait_response(incoming, "127.0.0.1", 200)[0] == 200
        print("PASS TCP stream")

        with tempfile.TemporaryDirectory() as directory:
            cert_path = directory + "/cert.pem"
            key_path = directory + "/key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=" + domain,
                            "-addext", "subjectAltName=DNS:" + domain, "-keyout", key_path, "-out", cert_path],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            cert = request("certificates/custom", "POST", {"nice_name": "smoke-cert-" + stamp,
                           "cert_pem": open(cert_path).read(), "key_pem": open(key_path).read()}, token)
        created.append(("certificates", cert["id"]))
        assert domain in cert["domain_names"] and cert["expires_at"]
        ssl_domain = "ssl-" + domain
        ssl_host = request("dead-hosts", "POST", {"domain_names": [ssl_domain], "status_code": 404,
                                                    "ssl_certificate_id": cert["id"]}, token)
        created.append(("dead-hosts", ssl_host["id"]))
        assert wait_response(443, ssl_domain, 404, secure=True)[0] == 404
        print("PASS custom certificate validation and HTTPS host")

        user_name = "bp_smoke_" + stamp[-6:]
        created_user_name = user_name
        user = request("users", "POST", {"username": user_name, "role": "tenant", "shell_mode": "sftp_only"}, token)
        created.append(("users", user["user"]["id"]))
        subprocess.run(["id", "-u", user_name], stdout=subprocess.DEVNULL, check=True)
        ssh_config = subprocess.check_output(["sshd", "-T", "-C", f"user={user_name},host=localhost,addr=127.0.0.1"], text=True)
        assert "forcecommand internal-sftp" in ssh_config.lower()
        cred = request(f"users/{user['user']['id']}/credentials", token=token)
        assert cred["public_key"] == user["ssh_credentials"]["public_key"]
        rotated = request(f"users/{user['user']['id']}/rotate-ssh", "POST", token=token)
        assert rotated["public_key"] != cred["public_key"]
        tenant_token = request("auth/login", "POST", {"username": user_name, "password": user["ssh_credentials"]["initial_password"]})["token"]
        try:
            forbidden = request("proxy-hosts", "POST", {"domain_names": ["blocked-" + domain],
                "forward_host": "127.0.0.1", "forward_port": 8443,
                "advanced_config": "add_header X-Smoke blocked;"}, tenant_token)
        except RuntimeError as error:
            assert "403" in str(error), error
        else:
            created.append(("proxy-hosts", forbidden["id"]))
            raise AssertionError("Tenant could inject Nginx directives")
        changed_password = "SmokeChangedPassword" + stamp[-6:]
        request("auth/change-password", "POST", {"current_password": user["ssh_credentials"]["initial_password"],
                                                   "new_password": changed_password}, tenant_token)
        assert request("auth/login", "POST", {"username": user_name, "password": changed_password})["token"]
        assert request(f"users/{user['user']['id']}/credentials", token=token)["initial_password"] is None
        print("PASS Linux user provisioning, SFTP restriction, SSH rotation and password change")

        subprocess.run(["nginx", "-t"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True)
        assert request("audit-logs", token=token)
        print("PASS Nginx syntax and audit endpoint")
    finally:
        cleanup_errors = []
        for kind, identifier in reversed(created):
            try:
                request(f"{kind}/{identifier}", "DELETE", token=token)
            except Exception as error:
                cleanup_errors.append((kind, identifier, str(error)))
        if created_user_name:
            try:
                pwd.getpwnam(created_user_name)
            except KeyError:
                for base in (Path("/home"), Path("/var/www/vhosts")):
                    path = base / created_user_name
                    if path.is_dir():
                        shutil.rmtree(path)
            else:
                cleanup_errors.append(("linux user", created_user_name, "still exists"))
        subprocess.run(["nginx", "-t"], check=True, stdout=subprocess.DEVNULL)
        if cleanup_errors:
            raise RuntimeError("Cleanup failed: " + repr(cleanup_errors))
        print("Cleanup complete")
    if tenant_token:
        try:
            request("auth/me", token=tenant_token)
        except RuntimeError as error:
            assert "401" in str(error), error
            print("PASS deleted-user token revoked")
        else:
            raise AssertionError("Deleted-user token remained valid")


if __name__ == "__main__":
    main()
