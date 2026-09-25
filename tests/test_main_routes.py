"""Route-level tests for the session-authenticated multi-user UI.

The app is built through the ``create_app`` factory with injected settings
and a temp SQLite store, so no env vars, Discord connection, or network
access is needed. Multiple users are simulated with separate TestClient
instances (their own cookie jars) sharing one app/store.
"""

from __future__ import annotations

from dataclasses import replace

from fastapi.testclient import TestClient

from app.main import create_app
from app.models import RelayMapping
from conftest import ADMIN_PASSWORD, ALICE_PASSWORD, BOB_PASSWORD, login

VALID_URL = "https://discord.com/api/webhooks/1001/secrettok-abcdefghijklmn"
OTHER_URL = "https://discord.com/api/webhooks/1002/secondtok-abcdefghijklmn"
CHANNEL = "123456789012345678"


def mapping_form(name="announcements", channel_id=CHANNEL, url=VALID_URL, **extra) -> dict:
    return {
        "name": name,
        "source_channel_id": channel_id,
        "target_webhook_url": url,
        **extra,
    }


def add_mapping(store, owner_id: str, *, name="mine", channel=int(CHANNEL), url=VALID_URL):
    """Insert a mapping straight through the store (setup helper)."""
    return store.add_mapping(
        RelayMapping(
            name=name,
            source_channel_id=channel,
            target_webhook_url=url,
            owner_user_id=owner_id,
        )
    )


# --------------------------------------------------------------------- #
# Public / unauthenticated behaviour
# --------------------------------------------------------------------- #


def test_health_is_public_and_minimal(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_login_page_is_public(client):
    response = client.get("/login")
    assert response.status_code == 200
    assert "Вход" in response.text


def test_dashboard_redirects_to_login_when_anonymous(client):
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"] == "/login"
    # Following the redirect lands on the login form.
    followed = client.get("/")
    assert followed.status_code == 200
    assert 'action="/login"' in followed.text


def test_api_routes_return_401_when_anonymous(client):
    # JSON/API guard: 401.
    assert client.get("/status").status_code == 401
    # HTML guards: browsers get redirected to /login instead.
    for page in ("/", "/account/password", "/admin/users", "/mappings/1/delete"):
        if page.endswith("/delete"):
            response = client.post(page, follow_redirects=False)
        else:
            response = client.get(page, follow_redirects=False)
        assert response.status_code == 302, page
        assert response.headers["location"] == "/login", page


# --------------------------------------------------------------------- #
# Login / logout
# --------------------------------------------------------------------- #


def test_login_bad_credentials_generic_message(client):
    wrong_password = login(client, "admin", "totally-wrong")
    assert wrong_password.status_code == 401
    assert "Неверный логин или пароль" in wrong_password.text
    assert "relay_session" not in wrong_password.headers.get("set-cookie", "")

    unknown_user = login(client, "nobody-at-all", "whatever123")
    assert unknown_user.status_code == 401
    # The same generic wording: the UI never reveals whether the user exists.
    assert "Неверный логин или пароль" in unknown_user.text


def test_login_good_credentials_sets_secure_cookie(client):
    response = login(client, "admin", ADMIN_PASSWORD)
    assert response.status_code == 303
    assert response.headers["location"] == "/"

    cookie_header = response.headers["set-cookie"]
    assert "relay_session=" in cookie_header
    assert "HttpOnly" in cookie_header
    assert "SameSite=lax" in cookie_header
    # Plain http test server -> the Secure flag must not be set.
    assert "Secure" not in cookie_header

    dashboard = client.get("/")
    assert dashboard.status_code == 200
    assert "Мои релеи" in dashboard.text
    assert "admin" in dashboard.text  # current username visible


def test_login_when_already_logged_in_redirects_home(admin_client):
    response = admin_client.get("/login", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"] == "/"


def test_logout_deletes_session_and_clears_cookie(admin_client, store):
    token = admin_client.cookies.get("relay_session")
    assert token is not None

    response = admin_client.post("/logout", follow_redirects=False)
    assert response.status_code == 303

    # Session row is gone server-side, cookie is gone client-side.
    assert store.get_user_by_token(token) is None
    assert not admin_client.cookies.get("relay_session")
    assert admin_client.get("/", follow_redirects=False).status_code == 302


# --------------------------------------------------------------------- #
# Dashboard: ownership + isolation
# --------------------------------------------------------------------- #


def test_dashboard_empty_for_new_user(app, alice):
    with TestClient(app) as alice_client:
        assert login(alice_client, "alice", ALICE_PASSWORD).status_code == 303
        page = alice_client.get("/")
        assert page.status_code == 200
        assert "Пока нет релеев" in page.text


def test_user_sees_only_own_mappings(app, store, alice, bob, second_client):
    with TestClient(app) as alice_client:
        assert login(alice_client, "alice", ALICE_PASSWORD).status_code == 303
        assert login(second_client, "bob", BOB_PASSWORD).status_code == 303

        alice_client.post(
            "/mappings", data=mapping_form(name="alice-relay"), follow_redirects=True
        )
        second_client.post(
            "/mappings",
            data=mapping_form(name="bob-relay", channel_id="222", url=OTHER_URL),
            follow_redirects=True,
        )

        alice_page = alice_client.get("/")
        assert "alice-relay" in alice_page.text
        assert "bob-relay" not in alice_page.text
        assert "Все релеи пользователей" not in alice_page.text  # admin-only section

        bob_page = second_client.get("/")
        assert "bob-relay" in bob_page.text
        assert "alice-relay" not in bob_page.text


def test_admin_dashboard_shows_all_mappings_with_owners(
    admin_client, second_client, store, alice
):
    assert login(second_client, "alice", ALICE_PASSWORD).status_code == 303
    second_client.post(
        "/mappings", data=mapping_form(name="alice-relay"), follow_redirects=True
    )
    admin_client.post(
        "/mappings",
        data=mapping_form(name="admin-relay", channel_id="222", url=OTHER_URL),
        follow_redirects=True,
    )

    page = admin_client.get("/")
    assert "Все релеи пользователей" in page.text
    assert "Владелец" in page.text
    assert "alice-relay" in page.text
    assert "admin-relay" in page.text
    # Owner column rendered in the admin section.
    assert "<b>alice</b>" in page.text


def test_mapping_owner_comes_from_session_not_form(app, store, alice):
    admin_id = store.get_user_by_username("admin").id
    with TestClient(app) as alice_client:
        assert login(alice_client, "alice", ALICE_PASSWORD).status_code == 303
        alice_client.post(
            "/mappings",
            data=mapping_form(name="sneaky", owner_user_id=admin_id),  # spoofed field
            follow_redirects=True,
        )
    created = store.list_mappings(alice.id)[0]
    assert created.name == "sneaky"
    assert created.owner_user_id == alice.id
    assert store.count_mappings(admin_id) == 0


def test_duplicate_channel_for_same_user_blocked(app, store, alice):
    with TestClient(app) as alice_client:
        assert login(alice_client, "alice", ALICE_PASSWORD).status_code == 303
        alice_client.post("/mappings", data=mapping_form(), follow_redirects=True)
        response = alice_client.post(
            "/mappings", data=mapping_form(name="dupe"), follow_redirects=True
        )
        assert "already exists" in response.text
        assert store.count_mappings(alice.id) == 1


def test_different_users_same_channel_allowed(app, store, alice, bob, second_client):
    with TestClient(app) as alice_client:
        assert login(alice_client, "alice", ALICE_PASSWORD).status_code == 303
        alice_client.post("/mappings", data=mapping_form(), follow_redirects=False)

        assert login(second_client, "bob", BOB_PASSWORD).status_code == 303
        response = second_client.post(
            "/mappings", data=mapping_form(name="bob-same-channel", url=OTHER_URL),
            follow_redirects=True,
        )
        assert response.status_code == 200
        assert "already exists" not in response.text
    assert len(store.get_all_by_channel(int(CHANNEL))) == 2


def test_invalid_webhook_url_and_channel_rejected(app, store, alice):
    with TestClient(app) as alice_client:
        assert login(alice_client, "alice", ALICE_PASSWORD).status_code == 303
        bad_url = alice_client.post(
            "/mappings",
            data=mapping_form(url="https://evil.example.com/steal"),
            follow_redirects=True,
        )
        assert "Invalid mapping" in bad_url.text
        bad_channel = alice_client.post(
            "/mappings",
            data=mapping_form(channel_id="not-a-number"),
            follow_redirects=True,
        )
        assert "Invalid mapping" in bad_channel.text
        assert store.count_mappings(alice.id) == 0


# --------------------------------------------------------------------- #
# Delete / test access checks
# --------------------------------------------------------------------- #


def test_delete_own_mapping(app, store, admin_client):
    admin = store.get_user_by_username("admin")
    mapping = add_mapping(store, admin.id, name="gone", channel=42)
    response = admin_client.post(f"/mappings/{mapping.id}/delete", follow_redirects=True)
    assert "Deleted mapping" in response.text
    assert store.get_mapping(mapping.id) is None


def test_user_cannot_delete_foreign_mapping(app, store, alice, bob, second_client):
    m = add_mapping(store, alice.id)
    assert login(second_client, "bob", BOB_PASSWORD).status_code == 303
    response = second_client.post(f"/mappings/{m.id}/delete", follow_redirects=True)
    # Same "not found" wording as for a truly-missing id: no existence leak.
    assert "not found" in response.text
    assert store.get_mapping(m.id) is not None
    # Unknown id yields the same message.
    missing = second_client.post("/mappings/nope/delete", follow_redirects=True)
    assert "not found" in missing.text


def test_admin_can_delete_any_mapping(admin_client, store, alice):
    m = add_mapping(store, alice.id, name="by-admin")
    response = admin_client.post(f"/mappings/{m.id}/delete", follow_redirects=True)
    assert "Deleted mapping" in response.text
    assert store.get_mapping(m.id) is None

    # The explicit admin route works too.
    m3 = add_mapping(store, alice.id, name="admin-del", channel=999)
    response = admin_client.post(f"/admin/mappings/{m3.id}/delete", follow_redirects=True)
    assert "Deleted mapping" in response.text
    assert store.get_mapping(m3.id) is None


def test_test_endpoint_respects_ownership(
    app, store, alice, bob, second_client, monkeypatch
):
    calls: list[str] = []

    async def fake_send(webhook_url, **kwargs):
        calls.append(webhook_url)
        return True

    monkeypatch.setattr("app.main.send_to_webhook", fake_send)

    m = add_mapping(store, alice.id)
    assert login(second_client, "bob", BOB_PASSWORD).status_code == 303
    response = second_client.post(f"/mappings/{m.id}/test", follow_redirects=True)
    assert "not found" in response.text
    assert calls == []  # a foreign mapping is never touched

    with TestClient(app) as alice_client:
        assert login(alice_client, "alice", ALICE_PASSWORD).status_code == 303
        response = alice_client.post(f"/mappings/{m.id}/test", follow_redirects=True)
        assert "Test message sent" in response.text
    assert calls == [VALID_URL]


# --------------------------------------------------------------------- #
# Secrets never leak
# --------------------------------------------------------------------- #


def test_dashboard_masks_webhook_token(app, store, alice):
    with TestClient(app) as alice_client:
        assert login(alice_client, "alice", ALICE_PASSWORD).status_code == 303
        alice_client.post("/mappings", data=mapping_form(), follow_redirects=True)
        page = alice_client.get("/")
        assert "secretto…" in page.text  # masked preview
        assert "secrettok-abcdefghijklmn" not in page.text


def test_status_json_is_scoped_and_secret_free(app, store, alice, admin_client):
    add_mapping(store, alice.id, name="a")

    # The bootstrap admin sees the cross-user total.
    status = admin_client.get("/status")
    assert status.status_code == 200
    data = status.json()
    assert data["user"] == {"username": "admin", "role": "admin"}
    assert data["bot_enabled"] is False  # no token in tests
    assert data["bot_running"] is False
    assert data["mappings"] == 1
    assert "webhooks/" not in status.text  # no webhook URLs at all
    assert "pbkdf2" not in status.text

    with TestClient(app) as alice_client:
        assert login(alice_client, "alice", ALICE_PASSWORD).status_code == 303
        alice_status = alice_client.get("/status").json()
        assert alice_status["user"] == {"username": "alice", "role": "user"}
        assert alice_status["mappings"] == 1  # her own mapping


# --------------------------------------------------------------------- #
# Admin user management
# --------------------------------------------------------------------- #


def test_admin_users_page_requires_admin(app, alice):
    with TestClient(app) as alice_client:
        assert login(alice_client, "alice", ALICE_PASSWORD).status_code == 303
        assert alice_client.get("/admin/users").status_code == 403


def test_admin_can_create_user_who_can_then_login(app, admin_client, store):
    response = admin_client.post(
        "/admin/users",
        data={"username": "carol", "password": "carol-pass-123", "role": "user"},
        follow_redirects=True,
    )
    assert "создан" in response.text
    assert store.get_user_by_username("carol") is not None

    with TestClient(app) as carol_client:
        assert login(carol_client, "carol", "carol-pass-123").status_code == 303
        assert carol_client.get("/").status_code == 200


def test_admin_user_form_validations(admin_client, store):
    short = admin_client.post(
        "/admin/users",
        data={"username": "dave", "password": "short", "role": "user"},
        follow_redirects=True,
    )
    assert "не короче" in short.text
    dup = admin_client.post(
        "/admin/users",
        data={"username": "admin", "password": "whatever123", "role": "user"},
        follow_redirects=True,
    )
    assert "уже существует" in dup.text
    assert store.get_user_by_username("dave") is None


def test_admin_cannot_disable_self(admin_client, store):
    admin = store.get_user_by_username("admin")
    response = admin_client.post(
        f"/admin/users/{admin.id}/toggle-active", follow_redirects=True
    )
    assert "Нельзя отключить собственную" in response.text
    assert store.get_user(admin.id).active is True


def test_disable_user_revokes_their_live_session(
    app, store, alice, admin_client, second_client
):
    assert login(second_client, "alice", ALICE_PASSWORD).status_code == 303
    assert second_client.get("/").status_code == 200

    response = admin_client.post(
        f"/admin/users/{alice.id}/toggle-active", follow_redirects=True
    )
    assert "отключён" in response.text
    # alice's existing session is dead immediately:
    assert second_client.get("/", follow_redirects=False).status_code == 302
    # ...and she cannot log in again until re-enabled.
    assert login(second_client, "alice", ALICE_PASSWORD).status_code == 401

    admin_client.post(f"/admin/users/{alice.id}/toggle-active", follow_redirects=True)
    assert login(second_client, "alice", ALICE_PASSWORD).status_code == 303


def test_admin_reset_password_revokes_sessions(
    app, store, alice, admin_client, second_client
):
    assert login(second_client, "alice", ALICE_PASSWORD).status_code == 303
    response = admin_client.post(
        f"/admin/users/{alice.id}/reset-password",
        data={"password": "new-alice-pass"},
        follow_redirects=True,
    )
    assert "обновлён" in response.text
    assert second_client.get("/", follow_redirects=False).status_code == 302
    assert login(second_client, "alice", ALICE_PASSWORD).status_code == 401
    assert login(second_client, "alice", "new-alice-pass").status_code == 303


def test_admin_users_page_does_not_leak_hashes(admin_client, store):
    store.create_user("erin", "erin-password-1")
    page = admin_client.get("/admin/users")
    assert "erin" in page.text
    assert "pbkdf2_sha256" not in page.text


# --------------------------------------------------------------------- #
# Self-service password change
# --------------------------------------------------------------------- #


def test_change_password_keeps_current_session_and_revokes_others(app, store, alice):
    with TestClient(app) as c1, TestClient(app) as c2:
        assert login(c1, "alice", ALICE_PASSWORD).status_code == 303
        assert login(c2, "alice", ALICE_PASSWORD).status_code == 303

        response = c1.post(
            "/account/password",
            data={
                "current_password": ALICE_PASSWORD,
                "new_password": "alice-new-pass-1",
                "confirm_password": "alice-new-pass-1",
            },
            follow_redirects=True,
        )
        assert "Пароль обновлён" in response.text

        # c1 stays logged in, c2 is kicked out.
        assert c1.get("/").status_code == 200
        assert c2.get("/", follow_redirects=False).status_code == 302

        # Old password no longer works; new one does.
        assert login(c2, "alice", ALICE_PASSWORD).status_code == 401
        assert login(c2, "alice", "alice-new-pass-1").status_code == 303


def test_change_password_validations(app, store, alice):
    with TestClient(app) as c1:
        assert login(c1, "alice", ALICE_PASSWORD).status_code == 303
        bad_current = c1.post(
            "/account/password",
            data={
                "current_password": "nope-nope-nope",
                "new_password": "aaaa-bbbb-1",
                "confirm_password": "aaaa-bbbb-1",
            },
            follow_redirects=True,
        )
        assert "Текущий пароль неверен" in bad_current.text
        mismatch = c1.post(
            "/account/password",
            data={
                "current_password": ALICE_PASSWORD,
                "new_password": "aaaa-bbbb-1",
                "confirm_password": "cccc-dddd-2",
            },
            follow_redirects=True,
        )
        assert "не совпадают" in mismatch.text
        short = c1.post(
            "/account/password",
            data={
                "current_password": ALICE_PASSWORD,
                "new_password": "tiny",
                "confirm_password": "tiny",
            },
            follow_redirects=True,
        )
        assert "не короче" in short.text
        assert store.authenticate("alice", ALICE_PASSWORD) is not None


# --------------------------------------------------------------------- #
# Bounded password cost (max length at every write boundary)
# --------------------------------------------------------------------- #


def test_login_rejects_oversized_password_with_generic_error(app, alice):
    with TestClient(app) as alice_client:
        huge = login(alice_client, "alice", "x" * 1500)
        assert huge.status_code == 401
        assert "Неверный логин или пароль" in huge.text
        # No hint about the length limit on the public login form.
        assert "1024" not in huge.text
        # The account is intact; the short correct password still works.
        assert login(alice_client, "alice", ALICE_PASSWORD).status_code == 303


def test_admin_create_user_rejects_too_long_password(admin_client, store):
    response = admin_client.post(
        "/admin/users",
        data={"username": "longy", "password": "x" * 1500, "role": "user"},
        follow_redirects=True,
    )
    assert "не длиннее 1024" in response.text
    assert store.get_user_by_username("longy") is None


def test_change_password_rejects_too_long_new_password(app, store, alice):
    with TestClient(app) as c1:
        assert login(c1, "alice", ALICE_PASSWORD).status_code == 303
        response = c1.post(
            "/account/password",
            data={
                "current_password": ALICE_PASSWORD,
                "new_password": "x" * 1500,
                "confirm_password": "x" * 1500,
            },
            follow_redirects=True,
        )
        assert "не длиннее 1024" in response.text
        # Old password untouched.
        assert store.authenticate("alice", ALICE_PASSWORD) is not None


def test_admin_reset_password_rejects_too_long(admin_client, store, alice):
    response = admin_client.post(
        f"/admin/users/{alice.id}/reset-password",
        data={"password": "x" * 1500},
        follow_redirects=True,
    )
    assert "не длиннее 1024" in response.text
    assert store.authenticate("alice", ALICE_PASSWORD) is not None


# --------------------------------------------------------------------- #
# Disabled users: relay stops, admin oversight continues
# --------------------------------------------------------------------- #


def test_admin_dashboard_still_lists_disabled_users_mappings(
    admin_client, store, alice
):
    add_mapping(store, alice.id, name="paused-relay")
    store.set_active(alice.id, False)
    page = admin_client.get("/")
    assert "paused-relay" in page.text
    assert "<b>alice</b>" in page.text


# --------------------------------------------------------------------- #
# SESSION_COOKIE_SECURE
# --------------------------------------------------------------------- #


def test_cookie_secure_true_forces_flag_on_plain_http(settings, store):
    app2 = create_app(settings=replace(settings, session_cookie_secure="true"), store=store)
    with TestClient(app2) as c:
        response = login(c, "admin", ADMIN_PASSWORD)
        assert response.status_code == 303
        assert "Secure" in response.headers["set-cookie"]


def test_cookie_secure_auto_sets_flag_behind_https_proxy(settings, store):
    app2 = create_app(settings=settings, store=store)  # auto by default
    with TestClient(app2) as c:
        response = c.post(
            "/login",
            data={"username": "admin", "password": ADMIN_PASSWORD},
            headers={"x-forwarded-proto": "https"},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert "Secure" in response.headers["set-cookie"]


def test_cookie_secure_false_never_sets_flag_even_over_https(settings, store):
    app2 = create_app(settings=replace(settings, session_cookie_secure="false"), store=store)
    with TestClient(app2) as c:
        response = c.post(
            "/login",
            data={"username": "admin", "password": ADMIN_PASSWORD},
            headers={"x-forwarded-proto": "https"},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert "Secure" not in response.headers["set-cookie"]
