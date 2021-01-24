import pytest
from datetime import timezone
from django.conf import settings
from django.utils.dateparse import parse_datetime
from core.models import Status, Severity


@pytest.mark.django_db
def test_list_users(client, add_user):

    user1 = add_user("zoki1", "zoranstoilov@yahoo.com", "zoran", "stoilov")
    user2 = add_user("zoki2", "zoranstoilov2@yahoo.com", "zoran2", "stoilov2")

    resp = client.get("/api/v1/users/")
    assert resp.status_code == 200
    assert len(resp.json()) == 2
    assert resp.json()[0]["id"] == user1.id
    assert resp.json()[0]["email"] == user1.email
    assert resp.json()[0]["first_name"] == user1.first_name
    assert resp.json()[0]["last_name"] == user1.last_name


@pytest.mark.django_db
def test_get_single_user(client, add_user):
    user1 = add_user("zoki1", "zoranstoilov@yahoo.com", "zoran", "stoilov")
    resp = client.get(f"/api/v1/users/{user1.id}/")
    assert resp.status_code == 200
    assert resp.json()["id"] == user1.id
    assert resp.json()["username"] == user1.username
    assert resp.json()["first_name"] == user1.first_name
    assert resp.json()["last_name"] == user1.last_name


@pytest.mark.django_db
def test_get_single_user_not_db_entries(client):
    resp = client.get(f"/api/v1/users/1/")
    assert resp.status_code == 404


@pytest.mark.django_db
def test_list_assets(client, add_asset):

    asset1 = add_asset("name", "description")
    asset2 = add_asset("name2", "description ")

    resp = client.get("/api/v1/assets/")
    assert resp.status_code == 200
    assert len(resp.json()) == 2
    assert resp.json()[1]["id"] == asset2.id
    assert resp.json()[1]["name"] == asset2.name
    assert resp.json()[1]["description"] == asset2.description
    assert resp.json()[1]["created"] == asset2.created.isoformat().replace(
        "+00:00", "Z"
    )


@pytest.mark.django_db
def test_get_single_asset(client, add_asset):
    asset1 = add_asset("name", "description")
    resp = client.get(f"/api/v1/assets/{asset1.id}/")

    assert resp.status_code == 200
    assert resp.json()["id"] == asset1.id
    assert resp.json()["name"] == asset1.name
    assert resp.json()["description"] == asset1.description
    assert resp.json()["created"] == asset1.created.isoformat().replace("+00:00", "Z")


@pytest.mark.django_db
def test_get_single_asset_no_db_entries(client):
    resp = client.get(f"/api/v1/assets/1/")
    assert resp.status_code == 404


@pytest.mark.django_db
def test_list_scans(client, add_user, add_asset, add_scan):
    user1 = add_user("zoki1", "zoranstoilov@yahoo.com", "zoran", "stoilov")
    asset1 = add_asset("name", "description")
    asset2 = add_asset("name2", "description ")

    scan = add_scan(
        name="scan",
        scanners=["Nexpose", "Openvas"],
        severity_counts={
            "critical": 0,
            "high": 0,
            "medium": 1,
            "low": 1,
            "information": 2,
        },
        requested_by=user1,
        assets=[asset1, asset2],
    )
    scan2 = add_scan(
        name="scan2",
        scanners=["Nexpose1", "Openvas1"],
        severity_counts={
            "critical": 5,
            "high": 5,
            "medium": 1,
            "low": 1,
            "information": 2,
        },
        requested_by=user1,
        assets=[asset2],
    )

    resp = client.get("/api/v1/scans/")

    assert resp.status_code == 200
    assert len(resp.json()) == 2

    assert resp.json()[0]["id"] == scan.id
    assert resp.json()[0]["name"] == scan.name
    assert (
        resp.json()[0]["status"] == Status.COMPLETED.value
    )  # that's default in add_scan
    assert resp.json()[0]["scanners"] == scan.scanners
    assert resp.json()[0]["severity_counts"] == scan.severity_counts

    assert len(resp.json()[0]["assets_scanned"]) == 2
    assert resp.json()[0]["assets_scanned"] == [
        f"http://testserver/api/v1/assets/{asset1.id}/",
        f"http://testserver/api/v1/assets/{asset2.id}/",
    ]
    assert (
        resp.json()[0]["requested_by"] == f"http://testserver/api/v1/users/{user1.id}/"
    )


@pytest.mark.django_db
def test_get_single_scan(client, add_user, add_asset, add_scan):
    user1 = add_user("zoki1", "zoranstoilov@yahoo.com", "zoran", "stoilov")
    asset1 = add_asset("name", "description")
    asset2 = add_asset("name2", "description ")

    scan = add_scan(
        name="scan",
        scanners=["Nexpose", "Openvas"],
        severity_counts={
            "critical": 0,
            "high": 0,
            "medium": 1,
            "low": 1,
            "information": 2,
        },
        requested_by=user1,
        assets=[asset1, asset2],
    )

    resp = client.get(f"/api/v1/scans/{scan.id}/")
    assert resp.status_code == 200
    assert resp.json()["id"] == scan.id
    assert resp.json()["name"] == scan.name
    assert resp.json()["status"] == Status.COMPLETED.value  # that's default in add_scan
    assert resp.json()["scanners"] == scan.scanners
    assert resp.json()["severity_counts"] == scan.severity_counts

    assert len(resp.json()["assets_scanned"]) == 2
    assert resp.json()["assets_scanned"] == [
        f"http://testserver/api/v1/assets/{asset1.id}/",
        f"http://testserver/api/v1/assets/{asset2.id}/",
    ]
    assert resp.json()["requested_by"] == f"http://testserver/api/v1/users/{user1.id}/"


@pytest.mark.django_db
def test_get_single_scan_no_db_entries(client):
    resp = client.get(f"/api/v1/scans/1/")
    assert resp.status_code == 404


@pytest.mark.django_db
def test_list_vulnerabilities(
    client,
    add_user,
    add_scan,
    add_asset,
    add_vulnerability,
):
    user1 = add_user("zoki1", "zoranstoilov@yahoo.com", "zoran", "stoilov")
    asset1 = add_asset("name", "description")
    asset2 = add_asset("name2", "description ")

    scan = add_scan(
        name="scan",
        scanners=["Nexpose", "Openvas"],
        severity_counts={
            "critical": 0,
            "high": 0,
            "medium": 1,
            "low": 1,
            "information": 2,
        },
        requested_by=user1,
        assets=[asset1, asset2],
    )

    vuln = add_vulnerability(
        name="name",
        description="description",
        solution="solution",
        references=[
            "http://www.cgisecurity.com/whitehat-mirror/WH-WhitePaper_XST_ebook.pdf"
        ],
        cvss_base_score=4.6,
        scan=scan,
        assets=[asset1, asset2],
    )

    resp = client.get("/api/v1/vulnerabilities/")
    assert resp.status_code == 200
    assert len(resp.json()) == 1
    assert resp.json()[0]["id"] == vuln.id
    assert resp.json()[0]["name"] == vuln.name
    assert resp.json()[0]["solution"] == vuln.solution
    assert resp.json()[0]["references"] == vuln.references
    assert resp.json()[0]["cvss_base_score"] == str(vuln.cvss_base_score)
    assert resp.json()[0]["from_scan"] == f"http://testserver/api/v1/scans/{scan.id}/"
    assert resp.json()[0]["affected_assets"] == [
        f"http://testserver/api/v1/assets/{asset1.id}/",
        f"http://testserver/api/v1/assets/{asset2.id}/",
    ]


@pytest.mark.django_db
def test_get_single_vulnerabily(
    client,
    add_user,
    add_scan,
    add_asset,
    add_vulnerability,
):
    user1 = add_user("zoki1", "zoranstoilov@yahoo.com", "zoran", "stoilov")
    asset1 = add_asset("name", "description")
    asset2 = add_asset("name2", "description ")

    scan = add_scan(
        name="scan",
        scanners=["Nexpose", "Openvas"],
        severity_counts={
            "critical": 0,
            "high": 0,
            "medium": 1,
            "low": 1,
            "information": 2,
        },
        requested_by=user1,
        assets=[asset1, asset2],
    )

    vuln = add_vulnerability(
        name="name",
        description="description",
        solution="solution",
        references=[
            "http://www.cgisecurity.com/whitehat-mirror/WH-WhitePaper_XST_ebook.pdf"
        ],
        cvss_base_score=4.6,
        scan=scan,
        assets=[asset1, asset2],
    )

    resp = client.get(f"/api/v1/vulnerabilities/{vuln.id}/")
    assert resp.status_code == 200

    assert resp.json()["id"] == vuln.id
    assert resp.json()["name"] == vuln.name
    assert resp.json()["solution"] == vuln.solution
    assert resp.json()["references"] == vuln.references
    assert resp.json()["cvss_base_score"] == str(vuln.cvss_base_score)
    assert resp.json()["from_scan"] == f"http://testserver/api/v1/scans/{scan.id}/"
    assert resp.json()["affected_assets"] == [
        f"http://testserver/api/v1/assets/{asset1.id}/",
        f"http://testserver/api/v1/assets/{asset2.id}/",
    ]


@pytest.mark.django_db
def test_get_single_vulnerability_no_db_entries(client):
    resp = client.get(f"/api/v1/vulnerabilities/1/")
    assert resp.status_code == 404