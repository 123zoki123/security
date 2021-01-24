import pytest
import datetime
from django.urls import reverse
from core.models import Scan, User, Asset, Vulnerability, Status, Severity


@pytest.mark.django_db
def test_user_creation():
    user = User.objects.create(
        username="zoki",
        email="zoranstoilov@yahoo.com",
        first_name="Zoran",
        last_name="Stoilov",
    )

    assert user.username == "zoki"
    assert user.email == "zoranstoilov@yahoo.com"
    assert user.first_name == "Zoran"
    assert user.last_name == "Stoilov"


@pytest.mark.django_db
def test_asset_creation():
    asset = Asset.objects.create(
        name="asset",
        description="does something",
        created="2018-09-03T13:19:33.000Z",
    )

    assert asset.name == "asset"
    assert asset.description == "does something"


@pytest.mark.django_db
def test_scan_creation():
    user = User.objects.create(
        username="zoki",
        email="zoranstoilov@yahoo.com",
        first_name="Zoran",
        last_name="Stoilov",
    )
    asset = Asset.objects.create(
        name="asset",
        description="does something",
        created="2018-09-03T13:19:33.000Z",
    )
    scan = Scan.objects.create(
        started_at="2020-01-01T00:00:00.000Z",
        finished_at="2020-01-01T00:12:56.000Z",
        requested_by=user,
        name="Monthly Vulnerability Scan",
        status=Status.COMPLETED,
        scanners=["Nexpose", "Openvas"],
        severity_counts={
            "critical": 0,
            "high": 0,
            "medium": 1,
            "low": 1,
            "information": 2,
        },
    )
    scan.assets.add(asset)
    scan.save()

    assert scan.name == "Monthly Vulnerability Scan"
    assert scan.status == Status.COMPLETED
    assert len(scan.scanners) == 2
    assert len(scan.severity_counts) == 5
    assert scan.requested_by.username == "zoki"
    assert len(scan.assets.all()) == 1
    assert scan.assets.all()[0].name == "asset"


@pytest.mark.django_db
def test_vulnerability_creation():
    asset = Asset.objects.create(
        name="asset",
        description="does something",
        created="2018-09-03T13:19:33.000Z",
    )
    user = User.objects.create(
        username="zoki",
        email="zoranstoilov@yahoo.com",
        first_name="Zoran",
        last_name="Stoilov",
    )
    scan = Scan.objects.create(
        started_at="2020-01-01T00:00:00.000Z",
        finished_at="2020-01-01T00:12:56.000Z",
        requested_by=user,
        name="Monthly Vulnerability Scan",
        status=Status.COMPLETED,
        scanners=["Nexpose", "Openvas"],
        severity_counts={
            "critical": 0,
            "high": 0,
            "medium": 1,
            "low": 1,
            "information": 2,
        },
    )
    vuln_obj = Vulnerability(
        severity=Severity.MEDIUM,
        name="HTTP TRACE / TRACK Methods Allowed",
        description="The remote web server supports the TRACE and/or TRACK methods.",
        solution="Disable these methods. Refer to the plugin output for more information.",
        cvss_base_score=5.0,
        references=[
            "http://www.cgisecurity.com/whitehat-mirror/WH-WhitePaper_XST_ebook.pdf"
        ],
    )
    vuln_obj.scan = scan
    vuln_obj.save()
    vuln_obj.assets.add(asset)
    vuln_obj.save()

    assert vuln_obj.name == "HTTP TRACE / TRACK Methods Allowed"
    assert vuln_obj.severity == Severity.MEDIUM
    assert (
        vuln_obj.description
        == "The remote web server supports the TRACE and/or TRACK methods."
    )
    assert len(vuln_obj.references) == 1
    assert len(vuln_obj.assets.all()) == 1
    assert vuln_obj.scan.name == "Monthly Vulnerability Scan"
    assert vuln_obj.assets.all()[0].name == "asset"