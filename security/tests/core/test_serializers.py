import pytest
from core.serializers import (
    UserSerializer,
    AssetSerializer,
    VulnerabilitySerializer,
    ScanSerializer,
)
from django.urls import reverse
from core.models import Status, Severity
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory


factory = APIRequestFactory()


@pytest.mark.django_db
def test_user_serializer(add_user):
    user = add_user("zoki", "zoranstoilov@yahoo.com", "Zoran", "Stoilov")
    req = factory.get(reverse("core:user-detail", kwargs={"pk": user.id}))
    context = {"request": Request(req)}

    user_ser = UserSerializer(user, context=context)

    assert user_ser.data["id"] == user.id
    assert user_ser.data["email"] == user.email
    assert user_ser.data["first_name"] == user.first_name
    assert user_ser.data["last_name"] == user.last_name
    assert user_ser.data["url"] == f"http://testserver/api/v1/users/{user.id}/"


@pytest.mark.django_db
def test_asset_serializer(add_asset):
    asset = add_asset("asset", "some description")
    req = factory.get(reverse("core:asset-detail", kwargs={"pk": asset.id}))
    context = {"request": Request(req)}

    asset_ser = AssetSerializer(asset, context=context)

    assert asset_ser.data["id"] == asset.id
    assert asset_ser.data["name"] == asset.name
    assert asset_ser.data["description"] == asset.description
    assert asset_ser.data["url"] == f"http://testserver/api/v1/assets/{asset.id}/"


@pytest.mark.django_db
def test_scan_serializer(add_user, add_asset, add_scan):
    user = add_user("zoki", "zoranstoilov@yahoo.com", "Zoran", "Stoilov")
    asset = add_asset("asset", "some description")

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
        requested_by=user,
        assets=[asset],
    )

    req = factory.get(reverse("core:scan-detail", kwargs={"pk": scan.id}))
    context = {"request": Request(req)}

    scan_ser = ScanSerializer(scan, context=context)

    assert scan_ser.data["id"] == scan.id
    assert scan_ser.data["name"] == scan.name
    assert scan_ser.data["severity_counts"] == {
        "critical": 0,
        "high": 0,
        "medium": 1,
        "low": 1,
        "information": 2,
    }
    assert scan_ser.data["status"] == Status.COMPLETED.value
    assert scan_ser.data["requested_by"] == f"http://testserver/api/v1/users/{user.id}/"
    assert (
        scan_ser.data["assets_scanned"][0]
        == f"http://testserver/api/v1/assets/{asset.id}/"
    )


@pytest.mark.django_db
def test_vuln_serializer(add_user, add_asset, add_scan, add_vulnerability):
    user = add_user("zoki", "zoranstoilov@yahoo.com", "Zoran", "Stoilov")
    asset = add_asset("asset", "some description")
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
        requested_by=user,
        assets=[asset],
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
        assets=[asset],
    )

    req = factory.get(reverse("core:vulnerability-detail", kwargs={"pk": vuln.id}))
    context = {"request": Request(req)}

    vuln_ser = VulnerabilitySerializer(vuln, context=context)

    assert vuln_ser.data["id"] == vuln.id
    assert vuln_ser.data["name"] == vuln.name
    assert vuln_ser.data["severity"] == Severity.HIGH.value
    assert vuln_ser.data["description"] == vuln.description
    assert vuln_ser.data["solution"] == vuln.solution
    assert vuln_ser.data["references"] == vuln.references
    assert vuln_ser.data["from_scan"] == f"http://testserver/api/v1/scans/{scan.id}/"
    assert (
        vuln_ser.data["affected_assets"][0]
        == f"http://testserver/api/v1/assets/{asset.id}/"
    )
