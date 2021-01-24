import pytest
import datetime
from core.models import Asset, User, Scan, Severity, Status, Vulnerability
from django.utils.timezone import make_aware


@pytest.fixture(scope="function")
def add_user():
    def _add_user(username, email, first_name, last_name):
        user = User.objects.create(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
        )
        return user

    return _add_user


@pytest.fixture(scope="function")
def add_asset():
    def _add_asset(name, description):
        asset = Asset.objects.create(
            name=name,
            description=description,
            created=make_aware(datetime.datetime.now()),
        )
        return asset

    return _add_asset


@pytest.fixture(scope="function")
def add_scan():
    def _add_scan(
        name,
        scanners,
        severity_counts,
        requested_by,
        assets,
    ):
        now = datetime.datetime.now()
        now = make_aware(now)
        now_plus_20 = now + datetime.timedelta(minutes=20)
        scan = Scan.objects.create(
            name=name,
            started_at=now,
            finished_at=now_plus_20,
            status=Status.COMPLETED.name,
            scanners=scanners,
            severity_counts=severity_counts,
            requested_by=requested_by,
        )
        for asset in assets:
            scan.assets.add(asset)
        scan.save()
        return scan

    return _add_scan


@pytest.fixture(scope="function")
def add_vulnerability():
    def _add_vulnerability(
        name,
        description,
        solution,
        references,
        cvss_base_score,
        scan,
        assets,
    ):
        vuln = Vulnerability.objects.create(
            severity=Severity.HIGH.name,
            name=name,
            description=description,
            solution=solution,
            references=references,
            cvss_base_score=cvss_base_score,
            scan=scan,
        )
        for asset in assets:
            vuln.assets.add(asset)
        vuln.save()
        return vuln

    return _add_vulnerability