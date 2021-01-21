from django.db import models
from enum import Enum
from django.contrib.postgres.fields import ArrayField
from django.contrib.postgres.fields.jsonb import JSONField


class Status(Enum):
    COMPLETED = "completed"
    FAILED = "failed"


class Severity(Enum):
    INFORMATION = "information"
    MEDIUM = "medium"
    HIGH = "high"
    LOW = "low"


# Not doing any search in the array fields therefor there won't be any performance issues, known for ArrayField
# for the sake of the project keeping it simple using these fields
# They are from postgres contrib however I do not chose postgres for these fields
# Another, and I think much better solution is to use foreign keys to other tables that contain the data and do calculations on those
# Once again, using ArrayField nad JSONField just for the sake of the example, to keep it short and simple
# Also not extending the django user model just because there won't be any authentication on the api endpoint
# fully aware that there can be restrictions however it isn't specified


class User(models.Model):
    username = models.CharField(max_length=255)
    email = models.EmailField()
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)


class Asset(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField()
    created = models.DateTimeField(auto_now_add=True)
    scan = models.ForeignKey(
        "Scan",
        on_delete=models.DO_NOTHING,
        related_name="assets_scanned",
    )
    vulnerability = models.ForeignKey(
        "Vulnerability",
        on_delete=models.DO_NOTHING,
        related_name="affected_assets",
    )


class Scan(models.Model):
    requested_by = models.ForeignKey(
        "User",
        on_delete=models.DO_NOTHING,
        related_name="user",
    )
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    name = models.CharField(max_length=255)
    status = models.CharField(
        max_length=50,
        choices=[(tag, tag.value) for tag in Status],
    )

    scanners = ArrayField(models.CharField(max_length=50, null=True, blank=True))
    severity_counts = JSONField(null=True, blank=True)


class Vulnerability(models.Model):
    severity = models.CharField(
        max_length=50,
        choices=[(tag, tag.value) for tag in Severity],
    )
    name = models.CharField(max_length=255)
    description = models.TextField()
    solution = models.TextField()
    references = ArrayField(models.URLField(null=True, blank=True))
    cvss_base_score = models.DecimalField(max_digits=2, decimal_places=1)
    scans = models.ForeignKey(
        "Scan",
        on_delete=models.DO_NOTHING,
        related_name="vulnerabilities",
    )
