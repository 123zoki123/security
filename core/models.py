from django.db import models
from enum import Enum, EnumMeta
from typing import List
from django.contrib.postgres.fields import ArrayField
from django.contrib.postgres.fields.jsonb import JSONField


class ChoicesMixin:
    @classmethod
    def get_choices(cls) -> List:
        return [(i, i.value) for i in cls]

    @classmethod
    def get_enum(cls, value: str):
        for i in cls:
            if i.value == value:
                return i

    @classmethod
    def get_value(cls, key: str) -> str:
        """
        key comes as ClassName.NAME
        so need to extract NAME from here
        """
        _, name = key.split(".")

        for i in cls:
            if i.name == name:
                return i.value


class Status(ChoicesMixin, Enum):
    COMPLETED = "completed"
    FAILED = "failed"


class Severity(
    ChoicesMixin,
    Enum,
):
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

    def __str__(self) -> str:
        return f"{self.email}"


class Asset(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField()
    created = models.DateTimeField()

    def __str__(self) -> str:
        return f"Scan name: {self.name}, id: {self.pk}"


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
        choices=Status.get_choices(),
    )
    assets = models.ManyToManyField("Asset")
    scanners = ArrayField(models.CharField(max_length=50, null=True, blank=True))
    severity_counts = JSONField(null=True, blank=True)

    def __str__(self) -> str:
        return f"{self.name} - {self.pk}"


class Vulnerability(models.Model):
    severity = models.CharField(
        max_length=50,
        choices=Severity.get_choices(),
    )
    name = models.CharField(max_length=255)
    description = models.TextField()
    solution = models.TextField(null=True, blank=True)
    references = ArrayField(models.URLField(null=True, blank=True))
    cvss_base_score = models.DecimalField(max_digits=2, decimal_places=1)
    scans = models.ForeignKey(
        "Scan",
        on_delete=models.DO_NOTHING,
        related_name="vulnerabilities",
    )
    affected_assets = models.ManyToManyField("Asset")

    def __str__(self) -> str:
        return f"{self.name} - {self.pk}"