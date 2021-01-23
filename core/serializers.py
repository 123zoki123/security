from rest_framework import serializers
from core.models import Scan, User, Vulnerability, Asset, Status, Severity

# class CustomChoiceField(serializers.ChoiceField):

#     def to_re


class UserSerializer(serializers.HyperlinkedModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name="core:user-detail")

    class Meta:
        model = User
        fields = ["id", "username", "email", "first_name", "last_name", "url"]


class AssetSerializer(serializers.HyperlinkedModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name="core:asset-detail")

    class Meta:
        model = Asset
        fields = ["id", "name", "description", "created", "url"]


class ScanSerializer(serializers.ModelSerializer):
    status = serializers.SerializerMethodField()
    assets_scanned = serializers.HyperlinkedRelatedField(
        view_name="core:asset-detail",
        read_only=True,
        many=True,
        source="assets",
    )
    requested_by = serializers.HyperlinkedRelatedField(
        view_name="core:user-detail",
        read_only=True,
    )

    class Meta:
        model = Scan
        fields = [
            "id",
            "requested_by",
            "started_at",
            "finished_at",
            "name",
            "status",
            "scanners",
            "severity_counts",
            "assets_scanned",
        ]

    def get_status(self, obj):
        return Status.get_value(obj.status)


class VulnerabilitySerializer(serializers.ModelSerializer):
    severity = serializers.SerializerMethodField()
    from_scan = serializers.HyperlinkedRelatedField(
        view_name="core:scan-detail",
        read_only=True,
        source="scans",
    )
    affected_assets = serializers.HyperlinkedRelatedField(
        many=True,
        read_only=True,
        view_name="core:asset-detail",
    )

    class Meta:
        model = Vulnerability
        fields = [
            "id",
            "from_scan",
            "severity",
            "name",
            "description",
            "solution",
            "references",
            "cvss_base_score",
            "affected_assets",
        ]

    def get_severity(self, obj):
        return Severity.get_value(obj.severity)