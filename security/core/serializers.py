from rest_framework import serializers
from core.models import Scan, User, Vulnerability, Asset, Status, Severity


class ChoiceField(serializers.ChoiceField):

    def to_representation(self, obj):
        if obj == '' and self.allow_blank:
            return obj
        return self._choices[obj]

    def to_internal_value(self, data):
        # To support inserts with the value
        if data == '' and self.allow_blank:
            return ''

        for key, val in self._choices.items():
            if val == data:
                return key
        self.fail('invalid_choice', input=data)


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
    status = ChoiceField(choices=Status.get_choices())
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


class VulnerabilitySerializer(serializers.ModelSerializer):
    severity = ChoiceField(choices=Severity.get_choices())
    from_scan = serializers.HyperlinkedRelatedField(
        view_name="core:scan-detail",
        read_only=True,
        source="scan",
    )
    affected_assets = serializers.HyperlinkedRelatedField(
        many=True,
        read_only=True,
        view_name="core:asset-detail",
        source="assets",
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
