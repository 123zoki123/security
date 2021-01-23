from typing import List
from django.shortcuts import get_object_or_404
from rest_framework.generics import GenericAPIView
from rest_framework.mixins import ListModelMixin
from rest_framework.response import Response
from rest_framework import serializers, viewsets
from core.models import Scan, Vulnerability, Asset, User
from core.serializers import (
    ScanSerializer,
    VulnerabilitySerializer,
    AssetSerializer,
    UserSerializer,
)


class UserViewSet(viewsets.ReadOnlyModelViewSet):
    """
    View to list all users in the system
    View to retrieve a single user
    :param pk int: requires primary key
    * Everybody can access this view
    """

    queryset = User.objects.all()
    serializer_class = UserSerializer


class AssetViewSet(viewsets.ReadOnlyModelViewSet):
    """
    View to list all assets
    View to retrieve a single asset
    :param pk int: requires primary key
    * Everybody can access this view
    """

    queryset = Asset.objects.all()
    serializer_class = AssetSerializer


class ScanViewSet(viewsets.ReadOnlyModelViewSet):
    """
    View to list all scans
    View to retrieve a single scan
    :param pk int: requires primary key
    * Everybody can access this view
    """

    queryset = Scan.objects.all()
    serializer_class = ScanSerializer


class VulnerabilityViewSet(viewsets.ReadOnlyModelViewSet):
    """
    View to list all vulnerabilities
    View to retrieve a single vulnerability
    :param pk int: requires primary key
    * Everybody can access this view
    """

    queryset = Vulnerability.objects.all()
    serializer_class = VulnerabilitySerializer