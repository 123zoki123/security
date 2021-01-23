from rest_framework import urlpatterns
from core.views import UserViewSet, AssetViewSet, ScanViewSet, VulnerabilityViewSet
from rest_framework.routers import DefaultRouter

router = DefaultRouter()
router.register(r"users", UserViewSet, basename="user")
router.register(r"assets", AssetViewSet, basename="asset")
router.register(r"scans", ScanViewSet, basename="scan")
router.register(r"vulnerabilities", VulnerabilityViewSet, basename="vulnerability")


urlpatterns = router.urls
