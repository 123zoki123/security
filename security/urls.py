from django.contrib import admin
from django.urls import path
from django.urls.conf import include
from core.urls import router

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/v1/", include((router.urls, "core"))),
]
