from django.contrib import admin
from core.models import Scan, User, Vulnerability, Asset


class AssetInline(admin.TabularInline):
    model = Asset
    fields = ["id"]


# Register your models here.
class ScanAdmin(admin.ModelAdmin):
    # inlines = [
    #     AssetInline,
    # ]
    pass


class UserAdmin(admin.ModelAdmin):
    pass


class VulnerabilityAdmin(admin.ModelAdmin):
    pass


class AssetAdmin(admin.ModelAdmin):
    pass


admin.site.register(Scan, ScanAdmin)
admin.site.register(User, UserAdmin)
admin.site.register(Vulnerability, VulnerabilityAdmin)
admin.site.register(Asset, AssetAdmin)