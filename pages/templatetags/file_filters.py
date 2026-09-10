from django import template
from django.conf import settings
import os

register = template.Library()

@register.filter
def basename(value):
    return os.path.basename(value)

@register.filter
def mediapath(value):
    return os.path.join(settings.MEDIA_ROOT, value)

@register.filter
def fileexists(value):
    return os.path.exists(value)

@register.filter
def filesizeformat(value):
    try:
        size = os.path.getsize(value)
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        else:
            return f"{size / (1024 * 1024):.1f} MB"
    except:
        return "N/A"

@register.filter
def is_previewable(value):
    # Add logic for file types you want to allow previewing
    preview_extensions = ['.txt', '.pdf', '.jpg', '.png', '.jpeg']
    return any(value.lower().endswith(ext) for ext in preview_extensions)