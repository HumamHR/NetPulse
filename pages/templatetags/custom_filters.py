from django import template
import json
register = template.Library()

@register.filter(name='get_item')
def get_item(dictionary, key):
    """Custom filter to get an item from a dictionary by key."""
    return dictionary.get(key)

@register.filter
def split_credential_type(value):
    """Extracts the credential type (e.g., 'HTTP Basic Auth')"""
    return value.split(':', 1)[0] if ':' in value else value

@register.filter
def split_credential_value(value):
    """Extracts the credential value (e.g., 'admin:password')"""
    return value.split(':', 1)[1] if ':' in value else ''

@register.filter
def split_credential_subtype(value):
    """Extracts the credential subtype (e.g., 'Login' from 'Telnet: Login')"""
    parts = value.split(':', 2)
    return parts[1].strip() if len(parts) > 1 else ''

@register.filter
def split_credential_details(value):
    """Extracts the credential details"""
    parts = value.split(':', 2)
    return parts[2].strip() if len(parts) > 2 else parts[-1].strip()

from django import template
import os
from django.conf import settings

register = template.Library()

@register.filter
def basename(value):
    return os.path.basename(value)

@register.filter
def media_fullpath(value):
    return os.path.join(settings.MEDIA_ROOT, value)

@register.filter
def is_previewable(value):
    previewable_extensions = ['.txt', '.jpg', '.jpeg', '.png', '.pdf']
    return any(value.lower().endswith(ext) for ext in previewable_extensions)

from django import template

register = template.Library()

@register.filter
def split(value, arg):
    return value.split(arg)

@register.filter
def cut(value, arg):
    return value.replace(arg, '')

from django import template

register = template.Library()

@register.filter(name='split')
def split(value, arg=None):
    """Safe split filter that handles both strings and lists"""
    if isinstance(value, str):
        if arg is None:
            return value.split()
        return value.split(arg)
    elif isinstance(value, (list, tuple)):
        # If it's a list, take the first string element or convert to string
        if value and isinstance(value[0], str):
            if arg is None:
                return value[0].split()
            return value[0].split(arg)
        return [str(value)]  # Fallback for non-string lists
    return [str(value)]  # Fallback for other types
