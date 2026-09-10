from django import template

register = template.Library()

@register.filter
def calc_percentage(value, max_value):
    try:
        return (value / max_value) * 100
    except (ValueError, ZeroDivisionError):
        return 0