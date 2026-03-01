"""
Delete old security events by retention window.
"""

from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from apps.security.models import SecurityEvent


class Command(BaseCommand):
    help = 'Delete SecurityEvent records older than the configured number of days.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--days',
            type=int,
            default=90,
            help='Retention window in days (default: 90).',
        )

    def handle(self, *args, **options):
        days = max(1, int(options['days']))
        cutoff = timezone.now() - timedelta(days=days)
        deleted_count, _ = SecurityEvent.objects.filter(timestamp__lt=cutoff).delete()
        self.stdout.write(
            self.style.SUCCESS(
                f'Deleted {deleted_count} security events older than {days} days.'
            )
        )

