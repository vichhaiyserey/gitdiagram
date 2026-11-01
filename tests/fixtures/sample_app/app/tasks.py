"""Background tasks."""

from celery import shared_task


@shared_task
def refresh_cache() -> None:
    return None
