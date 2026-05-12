"""
MASVS Audit Copilot — Celery Application
Asynchronous task queue for running security scans in the background.
"""

from celery import Celery
from app.core.config import settings

# ─── Create Celery App ───
celery_app = Celery(
    "masvs_copilot",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
)

# ─── Celery Configuration ───
celery_app.conf.update(
    # Serialization
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",

    # Timezone
    timezone="UTC",
    enable_utc=True,

    # Task settings
    task_track_started=True,
    task_time_limit=1800,  # 30 min max per task
    task_soft_time_limit=1500,  # Soft limit at 25 min
    worker_max_tasks_per_child=50,  # Restart worker after 50 tasks (memory leak prevention)

    # Result backend
    result_expires=86400,  # Results expire after 24h
)

# ─── Register tasks explicitly ───
# Force import so Celery registers the task regardless of autodiscovery timing
celery_app.conf.imports = ["app.tasks.scan_tasks", "app.tasks.dynamic_scan_tasks"]
celery_app.autodiscover_tasks(["app.tasks"])

# Import after configuration to register tasks
import app.tasks.scan_tasks  # noqa: F401, E402
import app.tasks.dynamic_scan_tasks  # noqa: F401, E402
