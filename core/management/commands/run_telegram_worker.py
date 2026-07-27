import asyncio

from django.core.management.base import BaseCommand

from core.services.telegram_worker import TelegramSupervisor


class Command(BaseCommand):
    help = "Run the multi-account Telegram supervisor"

    def handle(self, *args: object, **options: object) -> None:
        asyncio.run(TelegramSupervisor().run())
