import asyncio
from telemetry import TelemetryEvent


class EventQueue:
    def __init__(self):
        self._queue = asyncio.Queue()

    async def add_event(self, event: TelemetryEvent):
        """Pushes system events into the in-memory queue instantly."""
        await self._queue.put(event)

    async def start_worker(self, callback_function):
        """Continuously pulls events off the queue and sends them to AI evaluation."""
        while True:
            event = await self._queue.get()
            try:
                await callback_function(event)
            finally:
                self._queue.task_done()
