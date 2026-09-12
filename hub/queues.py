"""Terminal output may be lossy under pressure; termination must not be."""
import asyncio


def offer_output(queue, item):
    try:
        queue.put_nowait(item)
    except asyncio.QueueFull:
        if item is None:
            queue.get_nowait()
            queue.put_nowait(None)
