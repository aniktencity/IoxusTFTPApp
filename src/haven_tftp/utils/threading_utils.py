import threading


def make_stop_event() -> threading.Event:
    return threading.Event()
