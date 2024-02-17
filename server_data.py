import asyncio
import dataclasses


@dataclasses.dataclass
class TypingSession:
    tsid: str
    meta: dict
    hdpid: str  # hashed device pairing id


class ServerData:

    def __init__(self):
        self.connected_clients: dict[str, asyncio.Protocol] = dict()
        self.typing_sessions: dict[str, TypingSession] = dict()

        self.shutdown_event = asyncio.Event()