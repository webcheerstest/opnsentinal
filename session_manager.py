import threading
import time
from typing import Dict, Optional
from models import ExtractedIntelligence
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class SessionData:
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.scam_detected = False
        self.message_count = 0
        self.intelligence = ExtractedIntelligence()
        self.scam_type = None
        self.created_at = datetime.now()
        self.last_activity = datetime.now()
        self.agent_notes: list = []
        self.callback_sent = False

    def add_note(self, note: str):
        self.agent_notes.append(note)

    def get_notes_string(self) -> str:
        return " | ".join(self.agent_notes) if self.agent_notes else "No specific notes"


class SessionManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance.sessions: Dict[str, SessionData] = {}
                    cls._instance._start_cleanup_loop()
        return cls._instance

    def _start_cleanup_loop(self):
        def cleanup_worker():
            while True:
                try:
                    self._check_inactive_sessions()
                except Exception as e:
                    logger.error(f"Error in cleanup worker: {e}")
                time.sleep(60)

        thread = threading.Thread(target=cleanup_worker, daemon=True)
        thread.start()

    def _check_inactive_sessions(self):
        from guvi_callback import send_callback_to_guvi

        now = datetime.now()
        timeout_seconds = 300

        for pid in list(self.sessions.keys()):
            session = self.sessions.get(pid)
            if not session:
                continue
            elapsed = (now - session.last_activity).total_seconds()
            if elapsed > timeout_seconds:
                if session.scam_detected and not session.callback_sent:
                    logger.info(f"Session {pid} timed out. Sending final callback.")
                    send_callback_to_guvi(session)
                    self.mark_callback_sent(pid)
                if elapsed > 3600:
                    self.clear_session(pid)

    def get_or_create_session(self, session_id: str) -> SessionData:
        if session_id not in self.sessions:
            self.sessions[session_id] = SessionData(session_id)
        return self.sessions[session_id]

    def get_session(self, session_id: str) -> Optional[SessionData]:
        return self.sessions.get(session_id)

    def update_session(
        self,
        session_id: str,
        scam_detected: bool = None,
        intelligence: ExtractedIntelligence = None,
        scam_type: str = None,
        increment_messages: bool = True,
    ) -> SessionData:
        session = self.get_or_create_session(session_id)

        if scam_detected is not None:
            session.scam_detected = scam_detected

        if intelligence is not None:
            session.intelligence = ExtractedIntelligence(
                phoneNumbers=list(set(session.intelligence.phoneNumbers + intelligence.phoneNumbers)),
                bankAccounts=list(set(session.intelligence.bankAccounts + intelligence.bankAccounts)),
                upiIds=list(set(session.intelligence.upiIds + intelligence.upiIds)),
                phishingLinks=list(set(session.intelligence.phishingLinks + intelligence.phishingLinks)),
                emailAddresses=list(set(session.intelligence.emailAddresses + intelligence.emailAddresses)),
            )

        if scam_type is not None:
            session.scam_type = scam_type

        if increment_messages:
            session.message_count += 1

        session.last_activity = datetime.now()
        return session

    def mark_callback_sent(self, session_id: str):
        session = self.get_session(session_id)
        if session:
            session.callback_sent = True

    def should_trigger_early_callback(self, session_id: str) -> bool:
        session = self.get_session(session_id)
        if not session or not session.scam_detected:
            return False
        return (
            len(session.intelligence.bankAccounts) > 0
            or len(session.intelligence.upiIds) > 0
            or len(session.intelligence.phoneNumbers) > 0
        )

    def clear_session(self, session_id: str):
        if session_id in self.sessions:
            del self.sessions[session_id]


# Global singleton
session_manager = SessionManager()
