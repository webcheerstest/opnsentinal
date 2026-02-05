from typing import Dict, Optional
from models import ExtractedIntelligence
from datetime import datetime
import threading

class SessionData:
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.scam_detected = False
        self.message_count = 0
        self.intelligence = ExtractedIntelligence()
        self.scam_type = None
        self.created_at = datetime.now()
        self.last_activity = datetime.now()
        self.agent_notes = []
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
        return cls._instance
    
    def get_or_create_session(self, session_id: str) -> SessionData:
        """Get existing session or create new one."""
        if session_id not in self.sessions:
            self.sessions[session_id] = SessionData(session_id)
        return self.sessions[session_id]
    
    def get_session(self, session_id: str) -> Optional[SessionData]:
        """Get session by ID."""
        return self.sessions.get(session_id)
    
    def update_session(self, session_id: str, 
                       scam_detected: bool = None,
                       intelligence: ExtractedIntelligence = None,
                       scam_type: str = None,
                       increment_messages: bool = True) -> SessionData:
        """Update session with new data."""
        session = self.get_or_create_session(session_id)
        
        if scam_detected is not None:
            session.scam_detected = scam_detected
        
        if intelligence is not None:
            # Merge intelligence
            session.intelligence = ExtractedIntelligence(
                bankAccounts=list(set(session.intelligence.bankAccounts + intelligence.bankAccounts)),
                upiIds=list(set(session.intelligence.upiIds + intelligence.upiIds)),
                phishingLinks=list(set(session.intelligence.phishingLinks + intelligence.phishingLinks)),
                phoneNumbers=list(set(session.intelligence.phoneNumbers + intelligence.phoneNumbers)),
                suspiciousKeywords=list(set(session.intelligence.suspiciousKeywords + intelligence.suspiciousKeywords))
            )
        
        if scam_type is not None:
            session.scam_type = scam_type
        
        if increment_messages:
            session.message_count += 1
        
        session.last_activity = datetime.now()
        return session
    
    def mark_callback_sent(self, session_id: str):
        """Mark that callback has been sent for this session."""
        session = self.get_session(session_id)
        if session:
            session.callback_sent = True
    
    def should_send_callback(self, session_id: str) -> bool:
        """Check if callback should be sent for this session."""
        session = self.get_session(session_id)
        if not session:
            return False
        
        # Send callback on EVERY request when:
        # 1. Scam is detected
        # 2. We have some meaningful intelligence extracted
        # This ensures GUVI always gets the LATEST accumulated data
        has_meaningful_intelligence = (
            len(session.intelligence.bankAccounts) > 0 or
            len(session.intelligence.upiIds) > 0 or
            len(session.intelligence.phoneNumbers) > 0
        )
        
        return (
            session.scam_detected and 
            has_meaningful_intelligence
        )
    
    def clear_session(self, session_id: str):
        """Remove a session."""
        if session_id in self.sessions:
            del self.sessions[session_id]

# Global session manager instance
session_manager = SessionManager()
