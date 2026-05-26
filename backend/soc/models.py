from sqlalchemy import Column, Integer, String, Text, DateTime
from datetime import datetime

from backend.soc.database import Base


class Incident(Base):

    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    risk_level = Column(String)
    risk_score = Column(Integer)

    executive_summary = Column(Text)

    original_text = Column(Text)

    domain = Column(String)

    action = Column(String)

    signals = Column(Text)