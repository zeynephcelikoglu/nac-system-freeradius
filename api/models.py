from sqlalchemy import Column, Integer, String, BigInteger, DateTime
from database import Base

# Table for user credentials
class RadCheck(Base):
    __tablename__ = "radcheck"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), index=True)
    attribute = Column(String(64))
    op = Column(String(2))
    value = Column(String(253))

# Table for session records
class RadAcct(Base):
    __tablename__ = "radacct"
    radacctid = Column(BigInteger, primary_key=True, index=True)
    acctsessionid = Column(String(64), index=True)
    username = Column(String(64), index=True)
    acctstarttime = Column(DateTime(timezone=True))
    acctstoptime = Column(DateTime(timezone=True))