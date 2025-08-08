from sqlalchemy import Column, Integer, String, Numeric, TIMESTAMP, UniqueConstraint, ForeignKeyConstraint, Enum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()

class Component(Base):
    __tablename__ = 'components'
    id = Column(Integer, primary_key=True, autoincrement=True)
    component_id = Column(String, nullable=False)
    name = Column(String, nullable=False)
    replica_id = Column(Integer, nullable=True)
    hostname = Column(String, nullable=False)
    docker_container_id = Column(String, nullable=False)
    
    events = relationship("ComponentEvent", back_populates="component")
    resources = relationship("Resource", back_populates="component")

    __table_args__ = (UniqueConstraint('component_id', 'name', 'replica_id', name='_component_id_name_replica_uc'),)

class ComponentEvent(Base):
    __tablename__ = 'component_events'
    event_id = Column(Integer, primary_key=True, autoincrement=True)
    component_id = Column(String, nullable=False)
    component_name = Column(String, nullable=False)
    replica_id = Column(Integer, nullable=True)
    timestamp = Column(TIMESTAMP(timezone=True), nullable=False)
    event = Column(String, nullable=False)
    message = Column(String, nullable=True)
    value = Column(Numeric, nullable=True)
    __table_args__ = (
        ForeignKeyConstraint(['component_id', 'component_name', 'replica_id'], ['components.component_id', 'components.name', 'components.replica_id']),
    )

    
    component = relationship("Component", back_populates="events")

class Resource(Base):
    __tablename__ = 'resources'
    resource_id = Column(Integer, primary_key=True, autoincrement=True)
    component_id = Column(String, nullable=False)
    component_name = Column(String, nullable=False)
    replica_id = Column(Integer, nullable=True)
    __table_args__ = (ForeignKeyConstraint(['component_id', 'component_name', 'replica_id'], ['components.component_id', 'components.name', 'components.replica_id']),)
    timestamp = Column(TIMESTAMP(timezone=True), nullable=False)
    cpu_usage = Column(Numeric, nullable=False)
    memory_usage = Column(Numeric, nullable=False)
    disk_usage = Column(Numeric, nullable=False)
    
    component = relationship("Component", back_populates="resources")

