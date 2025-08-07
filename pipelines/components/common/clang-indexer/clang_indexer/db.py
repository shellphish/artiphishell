from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class FunctionInfo(Base):
    __tablename__ = 'function_info'

    hash = Column(String, primary_key=True)
    code = Column(String)
    signature = Column(String)
    start_line = Column(Integer)
    start_column = Column(Integer)
    start_offset = Column(Integer)
    end_line = Column(Integer)
    end_column = Column(Integer)
    end_offset = Column(Integer)
    src_path = Column(String)
    global_variables = Column(String)

    name = Column(String)
    mangled_name = Column(String)
    comment = Column(String)
    calls = Column(String)

class MethodInfo(Base):
    __tablename__ = 'method_info'

    hash = Column(String, primary_key=True)
    code = Column(String)
    signature = Column(String)
    start_line = Column(Integer)
    start_column = Column(Integer)
    start_offset = Column(Integer)
    end_line = Column(Integer)
    end_column = Column(Integer)
    end_offset = Column(Integer)
    src_path = Column(String)
    global_variables = Column(String)

    full_name = Column(String)
    method_name = Column(String)
    mangled_name = Column(String)
    comment = Column(String)
    calls = Column(String)

class MacroInfo(Base):
    __tablename__ = 'macro_info'

    hash = Column(String, primary_key=True)
    code = Column(String)
    signature = Column(String)
    start_line = Column(Integer)
    start_column = Column(Integer)
    start_offset = Column(Integer)
    end_line = Column(Integer)
    end_column = Column(Integer)
    end_offset = Column(Integer)
    src_path = Column(String)
    global_variables = Column(String)

    name = Column(String)
