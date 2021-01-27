
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import globals as gv


engine = create_engine(str(gv._MP_TO_MISP_DB))
Session = sessionmaker(bind=engine)
