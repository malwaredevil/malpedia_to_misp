from sqlalchemy import BigInteger, Column, Index, Text, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy_utils import UUIDType
import uuid
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema

Base = declarative_base()
metadata = Base.metadata

#---------------------------------------------------------------------------------------------- 
class ManualTagMap(Base):
    __tablename__ = 'manual_tag_maps'

    uuid = Column(UUIDType(), primary_key=True, nullable=False, default=uuid.uuid4, index=True)
    tagvalue = Column(Text, primary_key=True, index=True)
    galaxy = Column(Text, index=True)
    tag = Column(Text)

    def __init__(self):
        self.uuid = uuid.uuid4()

class ManualTagMapSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = ManualTagMap
        include_fk = True
        include_relationships = True
        load_instance = True   

#---------------------------------------------------------------------------------------------- 
class MispGalaxyCluster(Base):
    __tablename__ = 'misp_galaxy_clusters'

    uuid = Column(UUIDType(), primary_key=True, nullable=False)
    galaxy = Column(Text, primary_key=True, nullable=False, index=True)
    tag = Column(Text, primary_key=True, nullable=False, index=True)
    description = Column(Text)

class MispGalaxyClusterSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = MispGalaxyCluster
        include_fk = True
        include_relationships = True
        load_instance = True   
#----------------------------------------------------------------------------------------------      
class MitreSoftwareXref(Base):
    __tablename__ = 'mitre_software_xref'

    uuid = Column(UUIDType(), primary_key=True, nullable=False, default=uuid.uuid4)
    mitreid = Column(Text)
    mitrename = Column(Text, primary_key=True, nullable=False, index=True)
    mitrecode = Column(Text, primary_key=True, nullable=False)

    def __init__(self):
        self.uuid = uuid.uuid4()

class MitreSoftwareXrefSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = MitreSoftwareXref
        include_fk = True
        include_relationships = True
        load_instance = True   

#----------------------------------------------------------------------------------------------       
class ActorCfrsuspectedvictim(Base):
    __tablename__ = 'malpedia_actor_cfrsuspectedvictims'

    uuid = Column(UUIDType(), primary_key=True, nullable=False)
    victim = Column(Text, primary_key=True, nullable=False)

class ActorCfrsuspectedvictimSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = ActorCfrsuspectedvictim
        include_fk = True
        include_relationships = True
        load_instance = True 

#---------------------------------------------------------------------------------------------- 
class ActorCfrtargetcategory(Base):
    __tablename__ = 'malpedia_actor_cfrtargetcategory'

    uuid = Column(UUIDType(), primary_key=True, nullable=False)
    category = Column(Text, primary_key=True, nullable=False)

class ActorCfrtargetcategorymSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = ActorCfrtargetcategory
        include_fk = True
        include_relationships = True
        load_instance = True 

#---------------------------------------------------------------------------------------------- 
class ActorMeta(Base):
    __tablename__ = 'malpedia_actor_meta'

    uuid = Column(UUIDType(), primary_key=True, index=True)
    shortname = Column(Text)
    commonname = Column(Text, index=True)
    country = Column(Text)
    victimology = Column(Text)
    cfrtypeofincident = Column(Text)
    cfrstatesponsor = Column(Text)
    since = Column(Text)
    modeofoperation = Column(Text)
    capabilities = Column(Text)
    last_update = Column(Text)
    description = Column(Text)

class ActorMetaSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = ActorMeta
        include_fk = True
        include_relationships = True
        load_instance = True 

#---------------------------------------------------------------------------------------------- 
class MalwareAttribution(Base):
    __tablename__ = 'malpedia_malware_attribution'

    uuid = Column(UUIDType(), primary_key=True, nullable=False)
    attribution = Column(Text, primary_key=True, nullable=False)

class MalwareAttributionSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = MalwareAttribution
        include_fk = True
        include_relationships = True
        load_instance = True 

#---------------------------------------------------------------------------------------------- 
class MalwareMeta(Base):
    __tablename__ = 'malpedia_malware_meta'

    uuid = Column(UUIDType(), primary_key=True, index=True)
    name = Column(Text, index=True)
    commonname = Column(Text)
    description = Column(Text)
    updated = Column(Text)

class MalwareMetaSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = MalwareMeta
        include_fk = True
        include_relationships = True
        load_instance = True 

#---------------------------------------------------------------------------------------------- 
class MalwareYaraPath(Base):
    __tablename__ = 'malpedia_malware_yara_path'

    uuid = Column(UUIDType(), index=True)
    attribute_uuid = Column(UUIDType())
    tlp = Column(Text)
    path_to_yara = Column(Text, primary_key=True)

class MalwareYaraPathSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = MalwareYaraPath
        include_fk = True
        include_relationships = True
        load_instance = True 

#---------------------------------------------------------------------------------------------- 
class ParentChildByUuid(Base):
    __tablename__ = 'malpedia_parent_child_by_uuid'

    uuid = Column(UUIDType(), index=True)
    parentuuid = Column(UUIDType(), nullable=True, index=True)
    name = Column(Text, primary_key=True, nullable=False, index=True)
    parentname = Column(Text, primary_key=True, nullable=False)
    isfile = Column(Boolean)
    path = Column(Text)
    version = Column(Text)
    date_added = Column(Text)
    mytype = Column(Text, index=True)
    parent_type = Column(Text)

class ParentChildByUuidSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = ParentChildByUuid
        include_fk = True
        include_relationships = True
        load_instance = True 

#---------------------------------------------------------------------------------------------- 
class Reference(Base):
    __tablename__ = 'malpedia_references'

    uuid = Column(UUIDType(), primary_key=True, nullable=False, index=True)
    url = Column(Text, primary_key=True, nullable=False, index=True)

class ReferenceSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = Reference
        include_fk = True
        include_relationships = True
        load_instance = True 

#---------------------------------------------------------------------------------------------- 
class Tag(Base):
    __tablename__ = 'malpedia_tags'

    uuid = Column(UUIDType(), primary_key=True, nullable=False)
    galaxy = Column(Text, primary_key=True, nullable=False)
    tag = Column(Text, primary_key=True, nullable=False)
    type = Column(Text, primary_key=True, nullable=False)

class TagSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = Tag
        include_fk = True
        include_relationships = True
        load_instance = True 
#---------------------------------------------------------------------------------------------- 
class Synonym(Base):
    __tablename__ = 'synonyms'

    uuid = Column(UUIDType(), primary_key=True, nullable=False, index=True)
    synonym = Column(Text, primary_key=True, nullable=False)
    source = Column(Text, primary_key=True, nullable=False)

class SynonymSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = Synonym
        include_fk = True
        include_relationships = True
        load_instance = True 

#---------------------------------------------------------------------------------------------- 