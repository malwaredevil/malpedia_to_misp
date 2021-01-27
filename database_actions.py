import globals as gv
import sys
import uuid
import pymisp as pm
from pymisp import MISPTag
import string
# import requests
# requests.packages.urllib3.disable_warnings() 
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import models as md
from app import Session
import sqlalchemy as sa


# INSERT DATA INTO MP_ACTOR_META
def insert_actor(iActorUUID, iShortName, iCommonName, iCountry, iVictimology, iTOI, iSS,iSince, iMOO, iCaps, iLastUpdate, iDescription):
    session = Session()
    try:
        dbInsert = md.ActorMeta()
        dbInsert.uuid = iActorUUID
        dbInsert.shortname = iShortName
        dbInsert.commonname = iCommonName
        dbInsert.country = iCountry
        dbInsert.victimology = iVictimology
        dbInsert.cfrtypeofincident = iTOI
        dbInsert.cfrstatesponsor = iSS
        dbInsert.since = iSince
        dbInsert.modeofoperation = iMOO
        dbInsert.capabilities = iCaps
        dbInsert.last_update = iLastUpdate
        dbInsert.description = iDescription

        session.merge(dbInsert)
        session.commit()
    except Exception as error:
        session.rollback()
        print("f(x) insert_actor: DATABASE ERROR: {}".format(error))
        sys.exit(error)
    finally:
        session.close()
    #DEBUG SEQ
    if gv._DEBUG:
        print("f(x) insert_actor: {} DATA ADDED TO ACTORS TABLE".format(iShortName))

# INSERT INTO VICTIMS TABLE
def insert_victims(iActorUUID, iVictim):
    session = Session()
    try:
        dbInsert = md.ActorCfrsuspectedvictim()
        dbInsert.uuid = iActorUUID
        dbInsert.victim = iVictim
        session.merge(dbInsert)
        session.commit()
        
    except Exception as error:
        session.rollback()
        print("f(x) insert_victims: DATABASE ERROR: {}".format(error))
        sys.exit(error)
    finally:
        session.close()
    #DEBUG SEQ
    if gv._DEBUG:
        print("f(x) insert_victims: {} DATA ADDED TO VICTIMS TABLE".format(iVictim))

# INSERT INTO REFERENCES TABLE
def insert_reference(iActorUUID, iValue):
    session = Session()
    try:
        dbInsert = md.Reference()
        dbInsert.uuid = iActorUUID
        dbInsert.url = iValue
        session.merge(dbInsert)
        session.commit()
    except Exception as error:
        session.rollback()
        print("f(x) insert_reference: DATABASE ERROR: {}".format(error))
        sys.exit(error)
    finally:
        session.close()
    #DEBUG SEQ
    if gv._DEBUG:
        print("f(x) insert_reference: {} DATA ADDED TO REFERENCES TABLE".format(iValue))

# INSERT INTO TARGETS TABLE
def insert_target(iActorUUID, iTarget):
    session = Session()
    try:
        dbInsert = md.ActorCfrtargetcategory()
        dbInsert.uuid = iActorUUID
        dbInsert.category = iTarget
        
        session.merge(dbInsert)
        session.commit()
    except Exception as error:
        session.rollback()
        print("f(x) insert_target: DATABASE ERROR: {}".format(error))
        sys.exit(error)
    finally:
        session.close()
    #DEBUG SEQ
    if gv._DEBUG:
        print("f(x) insert_target: {} DATA ADDED TO TARGET TABLE".format(iTarget))

# INSERT INTO MALWARE META TABLE
def insert_malware_meta(iFamilyUUID, iFamilyName, iCommonName, iDescription, iUpdated):
    session = Session()
    try:
        dbInsert = md.MalwareMeta()
        dbInsert.uuid = iFamilyUUID
        dbInsert.name = iFamilyName
        dbInsert.commonname = iCommonName
        dbInsert.description = iDescription
        dbInsert.updated = iUpdated
        
        session.merge(dbInsert)
        session.commit()
    except Exception as error:
        session.rollback()
        print("f(x) insert_malware_meta: DATABASE ERROR: {}".format(error))
        sys.exit(error)
    finally:
        session.close()
    #DEBUG SEQ
    if gv._DEBUG:
        print("f(x) insert_malware_meta: {} DATA ADDED MALWARE META TABLE".format(iFamilyName))

# INSERT INTO MALWARE ATTRIBUTION TABLE
def insert_malware_attribution(iFamilyUUID, iAttribution):
    session = Session()
    try:
        dbInsert = md.MalwareAttribution()
        dbInsert.uuid = iFamilyUUID
        dbInsert.attribution = iAttribution        
        
        session.merge(dbInsert)
        session.commit()
    except Exception as error:
        session.rollback()
        print("f(x) insert_malware_attribution: DATABASE ERROR: {}".format(error))
        sys.exit(error)
    finally:
        session.close()
    #DEBUG SEQ
    if gv._DEBUG:
        print("f(x) insert_malware_attribution: {}: {} DATA ADDED TO MALWARE ATTRIBUTION TABLE".format(iFamilyUUID, iAttribution))

# INSERT INTO MALWARE YARA PATH
def insert_malware_yara(iFamilyUUID, iTLP, iYaraPath, iUUID):
    session = Session()
    try:
        dbInsert = md.MalwareYaraPath()
        dbInsert.uuid = iFamilyUUID  
        dbInsert.path_to_yara = iYaraPath  
        dbInsert.tlp = iTLP
        dbInsert.attribute_uuid = iUUID    
        
        session.merge(dbInsert)
        session.commit()
    except Exception as error:
        session.rollback()
        print("f(x) insert_malware_yara: DATABASE ERROR: {}".format(error))
        sys.exit(error)
    finally:
        session.close()
    #DEBUG SEQ
    if gv._DEBUG:
        print("f(x) insert_malware_yara: {}:{}:{} DATA ADDED TO YARA TABLE".format(iUUID, iTLP, iYaraPath))

# INSERT INTO PARENT CHILD TABLE
def insert_parent_child(iUUID, iParentUUID, iName, iParentName, iIsFile, iPath, iVersion, iDate, iMytype, iParent_Type):
    session = Session()
    try:
        dbInsert = md.ParentChildByUuid()
        dbInsert.uuid = iUUID
        if not iParentUUID:
            iParentUUID = None
        dbInsert.parentuuid = iParentUUID
        dbInsert.name = iName
        dbInsert.parentname = iParentName
        dbInsert.isfile = iIsFile
        dbInsert.path = iPath
        dbInsert.version = iVersion
        dbInsert.date_added = iDate
        dbInsert.mytype = iMytype
        dbInsert.parent_type = iParent_Type
        
        session.merge(dbInsert)
        session.commit()
    except Exception as error:
        session.rollback()
        print("f(x) insert_parent_child: DATABASE ERROR: {}".format(error))
        sys.exit(error)
    finally:
        session.close()
    #DEBUG SEQ
    if gv._DEBUG:
        # # print("*" * 50)
        print ("f(x) insert_parent_child:")
        print ("ADDED TO PARENT CHILD TABLE:")
        print ("MYUUID: {}".format(iUUID))
        print ("PARENTUUID: {}".format(iParentUUID))
        print ("MY NAME: {}".format(iName))
        print ("PARENT NAME: {}".format(iParentName))
        print ("ISFILE: {}".format(iIsFile))
        print ("PATH: {}".format(iPath))
        print ("VERSION: {}".format(iVersion))
        # # print("*" * 50)

# INSERT SYNONIMS
def insert_synonym(iActorUUID, iSynonym, iSource="UNK"):
    session = Session()
    try:
        dbInsert = md.Synonym()
        dbInsert.uuid = iActorUUID
        dbInsert.synonym = iSynonym
        dbInsert.source = iSource
        
        session.merge(dbInsert)
        session.commit()
    except Exception as error:
        session.rollback()
        print("f(x) insert_synonym: DATABASE ERROR: {}".format(error))
        sys.exit(error)
    finally:
        session.close()
    #DEBUG SEQ
    if gv._DEBUG:
        print("f(x) insert_synonym: {}: {} DATA ADDED TO synonym TABLE".format(iActorUUID, iSynonym))
        # ---------------------------------------------------------------------

#INSERT INTO GALAXY TABLE
def insert_galaxy(iTagUUID, iGalaxy, iTag, iDescription):
    session = Session()
    try:
        dbInsert = md.MispGalaxyCluster()
        dbInsert.uuid = iTagUUID
        dbInsert.galaxy = iGalaxy
        dbInsert.tag = iTag
        dbInsert.description = iDescription

        session.merge(dbInsert)
        session.commit()
    except Exception as error:
        session.rollback()
        print("f(x) insert_galaxy: DATABASE ERROR: {}".format(error))
        sys.exit(error)
    finally:
        session.close()

# INSERT INTO TAGS TABLE
def insert_tag(iUUID="", iGalaxy="", iTag="", iType="", iMalwareShortName="", iIsList=False, iList=[] ):
    if not iGalaxy and not iTag and not iList:
        return
    session = Session()
    #TO DO ADD A CHECK MAYBE THIS CAN BE DONE SOME OTHER WAY RATHER THAN INSERTING TABLE OR IS THAT FASTER?
    # manual_tag_check = get_manual_tags(iMalwareShortName, iGalaxy)
    try:
        if iIsList == False:
            dbInsert = md.Tag()
            dbInsert.uuid = iUUID
            dbInsert.galaxy = iGalaxy
            dbInsert.tag = iTag
            dbInsert.type = iType
            session.merge(dbInsert)
        else:
            for tag in iList:
                dbInsert = md.Tag()
                dbInsert.uuid = tag[0]
                dbInsert.galaxy = tag[1]
                dbInsert.tag = tag[2]
                dbInsert.type = tag[3]
                session.merge(dbInsert) 

        session.commit() 
    except Exception as error:
        session.rollback()
        print("f(x) insert_tag: DATABASE ERROR: {}".format(error))
        sys.exit(error)
    finally:
        session.close()

# INSERT INTO MITRE SOFTWARE XREF
def insert_mitre_software(iMitreID, iMitreName, iMitreCode):
    session = Session()
    try:
        dbInsert = md.MitreSoftwareXref()
        dbInsert.mitreid = iMitreID
        dbInsert.mitrename = iMitreName
        dbInsert.mitrecode = iMitreCode

        session.merge(dbInsert)
        session.commit()
    except Exception as error:
        session.rollback()
        print("f(x) insert_mitre_software: DATABASE ERROR: {}".format(error))
        sys.exit(error)
    finally:
        session.close()
    #DEBUG SEQ
    if gv._DEBUG:
        print("f(x) insert_mitre_software: {} : {} : {} DATA ADDED TO mitre_software_xref TABLE".format(iMitreID, iMitreName, iMitreCode))
        # ---------------------------------------------------------------------



# INSERT INTO MANUAL TAG MAPS
def insert_manual_tags():
    session = Session()
    try:
        for tag in gv._MANUAL_TAGS:
            dbInsert = md.ManualTagMap()
            dbInsert.tagvalue = tag["tagvalue"]
            dbInsert.galaxy = tag["galaxy"]
            dbInsert.tag = tag["tag"]
            session.merge(dbInsert)
        
        session.commit()
    except Exception as error:
        session.rollback()
        print("f(x) insert_manual_tags: DATABASE ERROR: {}".format(error))
        sys.exit(error)
    finally:
        session.close()


# GET THE TAGS THAT ARE MANUALLY PUT IN
def get_mitre_software_code(iValue):
    ret_list = []
    session = Session()
    try:
        namevariations = iValue.replace("-", "").replace(" ", "").replace("(" , "").replace(")", "").replace("/", "").replace("\\", "")
        # query = "select * from mitre_software_xref where mitreName like ? or mitreName like ?"
        ret_list = session.query(md.MitreSoftwareXref). \
                        filter(sa.or_(md.MitreSoftwareXref.mitrename.ilike(iValue), md.MitreSoftwareXref.mitrename.ilike(namevariations))). \
                        all()
        
        return md.MitreSoftwareXrefSchema(many=True).dump(ret_list) 
    except Exception as error:
        print("f(x) get_mitre_software_code: DATABASE ERROR: {}".format(error))
        sys.exit(error)
    finally:
        session.close()

# GET THE TAGS THAT ARE MANUALLY PUT IN
def get_manual_tags(iSearchTag, iSearchGalaxy):
    ret_list = []
    session = Session()
    try:
        # query = "select * from  manual_tag_maps where tagvalue = ? and galaxy like ?"
        ret_list = session.query(md.ManualTagMap). \
                        filter(sa.and_(md.ManualTagMap.tagvalue == iSearchTag, md.ManualTagMap.galaxy.ilike(iSearchGalaxy))). \
                        all()

        return md.ManualTagMapSchema(many=True).dump(ret_list) 
    except Exception as error:
        session.rollback()
        print("f(x) insert_galaxy: DATABASE ERROR: {}".format(error))
        sys.exit(error)
    finally:
        session.close()

# FIND MITRE TAGS (REQUIRES A T#### CODE)
def get_galaxy_specific_tags(iSearchTerm, iGalaxy="mitre-attack-pattern"):
    ret_list = []
    session = Session()
    try:
        # STANDARD SEARCH IN DESCRIPTIONS AND tAG
        if iGalaxy == "":
            iSearchTerm = "%" + iSearchTerm + "%"
            # query = "select galaxy, tag from  misp_galaxy_clusters where  tag like ?"
            ret_list = session.query(md.MispGalaxyCluster). \
                        filter(md.MispGalaxyCluster.tag.ilike(iSearchTerm)). \
                        all()
        elif iGalaxy == "malware":
            iSearchTerm = "%- " + iSearchTerm + "%"
            # query = "select galaxy, tag from  misp_galaxy_clusters where (galaxy = 'mitre-tool' or galaxy = 'mitre-malware') AND tag like ?"
            ret_list = session.query(md.MispGalaxyCluster). \
                        filter(md.MispGalaxyCluster.tag.ilike(iSearchTerm)). \
                        filter(sa.or_(md.MispGalaxyCluster.galaxy == 'mitre-tool', md.MispGalaxyCluster.galaxy == 'mitre-tool')). \
                        all()
        else:
            iSearchTerm = "%- " + iSearchTerm + "%"
            # query = "select galaxy, tag from  misp_galaxy_clusters where galaxy=? and tag like ?"
            ret_list = session.query(md.MispGalaxyCluster). \
                        filter(sa.and_(md.MispGalaxyCluster.galaxy.ilike(iGalaxy), md.MispGalaxyCluster.tag.ilike(iSearchTerm))). \
                        all()
        return md.MispGalaxyClusterSchema(many=True).dump(ret_list) 
    except Exception as error:
        print("f(x) get_galaxy_specific_tags: DATABASE ERROR: {}".format(error))
        sys.exit(error)
    finally:
        session.close()

# PULL A LIST OF SYNONIMS
def get_synonyms(iUUID):
    ret_list = []
    session = Session()
    try:
            # query = "select * from  synonyms where uuid = ?"
        ret_list = session.query(md.Synonym). \
                        filter(md.Synonym.uuid == iUUID). \
                        all()

        return md.SynonymSchema(many=True).dump(ret_list) 
   
    except Exception as error:
        print("f(x) get_synonyms: DATABASE ERROR: {}".format(error))
        sys.exit(error)
    finally:
        session.close()

# TAKES UUID AND GETS THE TAGS. ALSO CREATES THE TAGS SO EVERYTHING IS UNIFORM
def get_set_all_tags(iUUID):
    ret_list = []
    session = Session()
    try:
        # query = "SELECT * FROM mp_tags WHERE uuid = ?"
        tmp_dict = session.query(md.Tag). \
                        filter(md.Tag.uuid == iUUID). \
                        all()

        tag_dict = md.TagSchema(many=True).dump(tmp_dict) 


        # BUILD RETURN LIST
        for tag in tag_dict:
            tmpGalaxy = tag["galaxy"]
            tmpTagVal = tag["tag"]
            tmpTypeTag = tag["type"]
            newTag = MISPTag()

            # POTENTIAL tmpTypeTag Values
            # "ACTOR"
            # "COUNTRY_SPONSOR"
            # "GALAXY"
            # "GALAXY_SYNONIM"
            # "ISO_COUNTRY"
            # "MALWARE"
            # "TARGETS"
            # "TYPE_OF_INCIDENT"
            # "VICTIMS"
            if "tlp:" in tmpTagVal:
                newTag.name = tmpTagVal
            elif tmpTypeTag == "ACTOR":
                newTag.name = "Actor: " + tmpTagVal
                newTag.colour = gv._ACTOR_TAG
            elif tmpTypeTag == "COUNTRY_SPONSOR":
                newTag.name = "Sponsor: " + tmpTagVal
                newTag.colour = gv._COUNTRY_SPONSOR_TAG
            elif tmpTypeTag == "GALAXY":
                if tmpGalaxy != "":
                    newTag.name = "misp-galaxy:"+ tmpGalaxy +"=\"" + tmpTagVal +"\""
                else:
                    newTag.name = "Synonym: " + tmpTagVal
                    newTag.colour = gv._GALAXY_SYNONIM_TAG
            elif tmpTypeTag == "GALAXY_SYNONIM":
                newTag.name = "Synonym: " + tmpTagVal
                newTag.colour = gv._GALAXY_SYNONIM_TAG
            elif tmpTypeTag == "ISO_COUNTRY":
                newTag.name = "Country ISO: " + tmpTagVal 
                newTag.colour = gv._ISO_COUNTRY_TAG
            elif tmpTypeTag == "MALWARE":
                newTag.name = "Malware: " + tmpTagVal
                newTag.colour = gv._MALWARE_TAG
            elif tmpTypeTag == "TARGETS":
                newTag.name = "Target: " + tmpTagVal
                newTag.colour = gv._TARGETS_TAG
            elif tmpTypeTag == "TYPE_OF_INCIDENT":
                newTag.name = "Type of Incident: " +  tmpTagVal
                newTag.colour = gv._TYPE_OF_INCIDENT_TAG
            elif tmpTypeTag == "VICTIMS":
                newTag.name = "Victim: " + tmpTagVal
                newTag.colour = gv._VICTIMS_TAG
            else:
                newTag.name = tmpTagVal
                newTag.colour = gv._OTHER_TAG
            
            ret_list.append(newTag)

        return ret_list
    except Exception as error:
        print("f(x) get_set_all_tags: DATABASE ERROR: {}".format(error))
        sys.exit(error)
    finally:
        session.close()
    
# COPY ALL TAGS FROM FROM ONE UUID TO ANOTHER
def copy_tags(iSourceUUID, iDestinationUUID):
    new_tags = []
    session = Session()
    try:
        temp_dict = session.query(md.Tag). \
                        filter(md.Tag.uuid == iSourceUUID). \
                        all()
        tag_dict = md.TagSchema(many=True).dump(temp_dict) 

        for row in tag_dict:
            if gv._DEBUG:
                print("f(x) copy_tags: VALUES BEFORE COPY: {}:{}:{}:{}".format(row["uuid"], row["galaxy"], row["tag"], row["type"]))
            newRecord = (iDestinationUUID, row["galaxy"], row["tag"], row["type"])
            new_tags.append(newRecord)

        return new_tags
    except Exception as error:
        print("f(x) get_parent_child_data: DATABASE ERROR: {}".format(error))
        sys.exit(error)
    finally:
        session.close()

# GETS A UUID BY NAME FROM PARENT CHILD TABLE
def get_parent_child_data(iValue="", iUUID=""):
    ret_list = ""
    session = Session()
    try:
        if gv._DEBUG:
            print("f(x) get_parent_child_data: PULLING UUID:VALUE: [{}]:[{}]".format(iUUID, iValue))
        
        if iValue == "all":
            # query = "select uuid from mp_parent_child_by_uuid"
            ret_list = session.query(md.ParentChildByUuid). \
                        with_entities(md.ParentChildByUuid.uuid). \
                        all()
            return md.ParentChildByUuidSchema(many=True).dump(ret_list) 
        elif iValue == "actor" or iValue == "family" or iValue == "path" or iValue == "malware":
            # query = "select uuid from mp_parent_child_by_uuid where mytype = ? order by path asc"
            # value = (iValue.upper(),)
            ret_list = session.query(md.ParentChildByUuid). \
                        with_entities(md.ParentChildByUuid.uuid). \
                        filter(md.ParentChildByUuid.mytype == iValue.upper()). \
                        order_by(md.ParentChildByUuid.path). \
                        all()
            return md.ParentChildByUuidSchema(many=True).dump(ret_list) 
        elif iValue == "" and iUUID != "":
            # query = "select * from  mp_parent_child_by_uuid where uuid = ?"
            # value = (iUUID,)
            # ret_val = cursor.fetchone()   
            ret_list = ret_list = session.query(md.ParentChildByUuid). \
                        filter(md.ParentChildByUuid.uuid == iUUID). \
                        first()   
            return md.ParentChildByUuidSchema(many=False).dump(ret_list) 
        elif iValue != "" and iUUID == "":
            # query = "select * from  mp_parent_child_by_uuid where name = ?"
            # ret_val = cursor.fetchone()
            ret_list = session.query(md.ParentChildByUuid). \
                        filter(md.ParentChildByUuid.name == iValue). \
                        first() 
            return md.ParentChildByUuidSchema(many=False).dump(ret_list) 
        elif  iValue != "" and iUUID != "":
            # query = "select * from  mp_parent_child_by_uuid where name = ? or uuid = ?"
            # value = (iValue, iUUID)
            # ret_val = cursor.fetchone()
            ret_list = session.query(md.ParentChildByUuid). \
                        filter(sa.or_(md.ParentChildByUuid.name == iValue, md.ParentChildByUuid.uuid == iUUID)). \
                        first()
            return md.ParentChildByUuidSchema(many=False).dump(ret_list) 
        else:
            return {}

    except Exception as error:
        print("f(x) get_parent_child_data: DATABASE ERROR: {}".format(error))
        sys.exit(error)
    finally:
        session.close()

# GET ALL LINKS RELATED TO THIS UUID
def get_links(iUUID):
    ret_list = []
    session = Session()
    try:
       
        # query = "SELECT url FROM mp_references WHERE mp_uuid = ?"
        ret_list = session.query(md.Reference). \
                        with_entities(md.Reference.url). \
                        filter(md.Reference.uuid == iUUID). \
                        order_by(md.Reference.url). \
                        all()

        return md.ReferenceSchema(many=True).dump(ret_list)
    except Exception as error:
        print("f(x) get_links: DATABASE ERROR: {}".format(error))
        sys.exit(error)
    finally:
        session.close()

# GET ALL ACTOR META INFORMATION
def get_actor_meta(iUUID="", iCommonName=""):
    ret_list = []
    session = Session()
    try:

        if iUUID:
            # query = "SELECT *  FROM mp_actor_meta WHERE mpactor_uuid = ? or mp_commonname = ? "
            # value = (iUUID, iCommonName)
            # ret_list = cursor.fetchall()
            ret_list = session.query(md.ActorMeta). \
                            filter(md.ActorMeta.uuid == iUUID). \
                            first()
            return md.ActorMetaSchema(many=False).dump(ret_list)
        elif iCommonName:
            ret_list = session.query(md.ActorMeta). \
                        filter(md.ActorMeta.commonname == iCommonName). \
                        first()  
            return md.ActorMetaSchema(many=False).dump(ret_list)
        else:
            return {}
    except Exception as error:
        print("f(x) get_actor_meta: DATABASE ERROR: {}".format(error))
        sys.exit(error)
    finally:
        session.close()

# GET ALL FAMILY META INFORMATION
def get_family_meta(iUUID="", iName=""):
    ret_list = []
    session = Session()
    try:
        if iUUID:
            # query = "SELECT * FROM mp_malware_meta WHERE mpmalware_uuid = ? or mp_name = ?"
            # value = (iUUID, iName)
            ret_list = session.query(md.MalwareMeta). \
                            filter(md.MalwareMeta.uuid == iUUID). \
                            first()
            return md.MalwareMetaSchema(many=False).dump(ret_list)
        elif iName:
            # query = "SELECT * FROM mp_malware_meta WHERE mpmalware_uuid = ? or mp_name = ?"
            # value = (iUUID, iName)
            ret_list = session.query(md.MalwareMeta). \
                            filter(md.MalwareMeta.name == iName). \
                            first()
            return md.MalwareMetaSchema(many=False).dump(ret_list)
        else:
            return {}

    except Exception as error:
        print("f(x) get_family_meta: DATABASE ERROR: {}".format(error))
        sys.exit(error)
    finally:
        session.close()

# GET ALL CHILDREN OF UUID
def get_children(iUUID):
    ret_list = []
    session = Session()
    try:
        # query = "SELECT  uuid FROM mp_parent_child_by_uuid WHERE parentuuid = ?"
        ret_list = session.query(md.ParentChildByUuid). \
                        with_entities(md.ParentChildByUuid.uuid). \
                        filter(md.ParentChildByUuid.parentuuid == iUUID). \
                        all()
        return md.ParentChildByUuidSchema(many=True).dump(ret_list)
    except Exception as error:
        print("f(x) get_children: DATABASE ERROR: {}".format(error))
        sys.exit(error)
    finally:
        session.close()

#GET ALL YARA RULES BASED ON A UUID
def get_yara_rules(iUUID):
    ret_list = []
    session = Session()
    try:
        if iUUID == "all":
            # query = "SELECT * FROMmp_malware_yara_path"
            ret_list = session.query(md.MalwareYaraPath). \
                        all()
                        
        else:
            # query = "SELECT * FROM mp_malware_yara_path WHERE mpmalware_uuid = ?"
            ret_list = session.query(md.MalwareYaraPath). \
                        filter(md.MalwareYaraPath.uuid == iUUID). \
                        all()
            return md.MalwareYaraPathSchema(many=True).dump(ret_list)
    except Exception as error:
        print("f(x) get_yara_rules: DATABASE ERROR: {}".format(error))
        sys.exit(error)
    finally:
        session.close()

# DRIVER FOR DEBUGGING
if __name__ == '__main__':
   print("DATABASE ACTIONS")