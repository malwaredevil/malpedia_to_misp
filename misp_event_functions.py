import pymisp as pm
import json
from pymisp.tools import make_binary_objects
from pymisp import MISPTag
from pymisp import ExpandedPyMISP, MISPEvent,  ExpandedPyMISP, MISPAttribute 
from pathlib import Path
import glob
import requests

from urllib3.exceptions import ProtocolError
import globals as gv
import sys
import os
import database_actions as db
import datetime
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# import threading
import concurrent.futures as cf
from globals import _EXECUTOR as executor, _UPLOAD_EXECUTOR as uexecutor
# import time

try:
    import lief  # type: ignore
    from lief import Logger  # type: ignore
    Logger.disable()
    HAS_LIEF = True

    # from .peobject import make_pe_objects
    # from .elfobject import make_elf_objects
    # from .machoobject import make_macho_objects

except ImportError:
    HAS_LIEF = False

from pymisp.tools.elfobject import make_elf_objects
import pydeep  # type: ignore
HAS_PYDEEP = True


# CHECK IF IS A VALID DATE
def valid_date(datestring):
    try:
        datetime.datetime.strptime(datestring, '%Y-%m-%d')
        return True
    except ValueError:
        return False 


def create_attribute(iCategory, iType, iValue, iIDS=1, iUUID="", iComment="", disableCorrelation=0):
    retAttribute = pm.MISPAttribute()
    try:
        
        retAttribute.category=iCategory,
        retAttribute.type = iType,
        retAttribute.value = iValue,
        retAttribute.to_ids = iIDS,
        retAttribute.disable_correlation = disableCorrelation
     

        if iUUID != "":
            retAttribute.uuid = iUUID
        
        if iComment != "":
            retAttribute.comment = iComment
        
        return retAttribute
    except Exception as e:
        exc_type, _, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print("f(x) create_attribute: {} {} {}".format(exc_type, fname, exc_tb.tb_lineno))
        sys.exit(e)
    
    
def pushToMISP(event, iUpdate=False, mURL="", mKey="", mVerifycert="", mDebug=""):
    try:
        mispDB = pm.ExpandedPyMISP(url=mURL, key=mKey, ssl=mVerifycert, debug=mDebug)
        if gv._DEBUG:
            print("f(x) pushToMISP(): PUSHING EVENT TO MISP: {}".format(event))

        # NEW EVENT
        if iUpdate == False:
            event.publish()
            event = mispDB.add_event(event, pythonify=True)
        else:
            event.publish()
            event = mispDB.update_event(event, pythonify=True)
    except Exception as e:
        if gv._DEBUG:
            print("f(x) pushToMISP() ERROR: {}".format(e))
        pass    
    finally:
        print("pushToMISP: CREATED MISP EVENT: {}".format(event.info))
        return True 


# def pushToMISPWithAttachment(event, iPath, iUpdate=False, mURL="", mKey="", mVerifycert="", mDebug="", fo=None, peo=None, seos=None):
#     mispDB = ExpandedPyMISP(mURL, mKey, mVerifycert)
    
#     # CREATE EVENT
#     if iUpdate == False:
#         event.publish()
#         mispDB.add_event(event, pythonify=True)
#     else:
#         event.publish()
#         mispDB.update_event(event, pythonify=True)

#     p = Path(iPath)
#     files = [p]
#     arg_type = 'malware-sample'

#     # Create attributes
#     attributes = []
#     for f in files:
#         a = MISPAttribute()
#         a.type = arg_type
#         a.value = f.name
#         a.data = f
#         a.comment = "DATA FROM MALPEDIA."
#         a.expand = 'binary'
#         attributes.append(a)

#     for a in attributes:
#         mispDB.add_attribute(event.uuid, a)
    
#     # # CREATE EVENT
#     # if iUpdate == False:
#     #     event.publish()
#     #     mispDB.add_event(event, pythonify=True)
#     # else:
#     #     event.publish()
#     #     mispDB.update_event(event, pythonify=True)   



def pushToMISPWithAttachment(event, iPath, iUpdate=False, mURL="", mKey="", mVerifycert="", mDebug="", fo=None, peo=None, seos=None):
    try:
        mispDB = pm.ExpandedPyMISP(url=mURL, key=mKey, ssl=mVerifycert, debug=mDebug)
        if gv._DEBUG:
            print("f(x) pushToMISPWithAttachment() EVENT: {}".format(event))
        # CREATE EVENT
        if iUpdate == False:
            event.publish()
            mispDB.add_event(event, pythonify=True)
        else:
            event.publish()
            mispDB.update_event(event, pythonify=True)
            

        # # ADD ATTACHMENT
        if iUpdate == False:
        #     myPath = iPath
        #     fo = None
        #     peo = None
        #     seos = None

        # for f in glob.glob(myPath):
            # try:
            #     fo , peo, seos = make_binary_objects(f)
            # except Exception as e:
            #     continue
            if seos:
                try:
                    for s in seos:
                        try:
                            mispDB.add_object(event.uuid, s)
                        except Exception as e:
                            continue
                except Exception as e:
                    pass
            if peo:
                try:
                    mispDB.add_object(event.uuid, peo, pythonify=True)
                    for ref in peo.ObjectReference:
                        try:
                            mispDB.add_object_reference(ref)
                        except Exception as e:
                            continue 
                except Exception as e:
                    pass
            if fo:
                try:
                    mispDB.add_object(event.uuid, fo)
                    for ref in fo.ObjectReference:
                        try:
                            mispDB.add_object_reference(ref, pythonify=True)
                        except Exception as e:
                            continue 
                except Exception as e:
                    pass

            # UPDATE EVENT AFTER ADDING ATTACHMENT
            try:
                event.publish()
                mispDB.publish(event)
                print("f(x) pushToMISPWithAttachment: CREATED MISP EVENT: {}".format(event.info))
            except Exception as e:
                pass
    except Exception as e:
        if gv._DEBUG:
            print("f(x) pushToMISPWithAttachment() ERROR: {}".format(e))
        pass
        # gv._THREAD_LIST.append(uexecutor.submit(pushToMISPWithAttachment,event, iPath, iUpdate, mURL, mKey, mVerifycert, mDebug, fo, peo, seos))


# CREATES AN EVENT BASED ON UUID FOUND IN PARENT CHILD TABLE
# USES THE FOLLOWING GLOBAL VARIABLES
# ITERATE THROUGH TREE TO CREATE CHILDREN EVENTS
# _MISP_CREATE_CHILDREN = True
# ATTACH THE MALWARE, WHEN APPLICABLE. IF FALSE, ONLY METADATA (SECTIONS, SSDEEP, ETC), WILL BE PRESENT
# _MISP_ATTACH_FILES = False
def createIncident(iUUID, iUpdate=False):
    try:
        if gv._DEBUG:
            print("f(x) createIncident: UUID: {}".format(iUUID))
        # fUNCTION SETUP
        # -----------------------------------------------
        myUUID = iUUID

        # GET UUID METADATA FROM PARENT CHILD TABLE
        # -----------------------------------------------
        iPC_META = db.get_parent_child_data(iUUID=myUUID)

        # POSSIBLE VALUES:
        # "ACTOR" : THREAT ACTOR: TOP LEVEL OF TREE.
        # "FAMILY" : FAMILY (E.G. WIN.XAGENT): USUALLY MIDDLE OF TREE
        # "MALWARE" : MALWARE FILE: BOTTOM OF TREE
        # "PATH" : PATH (E.G. MODULES): USED WHEN IT IS NOT A FAMILY, FILE, OR ACTOR. JUST IN DISK PATH OF ACTUAL MALWARE
        myType = iPC_META["mytype"]
        
        if gv._DEBUG:
            print("f(x) createIncident: TYPE: {}".format(myType))

        # IF IT IS AN ACTOR
        if myType == "ACTOR":
            createActor(myUUID, iUpdate)
        # IF IT IS A FAMILY
        elif myType == "FAMILY":
            createFamily(myUUID, iUpdate)
        # IF IT IS MALWARE
        elif myType == "MALWARE":
            createMalware(iUUID, iUpdate)
        # IF IT IS A PATH
        elif myType == "PATH":
           createPath(iUUID, iUpdate)
        # CATCH EVERYTHING ELSE AND STOP PROCESS:
        else:
            print("f(x) createIncident: UNKNOWN TYPE")
            sys.exit(0)
    except Exception as e:
        exc_type, _, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print("f(x) createIncident: {} {} {}".format(exc_type, fname, exc_tb.tb_lineno))
        sys.exit(e)

# CREATE AN ACTOR [INCIDENT] IN MISP
def createActor(iUUID, iUpdate=False):
    try:
        # fUNCTION SETUP
        # -----------------------------------------------
        myUUID = iUUID
        myLinks = []
        myTags = []
        myMeta = []
        myCommonName = ""

        # ATTRIBUTES COMMON FIELDS
        # -----------------------------------------------
        attributeToIDS = 0 # 0 false : 1 true
        attributeComment = ""
        attribDisableCorrelation = 1 # 0 false : 1 true

        # MISP SETUP
        # -----------------------------------------------
        
        event = pm.MISPEvent() 
        event.uuid = myUUID

        # GET META FOR ACTOR (USE COMMON NAME AS INCIDENT NAME)
        myMeta = db.get_actor_meta(myUUID)
        if gv._DEBUG:
            print("f(x) createActor: ACTOR META")  
            print(json.dumps(myMeta, indent=4))
        
        # USED AS INCIDENT NAME
        myCommonName = myMeta["commonname"]
        event.info = "Threat Actor: " + myCommonName
        if gv._DEBUG:
            print("f(x) createActor: ACTOR COMMON NAME: {}".format(myCommonName))
        
        # USED AS A TEXT ATTRIBUTE
        myDescription = myMeta["description"]
        if myDescription != "":
            attributeType = "text"
            attributeCategory = "Internal reference"
            if gv._DEBUG:
                print("f(x) createFamily: CREATING FAMILY COMMENT: \nCATEGORY: {} \nTYPE: {} \nVALUE: {} \nCOMMENT: {} \nDISABLE CORRELATION: {} \
                    ".format(attributeCategory, attributeType, myDescription, attributeToIDS, attributeComment,  attribDisableCorrelation))

            event.add_attribute(attributeType, myDescription, comment=attributeComment, category=attributeCategory, to_ids=attributeToIDS, disable_correlation=attribDisableCorrelation)



        # -----------------------------------------------
        # GET TAGS
        if myCommonName != "UNATTRIBUTED" and myCommonName != "ERROR":
            # GET TAGS
            myTags = db.get_set_all_tags(myUUID)
            event.tags = myTags
            if gv._DEBUG:
                print("f(x) createActor: TAGS CREATED")    
                print(*myTags, sep = "\n")  

            # REFERENCES/URLS
            myLinks = db.get_links(myUUID)
            for link in myLinks:
                attributeType = "link"
                attributeCategory = "Internal reference"
                if gv._DEBUG:
                    print("f(x) createActor: CREATING ACTOR LINK: \nCATEGORY: {} \nTYPE: {} \nVALUE: {} \nTO_IDS: {} \nCOMMENT: {}\nDISABLE CORRELATION: {} \
                            ".format(attributeCategory, attributeType, link["url"], attributeToIDS, attributeComment,  attribDisableCorrelation))
                event.add_attribute(attributeType, link["url"], comment=attributeComment, category=attributeCategory, to_ids=attributeToIDS, disable_correlation=attribDisableCorrelation)
  



        # MARK SOURCE OF INFORMATION
        attributeType = "link"
        attributeCategory = "Internal reference"
        attributeComment = "DATA FROM MALPEDIA." 
        if gv._DEBUG:
            print("f(x) createActor: CREATING ACTOR ATTRIBUTION LINK: \nCATEGORY: {} \nTYPE: {} \nVALUE: {} \nTO_IDS: {} \nCOMMENT: {} \nDISABLE CORRELATION: {} \
                    ".format(attributeCategory, attributeType, gv._MALPEDIA_URL, attributeToIDS, attributeComment,  attribDisableCorrelation))
  
        event.add_attribute(attributeType, gv._MALPEDIA_URL, comment=attributeComment, category=attributeCategory, to_ids=attributeToIDS, disable_correlation=attribDisableCorrelation)
        
        
        gv._THREAD_LIST.append(executor.submit(pushToMISP, event, iUpdate, gv._MISP_URL, gv._MISP_KEY, gv._MISP_VERIFYCERT, gv._DEBUG))
        # pushToMISP(event, iUpdate, gv._MISP_URL, gv._MISP_KEY, gv._MISP_VERIFYCERT, gv._DEBUG)
            

    except Exception as e:
        exc_type, _, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print("f(x) createActor: {}: {}: {}".format(exc_type, fname, exc_tb.tb_lineno))
        sys.exit(e)  

# CREATE A FAMILY [INCIDENT] IN MISP
def createFamily(iUUID, iUpdate=False ):
    try:
        # fUNCTION SETUP
        # -----------------------------------------------
        myUUID = iUUID
        myLinks = []
        myTags = []
        myMeta = []
        myCommonName = ""

        # ATTRIBUTES COMMON FIELDS
        # -----------------------------------------------
        attributeToIDS = 0 # 0 false : 1 true
        attributeComment = ""
        attribDisableCorrelation = 1 # 0 false : 1 true

        # MISP SETUP
        # -----------------------------------------------
        event = pm.MISPEvent() 
        event.uuid = myUUID

        # GET UUID METADATA FROM PARENT CHILD TABLE
        # -----------------------------------------------
        iPC_META = db.get_parent_child_data(iUUID=myUUID)
        parentuuid = iPC_META["parentuuid"]
        event.extends_uuid = parentuuid


        # -----------------------------------------------
        # REFERENCES/URLS
        myLinks = db.get_links(myUUID)
        for link in myLinks:
            attributeType = "link"
            attributeCategory = "Internal reference"
            if gv._DEBUG:
                print("f(x) createFamily: LINK: \nCATEGORY: {} \nTYPE: {} \nVALUE: {} \nTO_IDS: {} \nCOMMENT: {}\nDISABLE CORRELATION: {} \
                        ".format(attributeCategory, attributeType, link["url"], attributeToIDS, attributeComment,  attribDisableCorrelation))
            event.add_attribute(attributeType, link["url"], comment=attributeComment, category=attributeCategory, to_ids=attributeToIDS, disable_correlation=attribDisableCorrelation)


        # GET TAGS
        myTags = db.get_set_all_tags(myUUID)
        event.tags = myTags
        if gv._DEBUG:
            print("f(x) createFamily: TAGS")    
            print(*myTags, sep = "\n")    

        # GET META FOR ACTOR (USE COMMON NAME AS INCIDENT NAME)
        myMeta = db.get_family_meta( iUUID=myUUID)
        if gv._DEBUG:
            print("f(x) createFamily: META")  
            print(json.dumps(myMeta, indent=4))
        
        # USED AS INCIDENT NAME
        myCommonName = myMeta["commonname"]
        event.info = myCommonName
        if gv._DEBUG:
            print("f(x) createFamily: COMMON NAME: {}".format(myCommonName))
        
        # USED AS A TEXT ATTRIBUTE
        myDescription = myMeta["description"]
        if myDescription != "":
            attributeType = "text"
            attributeCategory = "Internal reference"
            if gv._DEBUG:
                print("f(x) createFamily: CREATING FAMILY COMMENT: \nCATEGORY: {} \nTYPE: {} \nVALUE: {} \nCOMMENT: {} \nDISABLE CORRELATION: {} \
                    ".format(attributeCategory, attributeType, myDescription, attributeToIDS, attributeComment,  attribDisableCorrelation))

            event.add_attribute(attributeType, myDescription, comment=attributeComment, category=attributeCategory, to_ids=attributeToIDS, disable_correlation=attribDisableCorrelation)


        # MARK SOURCE OF INFORMATION
        attributeType = "link"
        attributeCategory = "Internal reference"
        attributeComment = "DATA FROM MALPEDIA." 
        if gv._DEBUG:
            print("f(x) createFamily: ATTRIBUTION LINK: \nCATEGORY: {} \nTYPE: {} \nVALUE: {} \nTO_IDS: {} \nCOMMENT: {} \nDISABLE CORRELATION: {} \
                    ".format(attributeCategory, attributeType, gv._MALPEDIA_URL, attributeToIDS, attributeComment,  attribDisableCorrelation))
  
        event.add_attribute(attributeType, gv._MALPEDIA_URL, comment=attributeComment, category=attributeCategory, to_ids=attributeToIDS, disable_correlation=attribDisableCorrelation)
        
        # YARA
        # ADD OBJECTS
        # -----------------------------------------------
        # YARA
        iYara = db.get_yara_rules(myUUID)
        tlp = ""
        yaraAbsPath = ""
        
        for yara in iYara:
            tagList = []
            newTag = MISPTag()
            tlp = yara["tlp"]
            yaraAbsPath = yara["path_to_yara"]
            tlpTag = "tlp:" + tlp.split("_")[1]
            newTag.name = tlpTag
            tagList.append(newTag)
            yaraUUID = yara["attribute_uuid"]

            yaraContents = ""
            
            with open(yaraAbsPath, 'r') as yaraIn:
                yaraContents =yaraIn.read()
                yaraIn.close()

            misp_object = pm.tools.GenericObjectGenerator("yara")
            misp_object.comment = tlpTag
            misp_object.uuid = yaraUUID
            
            

            subAttribute = misp_object.add_attribute("yara", yaraContents)
            subAttribute.disable_correlation = True
            subAttribute.to_ids = False
            subAttribute.comment = tlpTag
            subAttribute.tags = tagList

            event.add_object(misp_object)
    
            if gv._DEBUG:
                print("f(x) createFamily: YARA")
                print(*iYara, sep = "\n") 


        gv._THREAD_LIST.append(executor.submit(pushToMISP, event, iUpdate, gv._MISP_URL, gv._MISP_KEY, gv._MISP_VERIFYCERT, gv._DEBUG))
        # pushToMISP(event, iUpdate, gv._MISP_URL, gv._MISP_KEY, gv._MISP_VERIFYCERT, gv._DEBUG)

    except Exception as e:
        exc_type, _, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print("f(x) createFamily: {}: {}: {}".format(exc_type, fname, exc_tb.tb_lineno))
        sys.exit(e)  


# CREATE A PATH [INCIDENT] IN MISP
def createPath(iUUID, iUpdate=False):
    try:
         # fUNCTION SETUP
        # -----------------------------------------------
        myUUID = iUUID
        myTags = []
        myName = ""

        # ATTRIBUTES COMMON FIELDS
        # -----------------------------------------------
        attributeToIDS = 0 # 0 false : 1 true
        attributeComment = ""
        attribDisableCorrelation = 1 # 0 false : 1 true

        # MISP SETUP
        # -----------------------------------------------
        event = pm.MISPEvent() 
        event.uuid = myUUID

        # GET UUID METADATA FROM PARENT CHILD TABLE
        # -----------------------------------------------
        iPC_META = db.get_parent_child_data(iUUID=myUUID)
        parentuuid = iPC_META["parentuuid"]
        myName = iPC_META["name"]
        event.extends_uuid = parentuuid
        event.info = myName

        # GET TAGS FROM PARENT AND ADD TO THIS PATH
        myTags = db.get_set_all_tags(myUUID)
        event.tags = myTags
        if gv._DEBUG:
            print("f(x) createPath: TAGS")    
            print(*myTags, sep = "\n")    

        # MARK SOURCE OF INFORMATION
        attributeType = "link"
        attributeCategory = "Internal reference"
        attributeComment = "DATA FROM MALPEDIA." 
        if gv._DEBUG:
            print("f(x) createPath: ATTRIBUTION LINK: \nCATEGORY: {} \nTYPE: {} \nVALUE: {} \nTO_IDS: {} \nCOMMENT: {} \nDISABLE CORRELATION: {} \
                    ".format(attributeCategory, attributeType, gv._MALPEDIA_URL, attributeToIDS, attributeComment,  attribDisableCorrelation))
  
        event.add_attribute(attributeType, gv._MALPEDIA_URL, comment=attributeComment, category=attributeCategory, to_ids=attributeToIDS, disable_correlation=attribDisableCorrelation)

        gv._THREAD_LIST.append(executor.submit(pushToMISP, event, iUpdate, gv._MISP_URL, gv._MISP_KEY, gv._MISP_VERIFYCERT, gv._DEBUG))
        # pushToMISP(event, iUpdate, gv._MISP_URL, gv._MISP_KEY, gv._MISP_VERIFYCERT, gv._DEBUG)

    except Exception as e:
        exc_type, _, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print("f(x) createPath: {}: {}: {}".format(exc_type, fname, exc_tb.tb_lineno))
        sys.exit(e)  
 

# CREATE A MALWARE [INCIDENT] IN MISP
def createMalware(iUUID, iUpdate=False):
    try:
        # fUNCTION SETUP
        # -----------------------------------------------
        myUUID = iUUID
        myTags = []

        # ATTRIBUTES COMMON FIELDS
        # -----------------------------------------------
        attributeToIDS = 0 # 0 false : 1 true
        attributeComment = ""
        attribDisableCorrelation = 1 # 0 false : 1 true

        # MISP SETUP
        # -----------------------------------------------
        event = pm.MISPEvent() 
        event.uuid = myUUID

        # GET UUID METADATA FROM PARENT CHILD TABLE
        # -----------------------------------------------
        iPC_META = db.get_parent_child_data(iUUID=myUUID)
        parentuuid = iPC_META["parentuuid"]
        event.extends_uuid = parentuuid

        name = iPC_META["name"]

        if name in gv._BLACKLISTED_FILES:
            return True

        event.info = name
        
        # SET VERSION
        myVersion = iPC_META["version"]
        if myVersion != "":
            attributeType = "text"
            attributeCategory = "Internal reference"
            if gv._DEBUG:
                print("f(x) createMalware: CREATING FAMILY COMMENT: \nCATEGORY: {} \nTYPE: {} \nVALUE: {} \nCOMMENT: {} \nDISABLE CORRELATION: {} \
                    ".format(attributeCategory, attributeType, myVersion, attributeToIDS, attributeComment,  attribDisableCorrelation))

            event.add_attribute(attributeType, myVersion, comment=attributeComment, category=attributeCategory, to_ids=attributeToIDS, disable_correlation=attribDisableCorrelation)


        # SET DATE ADDED
        date_added = iPC_META["date_added"]
        if valid_date(date_added):
            event.date = date_added
        else:
            event.date = datetime.date.today()
        
        # GET TAGS
        myTags = db.get_set_all_tags(myUUID)
        event.tags = myTags
        if gv._DEBUG:
            print("f(x) createMalware: TAGS")    
            print(*myTags, sep = "\n")    

        # MARK SOURCE OF INFORMATION
        attributeType = "link"
        attributeCategory = "Internal reference"
        attributeComment = "DATA FROM MALPEDIA." 
        if gv._DEBUG:
            print("f(x) createMalware: ATTRIBUTION LINK: \nCATEGORY: {} \nTYPE: {} \nVALUE: {} \nTO_IDS: {} \nCOMMENT: {} \nDISABLE CORRELATION: {} \
                    ".format(attributeCategory, attributeType, gv._MALPEDIA_URL, attributeToIDS, attributeComment,  attribDisableCorrelation))
  
        event.add_attribute(attributeType, gv._MALPEDIA_URL, comment=attributeComment, category=attributeCategory, to_ids=attributeToIDS, disable_correlation=attribDisableCorrelation)
        
        # ADD ATTACHMENT
        myPath = iPC_META["path"]
        fo = None
        peo = None
        seos = None

        # CREATE ATTACHMENT BUT DON'T UPLOAD IT AGAIN IF THIS IS JUST AN UPDATE
        if iUpdate == False:
            for f in glob.glob(iPC_META["path"]):
                try:
                    fo , peo, seos = make_binary_objects(f)
                except Exception as e:
                    continue
    
        
        
        gv._THREAD_LIST.append(uexecutor.submit(pushToMISPWithAttachment, event, myPath, iUpdate, gv._MISP_URL, gv._MISP_KEY, gv._MISP_VERIFYCERT, gv._DEBUG, fo , peo, seos))
        # pushToMISPWithAttachment(event, myPath, iUpdate, gv._MISP_URL, gv._MISP_KEY, gv._MISP_VERIFYCERT, gv._DEBUG, fo , peo, seos)

    except Exception as e:
        exc_type, _, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print("f(x) createMalware: {}: {}: {}".format(exc_type, fname, exc_tb.tb_lineno))
        sys.exit(e)  

def uuidSearch (iUUID):
    try:
        if gv._DEBUG:
            print("f(x) uuidSearch() UUID: {}".format(iUUID))
            
        relative_path = '/events/restSearch'
        body = {
            "returnFormat": "json", 
            "limit": 1, 
            "withAttachments": 0, 
            "metadata": 0, 
            "enforceWarninglist": 0, 
            "includeEventUuid": 0, 
            "includeEventTags": 0, 
            "sgReferenceOnly": 0, 
            "includeContext": 0, 
            "headerless": 0, 
            "includeSightings": 0, 
            "includeDecayScore": 0, 
            "includeCorrelations": 0
        }

        body["uuid"] = iUUID
        retVal = 0
        headers ={}
        headers["Authorization"] = "IC88QRVqUSPOkNP9K6M7VEF4A41OvJD7upGXzPJu"
        headers["Accept"]="application/json" 
        headers["Content-type"]= "application/json"

        # mispDB = pm.ExpandedPyMISP(url=gv._MISP_URL, key=gv._MISP_KEY, ssl=gv._MISP_VERIFYCERT)
        # kwargs = {"uuid" : iUUID}
        # result = mispDB.search(controller='events', return_format='json', limit=1, **kwargs,)
        # result = mispDB.direct_call(relative_path, body)

        if gv._DEBUG:
            print("f(x) uuidSearch(): requests.post({}, data={}, headers={}, verify={} )".format(gv._MISP_URL +  relative_path, json.dumps(body), json.dumps(headers), gv._MISP_VERIFYCERT))
        result = requests.post(gv._MISP_URL +  relative_path, data=json.dumps(body), headers=headers, verify=gv._MISP_VERIFYCERT )
        lst = json.loads(result.json())
        if gv._DEBUG:
            print("f(x) uuidSearch(): TYPE: {}".format(type(lst)))
        count = 0
        for x in lst:
            if x != "":
                count += 1
                print("f(x) uuidSearch(): NEW COUNT: {}: X: {}".format(count, x))
        retVal = count
        if gv._DEBUG:
            print("f(x) uuidSearch(): RESULT: {}: LEN: {}".format(result.json(), count))
        return retVal
    except Exception as e:
        if gv._DEBUG:
            print("f(x) uuidSearch(): ERROR: {}".format(e))
        print (e)

def deleteEvent(iUUID="", iEventID=""):
    try:
        mispDB = pm.ExpandedPyMISP(url=gv._MISP_URL, key=gv._MISP_KEY, ssl=gv._MISP_VERIFYCERT)
        event_id = ""
        
        if iUUID != "":
            kwargs = {"uuid" : iUUID}
            result = mispDB.search(controller='events', return_format='json', limit=1, **kwargs)
            for val in result:
                event_id = val["Event"]["id"]
        elif iEventID != "":
            event_id = iEventID
        
        if event_id != "":
            if gv._DEBUG:
                print("f(x) deleteEvent: ATTEMPTING TO DELETE EVENT [IF EXISTS]: {}".format(event_id))
            mispDB.delete_event(event_id)
            
            
        else:
            print("f(x) deleteEvent: EMPTY EVENT_ID FOUND. NO DELETION MADE\niUUID: {}\niEventID: {}\nRETURNED EVENT ID [IF APPLICABLE]: {}".format( iUUID, iEventID, event_id))
     



    except Exception as e:
        print (e)


def getOrgEvents(iOrgID):
    try:
        misp = pm.ExpandedPyMISP(gv._MISP_URL, gv._MISP_KEY, gv._MISP_VERIFYCERT)
        kwargs = {"org_id" : iOrgID}
        # result = misp.search('events', published=0, **kwargs)
        result = misp.search('events', published=1, **kwargs)
        return result         
        
        
    except Exception as e:
        print (e)

if __name__ == '__main__':
    print("INIT")