from copy import Error

from pymisp import api
import malpedia_client as mp_Client
import mitre_functions as mf
import sanitizitation_functions as sf
import globals as gv
import misp_event_functions as mef
import database_actions as db
import os
import sys
import json
import time
import math
import glob
import datetime
import uuid
import misp_galaxy_functions as mgf
import git_actions
import yaml
# import threading
import concurrent.futures as cf
from globals import _EXECUTOR as executor




# AUTHENTICATE TO MALPEDIA
def Authenticate():
    try:
        retClient = mp_Client.Client(apitoken=gv._MALPEDIA_KEY)
        return retClient
    except Exception as e:
        print("f(x) Authenticate Error: {}".format(e))
        sys.exit(e)

# CHECK IF IS A VALID DATE
def valid_date(datestring):
    try:
        datetime.datetime.strptime(datestring, '%Y-%m-%d')
        return True
    except ValueError:
        return False

# FIX MALFORMED JSON
def fix_json(iJSON):
    try:
        yamlData = yaml.safe_load(iJSON)
        jsonData = json.dumps(yamlData)
        return jsonData
    except:
        exc_type, _, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print("f(x) fix_json: ERROR: {}: {}: {}".format(exc_type, fname, exc_tb.tb_lineno))


# READ SPECIMEN DATA FROM JSON FILE
def getSpecimenData(iFamilyName, iSha256):
    # if not gv._DEBUG:
    #     print("{}:{}".format(iFamilyName, iSha256))
    specimen_dict = {}
    status = ""
    version = ""
    sha256 = ""
    with open(gv._MALPEDIA_OUTPUT + "malware/" + iFamilyName + ".json", 'r') as jsonIn:
        
        specimen_dict = json.loads(fix_json(jsonIn))
        jsonIn.close()

    for specimen in specimen_dict:
        sha256 = specimen["sha256"]
        if sha256 == iSha256:
            status = specimen["status"]
            version = specimen["version"]
            break

    return status, version, sha256



def stageMalwareSpecimens():
    dirList = []

    for path in gv._DIR_MALPEDIA_GIT_LIST:
        listPath = path.split("/")
        if len(listPath) > (gv._FAMILY_SPLIT_DEPTH + 1):
            family = path.split("/")[gv._FAMILY_SPLIT_DEPTH]
            dirList.append(family)
    dirList.sort()
    gv._MALWARE_FAMILY_SET = set(dirList)

    try:
        # DOWNLOAD MALWARE SPECIMENT LISTS AND WRITE THEM TO JSON
        # THROTTLE SO IT DOESN'T LOCK API KEY
        max_requests_per_minute = 40 #60 requests per minute is the max
        current_request_count = 1
        completed_malware_list = []

        # MAKE THE COMPLETED FILE IF IT DOESN'T EXIST
        completed_malware_file_path = gv._MALPEDIA_OUTPUT + "malware/" + "001.completed.maware.json"

        if os.path.isfile(completed_malware_file_path):
            
            completed_malware_file =  open(completed_malware_file_path, 'r')
            completed_malware_list = json.loads(fix_json(completed_malware_file.read()))
            completed_malware_file.close()
        else:
            completed_malware_file =  open(completed_malware_file_path, 'w')
            completed_malware_file.write(json.dumps("[]"))
            completed_malware_file.close


        tStart = time.time()
        tNow = None
        tDiff = 0
        iWait = 140
        for malware in gv._MALWARE_FAMILY_SET:
            if malware in completed_malware_list:
                continue
            with open(gv._MALPEDIA_OUTPUT + "malware/" + malware + ".json", 'w') as jsonOut:
                print("f(x) stageMalwareSpecimens: PULLING DATA FOR MALWARE: {}".format(malware))
                mpClient = Authenticate()
                gv._CURRENT_FAMILY_CURRENT_SPECIMEN_DICT = mpClient.list_samples(malware)
                jsonOut.write(json.dumps(gv._CURRENT_FAMILY_CURRENT_SPECIMEN_DICT))
                jsonOut.close()
                tNow = time.time()
                tDiff = tNow - tStart
                if ((current_request_count == max_requests_per_minute) and (tDiff <= iWait )):
                    tNow = time.time()
                    tDiff = tNow - tStart
                    print("f(x) stageMalwareSpecimens: API PULL THRESHHOLD REACHED.")
                    while (tDiff <= iWait):
                        time.sleep(1)
                        tNow = time.time()
                        tDiff = (tNow - tStart)
                        print("f(x) stageMalwareSpecimens: WAITING {} SECONDS.".format(math.ceil(iWait - tDiff)))

                    tStart = time.time()
                    current_request_count = 1
                    print("f(x) stageMalwareSpecimens: RESUMING PULLS")
                else:
                    completed_malware_list.append(malware)
                    completed_malware_file =  open(completed_malware_file_path, 'w')
                    completed_malware_file.write(json.dumps(completed_malware_list))
                    completed_malware_file.close
                    current_request_count += 1

                    # DEBUG SEQ
                    if gv._DEBUG:
                        print("f(x) stageMalwareSpecimens: {}: ADDED TO COMPLETED MALWARE.".format(malware))
        # os.remove(completed_malware_file_path)
        print("f(x) stageMalwareSpecimens: COMPLETED DOWNLOAD OF MALWARE SPECIMEN INFO")
    except Exception as e:
        exc_type, _, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print("f(x) stageMalwareSpecimens: {}: {}: {}".format(exc_type, fname, exc_tb.tb_lineno))
        sys.exit(e)

def build_actor_malware_tree(threat_actor):
    print("f(x) build_actor_malware_tree: GETTING DATA FOR {}".format(threat_actor.upper()))
    lastupdated = datetime.date.today()
    path_to_json = gv._MALPEDIA_OUTPUT + "actors/" + threat_actor + ".json"
    print("f(x) build_actor_malware_tree: IMPORTING ACTOR: {}".format(threat_actor.upper()))

    # READ THE THREAT ACTOR JSON FILE
    gv._CURRENT_ACTOR_MITRE_GROUP_CODE = "NONE"
    gv._CURRENT_ACTOR_MITRE_TECHNIQUE_IDS = []
    gv._CURRENT_ACTOR_TECHNIQUE_TAGS = []

    with open(path_to_json, 'r') as jsonIn:
        
        
        try:
            gv._CURRENT_ACTOR_INFO_DICT = json.loads(fix_json(jsonIn))
            jsonIn.close()
        except:
            exc_type, _, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print("f(x) build_actor_malware_tree: BUILD THREAT ACTOR JSON FILE ERROR: {}: {}: {}".format(exc_type, fname, exc_tb.tb_lineno))


        #-----------------------------------------------------------------------------------------------------------------
        # TOP LEVEL VALUES------------------------------------------------------------------------------------------------
        #-----------------------------------------------------------------------------------------------------------------
        if gv._DEBUG:
            print("f(x) build_actor_malware_tree: TOP LEVEL")
            print("+" * 75)
        # STRING NAME OF ACTOR WITH FIRST CHARACTER CAPITALIZED
        try:
            gv._CURRENT_ACTOR_NAME_STR = gv._CURRENT_ACTOR_INFO_DICT["value"].strip()
        except:
            gv._CURRENT_ACTOR_NAME_STR = ""
        # DEBUG SEQ
        if gv._DEBUG:
            print("f(x) build_actor_malware_tree: ACTOR NAME: {}".format(gv._CURRENT_ACTOR_NAME_STR))

        # STRING OF ACTOR DESCRIPTION
        try:
            gv._CURRENT_ACTOR_DESCRIPTION_STR = gv._CURRENT_ACTOR_INFO_DICT["description"].strip()
        except:
            gv._CURRENT_ACTOR_DESCRIPTION_STR = ""
        # DEBUG SEQ
        if gv._DEBUG:
            print("f(x) build_actor_malware_tree: ACTOR DESCRIPTION: {}".format(gv._CURRENT_ACTOR_DESCRIPTION_STR))

        # STRING OF UUID
        try:
            gv._CURRENT_ACTOR_UUID_STR = gv._CURRENT_ACTOR_INFO_DICT["uuid"].strip()
            gv._ACTOR_UUID_DICT.update({gv._CURRENT_ACTOR_NAME_STR : gv._CURRENT_ACTOR_UUID_STR})
        except:
            gv._CURRENT_ACTOR_UUID_STR = ""
        # DEBUG SEQ
        if gv._DEBUG:
            print("f(x) build_actor_malware_tree: ACTOR UUID: {}".format(gv._CURRENT_ACTOR_UUID_STR))
            print("+" * 75)

        #-----------------------------------------------------------------------------------------------------------------
        # ACTOR META SECTION----------------------------------------------------------------------------------------------------
        #-----------------------------------------------------------------------------------------------------------------

        # GET META SECTION
        try:
            gv._CURRENT_ACTOR_META_DICT = gv._CURRENT_ACTOR_INFO_DICT["meta"]
        except:
            gv._CURRENT_ACTOR_META_DICT = {}
        if gv._DEBUG:
            print("f(x) build_actor_malware_tree: ACTOR META")
            print("+" * 75)

        # LIST OF STRINGS OF COUNTRY NAMES
        try:
            gv._CURRENT_ACTOR_META_CFR_SUSPECTED_VICTIMS_LIST = gv._CURRENT_ACTOR_META_DICT["cfr-suspected-victims"]
        except:
            gv._CURRENT_ACTOR_META_CFR_SUSPECTED_VICTIMS_LIST = []
        # DEBUG SEQ
        if gv._DEBUG:
            print("f(x) build_actor_malware_tree: ACTOR SUSPECTED VICTIMS")
            print(*gv._CURRENT_ACTOR_META_CFR_SUSPECTED_VICTIMS_LIST, sep = "\n") 

        # STRING OF TWO DIGIT COUNTRY CODE
        try:
            gv._CURRENT_ACTOR_META_COUNTRY_STR = gv._CURRENT_ACTOR_META_DICT["country"].strip()
        except:
            gv._CURRENT_ACTOR_META_COUNTRY_STR = ""
        # DEBUG SEQ
        if gv._DEBUG:
            print("f(x) build_actor_malware_tree: ACTOR COUNTRY: {}".format(gv._CURRENT_ACTOR_META_COUNTRY_STR))
            # print("*" * 50)

        # LIST OF STRINGS OF LINKS TO ARTICLES
        try:
            gv._CURRENT_ACTOR_META_REFS_LIST = gv._CURRENT_ACTOR_META_DICT["refs"]
        except:
            gv._CURRENT_ACTOR_META_REFS_LIST = []
        # DEBUG SEQ
        if gv._DEBUG:
            print("f(x) build_actor_malware_tree: ACTOR REFERENCES")
            print(*gv._CURRENT_ACTOR_META_REFS_LIST, sep = "\n") 

        # LIST OF STRINGS OF TYPE OF ACTOR
        try:
            gv._CURRENT_ACTOR_META_CFR_TARGET_CATEGORY_LIST = gv._CURRENT_ACTOR_META_DICT["cfr-target-category"]
        except:
            gv._CURRENT_ACTOR_META_CFR_TARGET_CATEGORY_LIST = []
        # DEBUG SEQ
        if gv._DEBUG:
            print("f(x) build_actor_malware_tree: TYPE OF ACTOR")
            print(*gv._CURRENT_ACTOR_META_CFR_TARGET_CATEGORY_LIST, sep = "\n") 

        # STRING OF TYPE OF INCIDENT
        try:
            gv._CURRENT_ACTOR_META_CFR_TYPE_OF_INCIDENT_STR = gv._CURRENT_ACTOR_META_DICT["cfr-type-of-incident"].strip()
        except:
            gv._CURRENT_ACTOR_META_CFR_TYPE_OF_INCIDENT_STR = ""
        # DEBUG SEQ
        if gv._DEBUG:
            print("f(x) build_actor_malware_tree: ACTOR INCIDENT TYPE: {}".format(gv._CURRENT_ACTOR_META_CFR_TYPE_OF_INCIDENT_STR))
            # print("*" * 50)

        # LIST OF STRINGS OF SYNONYMS
        try:
            gv._CURRENT_ACTOR_META_SYNONYMS_LIST = gv._CURRENT_ACTOR_META_DICT["synonyms"]
        except:
            gv._CURRENT_ACTOR_META_SYNONYMS_LIST = []
        # DEBUG SEQ
        if gv._DEBUG:
            print("f(x) build_actor_malware_tree: ACTOR SYNONYMS")
            print(*gv._CURRENT_ACTOR_META_SYNONYMS_LIST, sep = "\n") 

        # STRING OF STATE SPONSOR
        try:
            gv._CURRENT_ACTOR_META_CFR_STATE_SPONSOR_STR = gv._CURRENT_ACTOR_META_DICT["cfr-suspected-state-sponsor"].strip()
        except:
            gv._CURRENT_ACTOR_META_CFR_STATE_SPONSOR_STR = ""
        # DEBUG SEQ
        if gv._DEBUG:
            print("f(x) build_actor_malware_tree: ACTOR STATE SPONSOR: {}".format(gv._CURRENT_ACTOR_META_CFR_STATE_SPONSOR_STR))
            # print("*" * 50)

        # STRING OF VICTIMOLOGY
        try:
            gv._CURRENT_ACTOR_META_VICTIMOLOGY_STR = gv._CURRENT_ACTOR_META_DICT["victimology"].strip()
        except:
            gv._CURRENT_ACTOR_META_VICTIMOLOGY_STR = ""
        # DEBUG SEQ
        if gv._DEBUG:
            print("f(x) build_actor_malware_tree: ACTOR VICTIMOLOGY: {}".format(gv._CURRENT_ACTOR_META_VICTIMOLOGY_STR))
            # print("*" * 50)

        # STRING OF SINCE
        try:
            gv._CURRENT_ACTOR_META_SINCE_STR = gv._CURRENT_ACTOR_META_DICT["since"].strip()
        except:
            gv._CURRENT_ACTOR_META_SINCE_STR = ""
        # DEBUG SEQ
        if gv._DEBUG:
            print("f(x) build_actor_malware_tree: ACTOR SINCE: {}".format(gv._CURRENT_ACTOR_META_SINCE_STR))
            # print("*" * 50)

        # STRING OF MODE OF OPERATION
        try:
            gv._CURRENT_ACTOR_META_MODEOFOPERATIONS_STR = gv._CURRENT_ACTOR_META_DICT["mode-of-operation"].strip()
        except:
            gv._CURRENT_ACTOR_META_MODEOFOPERATIONS_STR = ""
        # DEBUG SEQ
        if gv._DEBUG:
            print("f(x) build_actor_malware_tree: ACTOR MODE OF OPERATION: {}".format(gv._CURRENT_ACTOR_META_MODEOFOPERATIONS_STR))
            # print("*" * 50)

        # STRING OF CAPABILITIES
        try:
            gv._CURRENT_ACTOR_META_CAPABILITIES_STR = gv._CURRENT_ACTOR_META_DICT["capabilities"].strip()
        except:
            gv._CURRENT_ACTOR_META_CAPABILITIES_STR = ""
        # DEBUG SEQ
        if gv._DEBUG:
            print("f(x) build_actor_malware_tree: ACTOR CAPABILITIES: {}".format(gv._CURRENT_ACTOR_META_CAPABILITIES_STR))
            # print("*" * 50)

        # ---------------------------------------------------------------------
        # BEGIN ACTOR META DATA DB INSERT
        # ---------------------------------------------------------------------

        # TAG FOR ACTOR
        # ---------------------------------------------------------------------
        # COMMON NAME
        if gv._DEBUG:
            print("f(x) build_actor_malware_tree: INSERT TAG: ACTOR: ACTOR COMMON NAME: {}".format(gv._CURRENT_ACTOR_NAME_STR))

        db.insert_tag(gv._CURRENT_ACTOR_UUID_STR, "", gv._CURRENT_ACTOR_NAME_STR, "ACTOR")
     

        # GET / INSERT MITRE GROUP DATA
        knownGroupCodes = set()
        
        group_code = ""
        if gv._CURRENT_ACTOR_MITRE_GROUP_CODE == "NONE":
            try:
                gv._CURRENT_ACTOR_MITRE_GROUP_CODE = mf.get_group_code(gv._CURRENT_ACTOR_NAME_STR)
            except:
                gv._CURRENT_ACTOR_MITRE_GROUP_CODE = "NONE"

        group_code = gv._CURRENT_ACTOR_MITRE_GROUP_CODE


        if group_code != "NONE":
            knownGroupCodes.add(group_code)
            # GET MITRE GALAXY TAG:
            mitre_tag = []
            try:
                mitre_tag = db.get_galaxy_specific_tags(group_code, "mitre-intrusion-set")
            except Exception as e:
                print(e)
                mitre_tag = []

            for tag in mitre_tag:
                iGalaxy = tag["galaxy"]
                iTag = tag["tag"]
                db.insert_tag(gv._CURRENT_ACTOR_UUID_STR, iGalaxy, iTag, "GALAXY")

        # GET ACTOR MITRE DATA TECHNIQUES
        groupMitreTechniques = []
        if len(gv._CURRENT_ACTOR_MITRE_TECHNIQUE_IDS) == 0:
            gv._CURRENT_ACTOR_MITRE_TECHNIQUE_IDS = mf.get_group_technique_ids(gv._CURRENT_ACTOR_FAMILIES_CURRENT_FAMILY_STR)
        else:
           groupMitreTechniques = gv._CURRENT_ACTOR_MITRE_TECHNIQUE_IDS

        groupMitreTags = []
        if len(gv._CURRENT_ACTOR_TECHNIQUE_TAGS) == 0:
            for tID in groupMitreTechniques:
                retTags = db.get_galaxy_specific_tags(tID)
                gv._CURRENT_ACTOR_TECHNIQUE_TAGS.append(retTags)
        else:
                groupMitreTags= gv._CURRENT_ACTOR_TECHNIQUE_TAGS



        for tag in groupMitreTags:
            for sub in tag:
                iGalaxy = sub["galaxy"]
                iTag = sub["tag"]
                db.insert_tag(gv._CURRENT_ACTOR_UUID_STR, iGalaxy, iTag, "GALAXY")



        # SHORT NAME
        if gv._DEBUG:
            print("f(x) build_actor_malware_tree: INSERT TAG: ACTOR: ACTOR SHORT NAME: {}".format(threat_actor))
        db.insert_tag(gv._CURRENT_ACTOR_UUID_STR, "", threat_actor, "ACTOR")

       
        # COUNTRY SPONSOR
        if gv._DEBUG:
            print("f(x) build_actor_malware_tree: INSERT TAG: ACTOR: ACTOR COUNTRY SPONSOR: {}".format(gv._CURRENT_ACTOR_META_CFR_STATE_SPONSOR_STR))
        db.insert_tag(gv._CURRENT_ACTOR_UUID_STR, "", gv._CURRENT_ACTOR_META_CFR_STATE_SPONSOR_STR, "COUNTRY_SPONSOR")
        
        # TYPES OF INCIDENTS
        if gv._DEBUG:
            print("f(x) build_actor_malware_tree: INSERT TAG: ACTOR: TYPES OF INCIDENTS: {}".format(gv._CURRENT_ACTOR_META_CFR_TYPE_OF_INCIDENT_STR))
        db.insert_tag(gv._CURRENT_ACTOR_UUID_STR, "", gv._CURRENT_ACTOR_META_CFR_TYPE_OF_INCIDENT_STR, "TYPE_OF_INCIDENT")
        

        # ISO COUNTRY (2 CHARACTER)
        if gv._DEBUG:
            print("f(x) build_actor_malware_tree: INSERT TAG: ACTOR: ISO COUNTRY (2 CHARACTER): {}".format(gv._CURRENT_ACTOR_META_COUNTRY_STR))
        db.insert_tag(gv._CURRENT_ACTOR_UUID_STR, "", gv._CURRENT_ACTOR_META_COUNTRY_STR, "ISO_COUNTRY")
        
        altActorTechniqueIDs = []
        altActorTechniqueTags = set()
        currentActorMetaSynonyms = set(gv._CURRENT_ACTOR_META_SYNONYMS_LIST)
        if gv._DEBUG:
            print("f(x) build_actor_malware_tree: INSERT TAG: ACTOR: ALT NAMES FOR THREAT ACTOR")
            print(*currentActorMetaSynonyms, sep = "\n") 
        for value in currentActorMetaSynonyms:    
            db.insert_tag(gv._CURRENT_ACTOR_UUID_STR, "", value, "ACTOR")
       
            # GET / INSERT MITRE GROUP DATA
            group_code = ""
            if gv._DEBUG:
                print("f(x) build_actor_malware_tree: GETTING MITRE GROUP DATA")
            try:
                group_code = mf.get_group_code(value)
            except:
                group_code = gv._CURRENT_ACTOR_MITRE_GROUP_CODE


            # IF IT IS NOT ONE WE ALREADY HAVE
            if group_code != "NONE" and gv._CURRENT_ACTOR_MITRE_GROUP_CODE != "NONE" and group_code not in knownGroupCodes:
                knownGroupCodes.add(group_code)
                if gv._DEBUG:
                    print("f(x) build_actor_malware_tree: ADDING GROUP CODE: {}".format(group_code))
                # GET MITRE GALAXY TAG:
                mitre_tag = []
                try:
                    mitre_tag = db.get_galaxy_specific_tags(group_code, "mitre-intrusion-set")
                except Exception as e:
                    print("f(x) build_actor_malware_tree: {}".format(e))
                    mitre_tag = []

                for tag in mitre_tag:
                    iGalaxy = tag["galaxy"]
                    iTag = tag["tag"]
                    db.insert_tag(gv._CURRENT_ACTOR_UUID_STR, iGalaxy, iTag, "GALAXY")
                    if gv._DEBUG:
                        print("f(x) build_actor_malware_tree: INSERT GALAXY: {}  TAG: {}".format(iGalaxy, iTag))


                altActorTechniqueIDs = mf.get_group_technique_ids(value)
                for tID in altActorTechniqueIDs:
                    retTags = db.get_galaxy_specific_tags(tID)
                    # INSERT NEWLY DISCOVERED TAGS INTO DATABASE
                    for sub in retTags:
                        if sub["uuid"] not in altActorTechniqueTags:
                            altActorTechniqueTags.add(sub["uuid"])
                                                
                            iGalaxy = sub["galaxy"]
                            iTag = sub["tag"]
                            db.insert_tag(gv._CURRENT_ACTOR_UUID_STR, iGalaxy, iTag, "GALAXY")
                            if gv._DEBUG:
                                print("f(x) build_actor_malware_tree: CORRELATING TAG FROM ALT NAME: {} GALAXY: {}  TAG: {}".format(value, iGalaxy, iTag))

            else:
                if gv._DEBUG:
                    print("f(x) build_actor_malware_tree: DUPLICATE GROUP CODE SKIPPED")

        # VICTIMS
        for value in gv._CURRENT_ACTOR_META_CFR_SUSPECTED_VICTIMS_LIST:
            if gv._DEBUG:
                print("f(x) build_actor_malware_tree: INSERT TAG: ACTOR: ACTOR VICTIMS: {}".format(value))
            db.insert_tag(gv._CURRENT_ACTOR_UUID_STR, "", value, "VICTIMS")
        # TARGETS
        for value in gv._CURRENT_ACTOR_META_CFR_TARGET_CATEGORY_LIST:
            if gv._DEBUG:
                print("f(x) build_actor_malware_tree: INSERT TAG: ACTOR:  TARGET: {}".format(value))
            db.insert_tag(gv._CURRENT_ACTOR_UUID_STR, "", value, "TARGETS")

        db.insert_actor(gv._CURRENT_ACTOR_UUID_STR, \
                        threat_actor, \
                        gv._CURRENT_ACTOR_NAME_STR, \
                        gv._CURRENT_ACTOR_META_COUNTRY_STR, \
                        gv._CURRENT_ACTOR_META_VICTIMOLOGY_STR, \
                        gv._CURRENT_ACTOR_META_CFR_TYPE_OF_INCIDENT_STR, \
                        gv._CURRENT_ACTOR_META_CFR_STATE_SPONSOR_STR, \
                        gv._CURRENT_ACTOR_META_SINCE_STR, \
                        gv._CURRENT_ACTOR_META_MODEOFOPERATIONS_STR, \
                        gv._CURRENT_ACTOR_META_CAPABILITIES_STR, \
                        lastupdated, \
                        gv._CURRENT_ACTOR_DESCRIPTION_STR )


        # ---------------------------------------------------------------------
        # ACTOR_CFRSUSPECTEDVICTIMS
        for victim in gv._CURRENT_ACTOR_META_CFR_SUSPECTED_VICTIMS_LIST:
            if gv._DEBUG:
                print("f(x) build_actor_malware_tree: INSERT TAG: VICTIM:  VICTIM: {}".format(victim))
            db.insert_victims(gv._CURRENT_ACTOR_UUID_STR, victim)

        # ---------------------------------------------------------------------
        # REFERENCES
        for reference in gv._CURRENT_ACTOR_META_REFS_LIST:
            if gv._DEBUG:
                print ("f(x) build_actor_malware_tree: INSERT REFERENCE: {}".format(reference))
            db.insert_reference(gv._CURRENT_ACTOR_UUID_STR, reference)
            


        # ---------------------------------------------------------------------
        # ACTOR_CFRTARGETCATEGORY
        for targetcategory in gv._CURRENT_ACTOR_META_CFR_TARGET_CATEGORY_LIST:
            if gv._DEBUG:
                print ("f(x) build_actor_malware_tree: INSERT TARGET CATEGORY: {}".format(targetcategory))
            db.insert_target(gv._CURRENT_ACTOR_UUID_STR,targetcategory)

        # ---------------------------------------------------------------------
        # ACTOR SYNONYMS
        for synonym in gv._CURRENT_ACTOR_META_SYNONYMS_LIST:
            if gv._DEBUG:
                print ("f(x) build_actor_malware_tree: INSERT ACTOR SYNONYM: {}".format(synonym))
            db.insert_synonym(gv._CURRENT_ACTOR_UUID_STR, synonym, "ACTOR")

        # ---------------------------------------------------------------------
        # END ACTOR META DATA DB INSERT
        # ---------------------------------------------------------------------

        db.insert_parent_child(gv._CURRENT_ACTOR_UUID_STR, \
                                "", \
                                threat_actor,
                                "", \
                                False, \
                                "", \
                                "", \
                                "", \
                                "ACTOR", \
                                "NONE")


def stageActorMalwareMeta():
    # BEGIN DOWNLOADING ALL ACTORS
    print("f(x) stageActorMalwareMeta: GETTING A LIST OF THREAT ACTORS FROM MALPEDIA")
    mpClient = Authenticate()
    gv._ACTORS_LIST = mpClient.list_actors()
    print("f(x) stageActorMalwareMeta: RETRIEVED LIST OF THREAT ACTORS FROM MALPEDIA")




    # WRITE OUT OUTPUT
    with open(gv._MALPEDIA_OUTPUT + "actors/" + "001.actors.json", 'w') as jsonOut:
        jsonOut.write(json.dumps(gv._ACTORS_LIST))
        jsonOut.close()


    #BEGIN ACTOR/MALWARE METADATA SECTION
    try:
        # DOWNLOAD ACTOR PROFILES AND WRITE THEM TO JSON
        # THROTTLE SO IT DOESN'T LOCK API KEY
        max_requests_per_minute = 40 #60 requests per minute is the max
        current_request_count = 1
        completed_actors_list = []

        # MAKE THE COMPLETED FILE IF IT DOESN'T EXIST
        completed_actors_file_path = gv._MALPEDIA_OUTPUT + "actors/" + "001.completed.actors.json"

        if os.path.isfile(completed_actors_file_path):
            with open(completed_actors_file_path, 'r') as jsonIn:
                completed_actors_list = json.loads(fix_json(jsonIn.read()))
                jsonIn.close()
        else:
            with open(completed_actors_file_path, 'w') as jsonOut:
                jsonOut.write(json.dumps(" "))
                jsonOut.close


        tStart = time.time()
        tNow = None
        tDiff = 0
        iWait = 140
        for actor_id in gv._ACTORS_LIST:
            if actor_id in completed_actors_list:
                continue
            with open(gv._MALPEDIA_OUTPUT + "actors/" + actor_id + ".json", 'w') as jsonOut:
                print("f(x) stageActorMalwareMeta: PULLING DATA FOR ACTOR: {}".format(actor_id))
                mpClient = Authenticate()
                gv._CURRENT_ACTOR_INFO_DICT = mpClient.get_actor(actor_id)
                jsonOut.write(json.dumps(gv._CURRENT_ACTOR_INFO_DICT))
                jsonOut.close()
                tNow = time.time()
                tDiff = tNow - tStart
                if ((current_request_count == max_requests_per_minute) and (tDiff <= iWait )):
                    tNow = time.time()
                    tDiff = tNow - tStart
                    print("f(x) stageActorMalwareMeta: API PULL THRESHHOLD REACHED.")
                    while (tDiff <= iWait):
                        time.sleep(1)
                        tNow = time.time()
                        tDiff = (tNow - tStart)
                        print("f(x) stageActorMalwareMeta: WAITING {} SECONDS.".format(math.ceil(iWait - tDiff)))

                    tStart = time.time()
                    current_request_count = 1
                    print("f(x) stageActorMalwareMeta: RESUMING PULLS")
                else:
                    completed_actors_list.append(actor_id)
                    completed_actors_file =  open(completed_actors_file_path, 'w')
                    completed_actors_file.write(json.dumps(completed_actors_list))
                    completed_actors_file.close
                    current_request_count += 1

                    # DEBUG SEQ
                    if gv._DEBUG:
                        print("f(x) stageActorMalwareMeta: {}: ADDED TO COMPLETED ACTORS.".format(actor_id))
        # os.remove(completed_actors_file_path)
        print("f(x) stageActorMalwareMeta: COMPLETED DOWNLOAD OF ACTOR META INFO")
    except Exception as e:
        exc_type, _, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print("f(x) stageActorMalwareMeta ERROR: {}: {}: {}".format(exc_type, fname, exc_tb.tb_lineno))
        sys.exit(e)

def initGlobals():
    if os.getenv('MISP_KEY') and os.getenv("MISP_URL") and os.getenv("MALPEDIA_KEY"):
        gv._MISP_KEY = os.getenv('MISP_KEY')
        gv._MISP_URL = os.getenv('MISP_URL')
        gv._MALPEDIA_KEY = os.getenv('MALPEDIA_KEY')
        print("f(x) initGlobals: KEYS SET:\n\tMISP KEY: {}\n\tMISP URL: {}\n\tMALPEDIA KEY: {}".format(gv._MISP_KEY, gv._MISP_URL, gv._MALPEDIA_KEY))
    else:
        print("f(x) initGlobals: MISP_KEY, MISP_URL, AND/OR MALPEDIA KEY. EXITING")
        return(1)

    # ADD MANUAL TAGS
    print("f(x) initGlobals: INSERTING MANUAL TAGS")
    db.insert_manual_tags()
    
    # PULL LATEST MISP GALAXIES
    print("f(x) initGlobals: CLONING MISP GALAXY REPO")
    if os.path.exists(gv._MISP_GALAXY_GIT):
        print("f(x) initGlobals: FOUND OLD  MISP GALAXY DIRECTORY. SKIPPING")
        #shutil.rmtree(gv._MISP_GALAXY_GIT)
    else:
        git_actions.clone_misp_galaxy()
        print("f(x) initGlobals: CLONED MISP GALAXY REPO")

    # PULL LATEST MALPEDIA
    print("f(x) initGlobals: PULLING MALPEDIA GITHUB")
    git_actions.pull_malpedia_git()
    print("f(x) initGlobals: PULLED MALPEDIA GITHUB")

    # CLONE MITRE REPO
    print("f(x) initGlobals: CLONING MITRE REPO")
    if os.path.exists(gv._MITRE_GIT):
        print("f(x) initGlobals: FOUND OLD MITRE DIRECTORY. SKIPPING")
        #shutil.rmtree(gv._MISP_GALAXY_GIT)
    else:
        git_actions.clone_mitre_git()
        print("f(x) initGlobals: CLONED MITRE REPO")


    # LOAD MITRE SOFTWARE
    print("f(x) initGlobals: LOADING MITRE SOFTWARE ALIASES INTO DB")
    mf.load_mitre_software()
    print("f(x) initGlobals: LOADED MITRE SOFTWARE ALIASES INTO DB")

    # CREATE OUTPUT DIRECTORIES IF THEY DON'T EXIST
    if not os.path.exists(gv._MALPEDIA_OUTPUT):
        os.makedirs(gv._MALPEDIA_OUTPUT)

    if not os.path.exists(gv._MALPEDIA_OUTPUT + "actors"):
        os.makedirs(gv._MALPEDIA_OUTPUT + "actors")

    if not os.path.exists(gv._MALPEDIA_OUTPUT + "malware"):
        os.makedirs(gv._MALPEDIA_OUTPUT + "malware")

    # GET NAME OF MALWARE FAMILIES FROM DIRECTORY LISTING
    for name in glob.glob(gv._MALPEDIA_REPOSITORY + "**", recursive=True):
        if "yara" not in name and ".json" not in name:
            gv._DIR_MALPEDIA_GIT_LIST.append(name)

    gv._DIR_MALPEDIA_GIT_LIST.sort()
    if gv._DEBUG:
        print(*gv._DIR_MALPEDIA_GIT_LIST, sep = "\n") 
    print("f(x) initGlobals: STAGED ENVIRONMENT")


def stageThreatActors():
    for actor in gv._ACTORS_LIST:
        if gv._DEBUG:
            print("INGESTING ACTOR INTO DATABASE: {}".format(actor))
        build_actor_malware_tree(actor)

def pushNewEventsIntoMisp(iUUIDS, update=False):
    try:
        for oUUID in iUUIDS:
            countUUID = mef.uuidSearch(oUUID["uuid"])
            
            # UUID NOT FOUND SO CREATE IT
            if countUUID == 0:
                if gv._DEBUG:
                    print("f(x) pushNewEventsIntoMisp:  CREATING MISP EVENT FOR UUID: {}".format(oUUID["uuid"]))
                # CREATE A MISP EVENT
                mef.createIncident(oUUID["uuid"],  False)
 
                # threads.append(eventThread)
            # UUID IS FOUND SO SKIP IT SINCE THIS IS THE FIRST RUN
            else:
                if update == True:
                    if gv._DEBUG:
                        print("f(x) pushNewEventsIntoMisp:  UPDATING MISP EVENT FOR UUID: {}".format(oUUID["uuid"]))
                    mef.createIncident(oUUID["uuid"], True)
                else:
                    print("f(x) pushNewEventsIntoMisp: DUPLICATE EVENT DETECTED. UUID: {}".format(oUUID["uuid"]))
            
        

    except Exception as e:
        exc_type, _, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print("f(x) pushNewEventsIntoMisp: {}: {}: {}".format(exc_type, fname, exc_tb.tb_lineno))
        sys.exit(e)

def stageUnattributedActor():
    try:
        # CREATE UNATTRIBUTED ACTOR
        myName = "UNATTRIBUTED"
        if gv._DEBUG:
            print("f(x) stageUnattributedActor: INITIALIZING DATA FOR: {}".format(myName))
        myUUID = str(uuid.uuid4())
        parentUUID = ""
        myType = "ACTOR"
        parentName = "NONE"
        myPath = ""
        myVersion = ""
        myDate = ""
        parentType = "NONE"

        db.insert_actor(myUUID, "UNATTRIBUTED", "UNATTRIBUTED", "", "", "", "","","","",datetime.date.today(),"UNATTRIBUTED")
        db.insert_parent_child(myUUID, parentUUID, myName, parentName, 0, myPath, myVersion, myDate, myType, parentType)

        # CREATE ERROR ACTOR
        myName = "ERROR"
        if gv._DEBUG:
            print("f(x) stageUnattributedActor: INITIALIZING DATA FOR: {}".format(myName))
        myUUID = str(uuid.uuid4())
        parentUUID = ""
        myType = "ACTOR"
        parentName = "NONE"
        myPath = ""
        myVersion = ""
        myDate = ""
        parentType = "NONE"

        db.insert_actor(myUUID, "ERROR", "ERROR", "", "", "", "","","","",datetime.date.today(),"ERROR")
        db.insert_parent_child(myUUID, parentUUID, myName, parentName, 0, myPath, myVersion, myDate, myType, parentType)

    except Exception as e:
        exc_type, _, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print("f(x) stageUnattributedActor: {}: {}: {}".format(exc_type, fname, exc_tb.tb_lineno))
        sys.exit(e)

def stageMalwareFamilies():
    try:
        malwareFamilySet = set()
        checkedSet = set()
    
        # GO THROUGH PATH
        for path in gv._DIR_MALPEDIA_GIT_LIST:
            lstPath = path.split("/")
            pathLen = len(lstPath)
            # LEVEL OF THE SHORT NAMES OF MALWARE
            currDirDepth = gv._CURRENT_DIR_DEPTH
            if pathLen > currDirDepth:
                myName = lstPath[currDirDepth-1]
                if myName not in malwareFamilySet and myName not in checkedSet:
                    checkedSet.add(myName)
                    stored_data = db.get_parent_child_data(iValue=myName)
                    # IF NONE, WE DONT HAVE THIS FAMILY
                    if not stored_data:
                        malwareFamilySet.add(myName)
                        if gv._DEBUG:
                            print("f(x) stageMalwareFamilies(): FOUND FAMILY IN PATH: {}".format(myName))


        for family in malwareFamilySet:
            if gv._DEBUG:
                print("f(x) stageMalwareFamilies(): INGESTING FAMILY: {}".format(family))
            insertFamilyIntoDB(family)


    except Exception as e:
        exc_type, _, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print("f(x) stageMalwareFamilies(): {}: {}: {}".format(exc_type, fname, exc_tb.tb_lineno))
        sys.exit(e)


def getFamilyInformation(iFamilyName):
    try:
        # GET THE FAMILY JSON FILE
        malware_family_json = gv._MALPEDIA_REPOSITORY + iFamilyName + "/" + iFamilyName + ".json"
        isFile = os.path.isfile(malware_family_json)
        if gv._DEBUG:
            print("f(x) getFamilyInformation(): GETTING FAMILY INFORMATION FOR:\nFAMILY: {}\nPATH: {}".format(iFamilyName, malware_family_json))

        if isFile:
            with open(malware_family_json, 'r') as jsonIn:
                # # IN ORDER TO 'FIX' ERRONEOUSLY FORMATTED JSON, YOU HAVE TO FIRST IMPORT THE FILE INTO YAML, THEN INTO JSON
                # yamlData = yaml.safe_load(jsonIn)
                # jsonData = json.dumps(yamlData)
                # fix_json(jsonIn)

                if gv._DEBUG:
                    print("f(x) getFamilyInformation() JSON DATA: {}".format(jsonIn))

                malware_family_data = json.loads(fix_json(jsonIn))

                jsonIn.close()
        else:
            return "NONE"

        return malware_family_data

    except Exception as e:
        exc_type, _, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print("f(x) getFamilyInformation ERROR: {}: {}: {}".format(exc_type, fname, exc_tb.tb_lineno))
        sys.exit(e)

def insertFamilyIntoDB(iFamilyName):

    threat_actor = ""
    threat_actor_UUID = ""
    try:
        malwareFamilyDict = getFamilyInformation(iFamilyName)

        malwareFamilyMitreSoftwareTags = []

        malwareFamilyMitreSoftwareTechniqueTags = []

        malwareFamilyAltNamesMitreSpecificTags = []

        actor_data = ""
        # STRING  OF COMMON NAME OF THIS MALWARE FAMILY
        try:
            commonName = malwareFamilyDict["common_name"].strip()
            print("f(x) insertFamilyIntoDB: IMPORTING MALWARE: {}".format(commonName.upper()))
        except:
            commonName = ""
        # DEBUG SEQ
        if gv._DEBUG:
            print("f(x) insertFamilyIntoDB: FAMILY COMMON NAME: {}".format(commonName))

        # LIST OF THE ALT NAMES ASSOCIATED WITH THIS MALWARE FAMILY
        try:
            altNames = malwareFamilyDict["alt_names"]
        except:
            altNames =  []
        # DEBUG SEQ
        if gv._DEBUG:
            print("f(x) insertFamilyIntoDB: FAMILY ALT NAMES:")
            print(*altNames, sep = "\n")

        # STRING  OF ATTRIBUTION OF THIS MALWARE FAMILY
        try:
            attribution = malwareFamilyDict["attribution"]
        except:
            attribution = []

        # IF NO ATTRIBUTION SET IT TO BE ATTRIBUTED TO BE UNATTRIBUTED
        if len(attribution) == 0:
            attribution = ["UNATTRIBUTED"]
            threat_actor = "UNATTRIBUTED"

        
        for attributed in attribution:
            actor_data = db.get_actor_meta(iCommonName=attributed)
            # ONLY GET THE FIRST ONE
            try:
                threat_actor = actor_data["shortname"]
                threat_actor_UUID = actor_data["uuid"]
            except:
                actor_data = db.get_actor_meta(iCommonName="ERROR")
                threat_actor = actor_data["shortname"]
                threat_actor_UUID = actor_data["uuid"]
            finally:
                break

        if gv._DEBUG:
                print("f(x) stageMalwareFamilies(): LOOKING FOR THREAT ACTOR: [{}]: UUID: [{}]".format(threat_actor, threat_actor_UUID))

        # STRING  OF DESCRIPTION OF THIS MALWARE FAMILY
        try:
            malwareDescription = malwareFamilyDict["description"].strip()
        except:
            malwareDescription = ""
        # DEBUG SEQ
        if gv._DEBUG:
            print("f(x) insertFamilyIntoDB: FAMILY DESCRIPTION: {}".format(malwareDescription))

        #STRING OF UUID OF CURRENT MALWARE FAMILY
        try:
            malwareUUID = malwareFamilyDict["uuid"].strip()
        except Exception as e:
            exc_type, _, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print("f(x) insertFamilyIntoDB: {}: {}: {}".format(exc_type, fname, exc_tb.tb_lineno))
            malwareUUID = ""
        # DEBUG SEQ
        if gv._DEBUG:
            print("f(x) insertFamilyIntoDB: FAMILY UUID: {}".format(malwareUUID))

        # STRING OF WHEN THIS FAMILY WAS LAST UPDATED
        try:
            malwareUpdated = malwareFamilyDict["updated"].strip()
        except:
            malwareUpdated = ""
        # DEBUG SEQ
        if gv._DEBUG:
            print("f(x) insertFamilyIntoDB: FAMILY LAST UPDATED: {}".format(malwareUpdated))

        # BUILD YARA PATH DICT [gv._CURRENT_ACTOR_FAMILIES_CURRENT_FAMILY_YARA_DICT]
        malwareYaraDict = {}
        try:
             for name in set(glob.glob(gv._MALPEDIA_REPOSITORY + "/" + iFamilyName + "/yara/tlp_*/*")):
                tlp = name.split("/")[gv._TLP_SPLIT_DEPTH]
                malwareyarapath = name
                malwareYaraDict[malwareyarapath] = tlp
        except Error as e:
            malwareYaraDict = {}
        #DEBUG SEQ
        if gv._DEBUG:
            print("f(x) insertFamilyIntoDB: FAMILY TLP AND YARA FILES")
            print(json.dumps(malwareYaraDict, indent=4))

        # LIST OF THE URLS ASSOCIATED WITH THIS MALWARE FAMILY
        try:
            malwareURLs = malwareFamilyDict["urls"]
        except:
            malwareURLs =  []
        # DEBUG SEQ
        if gv._DEBUG:
            print("f(x) insertFamilyIntoDB: FAMILY URLS")
            print(*malwareURLs, sep = "\n")

        # ---------------------------------------------------------------------
        # BEGIN INSERT MALWARE METADATA INTO DB
        # ---------------------------------------------------------------------

        # TAGS FOR MALWARE
        # ---------------------------------------------------------------------

        # ATTRIBUTION
        threat_actor_all_syn = db.get_synonyms(threat_actor_UUID)

        threat_actor_set = set()

        for synonym in threat_actor_all_syn:
            threat_actor_set.add(synonym["synonym"])


        for value in threat_actor_set:
            if gv._DEBUG:
                print("f(x) insertFamilyIntoDB: INSERT TAG: ACTOR: ACTOR SYNONYMS: {}".format(value))
            db.insert_tag(malwareUUID, "", value, "ACTOR")



        # ACTOR FAMILY RELATIONSHIP (PARENT AND CHILD UUIDS)
        db.insert_parent_child(malwareUUID, threat_actor_UUID, iFamilyName, threat_actor, False, "", "",  "", "FAMILY", "ACTOR")

        # MALWARE META
        db.insert_malware_meta( malwareUUID, iFamilyName, commonName, malwareDescription, malwareUpdated)


        # MALWARE ATTRIBUTION
        for attributed in attribution:
            db.insert_malware_attribution(malwareUUID, attributed)



        # MALWARE SYNONYMS
        for altname in altNames:
            db.insert_synonym(malwareUUID, altname, "MALWARE")



        # MALWARE REFERENCES
        for url in malwareURLs:
            db.insert_reference(malwareUUID, url)
        # DEBUG SEQ
            if gv._DEBUG:
                print("f(x) insertFamilyIntoDB: {}: {}".format(malwareUUID, url))

        # MALWARE YARA PATH
        for key, value in malwareYaraDict.items():
            myUUID = str(uuid.uuid4())
            db.insert_malware_yara(malwareUUID, value, key, myUUID)


        # MALWARE TAGS
        db.insert_tag(malwareUUID, "", iFamilyName, "MALWARE")
        # db.insert_tag(threat_actor_UUID, "", iFamilyName, "MALWARE")

        
        # MALPEDIA TAGS
        db.insert_tag(malwareUUID, "Malpedia", commonName, "GALAXY", iFamilyName)
        # db.insert_tag(threat_actor_UUID, "Malpedia", commonName, "GALAXY", iFamilyName)

        # COMMON NAME OF MALWARE
        db.insert_tag(malwareUUID, "", commonName, "MALWARE")
        # db.insert_tag(threat_actor_UUID, "", commonName, "MALWARE")

        # COMMON NAME OF THIS THREAT ACTOR
        db.insert_tag(malwareUUID, "", gv._CURRENT_ACTOR_NAME_STR, "ACTOR")

        # SHORT NAME OF THIS THREAT ACTOR
        db.insert_tag(malwareUUID, "", threat_actor, "ACTOR")


        # MITRE
        # ----------------------------------------------------------------------------------
        # GET S CODE FROM COMMON NAME IN MITRE TABLE FOR SOFTWARE
        software_codes = []

        try:
            software_codes = db.get_mitre_software_code(commonName)
        except:
            software_codes = []


        if gv._DEBUG:
            print("f(x) insertFamilyIntoDB: RETRIEVED MALWARE CODE FOR: {}".format(commonName))

        if software_codes:
            iMitreSCode = software_codes[0]["mitrecode"]
            mitre_tag = []

            if len(malwareFamilyMitreSoftwareTags)  == 0:
                try:
                    malwareFamilyMitreSoftwareTags = db.get_galaxy_specific_tags(iMitreSCode, "malware")
                except:
                    malwareFamilyMitreSoftwareTags = []

        if gv._DEBUG:
            print("f(x) insertFamilyIntoDB: BUILT MITRE SOFTWARE TAGS FOR: {}".format(commonName))

        # GET/ INSERT SOFTWARE CAPABILIIES/TECHNIQUES FROM COMMON NAME OF SOFTWARE
        technique_list = []
        try:
            if gv._DEBUG:
                print("f(x) insertFamilyIntoDB: GETTING MITRE MALWARE TECHNIQUE IDS")
            technique_list = mf.get_software_technique_ids_from_software_name(commonName)
        except:
            technique_list = []

        for technique in technique_list:
            malwareFamilyMitreSoftwareTechniqueTags.append(db.get_galaxy_specific_tags(technique))

        if gv._DEBUG:
            print("f(x) insertFamilyIntoDB: BUILT MITRE SOFTWARE TECHNIQUE TAGS FOR: {}".format(commonName))

        # TLP TAGS
        db.insert_tag(malwareUUID, "", "tlp:amber", "MALWARE")
        
        malwareFamilyAltNamesMitreSpecificTags.clear()
        altCount = 0
        # ALT NAMES FOR THIS FAMILY OF MALWARE
        for value in altNames:
            altCount += 1
            
            db.insert_tag(malwareUUID, "", value, "MALWARE")
            # db.insert_tag(threat_actor_UUID, "", value, "MALWARE")

            # GET S CODE FROM ALIASES MITRE TABLE FOR SOFTWARE
            software_codes = []
            try:
                software_codes = db.get_mitre_software_code(value)
            except:
                software_codes = []
            if gv._DEBUG:
                print("f(x) insertFamilyIntoDB: RETRIEVED SOFTWARE CODES FOR: [{}]: {}".format(altCount, value))

            if software_codes:
                iMitreSCode = software_codes[0]["mitrecode"]
                mitre_tag = []

                try:
                    mitre_tag = db.get_galaxy_specific_tags(iMitreSCode, "malware")
                except:
                    mitre_tag = []

                for tags in mitre_tag:
                    malwareFamilyAltNamesMitreSpecificTags.append(tags)

                if gv._DEBUG:
                    print("f(x) insertFamilyIntoDB: RETRIEVED SOFTWARE TAGS FOR: {}".format(value))

                knownTags = False
                j = 0
                mergeList = []
                for value in malwareFamilyAltNamesMitreSpecificTags:
                    j += 1
                    b = 0
                    for tag in malwareFamilyMitreSoftwareTags:
                        b += 1
                        iTag = tag["tag"]

                        if gv._DEBUG:
                            print("f(x) insertFamilyIntoDB: COMPARING:[{}][{}] {}:{}".format(j, b, iTag, value["tag"]))

                        if value["tag"] == iTag:
                            knownTags = True
                            if gv._DEBUG:
                                print("f(x) insertFamilyIntoDB: TAGS ALREADY KNOWN FOR: [{}]:{}".format(altCount, value["tag"]))
                            break
                        else:
                            if gv._DEBUG:
                                print("f(x) insertFamilyIntoDB: UNKNOWN TAG: [{}]:{}".format(altCount, value["tag"]))
                            mergeList.append(tag)


                if knownTags == False:
                    malwareFamilyMitreSoftwareTags += mergeList

                    malwareFamilyMitreSoftwareTechniqueTags.append(db.get_galaxy_specific_tags(iMitreSCode, "malware"))
                    if gv._DEBUG:
                            print("f(x) insertFamilyIntoDB: ADDING NEW DATA TAG: [{}]:{}".format(altCount, value))
                    # GET/ INSERT SOFTWARE CAPABILIIES/TECHNIQUES FROM ALT NAMES OF SOFTWARE
                    technique_list = []
                    try:
                        technique_list = mf.get_software_technique_ids_from_software_name(value)
                    except:
                        technique_list = []

                    if gv._DEBUG:
                            print("f(x) insertFamilyIntoDB: RETRIEVED TECHNIQUE IDS FOR: {}".format(value))

                    for technique in technique_list:
                            malwareFamilyMitreSoftwareTechniqueTags.append(db.get_galaxy_specific_tags(technique))

                    if gv._DEBUG:
                        print("f(x) insertFamilyIntoDB: BUILT MITRE SOFTWARE TECHNIQUE TAGS FOR: {}".format(value))


            # ADD THE MITRE TAGS
            for tag in malwareFamilyMitreSoftwareTechniqueTags:
                for var in tag:
                    iGalaxy = var["galaxy"]
                    iTag = var["tag"]
                    db.insert_tag(malwareUUID, iGalaxy, iTag, "GALAXY")
                    db.insert_tag(threat_actor_UUID, iGalaxy, iTag, "GALAXY")


            # MITRE SOFTWARE ID
            mitre_tag = malwareFamilyMitreSoftwareTags
            # INSERT TAG WITH mitre-malware or GALAXY AS SOURCE
            for tag in mitre_tag:
                iGalaxy = tag["galaxy"]
                iTag = tag["tag"]
                db.insert_tag(malwareUUID, iGalaxy, iTag, "GALAXY")
                db.insert_tag(threat_actor_UUID, iGalaxy, iTag, "GALAXY")

    except Exception as e:
        exc_type, _, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print("f(x) insertFamilyIntoDB: {}: {}: {}".format(exc_type, fname, exc_tb.tb_lineno))
        sys.exit(e)

# INSERT FAMILY SPECIFIC PATHS AND FILES IN DATABASE
def stagePathsAndFiles(iFamilyName=""):
    if gv._DEBUG:
        print("f(x) stagePathsAndFiles: ANALYZING MALWARE ON DISK")
    parentUUID = None
    searchDir = sorted(glob.glob(gv._MALPEDIA_REPOSITORY + iFamilyName + "/**/*", recursive=True))
    for path in searchDir:
        # WE DON'T WANT YARA OR JSON FILES
        if "yara" in path or ".json" in path:
            continue
        try:
            pathLen = len(path.split("/"))
            lstPath = path.split("/")
            currDirDepth = gv._CURRENT_DIR_DEPTH
            parentName = iFamilyName
            
            while currDirDepth < pathLen:
                if gv._DEBUG:
                    print("f(x) stagePathsAndFiles: ANALYZING PATH: {}".format(path))

                myName = lstPath[currDirDepth]
                stored_data = db.get_parent_child_data( iValue=myName)
                myUUID = ""
                myType = ""
                myPath = "/"
                myPath = myPath.join(lstPath[0:currDirDepth+1])
                isFile = os.path.isfile(myPath)
                parentLookup = False

                # MALWARE FAMILY COMMON NAME AND UUID
                malwareFamilyMeta = db.get_family_meta(iName=iFamilyName)
                malwareFamilyUUID = malwareFamilyMeta["uuid"]

                if gv._DEBUG:
                    print("f(x) stagePathsAndFiles: ANALYZING: {}".format(myName))

                if not stored_data:
                    myUUID = str(uuid.uuid4())
                    parentLookup = True
                else:
                    stored_path = stored_data["path"]
                    # IN CASE SAME FILE IS UPLOADED TO MULTIPLE PLACES
                    if stored_path == myPath:
                        myUUID = stored_data["uuid"]
                        myType = stored_data["mytype"]
                        parentUUID = stored_data["parentuuid"]
                        parentName = stored_data["parentname"]
                    else:
                        myUUID = str(uuid.uuid4())
                        parentLookup = True

                myStatus = ""
                myVersion = ""
                myDate = ""
                parentType = ""

                if parentLookup == True:
                    parent_info = db.get_parent_child_data( iValue=parentName)
                    if parent_info:
                        parentUUID = parent_info["uuid"]
                        parentName = parent_info["name"]
                        if gv._DEBUG:
                            print("f(x) stagePathsAndFiles: PARENT FOUND: {}".format(parentName))

                if currDirDepth == gv._CURRENT_DIR_DEPTH:
                    parentType = "FAMILY"
                    if not isFile:
                        myType = "PATH"
                    else:
                        myType = "MALWARE"
                else:
                    parentType= "PATH"
                    if not isFile:
                        myType = "PATH"
                    else:
                        myType = "MALWARE"

                if gv._DEBUG:
                    print("f(x) stagePathsAndFiles: INSERTING PARENT CHILD DATA FOR: {}".format(myName))
                # INSERT PARENT CHILD RELATIONSHIP WITH META DATA
                db.insert_parent_child(   myUUID, \
                                        parentUUID, \
                                        myName, \
                                        parentName, \
                                        isFile, \
                                        myPath, \
                                        myVersion, \
                                        myDate, \
                                        myType, \
                                        parentType
                )

                # ADD ALL TAGS FROM MALWARE FAMILY TO PATH AND SPECIMEN
                mitre_tags_for_self = db.copy_tags(iSourceUUID=malwareFamilyUUID, iDestinationUUID=myUUID)
                db.insert_tag(iIsList=True, iList=mitre_tags_for_self)
                # INSERT TAG WITH mitre-malware or GALAXY AS SOURCE
                if gv._DEBUG:
                    print("f(x) stagePathsAndFiles: DUPLICATING MALWARE FAMILY TAGS TO: {}".format(myName))

                if parentType != "FAMILY":
                    mitre_tags_for_parent = db.copy_tags(iSourceUUID=malwareFamilyUUID, iDestinationUUID=parentUUID)
                    db.insert_tag(iIsList=True, iList=mitre_tags_for_parent)
                    if gv._DEBUG:
                        print("f(x) stagePathsAndFiles: DUPLICATING MALWARE FAMILY TAGS TO: {}".format(parentName))

                if isFile == True:
                    myType = "MALWARE"

                    myStatus, myVersion, _ = getSpecimenData(iFamilyName, myName[0:64])
                    if valid_date(myVersion):
                        myDate = myVersion
                    else:
                        myDate = datetime.date.today()

                    # ADD SPECIMEN AND PATH SPECIFIC TAGS
                    #TLP
                    db.insert_tag(myUUID, "", "tlp:amber", "MALWARE")

                    # VERSION
                    if myVersion != "":
                        if gv._DEBUG:
                            print("f(x) stagePathsAndFiles: INSERT TAG: SPECIMEN AND PATH [IF REQUIRED]: SPECIMEN VERSION: {}".format(myVersion))
                        db.insert_tag(myUUID, "", myVersion, "VERSION")

                    # STATUS
                    if myStatus != "":
                        if gv._DEBUG:
                            print("f(x) stagePathsAndFiles: INSERT TAG: SPECIMEN AND PATH [IF REQUIRED]: SPECIMEN STATUS: {}".format(myStatus))
                        db.insert_tag(myUUID, "", myStatus, "STATUS")
                else:
                    parentUUID = myUUID
                    parentName = myName

                currDirDepth += 1
        except Exception as e:
            sys.exit(e)

def iterateStageAllFiles():
    path_to_malware_json = gv._MALPEDIA_OUTPUT + "malware/"
    malwareFamilies = []
    for name in glob.glob(path_to_malware_json + "*.json"):
        if "completed" not in name:
            lstName = name.split("/")
            malwareName = lstName[7]
            malwareFamilies.append(malwareName.replace(".json", ""))

    for oFamily in malwareFamilies:
        if gv._DEBUG:
            print("f(x) iterateStageAllFiles: PROCESSING FAMILY SPECIMENS: {}".format(oFamily))
        stagePathsAndFiles(oFamily)


if __name__ == '__main__':

    # INITIALIZE GLOBAL VARIABLES
    print("f(x) INITIALIZE: INITIALIZE GLOBAL VARIABLES")
    if initGlobals() == 1:
        print("Critical enviroment variables not set. Normally this is done prior to running \"docker-compose up\" and in the .env file. Please refer to the readme file for proper configuration.")
        sys.exit(1)

    # # UPDATE AND PUSH MISP GALAXIES INTO DATABASE FOR QUICK SEARCHING
    # print("f(x) INITIALIZE: UPDATE AND PUSH MISP GALAXIES INTO DATABASE FOR QUICK SEARCHING")
    # mgf.importMISPGalaxies()

    # # DOWNLOAD UPDATED ACTOR JSON FILES FROM MALPEDIA
    # print("f(x) INITIALIZE: DOWNLOAD UPDATED ACTOR JSON FILES FROM MALPEDIA")
    # stageActorMalwareMeta()

    # # DOWNLOAD UPDATED MALWARE JSON FILES FROM MALPEDIA
    # print("f(x) INITIALIZE: DOWNLOAD UPDATED MALWARE JSON FILES FROM MALPEDIA")
    # stageMalwareSpecimens()

    # # STAGE AN UNATTRIBUTED (CATCHALL) MALWARE ACTOR AND ERROR ACTOR TO CATCH MALPEDIA ATTRIBUTION ERRORS.
    # print("f(x) INITIALIZE: STAGE AN UNATTRIBUTED (CATCHALL) MALWARE ACTOR AND ERROR ACTOR TO CATCH MALPEDIA ATTRIBUTION ERRORS.")
    # stageUnattributedActor()

    # # STAGE KNOWN ACTORS AND FAMILIES
    # print("f(x) INITIALIZE: STAGE KNOWN ACTORS AND FAMILIES")
    # stageThreatActors()

    # # STAGE FAMILIES
    # print("f(x) INITIALIZE: STAGE FAMILIES")
    # stageMalwareFamilies()

    # # FINALLY STAGE MALWARE SPECIMENS TO INCLUDE ADDING PATHS TO THEM IN PARENT CHILD TABLE
    # print("f(x) INITIALIZE: STAGE MALWARE SPECIMENS TO INCLUDE ADDING PATHS TO THEM IN PARENT CHILD TABLE")
    # iterateStageAllFiles()

    # PUSH ACTORS TO MISP
    print ("f(x) INITIALIZE: CREATING MISP ACTOR EVENTS")
    actorUUIDs = set()
    actorUUIDs = db.get_parent_child_data("actor")
    pushNewEventsIntoMisp(actorUUIDs, update=False)
    cf.wait(gv._THREAD_LIST)
    gv._THREAD_LIST = []

    # # PUSH FAMILIES TO MISP
    # print ("f(x) INITIALIZE: CREATING MISP FAMILY EVENTS")
    # familyUUIDs = set()
    # familyUUIDs = db.get_parent_child_data("family")
    # pushNewEventsIntoMisp(familyUUIDs, update=False)
    # cf.wait(gv._THREAD_LIST)
    # gv._THREAD_LIST = []

    # # PUSH PATHS TO MISP
    # print ("f(x) INITIALIZE: CREATING MISP PATH EVENTS")
    # pathUUIDs = set()
    # pathUUIDs = db.get_parent_child_data("path")
    # pushNewEventsIntoMisp(pathUUIDs, update=False)
    # cf.wait(gv._THREAD_LIST)
    # gv._THREAD_LIST = []

    # # PUSH MALWARE TO MISP
    # print ("f(x) INITIALIZE: CREATING MISP MALWARE EVENTS")
    # malwareUUIDs = set()
    # malwareUUIDs = db.get_parent_child_data("malware")
    # pushNewEventsIntoMisp(malwareUUIDs, update=False)
    # cf.wait(gv._THREAD_LIST)
    # gv._THREAD_LIST = []
  
    # # SANITIZE AND CLEAN DATA
    # # EMPTY SSDEEP CORRELATIONS
    # print("f(x) INITIALIZE: REMOVING EMPTY SSDEEP CORRELATIONS AND TO IDS FLAGS FROM INVALID CORRELATIONS")
    # sf.removeFalsePositiveIDS()

    # # PUBLISH ALL EVENTS
    # print("f(x) INITIALIZE: PUBLISHING ALL UNPUBLISHED")
    # sf.publishUnpublished()

    print("INITIALIZATION COMPLETE")
