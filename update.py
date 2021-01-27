import initialize as iV
import misp_galaxy_functions as mgf
import database_actions as db
import sanitizitation_functions as sf

if __name__ == '__main__':
    # INITIALIZE GLOBAL VARIABLES
    print("f(x) INITIALIZE: INITIALIZE GLOBAL VARIABLES")
    iV.initGlobals()

    # UPDATE AND PUSH MISP GALAXIES INTO DATABASE FOR QUICK SEARCHING
    print("f(x) INITIALIZE: UPDATE AND PUSH MISP GALAXIES INTO DATABASE FOR QUICK SEARCHING")
    mgf.importMISPGalaxies()

    # DOWNLOAD UPDATED ACTOR JSON FILES FROM MALPEDIA
    print("f(x) INITIALIZE: DOWNLOAD UPDATED ACTOR JSON FILES FROM MALPEDIA")
    iV.stageActorMalwareMeta()

    # DOWNLOAD UPDATED MALWARE JSON FILES FROM MALPEDIA
    print("f(x) INITIALIZE: DOWNLOAD UPDATED MALWARE JSON FILES FROM MALPEDIA")
    iV.stageMalwareSpecimens()

    # STAGE KNOWN ACTORS AND FAMILIES
    print("f(x) INITIALIZE: STAGE KNOWN ACTORS AND FAMILIES")
    iV.stageThreatActors()
    
    # STAGE AN UNATTRIBUTED (CATCHALL) MALWARE ACTOR AND ERROR ACTOR TO CATCH MALPEDIA ATTRIBUTION ERRORS.
    print("f(x) INITIALIZE: STAGE AN UNATTRIBUTED (CATCHALL) MALWARE ACTOR AND ERROR ACTOR TO CATCH MALPEDIA ATTRIBUTION ERRORS.")
    iV.stageUnattributedActor()
    
    # STAGE FAMILIES 
    print("f(x) INITIALIZE: STAGE FAMILIES")
    iV.stageMalwareFamilies()

    # FINALLY STAGE MALWARE SPECIMENS TO INCLUDE ADDING PATHS TO THEM IN PARENT CHILD TABLE
    print("f(x) INITIALIZE: STAGE MALWARE SPECIMENS TO INCLUDE ADDING PATHS TO THEM IN PARENT CHILD TABLE")
    iV.iterateStageAllFiles()

    # PUSH ACTORS TO MISP
    print ("f(x) INITIALIZE: CREATING MISP ACTOR EVENTS")
    actorUUIDs = set()
    actorUUIDs = db.get_parent_child_data("actor")
    iV.pushNewEventsIntoMisp(actorUUIDs, update=True)

    # PUSH FAMILIES TO MISP
    print ("f(x) INITIALIZE: CREATING MISP FAMILY EVENTS")
    familyUUIDs = set()
    familyUUIDs = db.get_parent_child_data("family")
    iV.pushNewEventsIntoMisp(familyUUIDs, update=True)

    # PUSH PATHS TO MISP
    print ("f(x) INITIALIZE: CREATING MISP PATH EVENTS")
    pathUUIDs = set()
    pathUUIDs = db.get_parent_child_data("path")
    iV.pushNewEventsIntoMisp(pathUUIDs, update=True)
    
    # PUSH MALWARE TO MISP
    print ("f(x) INITIALIZE: CREATING MISP MALWARE EVENTS")
    malwareUUIDs = set()
    malwareUUIDs = db.get_parent_child_data("malware")
    iV.pushNewEventsIntoMisp(malwareUUIDs, update=False)

    # SANITIZE AND CLEAN DATA 
    # EMPTY SSDEEP CORRELATIONS
    print("f(x) INITIALIZE: REMOVING EMPTY SSDEEP CORRELATIONS AND TO IDS")
    sf.removeFalsePositiveIDS()

    # PUBLISH ALL EVENTS
    print("f(x) INITIALIZE: PUBLISHING ALL UNPUBLISHED")
    sf.publishUnpublished()
