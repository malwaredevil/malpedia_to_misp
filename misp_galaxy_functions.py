
import glob
import globals as gv
import sqlite3
import json
import sys
import database_actions

def importMISPGalaxies():
    for name in glob.glob(gv._MISP_GALAXY_GIT + "clusters/*.json"):
        lstGalaxy = name.split("/")
        if gv._DEBUG:
            print("f(x) importMISPGalaxies: IMPORTING DATA FOR GALAXY: {}".format(lstGalaxy))
        lstName = lstGalaxy[gv._MISP_GALAXY_SPLIT_DEPTH].split(".")
        galaxyName = lstName[0]
        if gv._DEBUG:
            print("f(x) importMISPGalaxies: IMPORTING DATA FOR CLUSER: {}".format(galaxyName))
        tags_dict = {}
        galaxy_dict = {}
        with open(name, 'r') as jsonIn:
            tags_dict = json.loads(jsonIn.read())
            jsonIn.close()

        galaxy_dict = tags_dict["values"]

        for cluster in galaxy_dict:
            try:
                myUUID = cluster["uuid"]
            except:
                myUUID = ""

            try:
                myTag = cluster["value"]
            except:
                myTag = ""

            try:
                myDescription = cluster["description"]
            except:
                myDescription = ""

            try:
                mymeta_dict = cluster["meta"]
            except:
                mymeta_dict = {}


            try:

                mySynonyms = mymeta_dict["synonyms"]
                # INSERT SYNONYMS
                for synonym in mySynonyms:
                    database_actions.insert_synonym(myUUID, synonym, "GALAXY_SYNONIM")
            except:
                mySynonyms = ""



            # GETTING THIS FOR MISP country CLUSTER
            if galaxyName == "country":
                try:
                    myISO = mymeta_dict["ISO"]
                    database_actions.insert_synonym(myUUID, myISO, "GALAXY")
                except:
                   pass


            #---------------------------------------------------------------------
            #INSERT INTO GALAXY TABLE
            database_actions.insert_galaxy(myUUID, galaxyName, myTag, myDescription )



    print("f(x) importMISPGalaxies: IMPORTED ALL MISP GALAXIES")
