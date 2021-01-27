from pymisp import ExpandedPyMISP, MISPEvent
import globals as gv
import urllib3
import sys
import os
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from globals import logger


def init(url, key, verifycert):
    '''
        Template to get MISP module started
    '''
    return ExpandedPyMISP(url=url, key=key, debug=gv._DEBUG, ssl=verifycert)

def removeFalsePositiveIDS():
    try:
        misp = init(gv._MISP_URL, gv._MISP_KEY, gv._MISP_VERIFYCERT)
        for fp in gv._KNOWN_FALSE_POSITIVES:
            kwargs = {"value" : fp}
            if gv._DEBUG:
                print ("*" * 50)
                print ("f(x)removeFalsePositiveIDS(): SEARCHING FOR FALSE POSITIVE: {}".format(fp))
                print ("*" * 50)
            completed = False
            while completed == False:
                result = misp.search(controller='attributes', limit=50, to_ids=1, **kwargs)
                    
                if not result['Attribute']:
                    completed == True
                    break
                else:
                    
                    for attribute in result['Attribute']:
                        attribute_id = attribute['id']
                        attribute_value = attribute['value']
                        attribute_uuid = attribute['uuid']
                        event_id = attribute['event_id']

                        # DONT USE THIS FOR (INTRUSION DETECTION SYSTEMS)IDS
                        misp.update_attribute( { 'uuid': attribute_uuid, 'to_ids': 0})
                        # DON'T CORRELATE BASED ON THIS VALUE
                        misp.update_attribute( { 'uuid': attribute_uuid, 'disable_correlation': 1})
                        misp.publish(event_id)
                        if gv._DEBUG:
                            print ("*" * 50)
                            print("f(x)removeFalsePositiveIDS(): CORRECTED EVENT ID: {}\nATTRIBUTE ID: {}\nATTRIBUTE UUID: {}\nATTRIBUTE VALUE: {}".format(event_id, attribute_id, attribute_uuid,  attribute_value))
                            print ("*" * 50)

    except Exception as e:
        print ("f(x)removeFalsePositiveIDS(): {}".format(e))
        sys.exit(e)

def publishUnpublished():
    try:
        misp = init(gv._MISP_URL, gv._MISP_KEY, gv._MISP_VERIFYCERT)

        completed = False
        while completed == False:

            result = misp.search(controller='events', limit=50, published=0)
            retLen = int(len(result))
            if retLen == 0:
                completed = True
            else:
                for retEvent in result:
                    event_id = retEvent["Event"]["id"]
                    misp.publish(event_id)
                    
                    if gv._DEBUG:
                        print ("*" * 50)
                        print("f(x) publishUnpublished: PUBLISHED PREVIOUSLY UNPUBLISHED EVENT: {}".format(event_id))
                        print ("*" * 50)
            
    
    except Exception as e:
        print ("f(x) publishUnpublished: ERROR: {}".format(e))
        sys.exit(e)

if __name__ == '__main__':

    if os.getenv('MISP_KEY') and os.getenv("MISP_URL") and os.getenv("MALPEDIA_KEY"):
        gv._MISP_KEY = os.getenv('MISP_KEY')
        gv._MISP_URL = os.getenv('MISP_URL')
        gv._MALPEDIA_KEY = os.getenv('MALPEDIA_KEY')
        print("f(x) initGlobals: KEYS SET:\n\tMISP KEY: {}\n\tMISP URL: {}\n\tMALPEDIA KEY: {}".format(gv._MISP_KEY, gv._MISP_URL, gv._MALPEDIA_KEY))
    else:
        print("f(x) initGlobals: MISP_KEY, MISP_URL, AND/OR MALPEDIA KEY. EXITING")
        sys.exit(1)
   
    print("f(x) INITIALIZE: REMOVING EMPTY SSDEEP CORRELATIONS AND TO IDS")
    removeFalsePositiveIDS()

    print("f(x) INITIALIZE: PUBLISHING ALL UNPUBLISHED")
    publishUnpublished()

    print("CLEANUP COMPLETE")