import misp_event_functions as mef
from pymisp import ExpandedPyMISP, MISPEvent
from globals import _MISP_URL as misp_url, _MISP_KEY as misp_key, _MISP_VERIFYCERT as misp_verifycert
import globals as gv
import argparse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

  
if __name__ == '__main__':
    # # # # # THE LOOPS BELOW DELETE EVENTS IN MISP
    # # # # # BY ORG ID
    # oResults = mef.getOrgEvents(iOrgID=1)
    # oMaxEvent = 
    # retLen = int(len(oResults))
    # if retLen > 0:
    #     for retEvent in oResults:
    #         event_id = retEvent["Event"]["id"]
    #         # mef.deleteEvent(iEventID=event_id)
            
    #         if gv._DEBUG:
    #             print("DELETED EVENT: {}".format(event_id))              

    # # # # # BY UUID
    # # # # all_uuids = db.get_parent_child_data(iValue="all")
    # # # # for oUUID in all_uuids:
    # # # #     if gv._DEBUG:
    # # # #         print("f(x) INITIALIZE: DELETING EVENT: {}".format(oUUID[0]))
    # # # #     mef.deleteEvent(iUUID=oUUID[0])

    # BY NUMBER [DECREMENT IN CASE THE INTIIAL FEW ARE BLANK]
    parser = argparse.ArgumentParser(description='Delete events from the specified event ID back to 1.')
    parser.add_argument('event_id', help='The id of the starting event you want to delete.', type=int)
    args = parser.parse_args()
    # start_event_id = int(args.event_id)
    for x in range(args.event_id, 0, -1):
        mef.deleteEvent(iEventID=x)