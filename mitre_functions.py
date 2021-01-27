from stix2 import FileSystemSource, Filter
from stix2.utils import get_type_from_id
import stix2 as sx
from itertools import chain
import sys
import globals as gv
import database_actions as db

enterprise_attack =  FileSystemSource(gv._MITRE_GIT + "enterprise-attack")
mobile_attack = FileSystemSource(gv._MITRE_GIT + "mobile-attack")
pre_attack = FileSystemSource(gv._MITRE_GIT + "pre-attack")
composite_ds = sx.CompositeDataSource()
composite_ds.add_data_sources([enterprise_attack, pre_attack, mobile_attack])

def get_all_techniques(src):
    filt = [Filter('type', '=', 'attack-pattern')]
    return src.query(filt)
    
def get_technique_by_name(src, name):
    filt = [
        Filter('type', '=', 'attack-pattern'),
        Filter('name', '=', name)
    ]
    return src.query(filt)

def get_techniques_by_content(src, content):
    techniques = get_all_techniques(src)
    return [
        tech for tech in techniques
        if content.lower() in tech.description.lower()
    ]
    
def get_all_software(src):
    filts = [
        [Filter('type', '=', 'malware')],
        [Filter('type', '=', 'tool')]
    ]
    return list(chain.from_iterable(
        src.query(f) for f in filts
    ))
    
   
def get_object_by_attack_id(src, typ, attack_id):
    filt = [
        Filter('type', '=', typ),
        Filter('external_references.external_id', '=', attack_id)
    ]
    return src.query(filt)

def get_software_by_alias(src, alias):
    filts = [
        [Filter('type', '=', 'malware'),Filter('x_mitre_aliases', '=', alias)],
        [Filter('type', '=', 'tool'), Filter('x_mitre_aliases', '=', alias)]
    ]
    return list(chain.from_iterable(
        src.query(f) for f in filts
    ))


def get_group_by_alias(src, alias):
    if not src:
        src = enterprise_attack
    return src.query([
        Filter('type', '=', 'intrusion-set'),
        Filter('aliases', '=', alias)
    ])

def get_technique_by_group(src, stix_id):
    relations = src.relationships(stix_id, 'uses', source_only=True)
    return src.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('id', 'in', [r.target_ref for r in relations])
    ])


def get_techniques_by_group_software(src, group_stix_id):
    # get the malware, tools that the group uses
    group_uses = [
        r for r in src.relationships(group_stix_id, 'uses', source_only=True)
        if get_type_from_id(r.target_ref) in ['malware', 'tool']
    ]

    # get the technique stix ids that the malware, tools use
    software_uses = src.query([
        Filter('type', '=', 'relationship'),
        Filter('relationship_type', '=', 'uses'),
        Filter('source_ref', 'in', [r.source_ref for r in group_uses])
    ])

    #get the techniques themselves
    return src.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('id', 'in', [r.target_ref for r in software_uses])
    ])

def get_software_technique_ids(src, iValue):
        # get the technique stix ids that the malware, tools use
    software_uses = src.query([
        Filter('type', '=', 'relationship'),
        Filter('relationship_type', '=', 'uses'),
        Filter('source_ref', 'in', iValue)
    ])

    #get the techniques themselves
    return src.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('id', 'in', [r.target_ref for r in software_uses])
    ])

def get_group_technique_ids(iValue):
    ret_list =[]
    try:
        oGroupName = get_group_by_alias(enterprise_attack, iValue)[0]
        techniques = get_technique_by_group(enterprise_attack, oGroupName)
        external_references_section = {}
        for gtech in techniques:
            external_references_section = gtech["external_references"]
            for x in external_references_section:
                #print(x)
                if "mitre" in x["source_name"]:
                    techniqueID = x["external_id"]
                    ret_list.append(techniqueID)
                    #print(techniqueID)
        return ret_list
    except:
        # print("f(x) get_technique_ids ERROR: {}".format(e))
        # sys.exit(e)
        return []

        

def get_software_technique_ids_from_software_name(iValue):
    ret_list =[]
    try:
        oSoftwareID = db.get_mitre_software_code(iValue)
        if oSoftwareID:
            techniques = get_software_technique_ids(enterprise_attack, oSoftwareID[0]["mitreid"])
            external_references_section = {}
            for gtech in techniques:
                external_references_section = gtech["external_references"]
                for x in external_references_section:
                    #print(x)
                    if "mitre" in x["source_name"]:
                        techniqueID = x["external_id"]
                        ret_list.append(techniqueID)
                        #print(techniqueID)
        return ret_list
    except Exception as e:
        print("f(x) get_technique_ids ERROR: {}".format(e))
        # sys.exit(e)
        return []
        

def load_mitre_software():
    try:
        allSW = get_all_software(enterprise_attack)

        for sw in allSW:
            software_id = sw["id"]
            software_name = sw["name"]

            # GET ALL THE ALIASES
            alias_list = []
            try:
                alias_list = sw["x_mitre_aliases"]
            except:
                alias_list = []

            # GET ALL THE REFERENCES
            external_references_section = ""
            try:
                external_references_section = sw["external_references"]
            except:
                external_references_section = ""

            # GET THE MITRE SOFTWARE CODE
            software_code = []
            for x in external_references_section:
                if x["source_name"] == "mitre-attack" or x["source_name"] == "mitre-mobile-attack":
                    software_code = x["external_id"]

            if gv._DEBUG:
                print("f(x) load_mitre_software inserting into database")
                print("ID: {}".format(software_id))
                print("NAME: {}".format(software_name.upper()))
                print("SOFTWARE CODE: {}".format(software_code))
                print("GALAXY: {}".format("mitre-attack-pattern"))
            
            db.insert_mitre_software(software_id,software_name.upper(),software_code)
            
            for val in alias_list:
                if gv._DEBUG:
                    print("f(x) load_mitre_software inserting into database")
                    print("ID: {}".format(software_id))
                    print("NAME: {}".format(val.upper()))
                    print("SOFTWARE CODE: {}".format(software_code))
                    print("GALAXY: {}".format("mitre-attack-pattern"))
                db.insert_mitre_software(software_id,val.upper(),software_code)            
    except Exception as e:
        print("f(x) load_mitre_software ERROR: {}".format(e))
        sys.exit(e)

def get_group_code(iValue):
    #ret_value = ""
    recValue = []
    recValue = get_group_by_alias(enterprise_attack, iValue)
    group_code = "NONE"

    try:
        for subVal in recValue:
            name_array = []
            try:
                name_array = subVal["external_references"]
            except:
                name_array = []

            for ref in name_array:
                if ref["source_name"] == "mitre-attack" or ref["source_name"] == "mitre-mobile-attack":
                    group_code = ref["external_id"]
        
        if gv._DEBUG:
            print("f(x) get_group_code GROUP CODE: {}".format(group_code))

        return group_code
    except:
        return "NONE"
        # print("ERROR: {}".format(e))
        # sys.exit(e)
        
    

if __name__ == '__main__':

    print("MITRE FUNCTIONS")
        