import pymisp
import logging
import os
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor
logger = logging.getLogger('pymisp')
logger.setLevel(logging.ERROR)
# logging.basicConfig(level=logging.ERROR, filename="pymisp.debug.log", filemode='w', format=pymisp.FORMAT)
# DEBUG MODE
_DEBUG = False

# BASE PATH OF THIS PROJECT
_MP_TO_MISP_BASE_LOCATION = "/opt/m2m/"

# BASE PATH TO DEPENDENCIES
_DEPENDENCIES = "/opt/m2m/dependencies/"

# LOCATION OF MALPEDIA GIT REPOSITORY ROOT [FULL PATH]
_MALPEDIA_REPOSITORY = _DEPENDENCIES + "malpedia/"

# MISP KEYS
_MISP_URL =  ''
# The MISP auth key can be found on the MISP web interface under the automation section
_MISP_KEY = ''
_MISP_VERIFYCERT = False
_MISP_CLIENT_CERT = ''
_PROOFPOINT_KEY = 'Your Proofpoint TAP auth key'

# MALPEDIA KEYS
_MALPEDIA_KEY = ''


# THE BELOW CAN LARGELY BE IGNORED. ONLY MODIFY IF YOU KNOW WHAT YOU ARE DOING

# MALPEDIA URL
_MALPEDIA_URL = "https://malpedia.caad.fkie.fraunhofer.de/"

# MANUAL KEYS
_MANUAL_TAGS = [
        {
            "tagvalue" : "elf.xagent",
            "galaxy" : "Malpedia",
            "tag" : "X-Agent (ELF)"

        },
        {
            "tagvalue" : "win.xagent",
            "galaxy" : "Malpedia",
            "tag" : "X-Agent (Windows)"

        },
        {
            "tagvalue" : "osx.xagent",
            "galaxy" : "Malpedia",
            "tag" : "X-Agent (OS X)"

        },
        {
            "tagvalue" : "apk.popr-d30",
            "galaxy" : "Malpedia",
            "tag" : "X-Agent (Android)"

        },
        {
            "tagvalue" : "win.xtunnel",
            "galaxy" : "Malpedia",
            "tag" : "X-Tunnel"

        },
        {
            "tagvalue" : "ios.xagent",
            "galaxy" : "Malpedia",
            "tag" : "X-Agent (IOS)"

        }
]


# THREADING EXECUTOR
_EXECUTOR = ThreadPoolExecutor()

# LIST OF THREADS
_THREAD_LIST = []

# THREADING EXECUTOR FOR UPLOAD. HAD TO THROTTLE
_UPLOAD_EXECUTOR = ThreadPoolExecutor()

# MALPEDIA CLIENT
_MALPEDIA_CLIENT = None

# JSON FOLDER FOR OUTPUT [FULL PATH]
_MALPEDIA_OUTPUT = _DEPENDENCIES  + "json/malpedia/"

# MISP GALAXIES FOLDER [FULL PATH]
_MISP_GALAXY_GIT = _DEPENDENCIES  + "misp-galaxy/"

# MITRE GIT FOLDER [FULL PATH]
_MITRE_GIT = _DEPENDENCIES  + "cti/"

# PATH TO POSTGRES DB
load_dotenv()
dbHost = os.environ.get('POSTGRES_HOST')
dbPort = os.environ.get('POSTGRES_PORT')
dbName = os.environ.get('POSTGRES_DB')
dbUser = os.environ.get('POSTGRES_USER')
dbPass = os.environ.get('POSTGRES_PASSWORD')
_MP_TO_MISP_DB=uri = 'postgresql://{user}:{pw}@{host}:{port}/{db}'.format(user=dbUser,pw=dbPass,host=dbHost,port=dbPort,db=dbName)

# DIRECTORY INSTRUCTIONS
_CURRENT_DIR_DEPTH = 6
_FAMILY_SPLIT_DEPTH = 5
_TLP_SPLIT_DEPTH = 8
_MISP_GALAXY_SPLIT_DEPTH = 6


# MALPEDIA BLACKILISTED FILE NOT FOR CONSUMPTION
_BLACKLISTED_FILES = [
    '7ecc0ab55a3f5e016f48eafafc26b7c7a1dd55db2d85d94f585618013b1fda4c_unpacked',
    '9a81bd6f077e444e55fc8f89a862d60dffdb31c7cfba41849a6b2d045d70e65',
    'f9a81bd6f077e444e55fc8f89a862d60dffdb31c7cfba41849a6b2d045d70e65',
    '56d57a09e2bef6f6f2640a7f0b95e77da258e02538d88f7790b24394f1f2a568',
    '06b077e31a6f339c4f3b1f61ba9a6a6ba827afe52ed5bed6a6bf56bf18a279ba_unpacked',
    'a8229522e6a25e2830a395bc1c372e735252ef84f481aedfea70c0bf062bd59b_unpacked',
    'be65dc1c2d2cb1ddbb7b08780e608eb0d9cabc706491f5bd7657326018c0c518_dump_0x1aa00000',
    '45abd87da6a584ab2a66a06b40d3c84650f2a33f5f55c5c2630263bc17ec4139',
    '3237ec73a4f16533fd2c3fb92b3caf43e42b5c9f11d61a5f8576a86c478f0b55',
    'fbe324e854a564a3c4276dab7bcb51dae9e0723b9d45cfd7bf9b488e48404977_unpacked',
    '6f0ecfa853bfbbfdcd7f75b75430c97e92a573a06168fac49d40031237a0de6f_dump_0x00400000',
    'ac6affcdec528aeea402fd9cfa0d607c338c845c537050ca0e245fad785ccbbd'
]

# _BLACKLISTED_FILES = [
#         '7ecc0ab55a3f5e016f48eafafc26b7c7a1dd55db2d85d94f585618013b1fda4c_unpacked',
#         'e148c5fbc84930ea84eb6faf1dc19d9b594eedb53276c1be2ec3f5d9847187bc_dump7_0x00400000',
#         'e148c5fbc84930ea84eb6faf1dc19d9b594eedb53276c1be2ec3f5d9847187bc',
#         'b4fcc933ce58349063693f4415343ff5eb640bef418b38dda2714f5c34c538f_unpacked',
#         'f98bcde75347ea723f0b0f70cce6dfe75525d1be9ca776a868da9402f2e06aff_unpacked',
#         '95b5ef4e0284f82d4f6e68d750645f3475e174e10a2c33da18e372a212976a8d_unpacked',
#         '95b5ef4e0284f82d4f6e68d750645f3475e174e10a2c33da18e372a212976a8d_dump7_0x00400000',
#         'fe580d1ff6731875a28c8c9370749aef80cc7ae1cf40d9a656148e00ecf3f5c9'
# ]


# ------------------------------------
# MALPEDIA TEMPORARY STORAGE

# /api/list/actors
_ACTORS_LIST = []

# /api/get/actor/XXXX
_CURRENT_ACTOR_INFO_DICT = {}
_CURRENT_ACTOR_NAME_STR = ""
_CURRENT_ACTOR_DESCRIPTION_STR = ""
_CURRENT_ACTOR_UUID_STR = ""

# META SUBSECTION
_CURRENT_ACTOR_META_DICT = {}
_CURRENT_ACTOR_META_CFR_SUSPECTED_VICTIMS_LIST = []
_CURRENT_ACTOR_META_COUNTRY_STR = ""
_CURRENT_ACTOR_META_REFS_LIST = []
_CURRENT_ACTOR_META_CFR_TARGET_CATEGORY_LIST = []
_CURRENT_ACTOR_META_CFR_TYPE_OF_INCIDENT_STR = ""
_CURRENT_ACTOR_META_SYNONYMS_LIST = []
_CURRENT_ACTOR_META_CFR_STATE_SPONSOR_STR = ""
_CURRENT_ACTOR_META_VICTIMOLOGY_STR = ""
_CURRENT_ACTOR_META_SINCE_STR = ""
_CURRENT_ACTOR_META_MODEOFOPERATIONS_STR = ""
_CURRENT_ACTOR_META_CAPABILITIES_STR = ""

# FAMILIES SUBSECTION
_CURRENT_ACTOR_FAMILIES_DICT = {}

# SPECIFIC MALWARE FAMILY SECTION
_CURRENT_ACTOR_FAMILIES_CURRENT_FAMILY_STR = ""
_CURRENT_ACTOR_FAMILIES_CURRENT_FAMILY_YARA_DICT = {}
_CURRENT_ACTOR_FAMILIES_CURRENT_FAMILY_YARA_TLP_LIST = []
_CURRENT_ACTOR_FAMILIES_CURRENT_FAMILY_YARA_TLP_PATH_STR = ""
_CURRENT_ACTOR_FAMILIES_CURRENT_MALWARE_DICT = {}
_CURRENT_ACTOR_FAMILIES_CURRENT_FAMILY_URLS_LIST = []
_CURRENT_ACTOR_FAMILIES_CURRENT_FAMILY_UPDATED_STR = ""
_CURRENT_ACTOR_FAMILIES_CURRENT_FAMILY_UUID_STR = ""
_CURRENT_ACTOR_FAMILIES_CURRENT_FAMILY_ALTNAMES_LIST = []
_CURRENT_ACTOR_FAMILIES_CURRENT_FAMILY_COMMON_NAME_STR = ""
_CURRENT_ACTOR_FAMILIES_CURRENT_FAMILY_ATTRIBUTION_LIST = []
_CURRENT_ACTOR_FAMILIES_CURRENT_FAMILY_DESCRIPTION_STR = ""

# /list/samples/XXXXX
# SPECIFIC MALWARE SAMPLE SECTION
_CURRENT_FAMILY_SPECIMENS_LIST = []
_CURRENT_FAMILY_CURRENT_SPECIMEN_DICT = {}
_CURRENT_FAMILY_CURRENT_SPECIMEN_VERSION_STR = ""
_CURRENT_FAMILY_CURRENT_SPECIMEN_STATUS_STR = ""
_CURRENT_FAMILY_CURRENT_SPECIMEN_SHA256_STR = ""
_CURRENT_FAMILY_CURRENT_SPECIMEN_PATH_STR = ""
_CURRENT_FAMILY_SPECIMENS_FILES_LIST = []
_CURRENT_FAMILY_SPECIMENS_FILE_PATH_STR = ""
# _CURRENT_FAMILY_SPECIMENS_FILE_PATHS_LIST = []


# RELATIONAL TABLES
_ACTOR_UUID_DICT={}
_MALWARE_UUID_DICT = {}
_MALWARE_META_DICT = {}
_MALWARE_SUBMODULE_DICT={}
_MALWARE_FAMILY_SET= None



# GLOBAL DIRECTORY LISTINGS
_DIR_MALPEDIA_GIT_LIST=[]
_DIR_YARA_LIST=[]


# BACKGROUND COLORS FOR TAGS
        # "ACTOR"
        # "COUNTRY_SPONSOR"
        # "GALAXY"
        # "GALAXY_SYNONIM"
        # "ISO_COUNTRY"
        # "MALWARE"
        # "TARGETS"
        # "TYPE_OF_INCIDENT"
        # "VICTIMS"
_ACTOR_TAG = "#000000"
_COUNTRY_SPONSOR_TAG ="#020052"
_GALAXY_SYNONIM_TAG = "#a6c200"
_ISO_COUNTRY_TAG = "#020052"
_MALWARE_TAG = "#960000"
_TARGETS_TAG = "#00872e"
_TYPE_OF_INCIDENT_TAG = "#ffc700"
_VICTIMS_TAG = "#9f30ba"
_OTHER_TAG = "#ffa43b"


_CURRENT_ACTOR_MITRE_GROUP_CODE = ""
_CURRENT_ACTOR_MITRE_TECHNIQUE_IDS = []
_CURRENT_ACTOR_TECHNIQUE_TAGS = []
_CURRENT_ACTOR_ALT_NAMES_MITRE_GROUP_CODE_LIST = ""
_CURRENT_ACTOR_ALT_NAMES_MITRE_TECHNIQUE_IDS = []
_CURRENT_ACTOR_ALT_NAMES_TECHNIQUE_TAGS = []


_MALWARE_FAMILY_MITRE_SOFTWARE_CODES = []
_MALWARE_FAMILY_MITRE_SOFTWARE_TAGS = []
_MALWARE_FAMILY_MITRE_SOFTWARE_TECHNIQUE_IDS = []
_MALWARE_FAMILY_MITRE_SOFTWARE_TECHNIQUE_TAGS = []

_MALWARE_FAMILY_ALT_NAMES_MITRE_SOFTWARE_CODES = []
_MALWARE_FAMILY_ALT_NAMES_MITRE_SOFTWARE_TECHNIQUE_IDS = []
_MALWARE_FAMILY_ALT_NAMES_TECHNIQUE_TAGS = []
_MALWARE_FAMILY_ALT_NAMES_MITRE_SPECIFIC_TAGS = set()



_UNATTRIBUTED_FAMILY = set()

_KNOWN_FALSE_POSITIVES = [
        "3::",
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
        "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b",
        "048846ed8ed185a26394adeb3f63274d1029bbd59cffa8e73a4ef8b19456de1d",
        "06f7826c2862d184a49e3672c0aa6097b11e7771a4bf613ec37941236c1a8e20",
        "07c4c7ae2c4c7cb3ccd2ba9cd70a94382395ca8e2b0312c1631d09d790b6db33",
        "0f343b0931126a20f133d67c2b018a3b",
        "10400c6faf166902b52fb97042f1e0eb",
        "125da188e26bd119ce8cad7eeb1fc2dfa147ad47",
        "16e8e953c65d610c3bfc595240f3f5b7",
        "183d0929423da2aa83441ee625de92b213f33948",
        "1ceaf73df40e531df3bfb26b4fb7cd95fb7bff1d",
        "200ceb26807d6bf99fd6f4f0d1ca54d4",
        "231a802e6ff1fae42f2b12561fff2767d473210b",
        "2daeaa8b5f19f0bc209d976c02bd6acb51b00b0a",
        "325472601571f31e1bf00674c368d335",
        "4194d1706ed1f408d5e02d672777019f4d5385c766a8c6ca8acba3167d36a7b9",
        "41f958d2d3e9ed4504b6a8863fd72b49",
        "4a15a6777284035dfd8df4ecf496b4f0557a9cc4ffaaf5887659031e843865e1",
        "4b298058e1d5fd3f2fa20ead21773912a5dc38da3c0da0bbc7de1adfb6011f1c",
        "4b6c7f3146f86136507497232d2f04a0",
        "4dde54cfc600dbd9a610645d197a632e064115ffaa3a1b595c3a23036e501678",
        "5ba93c9db0cff93f52b521d7420e43f6eda2784f",
        "5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
        "605db3fdbaff4ba13729371ad0c4fbab3889378e",
        "60cacbf3d72e1e7834203da608037b1bf83b40e8",
        "620f0b67a91f7f74151bc5be745b7110",
        "68b329da9893e34099c7d8ad5cb9c940",
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "72c2dbbb1fe642073002b30987fcd68921a6b140",
        "7eb70257593da06f682a3ddda54a9d260d4fc514f645237f5ca74b08f8da61a6",
        "8094af5ee310714caebccaeee7769ffb08048503ba478b879edfef5f1a24fefe",
        "81051bcc2cf1bedf378224b0a93e2877",
        "86f1895ae8c5e8b17d99ece768a70732",
        "8a798890fe93817163b10b5f7bd2ca4d25d84c52739a645a889c173eee7d9d3d",
        "93b885adfe0da089cdf634904fd59f71",
        "995c770caeb45f7f0c1bc3affc60f11d8c40e16027df2cf711f95824f3534b6f",
        "a11a2f0cfe6d0b4c50945989db6360cd",
        "a6105c0a611b41b08f1209506350279e",
        "ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7",
        "adc83b19e793491b1c6ea0fd8b46cd9f32e592fc",
        "b1442e85b03bdcaf66dc58c7abb98745dd2687d86350be9a298a1d9382ac849b",
        "b3aca92c793ee0e9b1a9b0a5f5fc044e05140df3",
        "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c",
        "b6f9aa44c5f0565b5deb761b1926e9b6",
        "ba8ab5a0280b953aa97435ff8946cbcbb2755a27",
        "c4232ddd4d37b9c0884bd44d8476578c54d7f98d58945728e425736a6a07e102",
        "c5e389341a0b19b6f045823abffc9814",
        "c82cee5f957ad01068f487eecd430a1389e0d922",
        "c929701c67a05f90827563eedccf5eba8e65b2da970189a0371f28cd896708b8",
        "c99a74c555371a433d121f551d6c6398",
        "d378bffb70923139d6a4f546864aa61c",
        "d3b07384d113edec49eaa6238ad5ff00",
        "d41d8cd98f00b204e9800998ecf8427e",
        "d5502a1d00787d68f548ddeebbde1eca5e2b38ca",
        "d583c3aa489ed954df3be71e71deae3a9895857e",
        "d991c16949bd5e85e768385440e18d493ce3aa46",
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "deabe082bc0f0f503292e537b2675c7c93dca40f",
        "df4e26a04a444901b95afef44e4a96cfae34690fff2ad2c66389c70079cdff2b",
        "e24133dd836d99182a6227dcf6613d08",
        "e2516fcd1573e70334c8f50bee5241cdfdf48a00",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "e5a00aa9991ac8a5ee3109844d84a55583bd20572ad3ffcd42792f3c36b183ad",
        "e617348b8947f28e2a280dd93c75a6ad",
        "f00aa51c2ed8b2f656318fdc01ee1cf5441011a4",
        "f1d2d2f924e986ac86fdf7b36c94bcdf32beec15",
        "f6d380b256b0e66ef347adc78195fd0f228b3e33",
        "fa8715078d45101200a6e2bf7321aa04",
        "fb360f9c09ac8c5edb2f18be5de4e80ea4c430d0",
        "fc4623b113a1f603c0d9ad5f83130bd6de1c62b973be9892305132389c8588de"
]




