from os import getenv
from dotenv import load_dotenv
load_dotenv()


class Config:
    TIMEOUT = 3
    TERMINATOR = 10 * 60
    DNS_SERVERS = ['193.17.47.1', '185.43.135.1']
    MAX_WORKERS = None
    # MongoDB
    MONGO_URI = getenv('DR_MONGO_URI', 'mongodb://localhost:27017/')
    MONGO_DB = 'drdb'
    MONGO_BATCH_SIZE = 500
    #
    UA_STRING = 'User-Agent:Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) ' \
                'Chrome/77.0.3865.90 Safari/537.36'
    # NERD
    NERD_URL = 'https://nerd.cesnet.cz/nerd/api/v1/ip/'
    NERD_TOKEN = getenv('DR_NERD_TOKEN')
    # MISP
    MISP_URL = 'https://feta3.fit.vutbr.cz/'
    # The MISP auth key can be found on the MISP web interface under the automation section
    MISP_KEY = getenv('DR_MISP_KEY')
    # MISP feed IDs and categories
    MISP_FEEDS = {
        'phishtank': ('1ecf04dc-88ea-494a-b3c3-104500768fbe', 'phishing'),
        'openphish': ('26b75f8f-eedb-4b4b-95ca-f70ec54109f8', 'phishing'),
        'cybercrime_tracker': ('02cbbdfe-a7c4-476c-be1a-7ef8b0b82f26', 'phishing')
    }
    MISP_VERIFYCERT = False
    MISP_CLIENT_CERT = ''
    # Service Principal from TAP (https://threatinsight.proofpoint.com/<custID>/settings/connected-applications)
    PROOFPOINT_SP = '<proofpoint service principal>'
    PROOFPOINT_SECRET = '<proofpoint secret>'
