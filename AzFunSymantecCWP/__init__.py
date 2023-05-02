import json
import requests
import datetime
import timedelta
import time
import os
import urllib3
import logging
import json
import hashlib
import hmac
import base64
import re
from threading import Thread
from io import StringIO
from datetime import datetime, timedelta
from dateutil.parser import parse
import azure.functions as func
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sentinel_customer_id = os.environ.get('WorkspaceID')
sentinel_shared_key = os.environ.get('WorkspaceKey')
sentinel_log_type = os.environ.get('LogAnalyticsCustomLogName')
fresh_event_timestamp = os.environ.get('FreshEventTimeStamp')
logAnalyticsUri = os.environ.get('LAURI')
page_size = os.environ.get('PageSize')
retry_count = 3
serverURL = os.environ.get('ServerURL')
customerID = os.environ.get('CustomerID')
domainID = os.environ.get('DomainID')
clientID = os.environ.get('ClientID')
clientsecret = os.environ.get('ClientSecret')
eventtypefilter = os.environ.get('EventTypeFilters')

if ((logAnalyticsUri in (None, '') or str(logAnalyticsUri).isspace())):    
    logAnalyticsUri = 'https://' + sentinel_customer_id + '.ods.opinsights.azure.com'

pattern = r'https:\/\/([\w\-]+)\.ods\.opinsights\.azure.([a-zA-Z\.]+)$'
match = re.match(pattern, str(logAnalyticsUri))
if(not match):
    raise Exception("Symantec Cloud Workload Protection: Invalid Log Analytics Uri.")


collection_schedule = int(fresh_event_timestamp)
page_size = int(page_size)

authHeaders = {'Content-type':'application/json'}
authRequest = {}
eventDatetime = ''

getScwpEventsRequest = {'pageSize':page_size, 'order':'ASCENDING','displayLabels':'false','searchFilter':{}}

def authenticate(scwpAuthUrl):
    for retry in range(retry_count):
        authRequestJson = json.dumps(authRequest)
        authResponse = requests.post(scwpAuthUrl, data=authRequestJson, headers=authHeaders, verify=False)
        if authResponse.status_code != requests.codes.ok:
            if retry >= retry_count:
                authResponse.raise_for_status()
                time.sleep(retry * 60)
                continue
            else:
                break
    accessToken = authResponse.json()['access_token']
    authHeaders['Authorization'] = 'Bearer ' + accessToken


def main(mytimer: func.TimerRequest) -> None:
    if mytimer.past_due:
        logging.info('The timer is past due!')

    logging.info('Starting program')

    try:
        scwpAuthUrl = serverURL + '/dcs-service/dcscloud/v1/oauth/tokens'
        getScwpEventsUrl = serverURL + '/dcs-service/dcscloud/v1/event/query'
        authHeaders['x-epmp-customer-id'] = customerID
        authHeaders['x-epmp-domain-id'] = domainID
        authRequest['client_id'] = clientID
        authRequest['client_secret'] = clientsecret
        startDate = (datetime.today() - timedelta(minutes=collection_schedule)).isoformat()
        if (startDate is None) or (startDate == ""):
            startDate = (datetime.today() - timedelta(minutes=10)).isoformat()
        else:
            if startDate.endswith('Z'):
                    startDate = (datetime.strptime(startDate, '%Y-%m-%dT%H:%M:%S.%fZ') + timedelta(milliseconds=1)).isoformat()
            else:
                    startDate = (datetime.strptime(startDate, '%Y-%m-%dT%H:%M:%S.%f') + timedelta(milliseconds=1)).isoformat()

        eventTypes = eventtypefilter.strip().split(',')
        eventTypesWithQuotes = ','.join('\"{0}\"'.format(eventType) for eventType in eventTypes)
        eventTypeFilter = 'type_class IN [' + eventTypesWithQuotes + ']'
        getScwpEventsRequest['startDate'] = startDate
        getScwpEventsRequest['endDate'] = datetime.now().isoformat()
        getScwpEventsRequest['additionalFilters'] = eventTypeFilter
    
        pageNumber = 0
        while True:
            getScwpEventsRequest['pageNumber'] = pageNumber
            getScwpEventsRequestJson = json.dumps(getScwpEventsRequest)
            scwpEventsResponse = requests.post(getScwpEventsUrl, data=getScwpEventsRequestJson, headers=authHeaders, verify=False)

            if scwpEventsResponse.status_code == 401:
                authenticate(scwpAuthUrl)
                scwpEventsResponse = requests.post(getScwpEventsUrl, data=getScwpEventsRequestJson, headers=authHeaders, verify=False)

            if scwpEventsResponse.status_code != requests.codes.ok:
                logging.error("Get events API is failed")
                scwpEventsResponse.raise_for_status()
            else:
                logging.info("Get Events API is successful")

            scwpEventsJson = scwpEventsResponse.json()
            scwpEvents = scwpEventsJson['result']
            totalScwpEvents = scwpEventsJson['total']
            if totalScwpEvents == 0:
                break 

            logging.info('Total number of CWP Events {}'.format(totalScwpEvents)) 
            failed_sent_events_number = 0
            successfull_sent_events_number = 0
            file_events = 0

            for event in scwpEvents:
                sentinel = AzureSentinelConnector(logAnalyticsUri, sentinel_customer_id, sentinel_shared_key, sentinel_log_type, queue_size=10000, bulks_number=10)
                with sentinel:
                    sentinel.send(event)
                file_events += 1 
                failed_sent_events_number += sentinel.failed_sent_events_number
                successfull_sent_events_number += sentinel.successfull_sent_events_number
            
            if failed_sent_events_number:
                logging.info('{} Symantec CWP Events have not been sent'.format(failed_sent_events_number))

            if successfull_sent_events_number:
                logging.info('Program finished. {} Symantec CWP Events have been sent.'.format(successfull_sent_events_number))

            if successfull_sent_events_number == 0 and failed_sent_events_number == 0:
                logging.info('No Fresh Symantec CWP Events')
            pageNumber += 1
    except Exception as err:
        logging.error('Error while getting objects list - {}'.format(err))
        raise Exception

class AzureSentinelConnector:
    def __init__(self, log_analytics_uri, customer_id, shared_key, log_type, queue_size=200, bulks_number=10, queue_size_bytes=25 * (2**20)):
        self.log_analytics_uri = log_analytics_uri
        self.customer_id = customer_id
        self.shared_key = shared_key
        self.log_type = log_type
        self.queue_size = queue_size
        self.bulks_number = bulks_number
        self.queue_size_bytes = queue_size_bytes
        self._queue = []
        self._bulks_list = []
        self.successfull_sent_events_number = 0
        self.failed_sent_events_number = 0

    def send(self, event):
        self._queue.append(event)
        if len(self._queue) >= self.queue_size:
            self.flush(force=False)

    def flush(self, force=True):
        self._bulks_list.append(self._queue)
        if force:
            self._flush_bulks()
        else:
            if len(self._bulks_list) >= self.bulks_number:
                self._flush_bulks()

        self._queue = []

    def _flush_bulks(self):
        jobs = []
        for queue in self._bulks_list:
            if queue:
                queue_list = self._split_big_request(queue)
                for q in queue_list:
                    jobs.append(Thread(target=self._post_data, args=(self.customer_id, self.shared_key, q, self.log_type, )))

        for job in jobs:
            job.start()

        for job in jobs:
            job.join()

        self._bulks_list = []

    def __enter__(self):
        pass

    def __exit__(self, type, value, traceback):
        self.flush()

    def _build_signature(self, customer_id, shared_key, date, content_length, method, content_type, resource):
        x_headers = 'x-ms-date:' + date
        string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
        bytes_to_hash = bytes(string_to_hash, encoding="utf-8")  
        decoded_key = base64.b64decode(shared_key)
        encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
        authorization = "SharedKey {}:{}".format(customer_id, encoded_hash)
        return authorization

    def _post_data(self, customer_id, shared_key, body, log_type):
        events_number = len(body)
        body = json.dumps(body)        
        method = 'POST'
        content_type = 'application/json'
        resource = '/api/logs'
        rfc1123date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        content_length = len(body)
        signature = self._build_signature(customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)
        uri = self.log_analytics_uri + resource + '?api-version=2016-04-01'
        
        headers = {
            'content-type': content_type,
            'Authorization': signature,
            'Log-Type': log_type,
            'x-ms-date': rfc1123date
        }

        response = requests.post(uri, data=body, headers=headers)
        if (response.status_code >= 200 and response.status_code <= 299):
            logging.info('{} events have been successfully sent to Azure Sentinel'.format(events_number))
            self.successfull_sent_events_number += events_number
        else:
            logging.error("Error during sending events to Azure Sentinel. Response code: {}".format(response.status_code))
            self.failed_sent_events_number += events_number

    def _check_size(self, queue):
        data_bytes_len = len(json.dumps(queue).encode())
        return data_bytes_len < self.queue_size_bytes

    def _split_big_request(self, queue):
        if self._check_size(queue):
            return [queue]
        else:
            middle = int(len(queue) / 2)
            queues_list = [queue[:middle], queue[middle:]]
            return self._split_big_request(queues_list[0]) + self._split_big_request(queues_list[1])