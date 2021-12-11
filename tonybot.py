import hmac
import hashlib
import time
import slack
#import json
import os
from pathlib import Path
from dotenv import load_dotenv
from flask import Flask, request, Response, jsonify
from slackeventsapi  import SlackEventAdapter
import requests
import threading

env_path = Path('.') / '.env'
load_dotenv(dotenv_path=env_path)

app = Flask(__name__)
slack_event_adapter = SlackEventAdapter(os.environ['SIGNING_SECRET'], '/slack/events',app)

client = slack.WebClient(token=os.environ['SLACK_TOKEN'])
BOT_ID = client.api_call("auth.test")['user_id']
bearertoken = os.environ['BEARER_TOKEN']

# def pp_json(json_thing, sort=False, indents=4):
#     if type(json_thing) is str:
#         return str(json.dumps(json.loads(json_thing), sort_keys=sort, indent=indents))
#     else:
#         return str(json.dumps(json_thing, sort_keys=sort, indent=indents))
#     return None

def verify_request(request):
    SIGNING_SECRET = os.environ['SIGNING_SECRET']
    # Convert your signing secret to bytes
    slack_signing_secret = bytes(SIGNING_SECRET, "utf-8")
    request_body = request.get_data().decode()
    slack_request_timestamp = request.headers["X-Slack-Request-Timestamp"]
    slack_signature = request.headers["X-Slack-Signature"]
    # Check that the request is no more than 60 seconds old
    if (int(time.time()) - int(slack_request_timestamp)) > 60:
        print("Verification failed. Request is out of date.")
        return False
    # Create a basestring by concatenating the version, the request  
      #timestamp, and the request body
    basestring = f"v0:{slack_request_timestamp}:{request_body}".encode("utf-8")
    # Hash the basestring using your signing secret, take the hex digest, and prefix with the version number
    my_signature = (
        "v0=" + hmac.new(slack_signing_secret, basestring, hashlib.sha256).hexdigest()
    )
    # Compare the resulting signature with the signature on the request to verify the request
    if hmac.compare_digest(my_signature, slack_signature):
        return True
    else:
        print("Verification failed. Signature invalid.")
        return False
#
def getNetworkFromJarvis(network, url, bearertoken):
    json_header = {}
    json_header['Authorization'] = bearertoken
    json_header['Accept'] = 'application/json'
    json_header['Content-Type'] = 'application/json'

    data_derived = '{"networkId": ' + '"' + network + '"}'
    response = requests.post(url, headers=json_header, data=data_derived)
    if response.status_code == 200:
        return True, response.json()
    else:
        return False, f'Error: {response.text} {response.status_code}'

def getFromJarvis(tenant, url, bearertoken):
    json_header = {}
    json_header['Authorization'] = bearertoken
    json_header['Accept'] = 'application/json'
    json_header['Content-Type'] = 'application/json'

    data_derived = '{"customerId": ' + '"' + tenant + '"}'
    response = requests.post(url, headers=json_header, data=data_derived)
    if response.status_code == 200:
        return True, response.json()
    else:
        return False, f'Error: {response.text} {response.status_code}'

# def getFromJarvis(key, value, url, bearertoken):
#     json_header = {}
#     json_header['Authorization'] = bearertoken
#     json_header['Accept'] = 'application/json'
#     json_header['Content-Type'] = 'application/json'
#
#     data_derived = '{"customerId": ' + '"' + value + '"}'
#     response = requests.post(url, headers=json_header, data=data_derived)
#     if response.status_code == 200:
#         return True, response.json()
#     else:
#         return False, f'Error: {response.text} {response.status_code}'

@app.route('/whoami', methods=['POST'])
def whoami():
	data = request.form
        #print(data)
	user_id = data.get('user_id')
	channel_id = data.get('channel_id')
	user_name = data.get('user_name')
	team_domain = data.get('team_domain')
	text = 'Hello, ' + user_name + '!' + ' You must be from ' + team_domain
	client.chat_postMessage(channel=channel_id, text=text)
	return Response(), 200


def whois_internal(tenant,channel_id, return_url):
    """function for doing the actual work in a thread"""

    # URLS
    url = 'https://api.perimeter81.com/api/jarvis/customer/header'
    general_url = 'https://api.perimeter81.com/api/jarvis/customer/general'
    platform_url = 'https://api.perimeter81.com/api/jarvis/customer/platform'
    platform_networks_list_url = 'https://api.perimeter81.com/api/jarvis/customer/platform/networks/list'
    more_url = 'https://api.perimeter81.com/api/jarvis/customer/platform/network/more'
    environment_url = 'https://api.perimeter81.com/api/jarvis/customer/environment'

    status, rpcjson = getFromJarvis(tenant, url, bearertoken)
    if not status:
        client.chat_postMessage(channel=channel_id, text=rpcjson)

    status, rpcjson_general = getFromJarvis(tenant, general_url, bearertoken)
    if not status:
        client.chat_postMessage(channel=channel_id, text=rpcjson_general)

    status, rpcjson_platform = getFromJarvis(tenant, platform_url, bearertoken)
    if not status:
        client.chat_postMessage(channel=channel_id, text=rpcjson_platform)

    status, rpcjson_platform_networks_list = getFromJarvis(tenant, platform_networks_list_url, bearertoken)
    if not status:
        client.chat_postMessage(channel=channel_id, text=rpcjson_platform_network_list)

    status, rpcjson_customer_environment = getFromJarvis(tenant, environment_url, bearertoken)
    if not status:
        client.chat_postMessage(channel=channel_id, text=rpcjson_customer_environment)

    # print(rpcjson_platform_networks_list)

    # print(rpcjson['statusCode'])
    final_slack_message = ''
    line = ''
    networks_one_message = ''
    tunnels_one_message = ''
    rpcjson_output = ''
    rpcjson_output += "If we can't protect the Earth, you can be damn well sure we'll avenge it! " + "\n"
    rpcjson_output += "You are requesting information regarding account: " + tenant + "\n"
    # print(rpcjson['body'].items())
    rpcjson_output += " " + "\n"
    rpcjson_output += '\n'.join(f'{k} : {v}' for k, v in rpcjson['body'].items())
    # rpcjson_output += '\n'.join(f'{k} : {v}' for k,v in rpcjson['body'].items() if k in ['companyName', 'accountManager', 'customerSuccessEngineer', 'country', 'plan'])

    # This chat post is for everything under rpcjson (regular headers page)

    #Do environment page next

    final_slack_message += rpcjson_output + "\n"
    final_slack_message += "ARR: " + str(rpcjson_general['body']['arr']) + "\n"


    environment_output = ''
    environment_output += '\n'.join(f'{k} : {v}' for k, v in rpcjson_customer_environment['body']['featureAdoption'].items() if v == True )

    final_slack_message += environment_output + "\n"

    line += "Company Size: " + rpcjson['body']['companySize'] + "\n"
    line += "Country: " + rpcjson['body']['country'] + "\n"
    line += "Plan: " + rpcjson['body']['plan'] + "\n"
    line += "Salesforce: " + "https://perimeter81.lightning.force.com/lightning/r/Account/" + rpcjson['body'][
        'salesforceAccountId'] + "/view" + "\n"
    line += "Workspace: " + rpcjson['body']['workspace'] + "\n"

    line += "Active Members: " + str(rpcjson_platform['body']['team']['members']) + "\n"
    network_ids = ''
    network_attributes = ''
    tunnels_id = ''
    network_map = ''

    for network_stanza in rpcjson_platform_networks_list['body']['networks']:
        network_map += "Network: " + network_stanza['networkName'] + " " + network_stanza['networkId'] + " " + ' '.join(f'( {k} : {v} )' for k, v in network_stanza['attributes'].items() if v == True) + "\n"

        status, rpcjson_platform_network_more = getNetworkFromJarvis(network_stanza['networkId'], more_url, bearertoken)
        for region in rpcjson_platform_network_more['body']['regions']:
            network_map += " ¬ " + "Region: " + region['name'] + "\n"
            for instance in region['instances']:
                network_map += "   ¬ " + "Instance: " + instance['ip'] + " " + region['provider']['type'] + " " + \
                               region['provider']['region'] + "\n"
                for tunnel in instance['tunnels']:
                    if tunnel['type'] == "ipsec":
                        network_map += "     ¬ " + "Tunnel: " + tunnel['interfaceName'] + " " + instance['ip'] + str(
                            tunnel['leftSubnets']) + " <> " + str(tunnel['rightSubnets']) + " " + tunnel[
                                           'right'] + " " + tunnel['type'] + "\n"
                    if tunnel['type'] == "connector":
                        network_map += "     ¬ " + "Tunnel: " + tunnel['interfaceName'] + " " + instance['ip'] + " " + \
                                       rpcjson_platform_network_more['body']['subnet'] + " <> " + str(
                            tunnel['leftAllowedIP']) + " " + tunnel['leftEndpoint'] + " " + tunnel['type'] + "\n"
                    if tunnel['type'] == "openvpn":
                        network_map += "     ¬ " + "Tunnel: " + tunnel['interfaceName'] + " " + tunnel['type'] + "\n"
        network_map += '\n'  # needed for formatting

    final_slack_message += network_map + "\n"
    client.chat_postMessage(channel=channel_id, text=final_slack_message)

@app.route('/whois', methods=['POST'])
def whois():
        if not verify_request(request):
            return('caller not verified', 403)
        data = request.form
        tenant = data.get('text')
        channel_id = data.get('channel_id')
        return_url = data.get('response_url')
        whois_internal_thread = threading.Thread(target=whois_internal, args=(tenant, channel_id, return_url))
        whois_internal_thread.start()
        return Response(), 200
        
if __name__ == "__main__":
	app.run(host="0.0.0.0",debug=True)
