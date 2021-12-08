import hmac
import hashlib
import time
import slack
import json
import os
from pathlib import Path
from dotenv import load_dotenv
from flask import Flask, request, Response, jsonify
from slackeventsapi  import SlackEventAdapter
import requests

env_path = Path('.') / '.env'
load_dotenv(dotenv_path=env_path)

app = Flask(__name__)
slack_event_adapter = SlackEventAdapter(os.environ['SIGNING_SECRET'], '/slack/events',app)

client = slack.WebClient(token=os.environ['SLACK_TOKEN'])
BOT_ID = client.api_call("auth.test")['user_id']
bearertoken = os.environ['BEARER_TOKEN']

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

def getAccountInfoJarvis(tenant):
    url = 'https://api.perimeter81.com/api/jarvis/customer/header'
    json_header = {}
    json_header['Authorization'] = bearertoken
    json_header['Accept'] = 'application/json'
    json_header['Content-Type'] = 'application/json'
    data_derived = {"customerId":tenant}

    response = requests.post(url, headers=json_header, data=data_derived)
    print(response)
    return Response(), 200

@slack_event_adapter.on('message')
def message(payload):
	event = payload.get('event', {})
	channel_id = event.get('channel')
	user_id = event.get('user')
	text = event.get('text')
	if BOT_ID != user_id:
		client.chat_postMessage(channel=channel_id, text=text)

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

@app.route('/whois', methods=['POST'])
def whois():
        if not verify_request(request):
            return('caller not verified', 403)
        data = request.form
        tenant = data.get('text')
        channel_id = data.get('channel_id')

        #URLS
        url = 'https://api.perimeter81.com/api/jarvis/customer/header'
        general_url = 'https://api.perimeter81.com/api/jarvis/customer/general'
        platform_url = 'https://api.perimeter81.com/api/jarvis/customer/platform'
        platform_networks_list_url = 'https://api.perimeter81.com/api/jarvis/customer/platform/networks/list'

        json_header = {}
        json_header['Authorization'] = bearertoken
        json_header['Accept'] = 'application/json'
        json_header['Content-Type'] = 'application/json'
        json_header['Host'] = 'api.perimeter81.com'
        json_header['Content-Length'] = '1000'
        data_derived = '{"customerId"' + ":" + '"' + tenant + '"}'
        response = requests.post(url, headers=json_header, data=data_derived)
        rpc = response.content.decode("utf-8")
        rpcjson = json.loads(rpc)

        response_general = requests.post(general_url, headers=json_header, data=data_derived)
        rpc_general = response_general.content.decode("utf-8")
        rpcjson_general = json.loads(rpc_general)

        response_platform = requests.post(platform_url, headers=json_header, data=data_derived)
        rpc_platform = response_platform.content.decode("utf-8")
        rpcjson_platform = json.loads(rpc_platform)

        response_platform_networks_list = requests.post(platform_networks_list_url, headers=json_header, data=data_derived)
        rpc_platform_networks_list = response_platform_networks_list.content.decode("utf-8")
        rpcjson_platform_networks_list = json.loads(rpc_platform_networks_list)
        #print(rpcjson_platform_networks_list)
        print(rpcjson['statusCode'])

        networks_one_message = ''
        tunnels_one_message = ''
        line = ''
        #line += "You are requesting information regarding account: " + tenant + "\n"
        line += "If we can't protect the Earth, you can be damn well sure we'll avenge it! " + "\n"
        line += "Let's start with:  " + tenant + "\n"
        line += "Status Code: " + str(rpcjson['statusCode']) + "\n"
        if rpcjson['statusCode'] == 200:
            line += "Company Name: " + rpcjson['body']['companyName'] + "\n"
            line += "Account Manager: " + rpcjson['body']['accountManager']  + "\n"
            line += "Customer Success Engineer: " + rpcjson['body']['customerSuccessEngineer'] + "\n"
            line += "Company Size: " + rpcjson['body']['companySize'] + "\n"
            line += "Country: " + rpcjson['body']['country'] + "\n"
            line += "Plan: " + rpcjson['body']['plan'] + "\n"
            line += "Salesforce: " + "https://perimeter81.lightning.force.com/lightning/r/Account/" + rpcjson['body']['salesforceAccountId'] + "/view" + "\n"
            line += "Workspace: " + rpcjson['body']['workspace'] + "\n"
            line += "ARR: " + str(rpcjson_general['body']['arr']) + "\n"
            line += "Active Members: " + str(rpcjson_platform['body']['team']['members']) + "\n"
            #line += "Networks: " + str(rpcjson_platform_networks_list['body']['networks']) + "\n"
            for list_network in rpcjson_platform_networks_list['body']['networks']:
                networks_one_message = []
                networks_one_message.append(list_network)
                for list_tunnel in list_network['tunnels']:
                    tunnels_one_message = []
                    tunnels_one_message.append(list_tunnel)
                print(tunnels_one_message)
            print(networks_one_message)
                #client.chat_postMessage(channel=channel_id, text=tunnels_one_message)
            #client.chat_postMessage(channel=channel_id, text=networks_one_message)



        client.chat_postMessage(channel=channel_id, text=line)
        return Response(), 200

if __name__ == "__main__":
	app.run(host="0.0.0.0",debug=True)
