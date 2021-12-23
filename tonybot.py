import hmac
import hashlib
from slack_sdk import WebClient
import os
from pathlib import Path
from dotenv import load_dotenv
from flask import Flask, request, Response
from slackeventsapi import SlackEventAdapter
import requests
import threading
import random   
import time

env_path = Path('.') / 'env'
load_dotenv(dotenv_path=env_path)

app = Flask(__name__)
slack_event_adapter = SlackEventAdapter(os.environ['SIGNING_SECRET'], '/slack/events', app)
client = WebClient(token=os.environ['SLACK_TOKEN'])
BOT_ID = client.api_call("auth.test")['user_id']
bearertoken = os.environ['BEARER_TOKEN']

def get_secret(secret_name:str) -> str:
    # Try to read from env, if you fail get the secret from AWS secret manager (use boto3)
    try:
        os.environ[secret_name]
    except Exception:
        pass
        #call boto and fetch the secrets

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
    # timestamp, and the request body
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

def searchJarvis():
    return True

def getNetworkFromJarvis(network_id, resource, bearertoken):
    data_derived = '{"networkId": ' + '"' + network_id + '"}'
    return getFromJarvis(data_derived, resource, bearertoken)

def getGeneralFromJarvis(tenant_name, resource, bearertoken):
    data_derived = '{"customerId": ' + '"' + tenant_name + '"}'
    return getFromJarvis(data_derived, resource, bearertoken)

def getFromJarvis(data_derived, resource, bearertoken):

    def url_builder(resource):
        resources = []
        if isinstance(resource, str):
            resources.append(resource)
        elif isinstance(resource, list):
            resources = resource
        else:
            raise ValueError(f'{type(resource)} is not supported')
        resources = [x.lower() for x in resources]
        print(f'https://api.perimeter81.com/api/jarvis/{"/".join(resources)}')
        return f'https://api.perimeter81.com/api/jarvis/{"/".join(resources)}'


    headers = {'Authorization': bearertoken, 'Accept': 'application/json', 'Content-Type': 'application/json'}
    response = requests.post(url_builder(resource), headers=headers,data=data_derived)
    if response.status_code == 200:
        return True, response.json()
    else:
        return False, response.status_code

@app.route('/whoami', methods=['POST'])
def whoami():
    data = request.form
    # print(data)
    user_id = data.get('user_id')
    channel_id = data.get('channel_id')
    user_name = data.get('user_name')
    team_domain = data.get('team_domain')
    text = 'Hello, ' + user_name + '!' + ' You must be from ' + team_domain
    client.chat_postMessage(channel=channel_id, text=text)
    return Response(), 200

def get_quote():

    all_quotes = open('tony_quotes.txt', 'r')
    quotes_lines = all_quotes.readlines()
    return random.choice(quotes_lines)

def whois_internal(tenant_name, channel_id, return_url):
    # function for doing the actual work in a thread

    status, rpcjson = getGeneralFromJarvis(tenant_name, ['customer','header'], bearertoken)
    if rpcjson == 500:
        #client.chat_postMessage(channel=channel_id, text="we have to call search")
        search_input = '{"filter": ' + '"' + tenant_name + '"}'
        search_results = ''
        response = getFromJarvis(search_input, ['customers','search'], bearertoken)
        for result in response[1]['body']['accounts']:
            search_results += "  ¬ " + str(result['customerId']) + " (" + str(result['companyName']) + ") " + "\n"
        if not search_results:
            client.chat_postMessage(channel=channel_id, text="I was unable to locate any account with that name")
        else:
            client.chat_postMessage(channel=channel_id, text="I was unable to locate any account with that name, but here are some similar results:\n")
            client.chat_postMessage(channel=channel_id, text=search_results)

    elif not status:
        client.chat_postMessage(channel=channel_id, text="Something went wrong, please check your input" + str(rpcjson))

    else:
        pass
    status, rpcjson_general = getGeneralFromJarvis(tenant_name, ['customer','general'], bearertoken)
    if not status:
        client.chat_postMessage(channel=channel_id, text=rpcjson_general)

    status, rpcjson_platform = getGeneralFromJarvis(tenant_name, ['customer','platform'], bearertoken)
    if not status:
        client.chat_postMessage(channel=channel_id, text=rpcjson_platform)

    status, rpcjson_platform_networks_list = getGeneralFromJarvis(tenant_name, ['customer','platform','networks','list'], bearertoken)
    if not status:
        client.chat_postMessage(channel=channel_id, text=rpcjson_platform_network_list)

    status, rpcjson_customer_environment = getGeneralFromJarvis(tenant_name, ['customer','environment'], bearertoken)
    if not status:
        client.chat_postMessage(channel=channel_id, text=rpcjson_customer_environment)

    final_slack_message = get_quote()
    final_slack_message += "\n"

    rpcjson_output = ''
    rpcjson_output += "Here is what we know about : " + tenant_name + "\n"
    #rpcjson_output += " " + "\n"
    rpcjson_output += '\n'.join(f'*{k}* : {v}' for k, v in rpcjson['body'].items())

    # TODO We need to look output order
    # rpcjson_output += '\n'.join(f'{k} : {v}' for k,v in rpcjson['body'].items() if k in ['companyName', 'accountManager', 'customerSuccessEngineer', 'country', 'plan'])

    final_slack_message += rpcjson_output + "\n"
    final_slack_message += "*ARR:* " + str(rpcjson_general['body']['arr']) + "\n"
    final_slack_message += "*Active Members*: " + str(rpcjson_platform['body']['team']['members']) + "\n"
    #TODO This needs a check for empty salesforceAccountId
    final_slack_message += "*Salesforce:* " + "https://perimeter81.lightning.force.com/lightning/r/Account/" + rpcjson['body']['salesforceAccountId'] + "/view" + "\n"
    final_slack_message += "*Company Size:* " + rpcjson['body']['companySize'] + "\n"
    final_slack_message += "*Country:* " + rpcjson['body']['country'] + "\n"
    final_slack_message += "*Plan:* " + rpcjson['body']['plan'] + "\n"
    #final_slack_message += "Workspace: " + rpcjson['body']['workspace'] + "\n"

    environment_output = '\n'.join(f'*{k}* : {v}' for k, v in rpcjson_customer_environment['body']['featureAdoption'].items() if v == True)

    final_slack_message += environment_output + "\n"

    network_map = ''

    if not isinstance(rpcjson_platform_networks_list['body']['networks'], bool):

        for network_stanza in rpcjson_platform_networks_list['body']['networks']:
            # TODO Create links for networkID and gateways to Grafana
            network_map += "*Network*: " + network_stanza['networkName'] + " " + network_stanza['networkId'] + " " + ' '.join(
                f'( *{k}* : {v} )' for k, v in network_stanza['attributes'].items() if v == True) + "\n"

            status, rpcjson_platform_network_more = getNetworkFromJarvis(network_stanza['networkId'],'platform/network/more', bearertoken)
            subnet = rpcjson_platform_network_more['body']['subnet']
            for region in rpcjson_platform_network_more['body']['regions']:
                network_map += "\n"
                network_map += " ¬ " + "*Region*: " + region['name'] + "\n"
                for instance in region['instances']:
                    network_map += "     ¬ " + "*Instance*: " + instance['ip'] + " " + region['provider']['type'] + " " + \
                                   region['provider']['region'] + "\n"
                    for tunnel in instance['tunnels']:
                        if tunnel['type'] == "ipsec":
                            network_map += "         ¬ " + "*Tunnel*: " + tunnel['interfaceName'] + " " + instance['ip'] + " <> " + tunnel['right'] + " " + tunnel['type'] + "\n"
                            for subnet in tunnel['rightSubnets']:
                                network_map += "             ¬ " + "*Security Association*: " + str(tunnel['leftSubnets'][0]) + " <> " + subnet + "\n"
                            network_map += "\n"

                        if tunnel['type'] == "connector":
                            network_map += "         ¬ " + "*Tunnel*: " + tunnel['interfaceName'] + " " + instance['ip'] + " <> " + tunnel['leftEndpoint'] + " " + tunnel['type'] + "\n"
                            for allowedIP in tunnel['leftAllowedIP']:
                                network_map += "             ¬ " + "*Security Association*: " + subnet + " <> " + allowedIP + "\n"
                            network_map += "\n"

                        if tunnel['type'] == "openvpn":
                            network_map += "         ¬ " + "*Tunnel*: " + tunnel['interfaceName'] + " " + tunnel['type'] + "\n"
            network_map += '\n'  # needed for formatting

    else:
        network_map += "There are no networks on this tenant"

    final_slack_message += network_map + "\n"

    client.chat_postMessage(channel=channel_id, text=final_slack_message)

@app.route('/whois', methods=['POST'])
def whois():
    print("GOT HERE")
    if not verify_request(request):
        return ('caller not verified', 403)
    data = request.form
    tenant = str(data.get('text').lower())
    channel_id = data.get('channel_id')
    return_url = data.get('response_url')
    whois_internal_thread = threading.Thread(target=whois_internal, args=(tenant, channel_id, return_url))
    whois_internal_thread.start()
    return Response(), 200


@app.route('/slack/events', methods=['POST'])

@app.route('/whatever', methods=['POST'])
def whatever():
    print("GOT HERE")
    return "good"

@slack_event_adapter.on('message')
def message(payload):
	event = payload.get('event', {})
	channel_id = event.get('channel')
	user_id = event.get('user')
	text = event.get('text')
	if BOT_ID != user_id:
	    client.chat_postMessage(channel=channel_id, text=text)

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
