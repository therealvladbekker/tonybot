from dotenv import load_dotenv
from pathlib import Path
import json
import boto3
from botocore.exceptions import ClientError


def get_secret(secret_name:str) -> str:
    region_name = "us-east-1"

    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name,
    )
     #Try to read from env
    # try:
    #      env_path = Path('.') / 'env'
    #      load_dotenv(dotenv_path=env_path)
    #      #print(os.environ[secret_name])
    #      #return os.environ[secret_name]
    # except Exception:
    #      pass

    # Go to AWS Secrets Manager

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print("The requested secret " + secret_name + " was not found")
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            print("The request was invalid due to:", e)
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            print("The request had invalid params:", e)
        elif e.response['Error']['Code'] == 'DecryptionFailure':
            print("The requested secret can't be decrypted using the provided KMS key:", e)
        elif e.response['Error']['Code'] == 'InternalServiceError':
            print("An error occurred on service side:", e)
    else:
        # Secrets Manager decrypts the secret value using the associated KMS CMK
        # Depending on whether the secret was a string or binary, only one of these fields will be populated
        if 'SecretString' in get_secret_value_response:
            text_secret_data = get_secret_value_response['SecretString']
            #print(get_secret_value_response['SecretString'])
            return json.loads(get_secret_value_response['SecretString'])[secret_name]
        else:
            binary_secret_data = get_secret_value_response['SecretBinary']