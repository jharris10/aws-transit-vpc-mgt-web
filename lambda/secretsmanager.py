import boto3
from botocore.exceptions import ClientError
import json



def get_secret():
    secret_name = "panwfw"
    endpoint_url = "https://secretsmanager.eu-west-1.amazonaws.com"
    region_name = "eu-west-1"

    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name,
        endpoint_url=endpoint_url
    )

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
    else:
        # Decrypted secret using the associated KMS CMK
        # Depending on whether the secret was a string or binary, one of these fields will be populated
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            secretjson = json.loads(secret)
        else:
            binary_secret_data = get_secret_value_response['SecretBinary']
        print ('secret {} type {}'.format(secret,(type(secretjson))))
        return secretjson

creds = get_secret()
for user, password in creds.items():
    print ("user {} password {}".format(user, password))
