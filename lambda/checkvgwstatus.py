import boto3
from boto3.dynamodb.conditions import Key, Attr
import logging
import os
import json
import sys



logger = logging.getLogger()
logger.setLevel(logging.INFO)


def response(message, status_code):
    logger.info('Called function response with {} {}'.format(message, status_code))
    return {
        'statusCode': str(status_code),
        'body': json.dumps(message),
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
    }

def isVgwAttachedToVpc(vpcId, awsRegion):
    logger.info('Called isVgwAttachedToVpc(vpcId,awsRegion) {} {}'.format(vpcId, awsRegion))
    """Verifies whether the VPC has any VGW attached, return either VgwId or False
    """
    try:
        ec2_conn = boto3.client('ec2', region_name=awsRegion)
        filters = [{'Name': 'attachment.vpc-id', 'Values': [vpcId]},
                   {'Name': 'attachment.state', 'Values': ['attached']}]
        output = ec2_conn.describe_vpn_gateways(Filters=filters)['VpnGateways']
        attachments = output[0]
        dictoutput = output[0]['VpcAttachments'][0]
        logger.error("dictoutput is: {}".format(dictoutput))
        logger.error("dictoutput is type: {}".format(attachments))
        if dictoutput:
            data= {
                "State" : dictoutput['State'],
                "VpnGatewayId": attachments['VpnGatewayId']
                }
            return data
        else:
            data = {
                "State": "attaching"
            }
            return data
    except Exception as e:
        logger.error("Error in isVgwAttachedToVpc(), Error: {}".format(str(e)))
        data = {
                "State": "Unknown - Cannot find VGW"
                }
        return data



def lambda_handler(event, context):
    logger.info("Got event: {}".format(str(event)))
    vpcId = event['queryStringParameters']['VpcId']
    region = event['queryStringParameters']['Region']
    result = isVgwAttachedToVpc(vpcId, region)
    
    apioutput = response(result, 200)
    logger.info("Sending : {}".format(apioutput))

    return apioutput
