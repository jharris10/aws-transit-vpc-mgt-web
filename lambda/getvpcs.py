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
    bodymessage = json.dumps(message)
    return {
        'statusCode': str(status_code),
        'body': bodymessage,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
    }


def lambda_handler(event, context):
    logger.info("Got event: {}".format(str(event)))
    #VpcId = event['queryStringParameters']['VpcId']
    #region = event['queryStringParameters']['Region']
    #VpcId = event['VpcId']
    #region = event['Region']
    region = "eu-west-1"


    vpcinfo = []

    ec2 = boto3.resource('ec2', region_name=region)
    client = boto3.client('ec2')
    output = client.describe_vpcs()
    #response = client.describe_vpcs(VpcIds=[VpcId])
    cidrblock = output['Vpcs'][0]['CidrBlock']

    for vpc in output['Vpcs']:
        vpcdata = {}
        VpcId = vpc['VpcId']
        CidrBlock = vpc['CidrBlock']
        vpcdata['VpcId'] = VpcId
        vpcdata['VpcCidr'] = CidrBlock
        vpcinfo.append(vpcdata)
        
    apioutput = response(vpcinfo, 200)
    logger.info("Sending response={}, hence proceeding  ".format(apioutput))
    
    return apioutput