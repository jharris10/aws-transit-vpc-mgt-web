
import json
import boto3

import logging
import os
import json
import sys



logger = logging.getLogger()
logger.setLevel(logging.INFO)

vpcinfo = []

ec2 = boto3.resource('ec2', region_name='eu-west-1')
client = boto3.client('ec2')
response = client.describe_vpcs()
#response = client.describe_vpcs(VpcIds=['vpc-a8185fce'])
cidrblock = response['Vpcs'][0]['CidrBlock']

for vpc in response['Vpcs']:
    vpcdata = {}
    VpcId = vpc['VpcId']
    CidrBlock = vpc['CidrBlock']

    vpcdata['VpcId'] = VpcId
    vpcdata['VpcCidr'] = CidrBlock

    vpcinfo.append(vpcdata)

vpcinfojson= json.dumps(vpcinfo)

print ('Vpcdata json is {}'.format(vpcinfojson))
