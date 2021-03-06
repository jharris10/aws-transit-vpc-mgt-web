import json
import logging
import os
import sys

import boto3
from boto3.dynamodb.conditions import Attr

logger = logging.getLogger()
logger.setLevel(logging.INFO)

'''
Input {
    "Result": 'Success',
    "VpcId": event['queryStringParameters']['VpcId'],
    "VpcCidr": event['queryStringParameters']['VpcCidr'],
    "PaGroupName": paGroup['PaGroupName'],
    "vgwAsn": str(vgwAsnNumber),
    "N1Eip": paGroup['N1Eip'],
    "N2Eip": paGroup['N2Eip'],
    "N1Asn": paGroup['N1Asn'],
    "N2Asn": paGroup['N2Asn'],
    "N1T1": bgpIpPool['N1T1'],
    "N1T2": bgpIpPool['N1T2'],
    "N2T1": bgpIpPool['N2T1'],
    "N2T2": bgpIpPool['N2T2'],
    "IpSegment": bgpIpPool['IpSegment'],
    "TransitVpnBucketName": transitConfig['TransitVpnBucketName'],
    "TransitAssumeRoleArn": transitConfig['TransitAssumeRoleArn'],
    "Region": region
}
'''

subscriberConfigTable = os.environ['subscriberConfigTable']
region = os.environ['Region']

subscriberConfig = {}

dynamodb = boto3.resource('dynamodb', region_name=region)
dryrun = False


#
# From commonLambdaFunction
#

# Not required as sent via SNS
# def fetchFromTransitConfigTable(transitConfigTable=None):
#     """Get the data from TransitConfig table and returns it as dictionary
#     """
#     try:
#         dynamodb = boto3.resource('dynamodb')
#         table = dynamodb.Table(transitConfigTable)
#         response = table.scan()
#         for item in response['Items']:
#             transitConfig[item['Property']] = item['Value']
#         return transitConfig
#         logger.info("Got trasnitConfig {}".format(transitConfig))
#     except Exception as e:
#         logger.info("Fetching From Config table failed, Error: {}".format(str(e)))
#         return False


def fetchFromSubscriberConfigTable(subscriberConfigTable=None):
    """Get the data from SubscriberConfig table and retruns it as dictionary
    """
    try:
        table = dynamodb.Table(subscriberConfigTable)
        response = table.scan()
        for item in response['Items']:
            subscriberConfig[item['Property']] = item['Value']
        return subscriberConfig
    except Exception as e:
        logger.info("Fetching From Config talbe is Failed, Error: {}".format(str(e)))
        return False


def uploadObjectToS3(vpnConfiguration, bucketName, assumeRoleArn=None):
    """Uploads an object(VPN Conf file) to S3 bucket
    """
    try:
        s3Connection = boto3.resource('s3')
        fileName = vpnConfiguration['VpnConnection']['VpnConnectionId'] + '.xml'
        vpnConfig = vpnConfiguration['VpnConnection']['CustomerGatewayConfiguration']
        # open(filePath).write(vpnConfiguration['VpnConnection']['CustomerGatewayConfiguration'])
        if assumeRoleArn:
            stsConnection = boto3.client('sts')
            assumedrole = stsConnection.assume_role(RoleArn=assumeRoleArn, RoleSessionName="Sample")
            s3 = boto3.resource('s3', aws_access_key_id=assumedrole['Credentials']['AccessKeyId'],
                                aws_secret_access_key=assumedrole['Credentials']['SecretAccessKey'],
                                aws_session_token=assumedrole['Credentials']['SessionToken'])
            s3.Object(bucketName, fileName).put(Body=vpnConfig)
            return True
        s3Connection.Object(bucketName, fileName).put(Body=vpnConfig)
        return True
    except Exception as e:
        logger.error("Error uploading file to S3 Bucket, Error : %s" % str(e))
        return False


def deleteVgw(vgwId, vpcId, awsRegion):
    logger.info('Called deleteVgw(vgwId, vpcId, awsRegion) {} {} {}'.format(vgwId, vpcId, awsRegion))
    """Detache and Deletes the VGW from VPC
    """
    try:
        ec2_conn = boto3.client('ec2', region_name=awsRegion)
        response = ec2_conn.describe_vpn_gateways(VpnGatewayIds=[vgwId])['VpnGateways']
        if response:
            ec2_conn.detach_vpn_gateway(VpnGatewayId=vgwId, VpcId=vpcId)
            logger.info("Detached VGW: {} from Vpc: {}".format(vgwId, vpcId))
            ec2_conn.delete_vpn_gateway(VpnGatewayId=vgwId)
            logger.info("Deleted VGW: {}".format(vgwId))
            return response[0]['AmazonSideAsn']
    except Exception as e:
        logger.error("Error in deleteVgw(), Error: {}".format(str(e)))
        pass


def createVpnConnectionUploadToS3(region, vgwId, cgwId, tunnelOneCidr, tunnelTwoCidr, tag, bucketName,
                                  assumeRoleArn=None):
    logger.info('Called createVpnConnectionUploadToS3')
    """Creates VPN connection and upload the VPN configuration to the S3 bucket
    """
    try:
        tags = [{'Key': 'Name', 'Value': tag}]
        ec2Connection = boto3.client('ec2', region_name=region)
        response = ec2Connection.create_vpn_connection(
            CustomerGatewayId=cgwId,
            Type='ipsec.1',
            VpnGatewayId=vgwId,
            DryRun=False,
            Options={
                'StaticRoutesOnly': False,
                'TunnelOptions': [
                    {
                        'TunnelInsideCidr': tunnelOneCidr
                    },
                    {
                        'TunnelInsideCidr': tunnelTwoCidr
                    }
                ]
            }
        )
        ec2Connection.create_tags(Resources=[response['VpnConnection']['VpnConnectionId']], Tags=tags)
        # Uploading VPN configuration to S3 bucket
        if assumeRoleArn:
            uploadObjectToS3(response, bucketName, assumeRoleArn)
        else:
            uploadObjectToS3(response, bucketName)
        return response['VpnConnection']['VpnConnectionId']
    except Exception as e:
        logger.error("Error Creating VPN Connection, Error: {}".format(str(e)))


def createCgw(cgwIp, cgwAsn, region, tag):
    logger.info('Called createCgw(cgwIp, cgwAsn, region, tag) {} {} {} {}'.format(cgwIp, cgwAsn, region, tag))
    """Creates CGW and returns CgwId
    """
    try:
        tags = [{'Key': 'Name', 'Value': tag}]
        ec2Connection = boto3.client('ec2', region_name=region)
        response = ec2Connection.create_customer_gateway(BgpAsn=int(cgwAsn), PublicIp=cgwIp, Type='ipsec.1')
        ec2Connection.create_tags(Resources=[response['CustomerGateway']['CustomerGatewayId']], Tags=tags)
        return response['CustomerGateway']['CustomerGatewayId']
    except Exception as e:
        logger.error("Error in createCgw(), Error: {}".format(str(e)))
        return False


def checkCgw(awsRegion, n1Eip, n2Eip):
    logger.info('Called checkCgw(awsRegion, n1Eip, n2Eip) {} {} {}'.format(awsRegion, n1Eip, n2Eip))
    """Verifies whether the CGWs are already created or not, returns either a list of cgwIds or False
    """
    try:
        cgwIds = []
        ec2_conn = boto3.client('ec2', region_name=awsRegion)
        filters = [{'Name': 'ip-address', 'Values': [n1Eip]}]
        response = ec2_conn.describe_customer_gateways(Filters=filters)['CustomerGateways']
        if response:
            for cgw in response:
                if cgw['State'] == 'available':
                    cgwIds.append(cgw['CustomerGatewayId'])
        filters = [{'Name': 'ip-address', 'Values': [n2Eip]}]
        response = ec2_conn.describe_customer_gateways(Filters=filters)['CustomerGateways']
        if response:
            for cgw in response:
                if cgw['State'] == 'available':
                    cgwIds.append(cgw['CustomerGatewayId'])
        if cgwIds:
            return cgwIds
        else:
            return False
    except Exception as e:
        logger.error("Error from checkCgw, Error: {}".format(str(e)))
        return False


def isVgwAttachedToVpc(vpcId, awsRegion):
    logger.info('Called isVgwAttachedToVpc(vpcId,awsRegion) {} {}'.format(vpcId, awsRegion))
    """Verifies whether the VPC has any VGW attached, return either VgwId or False
    """
    try:
        ec2_conn = boto3.client('ec2', region_name=awsRegion)
        filters = [{'Name': 'attachment.vpc-id', 'Values': [vpcId]},
                   {'Name': 'attachment.state', 'Values': ['attached']}]
        response = ec2_conn.describe_vpn_gateways(Filters=filters)['VpnGateways']
        if response:
            return response[0]
        else:
            return False
    except Exception as e:
        logger.error("Error in isVgwAttachedToVpc(), Error: {}".format(str(e)))
        return False


def updateDynamoDb(tableName, vpcId, vpcCidr, awsRegion):
    logger.info('Called updateDynamoDb with {} {} {} {}'.format(tableName, vpcId, vpcCidr, awsRegion))
    """Updates SubscriberLocalDb with VpcId, VpcCidr and Region
    """
    try:
        dynamodb = boto3.resource('dynamodb', region_name=awsRegion)
        table = dynamodb.Table(tableName)
        item = {'VpcId': vpcId, 'VpcCidr': vpcCidr, 'Region': awsRegion}
        table.put_item(Item=item)
        logger.info("Updated Subscriber local DynmodDB with vpc-id: {} and vpc-cidr: {}".format(vpcId, vpcCidr))
    except Exception as e:
        logger.error("Error from updateDynamoDb(), {}".format(str(e)))


def updateTags(awsRegion, vpcId, oldVpc):
    logger.info('Called updateTabs with {} {} {}'.format(awsRegion, vpcId, oldVpc))
    """Updates VPC tags with VPN-Failed keys
    """
    try:
        # Update VPC tags with
        # Key                            Value
        # ConfigStatus           Vpn-Failed
        # ConfigReason           VPC-CIDR Conflicts
        ec2Connection = boto3.client('ec2', region_name=awsRegion)
        configReason = 'Vpc-CIDR Conflicts with ' + oldVpc['VpcId'] + ':' + oldVpc['Region']
        tags = [
            {'Key': 'ConfigStatus', 'Value': 'Vpn-Failed'},
            {'Key': 'ConfigReason', 'Value': configReason}
        ]
        ec2Connection.create_tags(Resources=[vpcId], Tags=tags)
        logger.info("Successfully Updated VPC-Failed tags to VPCID: {}".format(vpcId))
        sys.exit(0)
    except Exception as e:
        logger.info("Updating VPC-Failed tags failed, Error: {}".format(str(e)))
        sys.exit(0)


def putItemSubscriberLocalDb(tableName, item):
    logger.info('Called putItemSubscriberLocalDb with {} {}'.format(tableName, item))
    """Puts an Item into the SubscriberLocalDb table with VpcId, VpcCidr, VgwId, Cgw1Id, Cgw2Id, Vpn1Id,Vpn2Id and PaGroupName
    """
    try:
        dynamodb = boto3.resource('dynamodb', region_name=item['Region'])
        table = dynamodb.Table(tableName)
        table.put_item(Item=item)
        logger.info("Updating LocalDb with data: {}".format(item))
    except Exception as e:
        logger.error("Updating LocalDb failed, Error: {}".format(str(e)))


def createVgwAttachToVpc(vpcId, vgwAsn, region, paGroup):
    logger.info(
        'Called createVgwAttachToVpc(vpcId, vgwAsn, region, paGroup) with {} {} {} {}'.format(vpcId, vgwAsn, region,
                                                                                              paGroup))
    """Creates a VGW and attach it to the VPC, returns VgwId
    """
    try:
        tags = [{'Key': 'Name', 'Value': paGroup}]
        import time
        ec2Connection = boto3.client('ec2', region_name=region)
        # Create VGW with vgwAsn
        response = ec2Connection.create_vpn_gateway(Type='ipsec.1', AmazonSideAsn=int(vgwAsn))
        # Attach VGW to VPC
        while True:
            status = ec2Connection.attach_vpn_gateway(VpcId=vpcId, VpnGatewayId=response['VpnGateway']['VpnGatewayId'],
                                                      DryRun=False)['VpcAttachment']
            if status['State'] == 'attaching':
                time.sleep(2)
            elif status['State'] == 'attached':
                ec2Connection.create_tags(Resources=[response['VpnGateway']['VpnGatewayId']], Tags=tags)
                return response['VpnGateway']['VpnGatewayId']
            else:
                return None
        return response['VpnGateway']['VpnGatewayId']
    except Exception as e:
        logger.error("Error creating Vgw and Attaching it to VPC, Error : {}".format(str(e)))
        return False


def updateVpcVpnTable(tableName, item):
    logger.info('Called function updateVpcVpnTable(tableName, item) with {} {}'.format(tableName, item))
    """Updates VpcVpnTable with VpnId, VpcId, PaGroupName and PaGroupNode
    """
    try:
        dynamodb = boto3.resource('dynamodb', region_name=item['Region'])
        table = dynamodb.Table(tableName)
        table.put_item(Item=item)
        logger.info("Updating VpcVpnTable is success with data: {}".format(item))
    except Exception as e:
        logger.error("Updating VpcVpnTable failed, Error: {}".format(str(e)))


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


# VpcId, Region, vgwAsn, PaGroupName, paGroup, bgpIpPool[],vgwAsnNumber

def uploadFileToS3(fileName, bucketName, updates, assumeRoleArn=False):
    """Uploads status file to S3 bucket
    """
    try:
        s3Connection = boto3.resource('s3')
        if assumeRoleArn:
            stsConnection = boto3.client('sts')
            assumedrole = stsConnection.assume_role(RoleArn=assumeRoleArn, RoleSessionName="Sample")
            s3 = boto3.resource('s3', aws_access_key_id=assumedrole['Credentials']['AccessKeyId'],
                                aws_secret_access_key=assumedrole['Credentials']['SecretAccessKey'],
                                aws_session_token=assumedrole['Credentials']['SessionToken'])
            s3.Object(bucketName, fileName).put(Body=updates)
            return True
        result = s3Connection.Object(bucketName, fileName).put(Body=json.dumps(updates))
        print ("result is {}".format(result))
        return True
    except Exception as e:
        print("Error uploading file to S3 Bucket, Error : %s" % str(e))
        return False


def lambda_handler(event1, context):
    # event = json.loads(event1['Records'][0]['Sns']['Message'])
    # Need fileName, bucketName,
    #
    rawmessage = event1['Records'][0]['Sns']['Message']
    event = json.loads(rawmessage)
    logger.info('event object is {}'.format(event))
    messagefileName = event['messagefileName']

    # Info send via SNS
    # transitConfig = fetchFromTransitConfigTable(transitConfigTable)

    try:
        logger.info('event object is {}'.format(event))
        subscriberConfig = fetchFromSubscriberConfigTable(subscriberConfigTable)
        logger.info("Got subscriberConfig from table {}".format(subscriberConfig))
        if subscriberConfig:
            vgwId = False
            vgwData = isVgwAttachedToVpc(event['VpcId'],
                                         event['Region'])
            logger.info("VGW event : {}".format(vgwData))
            if vgwData: vgwId = vgwData['VpnGatewayId']
            if not vgwId:
                # Create VGW and attach it to VPC
                vgwId = createVgwAttachToVpc(event['VpcId'], int(event['vgwAsn']),
                                             event['Region'],
                                             event['PaGroupName'])
                logger.info("VGW - {} is created and attached to VPC - {}".format(vgwId, event['VpcId']))
            else:
                logger.info(
                    "Using existing Vgw: {} for VPC: {} ".format(vgwId, event['VpcId']))
            logger.info("Checking whether CGWs are already created or not")
            cgwIds = checkCgw(event['Region'], event['N1Eip'], event['N2Eip'])
            if not cgwIds:
                logger.info("CGWs are not created before, hence creating them now")
                # Create CGW1
                cgw1Tag = event['PaGroupName'] + '-N1'
                cgwNode1Id = createCgw(event['N1Eip'], str(event['N1Asn']),
                                       event['Region'], cgw1Tag)
                logger.info(
                    "CGW - {} is created for VPC - {}".format(cgwNode1Id, event['VpcId']))
                # Create CGW2
                cgw2Tag = event['PaGroupName'] + '-N2'
                cgwNode2Id = createCgw(event['N2Eip'], str(event['N2Asn']),
                                       event['Region'], cgw2Tag)
                logger.info(
                    "CGW - {} is created for VPC - {}".format(cgwNode1Id, event['VpcId']))
            else:
                logger.info("CGWs are already created, CgwNode1Id: {}, CgwNode2Id: {}".format(cgwIds[0], cgwIds[1]))
                cgwNode1Id = cgwIds[0]
                cgwNode2Id = cgwIds[1]

            # VPN Connection
            logger.info('Creating vpnXTag with PagroupName {}'.format(event['PaGroupName']))
            vpn1Tag = event['VpcId'] + '-' + event['PaGroupName'] + '-N1'
            vpn2Tag = event['VpcId'] + '-' + event['PaGroupName'] + '-N2'
            # Create VPN1 connection with Node1
            #
            if vgwId: vpnId1 = createVpnConnectionUploadToS3(event['Region'], vgwId,
                                                             cgwNode1Id, event['N1T1'],
                                                             event['N1T2'], vpn1Tag,
                                                             event['TransitVpnBucketName'],
                                                             event['TransitAssumeRoleArn'])
            logger.info("VPN1 - {} is created for VPC - {} with PA-Group: {}".format(vpnId1,
                                                                                     event[
                                                                                         'VpcId'],
                                                                                     event['PaGroupName']))
            # Crete VPN2 connection with Node2
            if vgwId: vpnId2 = createVpnConnectionUploadToS3(event['Region'], vgwId,
                                                             cgwNode2Id, event['N2T1'],
                                                             event['N2T2'], vpn2Tag,
                                                             event['TransitVpnBucketName'],
                                                             event['TransitAssumeRoleArn'])
            logger.info("VPN2 - {} is created for VPC - {} with PA-Group: {}".format(vpnId2,
                                                                                     event[
                                                                                         'VpcId'],
                                                                                     event['PaGroupName']))

            #
            # End of VPC setup
            #
            #
            # Forming an output to send to The Browser

            # Update SubcriberDynamoDB with VPN1-ID, VPN1-ID, VGW, CGW1, CGW2 and PA-Group-Name
            if vpnId1 and vpnId2:
                data = {
                    'Result': 'Success',
                    'VpcId': event['VpcId'],
                    'VpcCidr': event['VpcCidr'],
                    'Region': event['Region'],
                    'VgwId': vgwId,
                    'PaGroupName': event['PaGroupName'],
                    'CgwN1': cgwNode1Id,
                    'CgwN2': cgwNode2Id,
                    'VpnN1': vpnId1,
                    'VpnN2': vpnId2,
                    'vgwAsn': str(event['vgwAsn']),
                    'IpSegment': event['IpSegment']
                }
                # if vgwData:data['VgwAsn'] = str(vgwData['AmazonSideAsn'])

                # Publish message to S3 bucket
                # publishToSns(event['TransitSnsArn'], update, event['TransitAssumeRoleArn'])
                uploadFileToS3(event['messagefileName'], event['TransitVpnBucketName'], json.dumps(data),
                               event['TransitAssumeRoleArn'])

                #
                #
                # filecontents = downloadFileFromS3(event['messagefileName'], event['TransitVpnBucketName'])
                # logger.info('Downloaded from S3 object and Result is {} '.format(filecontents['Result']))
                #

            if vpnId1 and vpnId2:
                data = {
                    'VpcId': event['VpcId'],
                    'VpcCidr': event['VpcCidr'],
                    'Region': event['Region'],
                    'VgwId': vgwId,
                    'PaGroupName': event['PaGroupName'],
                    'CgwN1': cgwNode1Id,
                    'CgwN2': cgwNode2Id,
                    'VpnN1': vpnId1,
                    'VpnN2': vpnId2
                }
                putItemSubscriberLocalDb(subscriberConfig['SubscriberLocalDb'], data)
                logger.info('Updated table {} with {} '.format(subscriberConfig['SubscriberLocalDb'], data))

            # #Update {} with VpnId, VpcId, PaGroup, PaGroupNode
            if vpnId1:
                update = {
                    'VpnId': vpnId1,
                    'VpcId': event['VpcId'],
                    'PaGroupName': event['PaGroupName'],
                    'PaGroupNode': event['N1Eip'],
                    'Region': event['Region']
                }
                updateVpcVpnTable(subscriberConfig['SubscriberVpcVpnTable'], update)
                logger.info('Updated table {} with {} '.format(subscriberConfig['SubscriberVpcVpnTable'], update))
            if vpnId2:
                update = {
                    'VpnId': vpnId2,
                    'VpcId': event['VpcId'],
                    'PaGroupName': event['PaGroupName'],
                    'PaGroupNode': event['N2Eip'],
                    'Region': event['Region']
                }
                updateVpcVpnTable(subscriberConfig['SubscriberVpcVpnTable'], update)
                logger.info('Updated table {} with {} '.format(subscriberConfig['SubscriberVpcVpnTable'], update))
            # # Publish message to Transit VPN
        else:
            logger.error("No event received from SubscriberConfig Table, Error")
    except Exception as e:
        logger.error("Error from subscriberVpn Configuration, Error: {}".format(str(e)))
        if vgwId: deleteVgw(vgwId, event['VpcId'],
                            event['Region'])

        
