import boto3
from boto3.dynamodb.conditions import Key, Attr
import logging
import os
import json
import sys



logger = logging.getLogger()
logger.setLevel(logging.INFO)

'''
Input:
{
    'VpcId'                     : 'vpc-xxxxxxx',
    'VpcCidr'                   : 'v.w.x.y/z',
    'Region'                    : 'AWS_Region'
}

Output:
{
    'VpcId' :'VpcId' , 
    'Region':'Region',
    'VgwAsn':'VgwAsn', 
    'PaGroupName':'PaGroupName',
    'N1Eip':"N1Eip", 
    'N2Eip':'N2Eip', 
    'N1Asn':'N1Asn', 
    'N2Asn':'N2Asn',
    'bgpIpPool':'bgpIpPool',
    'vgwAsnNumber':'vgwAsnNumber'
}
'''

subscriberConfigTable = os.environ['subscriberConfigTable']
subscriberAssumeRoleArn = os.environ['SubscriberAssumeRoleArn']
transitConfigTable = os.environ['transitConfigTable']
region = os.environ['Region']
apicreatevgwSnsArn = os.environ['apiCreateVgwSnsArn']
dynamodb = boto3.resource('dynamodb', region_name=region)
dryrun = False
transitConfig = {}
subscriberConfig = {}


#
# From commonLambdaFunction
#

def publishToSns(snsTopicArn, message, roleArn=None):
    """Publish message to SNS Topic
    """
    try:
        snsConnection = boto3.client('sns', region_name=snsTopicArn.split(':')[3])
        if roleArn:
            stsConnection = boto3.client('sts')
            assumedrole = stsConnection.assume_role(RoleArn=roleArn, RoleSessionName="Sample")
            snsConn = boto3.client('sns', region_name=snsTopicArn.split(':')[3],
                                   aws_access_key_id=assumedrole['Credentials']['AccessKeyId'],
                                   aws_secret_access_key=assumedrole['Credentials']['SecretAccessKey'],
                                   aws_session_token=assumedrole['Credentials']['SessionToken'])
            snsConn.publish(TopicArn=snsTopicArn, Message=json.dumps(message))
            return True
        snsConnection.publish(TopicArn=snsTopicArn, Message=json.dumps(message))
        return True
    except Exception as e:
        logger.error("Error in publishToSns(), Error: {}".format(str(e)))
        # return False

def fetchFromTransitConfigTable(transitConfigTable=None):
    """Get the data from TransitConfig table and returns it as dictionary
    """
    try:
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table(transitConfigTable)
        response = table.scan()
        for item in response['Items']:
            transitConfig[item['Property']] = item['Value']
        return transitConfig
    except Exception as e:
        logger.info("Fetching From Config talbe is Failed, Error: {}".format(str(e)))
        return False


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


#
# From fetchVpnServerDetailsLambda
#
def checkVpcCidrConflicts(vpcCidr, tableName):
    logger.info('Called checkVpcCidrConflicts(vpcCidr, tableName) {} {}'.format(vpcCidr, tableName))
    """Check whether there is a VPCCIDR conflict:
    If yes send notification back to Subscriber SNS that Vpn configuration failed
    Create log VPCCIDR conflict “New VPCID, NewVPC CIDR, Existing VPCID, Existing VPCCIDR
    """
    try:
        table = dynamodb.Table(tableName)
        response = table.scan(FilterExpression=Attr('VpcCidr').eq(vpcCidr))['Items']
        logger.info("Scan results of VpcTable: {}".format(response))
        if not response:
            return True
        return False
    except Exception as e:
        logger.error("Checking of CIDR confilcts failed, Error: {}".format(str(e)))


def getAvailableBgpTunnelIpPool(tableName, vpcId, paGroupName):
    logger.info('Called getAvailableBgpTunnelIpPool(tableName, vpcId, paGroupName) {} {} {}'.format(tableName, vpcId,
                                                                                                    paGroupName))
    """Scans the BgpTunnleIpPool table with attribute 'Avaliable=YES', if it finds any items with this condition returns that item otherwise returns false
    Calls the updateBgpTunnleIpPool function to update the attribute 'Available' to NO
    """
    try:
        logger.info("Fetching BgpTunnelIpPool data with fileter status=available")
        table = dynamodb.Table(tableName)
        response = table.scan(FilterExpression=Attr('Available').eq('YES'))['Items']
        if response:
            # Update BgpTunnelIpPool table Attribute "Available"="NO"
            if not dryrun: updateBgpTunnelIpPool(response[0]['IpSegment'], table, vpcId, paGroupName)
            return response[0]
        else:
            return False
    except Exception as e:
        logger.error("getAvailableBgpTunnelIpPool failed, Error: {}".format(str(e)))


def getAvailablePaGroup(tableName, maxCount):
    logger.info('Called getAvailablePaGroup(tableName, maxCount) {} {}'.format(tableName, maxCount))
    """Scans the PaGroupInfo table with attributes 'InUse=YES' and 'VpcCount' less than MaxPaGroupCapacity, if it finds an items it will return that item, otherwise
    Otherwise: it scans the table with attribute 'InUse=NO', if it finds an item it will return othrwise returns False
    Calls updatePaGroup() function to update the 'InUse' to YES and increment the VpcCount by +1
    """
    try:
        table = dynamodb.Table(tableName)
        response = table.scan(FilterExpression=Attr('InUse').eq('YES') & Attr('VpcCount').lt(maxCount))['Items']
        logger.info(
            "PaGroup Info scan result with Fileter InUse=YES and VpcCount < {} is: {}".format(maxCount, response))
        if response:
            # Logic to return the PaGroup which has nearest capacity
            value = response[0]['VpcCount']
            paGroupToReturn = response[0]
            for item in response:
                if 'N1Eip' in item:
                    if value < item['VpcCount']:
                        value = item['VpcCount']
                        paGroupToReturn = item
                else:
                    return False
            logger.info("Returing the Pa Group which has nearest capacity, PA-Group Name: {}".format(
                paGroupToReturn['PaGroupName']))
            # Update PaGroupInfo Table InUse="Yes" and increment VpcCount+1
            if not dryrun: updatePaGroup(paGroupToReturn['PaGroupName'], table)
            return paGroupToReturn
        else:
            response = table.scan(FilterExpression=Attr('InUse').eq('NO'))['Items']
            if response:
                for group in response:
                    if 'N1Eip' in group:
                        # Update PaGroupInfo Table InUse="Yes" and increment VpcCount+1
                        logger.info("Returing the PA-Group Name: {}".format(group['PaGroupName']))
                        updatePaGroup(group['PaGroupName'], table)
                        return group
                else:
                    return False
            else:
                return False
    except Exception as e:
        logger.error("getAvailablePaGroup is failed, Error: {}".format(str(e)))


def getAvailableVgwAsn(tableName, data):
    logger.info('Called getAvailableVgwAsn(tableName, data) {} {}'.format(tableName, data))
    """Scans the VgwAsn table with attribute 'InUse=NO', if it finds an item it will return that item, otherwise exit from the process
    Calls updateVgwAnsTable() function to update the 'InUse' to YES and VpcId and VpcCidr
    """
    VpcId = data['queryStringParameters']['VpcId']
    logger.info('Got VpcId {}'.format(VpcId))
    try:
        table = dynamodb.Table(tableName)
        # Check whether the VPC is assigned with VgwAsn number
        res = table.scan(FilterExpression=Attr('VpcId').eq(VpcId))['Items']
        if res:
            logger.info(
                "The VPC: {} is already assigned with VgwAsn: {}".format(data['VpcId'], res['Items'][0]['VgwAsn']))
            return res[0]['VgwAsn']
        response = table.scan(FilterExpression=Attr('InUse').eq('NO'))['Items']
        if response:
            # Update VgwAsn Table with InUse=YES, VpcId and VpcCidr values
            if not dryrun: result = updateVgwAsnTable(response[0]['VgwAsn'], data, table)
            return response[0]['VgwAsn']
        else:
            logger.error("VgwAsn numbers are exhausted, so Pleas add some more ASN numbers to VgwAsn Table")
            sys.exit(0)
    except Exception as e:
        logger.error("getAvailableVgwAsn is failed, Error: {}".format(str(e)))


def updateBgpTunnelIpPool(ipSegment, tableConn, vpcId, paGroupName):
    logger.info('Called updateBgpTunnelIpPool with {} {} {} {}'.format(ipSegment, tableConn, vpcId, paGroupName))
    """Updates the BgpTunnelIpPool table attributes Available=NO, and add VpcId and PaGroup names to the item
    """
    try:
        # Update BgpTunnelIpPool table Attribute "Available"="NO"
        if not dryrun: tableConn.update_item(Key={'IpSegment': ipSegment},
                                             AttributeUpdates={'Available': {'Value': 'NO', 'Action': 'PUT'},
                                                               'VpcId': {'Value': vpcId, 'Action': 'PUT'},
                                                               'PaGroupName': {'Value': paGroupName, 'Action': 'PUT'}})
        logger.info(
            "Successfully Updated BgpIpPoolTable attribute Available=NO, VpcId: {} and PaGroupName: {}".format(vpcId,
                                                                                                               paGroupName))
    except Exception as e:
        logger.error("Error from updateBgpTunnelIpPool, {}".format(str(e)))


def updatePaGroup(paGroupName, tableConn):
    logger.info('Called updatePaGroup with {} {}'.format(paGroupName, tableConn))
    """Updates the Transit PaGroupInfo table with InUse=YES and increments the VpcCount by +1
    """
    try:
        if not dryrun: tableConn.update_item(Key={'PaGroupName': paGroupName},
                                             AttributeUpdates={'InUse': {'Value': 'YES', 'Action': 'PUT'},
                                                               'VpcCount': {'Value': 1, 'Action': 'ADD'}})
        logger.info("Successfully Updated PaGroupInfoTable attributes InUse=YES and incremented VpcCount")
    except Exception as e:
        logger.error("Error from updatePaGroup, {}".format(str(e)))


def updateVgwAsnTable(id, data, tableConn):
    logger.info('Called updateVgwAsnTable with {} {} {}'.format(id, data, tableConn))
    """Updates Transit VgwAsn table with VpcId, VpcCidr, an InUse=YES
    """
    try:
        # Update VgwAsn Table with InUse=YES, VpcId and VpcCidr values
        if not dryrun: tableConn.update_item(Key={'VgwAsn': id},
                                             AttributeUpdates={'InUse': {'Value': 'YES', 'Action': 'PUT'},
                                                               'VpcId': {
                                                                   'Value': data['queryStringParameters']['VpcId'],
                                                                   'Action': 'PUT'}, 'VpcCidr': {
                                                     'Value': data['queryStringParameters']['VpcCidr'],
                                                     'Action': 'PUT'}})
        logger.info("Successfully Updated VgwAsnTable attributes InUse=YES and VpcId: {}, VpcCidr:{}".format(
            data['queryStringParameters']['VpcId'], data['queryStringParameters']['VpcCidr']))
    except Exception as e:
        logger.error("Error from updateVgwAsnTable, {}".format(str(e)))


def updateVpcTable(tableName, data, paGroupName):
    logger.info('Called updateVpcTable with {} {} {}'.format(tableName, data, paGroupName))
    """Updates the Transit VpcTable with VpcId, VpcCidr, Region, SubscriberSnsArn, SubscriberAssumeRoleArn, PaGroupName and CurrentStatus of VPN connection
    """
    try:
        # VpcCidr is the primary key for VpcTable
        table = dynamodb.Table(tableName)
        item = {
            'VpcId': data['queryStringParameters']['VpcId'],
            'VpcCidr': data['queryStringParameters']['VpcCidr'],
            'Region': data['queryStringParameters']['Region'],
            # 'SubscriberAssumeRoleArn': data['queryStringParameters']['SubscriberAssumeRoleArn'],
            'SubscriberAssumeRoleArn': subscriberAssumeRoleArn,
            'PaGroupName': paGroupName,
            'CurrentStatus': 'Inprogress'
        }
        logger.error("Updating Transit VpcTable with item: {}".format(item))
        if not dryrun: response = table.put_item(Item=item)
    except Exception as e:
        logger.error("Updating Transit VpcTalbe is Failed, Error: {}".format(str(e)))


#
# End of From fetchVpnServerDetailsLambda
#

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


def lambda_handler(event, context):
    global dryrun
    dryrun = False
    logger.info("Got Event: {}".format(event))
    logger.info("Got SNS Topict: {}".format(apicreatevgwSnsArn))

    if event['queryStringParameters']['dryrun'] == 'Yes':  # Set True for 'Yes' False for "No'
        dryrun = True
    try:
        transitConfig = fetchFromTransitConfigTable(transitConfigTable)
        paloAltoGroupCapacity = transitConfig['PaGroupMaxVpc']
        if transitConfig:
            subscriberAssumeRoleArn = os.environ['SubscriberAssumeRoleArn']

            # subscriberAssumeRoleArn=event['SubscriberAssumeRoleArn']

            # TransitTaskHandler data event
            transitTaskHandler = {'Action': 'TransitTaskHandler'}

            # Check VPC CIDR Conflicts
            result = checkVpcCidrConflicts(event['queryStringParameters']['VpcCidr'], transitConfig['TransitVpcTable'])
            if result:
                logger.debug(
                    "No VPC Cidr conflict. Ok to get PAGroup Info")
                # Get Available PA-Group
                paGroup = getAvailablePaGroup(transitConfig['TransitPaGroupInfo'], int(transitConfig['PaGroupMaxVpc']))
                if paGroup:
                    logger.info(
                        "Got PaGroup Details {} , hence proceeding to get available VGW ASN Number ".format(paGroup))
                    # Get Available VgwAsn Number
                    vgwAsnNumber = getAvailableVgwAsn(transitConfig['TransitVgwAsn'], event)
                    logger.info(
                        "Got vgwAsnNumber {}  ".format(vgwAsnNumber))
                    if vgwAsnNumber:
                        logger.info(
                            "Got vgwAsnNumber={}, hence proceeding to get available BgpIpPool Cidr ranges".format(
                                vgwAsnNumber))
                        # Get Available Tunnel IP Pool Ranges
                        bgpIpPool = getAvailableBgpTunnelIpPool(transitConfig['TransitBgpTunnelIpPool'],
                                                                event['queryStringParameters']['VpcId'],
                                                                paGroup['PaGroupName'])
                        if bgpIpPool:
                            logger.info("Got bgpIpPool={}, hence proceeding  ".format(bgpIpPool))

                            # Update VpcTable with VpcId, VpcCidr and SubsriberSnsArn
                            if not dryrun:
                                updateVpcTable(transitConfig['TransitVpcTable'], event, paGroup['PaGroupName'])


                                data10 = {
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
                                    "Region": region
                                }
                                data11 = {
                                    'Result': 'Success',
                                    'VpcId': event['queryStringParameters']['VpcId'],
                                    'VpcCidr': event['queryStringParameters']['VpcCidr'],
                                    'paGroup': 'paGroup',
                                    'VgwAsn': str(vgwAsnNumber),
                                    'BGP Pool': bgpIpPool,
                                    'Region': 'Region',
                                }
                                logger.info('Created data object {}'.format(data10))
                                publishToSns(apicreatevgwSnsArn, data10, subscriberAssumeRoleArn)
                                apioutput = response(data11, 200)
                                logger.info(
                                    "Updated VpcTable: {} with : {}".format(transitConfig['TransitVpcTable'], event))
                                logger.info("Requesting VGW creation with parameters {}, hence proceeding  ".format(apioutput))
                                return apioutput


                            # return transitTaskHandler
                            if dryrun:
                                bgpIpPoolStr = json.dumps(bgpIpPool)
                                logger.info('Creating data object')
                                data = {
                                    'Result': 'Success',
                                    'VpcId': event['queryStringParameters']['VpcId'],
                                    'VpcCidr': event['queryStringParameters']['VpcCidr'],
                                    'PaGroupName': paGroup['PaGroupName'],
                                    'VgwAsn': str(vgwAsnNumber),
                                    'BGP Pool': bgpIpPoolStr
                                }
                                logger.info('Created data object {} in dryrun'.format(data))
                                apioutput = response(data, 200)
                                logger.info("Sending response={}, hence proceeding  ".format(apioutput))
                                return apioutput


                        else:
                            logger.error("BgpTunnelIpPools are exausted, hence exiting from setup")
                            data1 = {
                                'Result': 'Failed',
                                'Reason': 'BgpTunnelIpPools are exausted, hence exiting from setup'
                            }
                            apioutput = response(data1, 200)
                            logger.info("Sending response={}, hence proceeding  ".format(apioutput))
                            return apioutput
                            sys.exit(0)
                    else:
                        logger.error("VgwAsns are exausted, hence exiting from setup")
                        data2 = {
                            'Result': 'Failed',
                            'Reason': 'VgwAsns are exausted, hence exiting from setup'
                        }
                        apioutput = response(data2, 200)
                        logger.info("Sending response={}, hence proceeding  ".format(apioutput))
                        return apioutput
                        sys.exit(0)
                else:
                    # Launch CFT to spin up new PA-Group
                    # Update the PaGroupInfo table with PaGroup, N1Asn, N2Asn, InUse, N1Mgmt, N2Mgmt, N1Eip, N2Eip, VpcCount
                    data3 = {
                        'Result': 'Failed',
                        'Reason': 'No Firewalls found'
                    }
                    apioutput = response(data3, 200)
                    logger.info("Sending response={}, hence proceeding  ".format(apioutput))
                    return apioutput
                    sys.exit(0)

            else:
                logger.info("Conflicts with VPC CIDR, NewVpcId={}".format(
                    event['queryStringParameters']['VpcId']))
                data4 = {
                    'Result': 'Failed',
                    'Reason': 'Conflicts with Existing VPC CIDR Block'
                }
                apioutput = response(data4, 200)
                logger.info("Sending response={}, hence proceeding  ".format(apioutput))
                return apioutput

        else:
            logger.error("Not Received any data from TransitConfig table")



    except Exception as e:
        logger.error("Error: {}".format(str(e)))