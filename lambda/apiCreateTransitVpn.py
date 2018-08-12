import boto3
from boto3.dynamodb.conditions import Key, Attr
import logging, os
from commonLambdaFunctions import publishToSns, fetchFromTransitConfigTable
import pan_vpn_generic
import json
from secretsmanager import get_secret
logger = logging.getLogger()
logger.setLevel(logging.INFO)

'''
data = {
                #         'Action': 'ConfigureTransitVpn',
                #         'PaGroupName': paGroup['PaGroupName'],
                #         'IpSegment': bgpIpPool['IpSegment'],
                #         'VpnN1': vpnId1,
                #         'VpnN2': vpnId2,
                #         'VgwAsn': str(vgwAsnNumber),
                #         'VpcId': input['VpcId'],
                #         'Region': input1['Region'],
                #         #'Rebalance': event['Rebalance'],
                #         'TransitVpnBucketName': event['TransitVpnBucketName'],
                #         'SubscriberSnsArn': subscriberConfig['SubscriberSnsArn'],
                #         'SubscriberAssumeRoleArn': subscriberConfig['SubscriberAssumeRoleArn']

Input:
{
    'Action': 'ConfigureTransitVpn',
    'PaGroupName': event['PaGroupName'],
    'IpSegment': event['IpSegment'],
    'VpnN1': vpnId1,
    'VpnN2': vpnId2,
    'VpcId': event['VpcId'],
    'Region': event['Region'],
    'TransitVpnBucketName': event['TransitVpnBucketName'],
    'SubscriberSnsArn': subscriberConfig['SubscriberSnsArn'],
    'SubscriberAssumeRoleArn': subscriberConfig['SubscriberAssumeRoleArn']
}

'''
#region = 'us-east-1'
transitConfigTable = os.environ['transitConfigTable']
region = os.environ['Region']
secretName = os.environ['secretName']
endpointUrl = os.environ['endpointUrl']



dynamodb = boto3.resource('dynamodb', region_name=region)


#transitConfigTable="TransitConfig"

def updateVpcTable(tableName,data,status):
    """Updates the Transit VpcTable with VpcId, Node1VpnId, Node2VpnId, Region, IpSegment and CurrentStatus
    """
    try:
        #VpcId is the primary key for VpcTable
        table=dynamodb.Table(tableName)
        response=table.update_item(Key={'VpcId':data['VpcId']},AttributeUpdates={'CurrentStatus':{'Value':status,'Action':'PUT'},'Node1VpnId':{'Value':data['VpnN1'],'Action':'PUT'},'Node2VpnId':{'Value':data['VpnN2'],'Action':'PUT'}, 'Region':{'Value':data['Region'],'Action':'PUT'}, 'IpSegment':{'Value':data['IpSegment'],'Action':'PUT'}})
        logger.info('Updated table {} with '.format(tableName,data['VpnN1'],data['VpnN2'],data['Region'],data['IpSegment']))
    except Exception as e:
        logger.error("Updating Transit VpcTalbe is Failed, Error: {}".format(str(e)))
def updateBgpTunnelIpPool(bgpTableName,ipSegment):
    """updates Transit BgpTunnleIpPool table attribute 'Available=YES'
    """
    try:
        table=dynamodb.Table(bgpTableName)
        #Update BgpTunnelIpPool table Attribute "Available"="YES"
        table.update_item(Key={'IpSegment':ipSegment},AttributeUpdates={'Available':{'Value':'YES','Action':'PUT'}})
        logger.info("Successfully Updated BgpTunnleIpPool Table attribute Available=YES")
    except Exception as e:
        logger.error("Update BgpTunnelIpPool is failed, Error: {}".format(str(e)))
        
def updatePaGroup(paGroupTableName,paGroupName,value):
    """Updates Transit PaGroupInfo table attribute VpcCount to either +1 or -1 based on the value paramater passed to the function
    """
    try:
        table=dynamodb.Table(paGroupTableName)
        response = table.query(KeyConditionExpression=Key('PaGroupName').eq(paGroupName))['Items']
        if response:
            if response[0]['VpcCount']>0:
                table.update_item(Key={'PaGroupName':paGroupName},AttributeUpdates={'InUse':{'Value':'YES','Action':'PUT'},'VpcCount':{'Value':value,'Action':'ADD'}})
                logger.info("Successfully Updated PaGroupInfoTable decremented VpcCount by 1")
    except Exception as e:
        logger.error("updatePaGroupInfo() Table is failed, Error: {}".format(str(e)))

def getPaGroupInfo(tableName,paGroup):
    """Returns the specified Pagroup item from the PaGroupInfo table
    """
    try:
        table=dynamodb.Table(tableName)
        response = table.query(KeyConditionExpression=Key('PaGroupName').eq(paGroup))['Items']
        return response[0]
    except Exception as e:
        logger.error("Fetch Item from PaGroupInfo failed, Error: {}".format(str(e)))

def getItemFromVpcTable(tableName,vpcId):
    """Returns the specified item from VpcTable
    """
    try:
        dynamodb = boto3.resource('dynamodb', region_name=region)
        table = dynamodb.Table(tableName)
        response = table.query(KeyConditionExpression=Key('VpcId').eq(vpcId))
        if response['Items']:
            return response['Items'][0]
        else:
            logger.info("No Item matched with VpcId: {}".format(vpcId))
            return False
    except Exception as e:
        logger.error("Error from getItemFromVpcTable, Error: {}".format(str(e)))

def updateVgwAsn(tableName, vpcId, vgwAsn):
    try:
        dynamodb = boto3.resource('dynamodb', region_name=region)
        table = dynamodb.Table(tableName)
        logger.info("Checking for VgwAsn mis-match in VgwAsn table")
        response = table.scan(FilterExpression=Attr('VpcId').eq(vpcId))
        LastEvaluatedKey = True
        while LastEvaluatedKey:
            for item in response['Items']:
                if 'VpcId' in item:
                    if item['VgwAsn']!=vgwAsn:
                        data = {'VgwAsn':item['VgwAsn'],'InUse':'NO'}
                        table.put_item(Item=data)
                        logger.info("VgwAsn are mis-matched, because user created the VGW and attached it to VPC, hence using the same VGW, updating previously allocated VgwAsn: {} with InUse=NO in Transit VgwAsn table".format(item['VgwAsn']))
                        return
            if 'LastEvaluatedKey' in response:
                response = table.scan(FilterExpression=Attr('VpcId').eq(vpcId),ExclusiveStartKey=response['LastEvaluatedKey'])
            else:
                LastEvaluatedKey = False
    except Exception as e:
        logger.error("Error from updateVgwAsn(), Error: {}".format(str(e)))
        
def downloadFileFromS3(file,bucket):
    #Downloads an object status file from S3 bucket
    #Returns Json list object that is updated
    #
    try:
            s3_client = boto3.client('s3')
            s3_response_object = s3_client.get_object(Bucket=bucket, Key=file)
            object_content = s3_response_object['Body'].read()
            object = json.loads(object_content)
            logger.info('Reading status file with  {}'.format(file))
            return object

    except Exception as e:
        logger.error("Error uploading file to S3 Bucket, Error : %s" % str(e))

def response(message, status_code):
            return{ 
                'statusCode': str(status_code),
                'body': json.dumps(message),
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
            }

def lambda_handler(event,context):
    logger.info("Got Event {}".format(event))
    testparams = event['queryStringParameters']
    logger.info("Got query parameter {}".format(testparams))
    config = fetchFromTransitConfigTable(transitConfigTable)
    filecontents = downloadFileFromS3(event['queryStringParameters']['messagefileName'], config['TransitVpnBucketName'])
    logger.info('Downloaded from S3 object and Result is {} '.format(filecontents))
    creds = get_secret(secretName,endpointUrl,region)
    username = list(creds.keys())[0]
    password = creds[login]

    
    if config:
        paGroupInfo = getPaGroupInfo(config['TransitPaGroupInfo'],filecontents['PaGroupName'])
        if paGroupInfo:
            api_key = pan_vpn_generic.getApiKey(paGroupInfo['N1Mgmt'], username, password)
            logger.info("Got api_key: {}".format(api_key))
            paVpnStatus = pan_vpn_generic.paGroupConfigureVpn(api_key, paGroupInfo, config['TransitVpnBucketName'], filecontents['VpnN1'],filecontents['VpnN2'])
            logger.info("Got paVpnStatus: {}".format(paVpnStatus))
            if paVpnStatus:
                updateVpcTable(config['TransitVpcTable'],filecontents,'Configured')
                logger.info("Updated Table: {}".format(config['TransitVpcTable']))
                updateVgwAsn(config['TransitVgwAsn'],filecontents['VpcId'],filecontents['vgwAsn'])
                logger.info("Updated Table: {}".format(config['TransitVgwAsn']))
                data={
                    'Action': 'VpnConfigured',
                    'VpcId': filecontents['VpcId'],
                    'PaGroupName': filecontents['PaGroupName'],
                    'Region': 'eu-west-1'
                }
                logger.info("Returning data: {}".format(data))

                apioutput = response(data, 200)
                logger.info("Sending response={}, hence proceeding  ".format(apioutput))
                return apioutput
            else:
                updatePaGroup(config['TransitPaGroupInfo'],filecontents['PaGroupName'], -1)
                updateBgpTunnelIpPool(config['TransitBgpTunnelIpPool'],filecontents['IpSegment'])
                updateVpcTable(config['TransitVpcTable'],filecontents,'Failed')
                updateVgwAsn(config['TransitVgwAsn'],filecontents['VpcId'],filecontents['vgwAsn'])
                #Publish Message to SubscriberSns
                data={
                    'Action': 'VpnFailed',
                    'VpcId': filecontents['VpcId'],
                    'Region': filecontents['Region']
                }
                logger.info("Sendig response data: {}".format(data))
                apioutput = response(data, 200)
                logger.info("Sending response={}, hence terminating  ".format(apioutput))
                return apioutput
                
        else:
            logger.error("No Item received from PaGroupInfo table with Key: {}".format(filecontents['PaGroupName']))
    else:
        logger.error("Not Received any data from TransitConfig table")
