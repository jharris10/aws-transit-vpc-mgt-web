import sys, os
import boto3
import pan_vpn_generic
from boto3.dynamodb.conditions import Key, Attr
import logging
from commonLambdaFunctions import fetchFromTransitConfigTable, publishToSns, sendToQueue

logger = logging.getLogger()
logger.setLevel(logging.INFO)

transitConfigTable = os.environ['transitConfigTable']
region = os.environ['Region']

def updatePaGroup(tableName, paGroup):
    """Updates the Transit PaGroupInfo table attribute InUse=YES by specifying the PaGroupName
    """
    try:
        dynamodb=boto3.resource('dynamodb',)
        table = dynamodb.Table(tableName)
        table.update_item(Key={'PaGroupName':paGroup},AttributeUpdates={'InUse':{'Value':'YES','Action':'PUT'}})
        logger.info("Successfully Updated PaGroupInfoTable attributes InUse=YES")
    except Exception as e:
        logger.error("Error from updatePaGroup, Faild to update table with: {}, Error: {}".format(data,str(e)))
    
def getPaGroupAndAsns(tableName):
    """Returns an Item from Transit PaGroupInfo table by filtering the table with InUse attribute value to NO
    """
    try:
        dynamodb=boto3.resource('dynamodb',region_name=region)
        table = dynamodb.Table(tableName)
        response=table.scan(FilterExpression=Attr('InUse').eq('NO'))['Items']
        if response:
            updatePaGroup(tableName, response[0]['PaGroupName'])
            return response[0]
        else:
            logger.error("No PaGroups available, Error: {}".format(str(e)))
            sys.exit(0)
    except Exception as e:
        logger.error("Error from updatePaGroup, Error: {}".format(str(e)))    
        
def httpresponse(message, status_code):
    return {
        'statusCode': str(status_code),
        'body': json.dumps(message),
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
    }        
        
def lambda_handler(event,context):
    if 'queryStringParameters' in event.keys():
        event = event['queryStringParameters']
        
    logger.info("Got Event: {}".format(event))
    config = fetchFromTransitConfigTable(transitConfigTable)
    logger.info("TransitConfig Data: {}".format(config))
    if config:
        paGroupTable = config['TransitPaGroupInfo']
        #Get the ANS number for Node1 and Node2
        result = getPaGroupAndAsns(paGroupTable)
        response = pan_vpn_generic.createNewPaGroup(region, result['PaGroupName'],config['PaGroupTemplateUrl'],result['PaGroupName'],config['SshKeyName'],config['TransitVpcMgmtAz1SubnetId'],config['TransitVpcMgmtAz2SubnetId'],config['TransitVpcDmzAz1SubnetId'],config['TransitVpcDmzAz2SubnetId'],config['TransitVpcTrustedSecurityGroupId'],config['TransitVpcUntrustedSecurityGroupId'],config['PaGroupInstanceProfileName'],config['PaBootstrapBucketName'], str(result['N1Asn']), str(result['N2Asn']), config['TransitVpcDmzAz1SubnetGateway'], config['TransitVpcDmzAz2SubnetGateway'])
        response['Region']=region
        response['StackName']=result['PaGroupName']
        logger.info("Sending Data {} to checkStackStaus() function".format(response))
        
        apioutput = httpresponse(response, 200)
        return apioutput
        
        #return response  
    else:
        logger.error("Not Received any data from TransitConfig table")
        return
