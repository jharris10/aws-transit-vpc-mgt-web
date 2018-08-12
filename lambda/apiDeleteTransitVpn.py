import json
import logging
import os

import boto3
import pan_vpn_generic
import sys
import traceback
from boto3.dynamodb.conditions import Key, Attr
from commonLambdaFunctions import fetchFromTransitConfigTable, publishToSns
from secretsmanager import get_secret

logger = logging.getLogger()
logger.setLevel(logging.INFO)

transitConfigTable = os.environ['transitConfigTable']
region = os.environ['Region']

'''
Input:
{
  "VpcId": "vpc-a8185fce",
  "VgwAsn": "64603"
}

Ouput:
{
        'Result'                    : 'Success / Failure',
        'Reason'                             : 'Text string describing failure'
}
'''


def deleteItemFromVpcTable(tableName, vpcId):
    """Deletes an Item from Transit VpcTable by specifying the VpcId key
    """
    try:
        dynamodb = boto3.resource('dynamodb', region_name=region)
        table = dynamodb.Table(tableName)
        table.delete_item(Key={'VpcId': vpcId})
        logger.info("Successfully Deleted Item  with vpc-id: {} from TransitVpcTable".format(vpcId))
    except Exception as e:
        logger.error("Error from deleteItemFromVpcTable, Error: {}".format(str(e)))


def updateVgwAsn(tableName, vgwAsn):
    """Updates Transit VgwAsn table attribute "InUse=NO"
    """
    try:
        dynamodb = boto3.resource('dynamodb', region_name=region)
        logger.info("VgwAsn TableName: {}, and typeofVgwAsn: {}".format(tableName, type(vgwAsn)))
        table = dynamodb.Table(tableName)
        # response = table.query(KeyConditionExpression=Key('VgwAsn').eq(str(vgwAsn)))['Items']
        #
        #   Use table scan instead of Query as the VpcId is not a key in the table
        response = table.scan(FilterExpression=Attr('VpcId').eq(VpcId))['Items']
        #    Response returns a list 
        #
        if response:
            entry = response[0]
            VgwAsn = entry['VgwAsn']
            item = {'VgwAsn': str(vgwAsn), 'InUse': 'NO'}
            table.put_item(Item=item)
            logger.info("Successfully updated VgwAsn: {}, InUse=NO".format(vgwAsn))
    except Exception as e:
        logger.error("Error from updateVgwAsn(), Error: {}".format(str(e)))
        # If the VGW was created by customer manually, we dont have that VgwAsn enrty in Transit VgwAsn table, hence we are throwing the error and proccedind
        pass


def updatePaGroupInfoTable(tableName, paGroupName):
    """Updates the Transit PaGroupInfo table  attribute VpcCount value to decremented by 1 (-1) by querying the table with PaGroupName
    """
    try:
        dynamodb = boto3.resource('dynamodb', region_name=region)
        table = dynamodb.Table(tableName)
        response = table.query(KeyConditionExpression=Key('PaGroupName').eq(paGroupName))['Items']
        logger.info("Got response {} to table query for table {}".format(response, tableName))
        if response:
            if response[0]['VpcCount'] > 0:
                table.update_item(Key={'PaGroupName': paGroupName},
                                  AttributeUpdates={'VpcCount': {'Value': -1, 'Action': 'ADD'}})
                logger.info("Successfully decremented PaGroup: {} VpcCount to -1".format(paGroupName))
    except Exception as e:
        logger.error("Error from updatePaGroupInfoTable, Error: {}".format(str(e)))


def updateBgpTunnleIpPool(tableName, vpcId):
    """Updates the Transit BgpTunnleIpPool attributes Available=YES, VpcId=Null and PaGroupName=Null
    """
    try:
        dynamodb = boto3.resource('dynamodb', region_name=region)
        table = dynamodb.Table(tableName)
        response = table.scan(FilterExpression=Attr('VpcId').eq(vpcId))
        logger.info("Got response {} to table scan for table {}".format(response, tableName))
        LastEvaluatedKey = True
        while LastEvaluatedKey:
            for item in response['Items']:
                if 'VpcId' in item:
                    if item['VpcId'] == vpcId:
                        table.update_item(Key={'IpSegment': item['IpSegment']},
                                          AttributeUpdates={'Available': {'Value': 'YES', 'Action': 'PUT'},
                                                            'VpcId': {'Value': 'Null', 'Action': 'PUT'},
                                                            'PaGroupName': {'Value': 'Null', 'Action': 'PUT'}})
                        logger.info(
                            "Successfully updated IpSegment: {} attriburte Available to YES, and VpcId & PaGroup to Null".format(
                                item['IpSegment']))
                        return
            if 'LastEvaluatedKey' in response:
                response = table.scan(FilterExpression=Attr('VpcId').eq(vpcId),
                                      ExclusiveStartKey=response['LastEvaluatedKey'])
            else:
                LastEvaluatedKey = False
    except Exception as e:
        logger.error("Error from updateBgpTunnleIpPool, Error: {}".format(str(e)))


def getItemFromVpcTable(tableName, vpcId):
    """Returns an Item from Transit VpcTable by querying the table with VpcId key
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


def getItemFromPaGroupInfo(tableName, paGroupName):
    """Returns an Item from PaGroupInfo table by querying the table with PaGroupName key
    """
    try:
        dynamodb = boto3.resource('dynamodb', region_name=region)
        table = dynamodb.Table(tableName)
        response = table.query(KeyConditionExpression=Key('PaGroupName').eq(paGroupName))
        if response['Items']:
            return response['Items'][0]
        else:
            logger.info("No Items matched with the GropuName: {}".format(paGroupName))
            return False
    except Exception as e:
        logger.error("Error from getItemFromPaGroupInfo, Error: {}".format(str(e)))


def response(message, status_code):
    return {
        'statusCode': str(status_code),
        'body': json.dumps(message),
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
    }


def lambda_handler(event, context):
    if 'queryStringParameters' in event.keys():
        event = event['queryStringParameters']
    logger.info("Got Event: {}".format(event))
    try:
        config = fetchFromTransitConfigTable(transitConfigTable)
        creds = get_secret()
        username = list(creds.keys())[0]
        password = creds[login]
        logger.info("Got config: {}".format(config))
        if config:
            # deleteVpnConfigurationFromPaGroup() this will be from pan_vpn_generic file
            vpcResult = getItemFromVpcTable(config['TransitVpcTable'], event['VpcId'])
            logger.info("Got vpcResult from {} table {}".format(vpcResult, config['TransitVpcTable']))
            if vpcResult:
                paGroupResult = getItemFromPaGroupInfo(config['TransitPaGroupInfo'], vpcResult['PaGroupName'])
                logger.info('Got paGroupResult {} from {}'.format(paGroupResult, config['TransitPaGroupInfo']))
                if paGroupResult:
                    api_key = pan_vpn_generic.getApiKey(paGroupResult['N1Mgmt'], username, password)
                    logger.info('Got apikey ')
                    # Deleting the VPN connections with the PA Group
                    logger.info('Calling paGroupDeleteVpn with {} {} {}'.format(paGroupResult, vpcResult['Node1VpnId'],
                                                                                vpcResult['Node2VpnId']))
                    pan_vpn_generic.paGroupDeleteVpn(api_key, paGroupResult, vpcResult['Node1VpnId'],
                                                     vpcResult['Node2VpnId'])
                    logger.info("Successfully deleted VPN connections VPN1: {}, VPN2: {} with PaGroup: {} ".format(
                        vpcResult['Node1VpnId'], vpcResult['Node2VpnId'], paGroupResult['PaGroupName']))
                    # Delete Item from TransitVpcTable with
                    res = deleteItemFromVpcTable(config['TransitVpcTable'], event['VpcId'])
                    logger.info('Deleted Item from table {}'.format(config['TransitVpcTable']))
                    updatePaGroupInfoTable(config['TransitPaGroupInfo'], vpcResult['PaGroupName'])

                    updateBgpTunnleIpPool(config['TransitBgpTunnelIpPool'], event['VpcId'])
                    if 'VgwAsn' in event:
                        updateVgwAsn(config['TransitVgwAsn'], event['VgwAsn'])
                        logger.info('Deleted VgwAsn from table {}'.format(config['TransitVgwAsn']))
                    data1 = {
                        'Result': 'Success',
                        'Reason': 'Updated deleted the VPN and updated the tables' + config['TransitVpcTable']
                    }
                    apioutput = response(data1, 200)
                    logger.info("Sending response={}, hence proceeding  ".format(apioutput))
                    return apioutput
                else:
                    logger.info("Sending response={}, hence proceeding  ".format(apioutput))
                    data2 = {
                        'Result': 'Success',
                        'Reason': 'No Items matched with the GroupName: {}' + vpcResult['PaGroupName']
                    }
                    apioutput = response(data2, 200)
                    return apioutput
            else:
                data3 = {
                    'Result': 'Failure',
                    'Reason': "No Item matched with VpcId {}".format(event['VpcId'])
                }
                apioutput = response(data3, 200)
                return apioutput
        else:
            logger.error("Not Received any data from TransitConfig table")
    except Exception as e:
        logger.error("Error from deleteTransitVpnConfiguration, Error: {}".format(str(e)))
