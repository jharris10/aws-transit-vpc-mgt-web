## apiCreateVgw:
  * Receives input parameters via Http get method
  * Input VpcId, Cidr Block of VPC, Region and DryRun = YES/NO
  * If YES then the function will perform checks but not write any values to the databases  
  * Checks for Vpc Cidr conflicts, if no conflicts proceed else exit
  * Checks for Available VGW Asns, if available proceed else exit 
  * Checks for Available PA Groups, if PA Groups are not present else exit 
  * Checks for Available BgpTunnelIpPools, if available proceed else exit 
  * If something fails in the above process, it will send a http 200 response with 'Response' : 'Failed'
  * If dryrun == True performs the following table updates.  If dryrun false skips the table updates
  * Updates the Transit-PaGroupInfo table with N1Eip, N1Mgmt, N1Pip, N2Eip, N2Mgmt, N2Pip, StackRegion
  * Updates the Transit-BgpTunnelIpPools with Available=NO, VpcId and PaGroupName
  * Updates the Transit-VgwAsn table with InUse=YES, VpcCidr, and VpcId
  * If the above checks pass, it will send a http 200 response with 'Response' : 'Success' 
  {
	"Result": "Success",
	"VpcId": event['queryStringParameters']['VpcId'],
	"VpcCidr": event['queryStringParameters']['VpcCidr'],
	"PaGroupName": paGroup['PaGroupName'],
	"VgwAsn": str(vgwAsnNumber),
	"BGP Pool": bgpIpPool,
	"Region": 'Region',
  }
  * Sends SNS message to apiAsynCreateVGW
  * When the browser receives the above 200 response it will monitor VGW creation via ## checkvgwstatus
  {
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
	"Region": region,
	"messagefileName": messagefileName
   }
      
## apiAsynCreateVGW:
  * Receives SNS event from apiCreateVGW
  * It will create VGW, CGW1, CGW2 if they are not created before and, creates VPN1 and VPN2
  * Updates the Subscriber LocalDB with VGW, CGW1, CGW2, VPN1 and VPN2
  * Updates Subscriber VpcVpnTable with VPNId, VPCId and PaGroup
    
## apiCreateTransitVpn:
  * It will create the VPN connections with the PA Group servers
  * Checks for the status of the VPN connections, if the connections failed sends a http 200 response to browser 
      * update the Transit-PaGroupInfo table VpcCount to -1
      * update the Transit-VpcVpnTable status to Failed
      * update the Transit-BgpTunnelIpPools table with Available=YES
  * If the VPN connections are established, it will update Transit PaGroupInfo table with VpcCount +1
      * update the Transit-PaGroupInfo table VpcCount to +1
      * update the Transit VpcTable with VpcId, CurrentStatus, IpSegment, Node1VpnId, Node2VpnId, PaGroupName, Region, SubscriberAssumeRoleArn, SubscriberSnsArn, VpcCidr, vpc-xxxxx

## apiDeleteTransitVpn:
  * Deletes the VPN connections with the PA Servers
  * Updates the Transit-PaGroupInfo table with VpcCount to -1
  * Updates the Transit-BgpTunnelIpPools table with Available= YES
  * Deletes entry from Transit-VpcTable
  
## apiDeleteSubsVpn:
  * Deletes two vpn connections associated with the VPC
  * Deletes the entry from the Subscriber Local DB which has the deteted VPN connections
  * Deletes VPN entries from the Subscriber VpcVpnTable
  