# NOTE: THIS FUNCTION IS SUPPOSED TO DENY EGRESS TRAFFIC TO SPECIFIC IPS WITH NACLS
# NOTE: IDK KNOW MUCH ABOUT THAT, BUT OBVIOUSLY WE GOTTA GET IT TOGETHER
# NOTE: DO YOUR THING TO FIX THE CODE SO THAT EVERYTIME GUARDDOG FINDS A BAD IP WE CAN MAKE SURE OUR UNICORNMGMTSYSTEM0 IS HEALTHY. 
# NOTE: https://www.youtube.com/watch?v=OFr74zI1LBM

import boto3
import os 

ec2 = boto3.client('ec2')

def lambda_handler(event, context):
    
    # List of Network ACLs where the Name is HostACL
    
    nacls = ec2.describe_network_acls(
        Filters = [
        {
            'Name': 'tag:Name',
            'Values': [
                'UnicornMgmtSystem0NACL',
            ]
        }
    ])
    
    ## Get the Network ACL ID
    
    UnicornMgmtSystem0NACL = nacls['NetworkAcls'][0]['NetworkAclId']
    
    # We have to make sure that the rule numbers don't conflict for the NACL Entries
    
    ## Initializing a list with the starter value of 100
    rules = [100]
    
    ### For loop that pulls the Rule Number for each NACL entry
    
    for item in nacls['NetworkAcls'][0]['Entries']:
        if item['RuleNumber'] not in rules:
            rules.append(item['RuleNumber'])
            rules.sort()
    
    # Get The IP you're tring to block from the event

    IPtoBlock = event['detail']['service']['action']['networkConnectionAction']['remoteIpDetails']['ipAddressV4'] ### INDEX INTO THE 'ipAddressV4'

    IPtoBlockCIDR = '{}/32'.format(IPtoBlock)

    newrulenumber = rules[0] - 1
    # Create a new NACL entry. 
    # Error handling (default soft limit for NACL rules is 20) 
    if len(rules) > 20:
        rules.pop()
        for rule in rules:
            response = ec2.delete_network_acl_entry(
            Egress=True,
            NetworkAclId=UnicornMgmtSystem0NACL,
            RuleNumber=rule
        )
        response = ec2.create_network_acl_entry(
            CidrBlock=IPtoBlockCIDR,
            Egress=True,
            NetworkAclId=UnicornMgmtSystem0NACL,
            Protocol='-1',
            RuleAction='deny',
            RuleNumber=(newrulenumber)
        )
    else: 
        response = ec2.create_network_acl_entry(
            CidrBlock=IPtoBlockCIDR,
            Egress=True,
            NetworkAclId=UnicornMgmtSystem0NACL,
            Protocol='-1',
            RuleAction='deny',
            RuleNumber=(newrulenumber)
        )
    
    print("Rule {} added to NACL:{}. DENY ALL outbound traffic to {}".format(newrulenumber, UnicornMgmtSystem0NACL, IPtoBlock))
