#!/usr/bin/python3

import boto3
import csv
import os
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--profile", help="specify aws profile to use")

# Logical groupings
parser.add_argument("--compute", type=bool, default=False, help="True enables counting compute resources")
parser.add_argument("--network", type=bool, default=False, help="True enables counting network resources")
parser.add_argument("--paas", type=bool, default=False, help="True enables counting paas resources")
parser.add_argument("--security", type=bool, default=False, help="True enables counting security resources")
parser.add_argument("--storage", type=bool, default=False, help="True enables counting storage resources")

# Specific api intensive modules
parser.add_argument("--s3Objects", type=bool, default=False, help="True enables counting s3 objects, default = false")
parser.add_argument("--sgRules", type=bool, default=False, help="True enables counting sg rules, default = false")
parser.add_argument("--naclRules", type=bool, default=False, help="True enables counting nacl rules, default = false")

args = parser.parse_args()
profile = args.profile


# COMPUTE
def aws_compute(regions):
    "This kicks off all compute inventory functions"
    aws_inventory["ec2_instances"]             = ec2_instances(regions)
    aws_inventory["ecs_clusters"]              = ecs_clusters(regions)
    aws_inventory["auto_scaling_groups"]       = auto_scaling_groups(regions)
    aws_inventory["lambda_functions"]          = lambda_functions(regions)
    aws_inventory["elastic_loadbalancers"]     = elastic_loadbalancers(regions)
    aws_inventory["application_loadbalancers"] = application_loadbalancers(regions)

def ec2_instances(regions):
    "This prints out count of ec2 instances on an account"
    i = 0
    for region in regions:
        try:
            j = sum(1 for _ in boto3.session.Session(profile_name=profile,region_name=region).resource('ec2').instances.filter(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]))
            i += j
            print("ec2.instances.{}:".format(region),j)
        except:
            print("ec2.instances.{}: none")
    return i

def ecs_clusters(regions):
    "Prints out a count of clusters"
    i = 0
    for region in regions:
        try:
            j = len(boto3.session.Session(profile_name=profile,region_name=region).client('ecs').list_clusters()["clusterArns"])
            i += j
            print("ecs.clusters.{}:".format(region),j)
        except:
            print("ecs.clusters.{}: unsupported".format(region))
    return i

def auto_scaling_groups(regions):
    "Prints out a count of autoscale groups"
    i = 0
    for region in regions:
        try:
            j = len(boto3.session.Session(profile_name=profile,region_name=region).client('autoscaling').describe_auto_scaling_groups()["AutoScalingGroups"])
            i += j
            print("asg.groups.{}:".format(region),j)
        except:
            print("asg.groups.{}: none".format(region))
    return i

def lambda_functions(regions):
    "Prints count of lambda functions"
    i = 0
    for region in regions:
        try:
            j = len(boto3.session.Session(profile_name=profile,region_name=region).client('lambda').list_functions()["Functions"])
            i += j
            print("lambda.functions.{}:".format(region),j)
        except:
            print("lambda.functions.{}: unsupported".format(region))
    return i

def elastic_loadbalancers(regions):
    "Prints count of classic elb"
    i = 0
    for region in regions:
        try:
            j = len(boto3.session.Session(profile_name=profile,region_name=region).client('elb').describe_load_balancers()["LoadBalancerDescriptions"])
            i += j
            print("elb.{}:".format(region),j)
        except:
            print("elb.{}: unsupported".format(region))
    return i

def application_loadbalancers(regions):
    "Prints count of alb"
    i = 0
    for region in regions:
        try:
            j = len(boto3.session.Session(profile_name=profile,region_name=region).client('elbv2').describe_load_balancers()["LoadBalancers"])
            i += j
            print("alb.{}:".format(region),j)
        except:
            print("alb.{}: unsupported".format(region))
    return i


# NETWORK
def aws_network(regions):
    "This kicks off all network inventory functions"
    aws_inventory["vpcs"] =         vpcs(regions)
    aws_inventory["vpns"] =         vpns(regions)
    aws_inventory["route_tables"] = route_tables(regions)
    aws_inventory["subnets"] =      subnets(regions)

def vpcs(regions):
    "Prints count of vpcs"
    i = 0
    for region in regions:
        try:
            j = len(boto3.session.Session(profile_name=profile,region_name=region).client('ec2').describe_vpcs()["Vpcs"])
            i += j
            print("vpc.{}:".format(region),j)
        except:
            print("vpc.{}: unsupported".format(region))
    return i

def vpns(regions):
    "Prints count of vpns"
    i = 0
    for region in regions:
        try:
            j = len(boto3.session.Session(profile_name=profile,region_name=region).client('ec2').describe_vpn_connections()["VpnConnections"])
            i += j
            print("vpn.{}:".format(region),j)
        except:
            print("vpn.{}: unsupported".format(region))
    return i

def route_tables(regions):
    "Prints count of route tables"
    i = 0
    for region in regions:
        try:
            j = len(boto3.session.Session(profile_name=profile,region_name=region).client('ec2').describe_route_tables()["RouteTables"])
            i += j
            print("route_tables.{}:".format(region),j)
        except:
            print("route_tables.{}: unsupported".format(region))
    return i

def subnets(regions):
    "Prints count of subnets"
    i = 0
    for region in regions:
        try:
            j = len(boto3.session.Session(profile_name=profile,region_name=region).client('ec2').describe_subnets()["Subnets"])
            i += j
            print("subnets.{}:".format(region),j)
        except:
            print("subnets.{}: unsupported".format(region))
    return i


# PAAS
def aws_paas(regions):
    "This kicks off all paas inventory functions"
    aws_inventory["cf_distributions"] = cf_distributions()
    aws_inventory["elastic_search"] = elastic_search()
    aws_inventory["aurora_clusters"] = aurora_clusters()
    aws_inventory["rds_instances"] = rds_instances(regions)
    aws_inventory["dynamo_db"] = dynamo_db()

def cf_distributions():
    "Prints count of cloudfront distributions"
    j = 0
    try:
        j = len(boto3.session.Session(profile_name=profile).client('cloudfront').list_distributions()["DistributionList"]["Items"])
        print("cf_distributions:",j)
    except:
        print("cf_distributions: unsupported")
    return j

def elastic_search():
    "Prints count of elastic search clusters"
    j = 0
    try:
        j = len(boto3.session.Session(profile_name=profile).client('es').list_domain_names()["DomainNames"])
        print("es.clusters:",j)
    except:
        print("es.clusters: unsupported")
    return j

def aurora_clusters():
    "Prints count of aurora clusters"
    j = 0
    try:
        j = len(boto3.session.Session(profile_name=profile).client('rds').describe_db_clusters()["DBClusters"])
        print("rds.aurora.clusters:",j)
    except:
        print("rds.aurora.clusters: unsupported")
    return j

def rds_instances(regions):
    "Prints count of rds instances"
    i = 0
    for region in regions:
        try:
            j = len(boto3.session.Session(profile_name=profile,region_name=region).client('rds').describe_db_instances()["DBInstances"])
            i += j
            print("rds.instances.{}:".format(region),j)
        except:
            print("rds.instances.{}: unsupported".format(region))
    return i

def dynamo_db():
    "Prints count of dynamo databases"
    j = 0
    try:
        j = len(boto3.session.Session(profile_name=profile).client('dynamodb').list_tables()["TableNames"])
        print("dynamodb.tables:",j)
    except:
        print("dynamodb.tables: unsupported")
    return j


# SECURITY
def aws_security(regions):
    "This kicks off all security inventory functions"
    aws_inventory["security_groups"]          = security_groups(regions)
    if args.sgRules:
        aws_inventory["security_group_rules"] = security_group_rules(regions)
    aws_inventory["nacls"]                    = nacls(regions)
    if args.naclRules:
        aws_inventory["nacl_rules"]           = nacl_rules(regions)
    aws_inventory["wafs"]                     = wafs(regions)

def security_groups(regions):
    "Prints count of security groups"
    i = 0
    for region in regions:
        try:
            j = len(boto3.session.Session(profile_name=profile,region_name=region).client('ec2').describe_security_groups()["SecurityGroups"])
            i += j
            print("sg.{}:".format(region),j)
        except:
            print("sg.{}: unsupported".format(region))
    return i

def security_group_rules(regions):
    "Prints count of security groups"
    i = 0
    for region in regions:
        try:
            response = boto3.session.Session(profile_name=profile,region_name=region).client('ec2').describe_security_groups()
            j = 0
            for sg in response["SecurityGroups"]:
                j += (len(sg["IpPermissions"]) + len(sg["IpPermissionsEgress"]))
            i += j
            print("sg.rules.{}:".format(region),j)
        except:
            print("sg.rules.{}: unsupported".format(region))
    return i

def nacls(regions):
    "Prints count of nacls"
    i = 0
    for region in regions:
        try:
            j = len(boto3.session.Session(profile_name=profile,region_name=region).client('ec2').describe_network_acls()["NetworkAcls"])
            i += j
            print("nacl.{}:".format(region),j)
        except:
            print("nacl.{}: unsupported".format(region))
    return i

def nacl_rules(regions):
    "Prints count of security groups"
    i = 0
    for region in regions:
        try:
            response = boto3.session.Session(profile_name=profile,region_name=region).client('ec2').describe_network_acls()
            j = 0
            for nacl in response["NetworkAcls"]:
                j += len(nacl["Entries"])
            i += j
            print("nacl.rules.{}:".format(region),j)
        except:
            print("nacl.rules.{}: unsupported".format(region))
    return i

def wafs(regions):
    "Prints count of wafs"
    i = 0
    for region in regions:
        try:
            j = len(boto3.session.Session(profile_name=profile,region_name=region).client('waf').list_web_acls()["WebACLs"])
            i += j
            print("waf.{}:".format(region),j)
        except:
            print("waf.{}: unsupported".format(region))
    return i


# STORAGE
def aws_storage(regions):
    "This kicks off all storage inventory functions"
    aws_inventory["ebs_volumes"]     = ebs_volumes(regions)
    aws_inventory["efs_filesystems"] = efs_filesystems()
    aws_inventory["s3_buckets"]      = s3_buckets()
    if args.s3Objects:
        aws_inventory["s3_objects"]  = s3_objects()

def ebs_volumes(regions):
    "Prints count of ebs volumes"
    i = 0
    try:
        for region in regions:
            ec2volumes = boto3.session.Session(profile_name=profile,region_name=region).client('ec2').describe_volumes().get('Volumes',[])
            j = len(sum(
                [
                    [i for i in r['Attachments']]
                    for r in ec2volumes
                ], []))
            i += j
            print("ebs.volumes.{}:".format(region),j)
    except:
        print("ebs.volumes.{}: none".format(region))
    return i

def efs_filesystems():
    "This prints count of efs file systems on account"
    i = 0
    try:
        j = len(boto3.session.Session(profile_name=profile).client('efs').describe_file_systems()['FileSystems'])
        i += j
        print("efs.filesystem.count:",j)
    except:
        print("efs.filesystem.count: none")
    return i

def s3_buckets():
    "This prints a count of buckets on an account"
    i = 0
    try:
        j = len(boto3.session.Session(profile_name=profile).client('s3').list_buckets()["Buckets"])
        i += j
        print("s3.bucket.count:",j)
    except:
        print("s3.bucket.count: none")
    return i

def s3_objects():
    "This prints object counts for all buckets of account"
    i = 0
    for bucket_name in boto3.session.Session(profile_name=profile).client('s3').list_buckets()["Buckets"]:
        try:
            j = sum(1 for _ in boto3.session.Session(profile_name=profile).resource('s3').Bucket(bucket_name["Name"]).objects.all())
            i += j
            print("s3.bucket.{}.objects:".format(bucket_name["Name"]),j)
        except:
            print("s3.bucket.{}.objects: none".format(bucket_name["Name"]))
    return i


# If ran directly this will start everything
if __name__ == '__main__':
    regions = [region['RegionName'] for region in boto3.session.Session(profile_name=profile).client('ec2').describe_regions()['Regions']]
    aws_inventory = dict([])

    # Run components by logical group
    if args.compute:
        aws_compute(regions)
    if args.network:
        aws_network(regions)
    if args.paas:
        aws_paas(regions)
    if args.security:
        aws_security(regions)
    if args.storage:
        aws_storage(regions)

    print(aws_inventory)
