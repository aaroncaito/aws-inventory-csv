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
parser.add_argument("--s3objects", type=bool, default=False, help="True enables counting s3 objects, default = false")
parser.add_argument("--sgRules", type=bool, default=False, help="True enables counting sg rules, default = false")
parser.add_argument("--naclRules", type=bool, default=False, help="True enables counting nacl rules, default = false")

args = parser.parse_args()
profile = args.profile


# COMPUTE
def aws_compute(aws,regions):
    "This kicks off all compute inventory functions"
    ec2_instances(aws,regions)
    ecs_clusters(aws,regions)
    auto_scaling_groups(aws,regions)
    lambda_functions(aws,regions)
    elastic_loadbalancers(aws,regions)
    application_loadbalancers(aws,regions)

def ec2_instances(aws,regions):
    "This prints out count of ec2 instances on an account"
    for region in regions:
        try:
            print("ec2.instances.{}:".format(region),sum(1 for _ in boto3.session.Session(profile_name=profile,region_name=region).resource('ec2').instances.filter(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])))
        except:
            print("ec2.instances.{}: none")
    return

def ecs_clusters(aws,regions):
    "Prints out a count of clusters"
    for region in regions:
        try:
            response = boto3.session.Session(profile_name=profile,region_name=region).client('ecs').list_clusters()
            print("ecs.clusters.{}:".format(region),len(response["clusterArns"]))
        except:
            print("ecs.clusters.{}: unsupported".format(region))
    return

def auto_scaling_groups(aws,regions):
    "Prints out a count of autoscale groups"
    for region in regions:
        try:
            response = boto3.session.Session(profile_name=profile,region_name=region).client('autoscaling').describe_auto_scaling_groups()
            print("asg.groups.{}:".format(region), len(response["AutoScalingGroups"]))
        except:
            print("asg.groups.{}: none".format(region))
    return

def lambda_functions(aws,regions):
    "Prints count of lambda functions"
    for region in regions:
        try:
            response = boto3.session.Session(profile_name=profile,region_name=region).client('lambda').list_functions()
            print("lambda.functions.{}:".format(region), len(response["Functions"]))
        except:
            print("lambda.functions.{}: unsupported".format(region))
    return

def elastic_loadbalancers(aws,regions):
    "Prints count of classic elb"
    for region in regions:
        try:
            response = boto3.session.Session(profile_name=profile,region_name=region).client('elb').describe_load_balancers()
            print("elb.{}:".format(region), len(response["LoadBalancerDescriptions"]))
        except:
            print("elb.{}: unsupported".format(region))
    return

def application_loadbalancers(aws,regions):
    "Prints count of alb"
    for region in regions:
        try:
            response = boto3.session.Session(profile_name=profile,region_name=region).client('elbv2').describe_load_balancers()
            print("alb.{}:".format(region), len(response["LoadBalancers"]))
        except:
            print("alb.{}: unsupported".format(region))
    return


# NETWORK
def aws_network(aws,regions):
    "This kicks off all network inventory functions"
    vpcs(aws,regions)
    vpns(aws,regions)
    route_tables(aws,regions)
    subnets(aws,regions)

def vpcs(aws,regions):
    "Prints count of vpcs"
    for region in regions:
        try:
            response = boto3.session.Session(profile_name=profile,region_name=region).client('ec2').describe_vpcs()
            print("vpc.{}:".format(region), len(response["Vpcs"]))
        except:
            print("vpc.{}: unsupported".format(region))
    return

def vpns(aws,regions):
    "Prints count of vpns"
    for region in regions:
        try:
            response = boto3.session.Session(profile_name=profile,region_name=region).client('ec2').describe_vpn_connections()
            print("vpn.{}:".format(region), len(response["VpnConnections"]))
        except:
            print("vpn.{}: unsupported".format(region))
    return

def route_tables(aws,regions):
    "Prints count of route tables"
    for region in regions:
        try:
            response = boto3.session.Session(profile_name=profile,region_name=region).client('ec2').describe_route_tables()
            print("route_tables.{}:".format(region), len(response["RouteTables"]))
        except:
            print("route_tables.{}: unsupported".format(region))
    return

def subnets(aws,regions):
    "Prints count of subnets"
    for region in regions:
        try:
            response = boto3.session.Session(profile_name=profile,region_name=region).client('ec2').describe_subnets()
            print("subnets.{}:".format(region), len(response["Subnets"]))
        except:
            print("subnets.{}: unsupported".format(region))
    return


# PAAS
def aws_paas(aws,regions):
    "This kicks off all paas inventory functions"
    cf_distributions(aws)
    elastic_search(aws)
    aurora_clusters(aws)
    rds_instances(aws,regions)
    dynamo_db(aws)

def cf_distributions(aws):
    "Prints count of cloudfront distributions"
    try:
        response = boto3.session.Session(profile_name=profile).client('cloudfront').list_distributions()["DistributionList"]
        print("cf_distributions:", len(response["Items"]))
    except:
        print("cf_distributions: unsupported")
    return

def elastic_search(aws):
    "Prints count of elastic search clusters"
    try:
        response = boto3.session.Session(profile_name=profile).client('es').list_domain_names()
        print("es.clusters:", len(response["DomainNames"]))
    except:
        print("es.clusters: unsupported")
    return

def aurora_clusters(aws):
    "Prints count of aurora clusters"
    try:
        response = boto3.session.Session(profile_name=profile).client('rds').describe_db_clusters()
        print("rds.aurora.clusters:", len(response["DBClusters"]))
    except:
        print("rds.aurora.clusters: unsupported")
    return

def rds_instances(aws,regions):
    "Prints count of rds instances"
    for region in regions:
        try:
            response = boto3.session.Session(profile_name=profile,region_name=region).client('rds').describe_db_instances()
            print("rds.instances.{}:".format(region), len(response["DBInstances"]))
        except:
            print("rds.instances.{}: unsupported".format(region))
    return

def dynamo_db(aws):
    "Prints count of dynamo databases"
    try:
        response = boto3.session.Session(profile_name=profile).client('dynamodb').list_tables()
        print("dynamodb.tables:", len(response["TableNames"]))
    except:
        print("dynamodb.tables: unsupported")
    return


# SECURITY
def aws_security(aws,regions):
    "This kicks off all security inventory functions"
    security_groups(aws,regions)
    if args.sgRules:
        security_group_rules(aws,regions)
    nacls(aws,regions)
    if args.naclRules:
        nacl_rules(aws,regions)
    wafs(aws,regions)

def security_groups(aws,regions):
    "Prints count of security groups"
    for region in regions:
        try:
            response = boto3.session.Session(profile_name=profile,region_name=region).client('ec2').describe_security_groups()
            print("sg.{}:".format(region), len(response["SecurityGroups"]))
        except:
            print("sg.{}: unsupported".format(region))
    return

def security_group_rules(aws,regions):
    "Prints count of security groups"
    for region in regions:
        try:
            response = boto3.session.Session(profile_name=profile,region_name=region).client('ec2').describe_security_groups()
            count = 0
            for sg in response["SecurityGroups"]:
                count += (len(sg["IpPermissions"]) + len(sg["IpPermissionsEgress"]))
            print("sg.rules.{}:".format(region), count)
        except:
            print("sg.rules.{}: unsupported".format(region))
    return

def nacls(aws,regions):
    "Prints count of nacls"
    for region in regions:
        try:
            response = boto3.session.Session(profile_name=profile,region_name=region).client('ec2').describe_network_acls()
            print("nacl.{}:".format(region), len(response["NetworkAcls"]))
        except:
            print("nacl.{}: unsupported".format(region))
    return

def nacl_rules(aws,regions):
    "Prints count of security groups"
    for region in regions:
        try:
            response = boto3.session.Session(profile_name=profile,region_name=region).client('ec2').describe_network_acls()
            count = 0
            for nacl in response["NetworkAcls"]:
                count += len(nacl["Entries"])
            print("nacl.rules.{}:".format(region), count)
        except:
            print("nacl.rules.{}: unsupported".format(region))
    return

def wafs(aws,regions):
    "Prints count of wafs"
    for region in regions:
        try:
            response = boto3.session.Session(profile_name=profile,region_name=region).client('waf').list_web_acls()
            print("waf.{}:".format(region), len(response["WebACLs"]))
        except:
            print("waf.{}: unsupported".format(region))
    return


# STORAGE
def aws_storage(aws,regions):
    "This kicks off all storage inventory functions"
    ebs_volumes(aws,regions)
    efs_filesystems(aws)
    s3_buckets(aws)
    if args.s3objects:
        s3_objects(aws)

def ebs_volumes(aws,regions):
    "Prints count of ebs volumes"
    try:
        for region in regions:
            ec2volumes = boto3.session.Session(profile_name=profile,region_name=region).client('ec2').describe_volumes().get('Volumes',[])
            volumes = sum(
                [
                    [i for i in r['Attachments']]
                    for r in ec2volumes
                ], [])
            print("ebs.volumes.{}:".format(region),len(volumes))
    except:
        print("ebs.volumes.{}: none".format(region))
    return

def efs_filesystems(aws):
    "This prints count of efs file systems on account"
    efsclient = aws.client('efs')
    try:
        response = efsclient.describe_file_systems()
        print("efs.filesystem.count:", len(response['FileSystems']))
    except:
        print("efs.filesystem.count: none")
    return

def s3_buckets(aws):
    "This prints a count of buckets on an account"
    s3client = aws.client('s3')
    try:
        response = s3client.list_buckets()
        print("s3.bucket.count:", len(response["Buckets"]))
    except:
        print("s3.bucket.count: none")
    return

def s3_objects(aws):
    "This prints object counts for all buckets of account"
    s3 = aws.resource('s3')
    s3client = aws.client('s3')
    response = s3client.list_buckets()
    for bucket_name in response["Buckets"]:
        try:
            bucket = s3.Bucket(bucket_name["Name"])
            print("s3.bucket.{}.objects:".format(bucket_name["Name"]),sum(1 for _ in bucket.objects.all()))
        except:
            print("s3.bucket.{}.objects: none".format(bucket_name["Name"]))
    return


# If ran directly this will start everything
if __name__ == '__main__':
    aws = boto3.session.Session(profile_name=profile)
    regions = [region['RegionName'] for region in aws.client('ec2').describe_regions()['Regions']]

    if args.compute:
        aws_compute(aws,regions)
    if args.network:
        aws_network(aws,regions)
    if args.paas:
        aws_paas(aws,regions)
    if args.security:
        aws_security(aws,regions)
    if args.storage:
        aws_storage(aws,regions)
