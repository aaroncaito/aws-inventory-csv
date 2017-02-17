#!/usr/bin/python3

# This script is to facilitate inventory reporting tooling
__author__ = 'Aaron Caito'

import boto3
import csv
import os
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--profile", help="specify aws profile to use")
parser.add_argument("--out_file", help="csv file to create")
parser.add_argument("--csv_test", type=bool, default=False, help="generate sample csv file")

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
def aws_compute(aws_sessions):
    "This kicks off all compute inventory functions"
    aws_inventory["ec2_instances"]             = ec2_instances(aws_sessions)
    aws_inventory["ecs_clusters"]              = ecs_clusters(aws_sessions)
    aws_inventory["auto_scaling_groups"]       = auto_scaling_groups(aws_sessions)
    aws_inventory["lambda_functions"]          = lambda_functions(aws_sessions)
    aws_inventory["elastic_loadbalancers"]     = elastic_loadbalancers(aws_sessions)
    aws_inventory["application_loadbalancers"] = application_loadbalancers(aws_sessions)

def ec2_instances(aws_sessions):
    "This prints out count of ec2 instances on an account"
    i = 0
    for region,session in aws_sessions.items():
        try:
            j = sum(1 for _ in session.resource('ec2').instances.filter(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]))
            i += j
            print("ec2.instances.{}:".format(region),j)
        except:
            print("ec2.instances.{}: none")
    return i

def ecs_clusters(aws_sessions):
    "Prints out a count of clusters"
    i = 0
    for region,session in aws_sessions.items():
        try:
            j = len(session.client('ecs').list_clusters()["clusterArns"])
            i += j
            print("ecs.clusters.{}:".format(region),j)
        except:
            print("ecs.clusters.{}: unsupported".format(region))
    return i

def auto_scaling_groups(aws_sessions):
    "Prints out a count of autoscale groups"
    i = 0
    for region,session in aws_sessions.items():
        try:
            j = len(session.client('autoscaling').describe_auto_scaling_groups()["AutoScalingGroups"])
            i += j
            print("asg.groups.{}:".format(region),j)
        except:
            print("asg.groups.{}: none".format(region))
    return i

def lambda_functions(aws_sessions):
    "Prints count of lambda functions"
    i = 0
    for region,session in aws_sessions.items():
        try:
            j = len(session.client('lambda').list_functions()["Functions"])
            i += j
            print("lambda.functions.{}:".format(region),j)
        except:
            print("lambda.functions.{}: unsupported".format(region))
    return i

def elastic_loadbalancers(aws_sessions):
    "Prints count of classic elb"
    i = 0
    for region,session in aws_sessions.items():
        try:
            j = len(session.client('elb').describe_load_balancers()["LoadBalancerDescriptions"])
            i += j
            print("elb.{}:".format(region),j)
        except:
            print("elb.{}: unsupported".format(region))
    return i

def application_loadbalancers(aws_sessions):
    "Prints count of alb"
    i = 0
    for region,session in aws_sessions.items():
        try:
            j = len(session.client('elbv2').describe_load_balancers()["LoadBalancers"])
            i += j
            print("alb.{}:".format(region),j)
        except:
            print("alb.{}: unsupported".format(region))
    return i


# NETWORK
def aws_network(aws_sessions):
    "This kicks off all network inventory functions"
    aws_inventory["vpcs"] =         vpcs(aws_sessions)
    aws_inventory["vpns"] =         vpns(aws_sessions)
    aws_inventory["route_tables"] = route_tables(aws_sessions)
    aws_inventory["subnets"] =      subnets(aws_sessions)

def vpcs(aws_sessions):
    "Prints count of vpcs"
    i = 0
    for region,session in aws_sessions.items():
        try:
            j = len(session.client('ec2').describe_vpcs()["Vpcs"])
            i += j
            print("vpc.{}:".format(region),j)
        except:
            print("vpc.{}: unsupported".format(region))
    return i

def vpns(aws_sessions):
    "Prints count of vpns"
    i = 0
    for region,session in aws_sessions.items():
        try:
            j = len(session.client('ec2').describe_vpn_connections()["VpnConnections"])
            i += j
            print("vpn.{}:".format(region),j)
        except:
            print("vpn.{}: unsupported".format(region))
    return i

def route_tables(aws_sessions):
    "Prints count of route tables"
    i = 0
    for region,session in aws_sessions.items():
        try:
            j = len(session.client('ec2').describe_route_tables()["RouteTables"])
            i += j
            print("route_tables.{}:".format(region),j)
        except:
            print("route_tables.{}: unsupported".format(region))
    return i

def subnets(aws_sessions):
    "Prints count of subnets"
    i = 0
    for region,session in aws_sessions.items():
        try:
            j = len(session.client('ec2').describe_subnets()["Subnets"])
            i += j
            print("subnets.{}:".format(region),j)
        except:
            print("subnets.{}: unsupported".format(region))
    return i


# PAAS
def aws_paas(aws_sessions):
    "This kicks off all paas inventory functions"
    aws_inventory["cf_distributions"] = cf_distributions(aws_sessions)
    aws_inventory["elastic_search"] = elastic_search(aws_sessions)
    aws_inventory["aurora_clusters"] = aurora_clusters(aws_sessions)
    aws_inventory["rds_instances"] = rds_instances(aws_sessions)
    aws_inventory["dynamo_db"] = dynamo_db(aws_sessions)

def cf_distributions(aws_sessions):
    "Prints count of cloudfront distributions"
    j = 0
    try:
        j = len(aws_sessions["us-east-1"].client('cloudfront').list_distributions()["DistributionList"]["Items"])
        print("cf_distributions:",j)
    except:
        print("cf_distributions: unsupported")
    return j

def elastic_search(aws_sessions):
    "Prints count of elastic search clusters"
    j = 0
    try:
        j = len(aws_sessions["us-east-1"].client('es').list_domain_names()["DomainNames"])
        print("es.clusters:",j)
    except:
        print("es.clusters: unsupported")
    return j

def aurora_clusters(aws_sessions):
    "Prints count of aurora clusters"
    j = 0
    try:
        j = len(aws_sessions["us-east-1"].client('rds').describe_db_clusters()["DBClusters"])
        print("rds.aurora.clusters:",j)
    except:
        print("rds.aurora.clusters: unsupported")
    return j

def rds_instances(aws_sessions):
    "Prints count of rds instances"
    i = 0
    for region,session in aws_sessions.items():
        try:
            j = len(session.client('rds').describe_db_instances()["DBInstances"])
            i += j
            print("rds.instances.{}:".format(region),j)
        except:
            print("rds.instances.{}: unsupported".format(region))
    return i

def dynamo_db(aws_sessions):
    "Prints count of dynamo databases"
    j = 0
    try:
        j = len(aws_sessions["us-east-1"].client('dynamodb').list_tables()["TableNames"])
        print("dynamodb.tables:",j)
    except:
        print("dynamodb.tables: unsupported")
    return j


# SECURITY
def aws_security(aws_sessions):
    "This kicks off all security inventory functions"
    aws_inventory["security_groups"]          = security_groups(aws_sessions)
    if args.sgRules:
        aws_inventory["security_group_rules"] = security_group_rules(aws_sessions)
    aws_inventory["nacls"]                    = nacls(aws_sessions)
    if args.naclRules:
        aws_inventory["nacl_rules"]           = nacl_rules(aws_sessions)
    aws_inventory["wafs"]                     = wafs(aws_sessions)

def security_groups(aws_sessions):
    "Prints count of security groups"
    i = 0
    for region,session in aws_sessions.items():
        try:
            j = len(session.client('ec2').describe_security_groups()["SecurityGroups"])
            i += j
            print("sg.{}:".format(region),j)
        except:
            print("sg.{}: unsupported".format(region))
    return i

def security_group_rules(aws_sessions):
    "Prints count of security groups"
    i = 0
    for region,session in aws_sessions.items():
        try:
            response = session.client('ec2').describe_security_groups()
            j = 0
            for sg in response["SecurityGroups"]:
                j += (len(sg["IpPermissions"]) + len(sg["IpPermissionsEgress"]))
            i += j
            print("sg.rules.{}:".format(region),j)
        except:
            print("sg.rules.{}: unsupported".format(region))
    return i

def nacls(aws_sessions):
    "Prints count of nacls"
    i = 0
    for region,session in aws_sessions.items():
        try:
            j = len(session.client('ec2').describe_network_acls()["NetworkAcls"])
            i += j
            print("nacl.{}:".format(region),j)
        except:
            print("nacl.{}: unsupported".format(region))
    return i

def nacl_rules(aws_sessions):
    "Prints count of security groups"
    i = 0
    for region,session in aws_sessions.items():
        try:
            response = session.client('ec2').describe_network_acls()
            j = 0
            for nacl in response["NetworkAcls"]:
                j += len(nacl["Entries"])
            i += j
            print("nacl.rules.{}:".format(region),j)
        except:
            print("nacl.rules.{}: unsupported".format(region))
    return i

def wafs(aws_sessions):
    "Prints count of wafs"
    i = 0
    for region,session in aws_sessions.items():
        try:
            j = len(session.client('waf').list_web_acls()["WebACLs"])
            i += j
            print("waf.{}:".format(region),j)
        except:
            print("waf.{}: unsupported".format(region))
    return i


# STORAGE
def aws_storage(aws_sessions):
    "This kicks off all storage inventory functions"
    aws_inventory["ebs_volumes"]     = ebs_volumes(aws_sessions)
    aws_inventory["efs_filesystems"] = efs_filesystems(aws_sessions)
    aws_inventory["s3_buckets"]      = s3_buckets(aws_sessions)
    if args.s3Objects:
        aws_inventory["s3_objects"]  = s3_objects(aws_sessions)

def ebs_volumes(aws_sessions):
    "Prints count of ebs volumes"
    i = 0
    try:
        for region,session in aws_sessions.items():
            ec2volumes = session.client('ec2').describe_volumes().get('Volumes',[])
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

def efs_filesystems(aws_sessions):
    "This prints count of efs file systems on account"
    i = 0
    try:
        j = len(aws_sessions["us-east-1"].client('efs').describe_file_systems()['FileSystems'])
        i += j
        print("efs.filesystem.count:",j)
    except:
        print("efs.filesystem.count: none")
    return i

def s3_buckets(aws_sessions):
    "This prints a count of buckets on an account"
    i = 0
    try:
        j = len(aws_sessions["us-east-1"].client('s3').list_buckets()["Buckets"])
        i += j
        print("s3.bucket.count:",j)
    except:
        print("s3.bucket.count: none")
    return i

def s3_objects(aws_sessions):
    "This prints object counts for all buckets of account"
    i = 0
    for bucket_name in aws_sessions["us-east-1"].client('s3').list_buckets()["Buckets"]:
        try:
            j = sum(1 for _ in aws_sessions["us-east-1"].resource('s3').Bucket(bucket_name["Name"]).objects.all())
            i += j
            print("s3.bucket.{}.objects:".format(bucket_name["Name"]),j)
        except:
            print("s3.bucket.{}.objects: none".format(bucket_name["Name"]))
    return i


# If ran directly this will start everything
if __name__ == '__main__':
    aws_inventory = dict([])
    aws_sessions = dict([])
    if args.profile:
        # Lets make a temporary keypair to use that does not require mfa
        # create policy
        # create user
        # create keypair
        # attach policy


        regions = [region['RegionName'] for region in boto3.session.Session(profile_name=profile).client('ec2').describe_regions()['Regions']]
        for region in regions:
            aws_sessions[region] = boto3.session.Session(profile_name=profile,region_name=region)

        # Run components by logical group
        if args.compute:
            aws_compute(aws_sessions)
        if args.network:
            aws_network(aws_sessions)
        if args.paas:
            aws_paas(aws_sessions)
        if args.security:
            aws_security(aws_sessions)
        if args.storage:
            aws_storage(aws_sessions)

        # Lets destroy that temporary user / keypair /policy

    if args.csv_test:
        aws_inventory = {'elastic_loadbalancers': 0, 'subnets': 34, 'nacls': 12, 'security_groups': 21, 'aurora_clusters': 0, 'rds_instances': 0, 'ec2_instances': 0, 'dynamo_db': 0, 'wafs': 0, 'vpns': 0, 's3_buckets': 17, 'application_loadbalancers': 0, 'auto_scaling_groups': 0, 'vpcs': 12, 'elastic_search': 0, 'lambda_functions': 0, 'ecs_clusters': 0, 'route_tables': 14, 'cf_distributions': 0, 'efs_filesystems': 0, 'ebs_volumes': 0}

    if args.out_file:
        with open(args.out_file, 'w+') as csvfile:
            fieldnames = ['vpcs','vpns','route_tables','subnets','ec2_instances','ecs_clusters','auto_scaling_groups','lambda_functions','elastic_loadbalancers','application_loadbalancers','ebs_volumes','efs_filesystems','s3_buckets','s3_objects','security_groups','security_group_rules','nacls','nacl_rules','wafs','cf_distributions','elastic_search','aurora_clusters','rds_instances','dynamo_db']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerow(aws_inventory)
