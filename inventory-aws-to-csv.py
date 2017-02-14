#!/usr/bin/python3

import boto3
import csv
import os
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--profile", help="specify aws profile to use")

# Logical groupings
parser.add_argument("--compute", type=bool, default=False, help="True enables counting compute resources
parser.add_argument("--network", type=bool, default=False, help="True enables counting network resources
parser.add_argument("--paas", type=bool, default=False, help="True enables counting paas resources
parser.add_argument("--security", type=bool, default=False, help="True enables counting security resources
parser.add_argument("--storage", type=bool, default=False, help="True enables counting storage resources")

# Specific api intensive modules
parser.add_argument("--s3objects", type=bool, default=False, help="True enables counting s3 objects, default = false")

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

## vpc
## vpn
## route tables
## subnets


# PAAS
def aws_paas(aws,regions):
    "This kicks off all paas inventory functions"
## cloudfront count
## elk count
## rds
## aurora
## dynamodb


# SECURITY
def aws_security(aws,regions):
    "This kicks off all security inventory functions"
## sg count
## sg rules
## nacl count
## nacl rules
## waf count


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
