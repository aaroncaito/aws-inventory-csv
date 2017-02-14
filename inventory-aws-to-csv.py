#!/usr/bin/python3

import boto3
import csv
import os
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--profile", help="specify aws profile to use")
parser.add_argument("--s3objects", type=bool, default=False, help="True enables counting s3 objects, default = false")
parser.add_argument("--volume_size", type=bool, help="returns volume sizes if true")
parser.add_argument("--region", help="specify region to report on")
parser.add_argument("--globals", type=bool, help="returns global data if true")
args = parser.parse_args()
profile = args.profile

#network
## vpc
## vpn
## route tables
## subnets

#compute
def aws_compute(aws,regions):
    "This kicks off all compute inventory functions"
    ec2_instances(aws,regions)

def ec2_instances(aws,regions):
    "This prints out count of ec2 instances on an account"
    for region in regions:
        print("ec2.instances.{}:".format(region),sum(1 for _ in boto3.session.Session(profile_name=profile,region_name=region).resource('ec2').instances.filter(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])))
    return

## ecs
## asg
## lambda
## elb
## alb

#storage
def aws_storage(aws):
    "This kicks off all storage inventory functions"
    efs_filesystems(aws)
    s3_buckets(aws)
    if args.s3objects:
        s3_objects(aws)

## ebs

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

#paas
## cloudfront count
## elk count
## rds
## aurora
## dynamodb

#security
## sg count
## sg rules
## nacl count
## nacl rules
## waf count


if __name__ == '__main__':
    aws = boto3.session.Session(profile_name=profile)
    regions = [region['RegionName'] for region in aws.client('ec2').describe_regions()['Regions']]
    aws_storage(aws)
    aws_compute(aws,regions)
