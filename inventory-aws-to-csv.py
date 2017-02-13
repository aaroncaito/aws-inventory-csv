#!/usr/bin/python3

import boto3
import csv
import os
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--profile", help="specify aws profile to use")
parser.add_argument("--volume_size", help="returns volume sizes if true", type=bool)
parser.add_argument("--region", help="specify region to report on")
parser.add_argument("--globals", help="returns global data if true", type=bool)
args = parser.parse_args()
profile = args.profile

#network
## vpc
## vpn
## route tables
## subnets

#compute
## ec2
## ecs
## asg
## lambda
## elb
## alb

#storage
def aws_storage(aws):
    s3_buckets(aws)
    s3_objects(aws)

## ebs
## efs
##s3
def s3_buckets(aws):
    "This prints a count of buckets on an account"
    s3 = aws.resource('s3')
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
    aws_storage(aws)
