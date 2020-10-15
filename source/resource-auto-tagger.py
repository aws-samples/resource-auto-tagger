#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

# Identity-based AWS resource tagger run by AWS Lambda

# Import AWS modules for python
import botocore
import boto3
# Import JSON
import json
# Import RegEx module
import re


def lambda_handler(event, context):
    
    #Get uncompressed CloudWatch Event data for parsing API calls
    def get_unc_cw_event_data(event):
        cw_data_dict = dict()
        cw_data_dict = event['detail']
        return cw_data_dict

    #Get resource tags assigned to a specified IAM role 
    #Returns a list of key:string,value:string resource tag dictionaries
    def get_role_tags(role_name):
        try:
            client = boto3.client('iam')
            response = dict()
            response = client.list_role_tags(
                RoleName=role_name
            )
        except botocore.exceptions.ClientError as error:
            print("Boto3 API returned error: ", error)
            print("No Tags Applied To: ", resource_id)
            no_tags = list()
            return no_tags
        return response['Tags']

    #Get resource tags stored in AWS SSM Parameter Store 
    #Returns a list of key:string,value:string resource tag dictionaries
    def get_ssm_parameter_tags(role_name, user_name):
        tag_list = list()
        try:
            path_string = "/auto-tag/" + role_name + "/" + user_name + "/tag"
            ssm_client = boto3.client('ssm')
            get_parameter_response = ssm_client.get_parameters_by_path(
            Path=path_string,
            Recursive=True,
            WithDecryption=True
            )
            for parameter in get_parameter_response['Parameters']:
                tag_dictionary = dict()
                path_components = parameter['Name'].split("/")
                tag_key = path_components[-1]
                tag_dictionary['Key'] = tag_key
                tag_dictionary['Value'] = parameter['Value']
                tag_list.append(tag_dictionary)
            return tag_list

        except botocore.exceptions.ClientError as error:
            print("Boto3 API returned error: ", error)
            tag_list.clear()
            return tag_list

    #Apply tags to resource
    def set_resource_tags(resource_id, resource_tags):
        # Is this an EC2 resource?
        if re.search("^i-", resource_id):
            try:
                client = boto3.client('ec2')
                response = client.create_tags(
                    Resources=[
                        resource_id
                    ],
                    Tags=resource_tags
                )
                response = client.describe_volumes(
                    Filters=[
                        {
                            'Name': 'attachment.instance-id',
                            'Values': [
                                resource_id
                            ]
                        }
                    ]
                )
                try:
                    for volume in response['Volumes']:
                        ec2 = boto3.resource('ec2')
                        ec2_vol = ec2.Volume(volume['VolumeId'])
                        vol_tags = ec2_vol.create_tags(
                        Tags=resource_tags
                        )
                except botocore.exceptions.ClientError as error:
                    print("Boto3 API returned error: ", error)
                    print("No Tags Applied To: ", response['Volumes'])
                    return False
            except botocore.exceptions.ClientError as error:
                print("Boto3 API returned error: ", error)
                print("No Tags Applied To: ", resource_id)
                return False
            return True
        else:
            return False

    data_dict = get_unc_cw_event_data(event)
    #data_dict = get_cw_event_data(event)
    user_id_arn = data_dict['userIdentity']['arn']
    user_id_components = user_id_arn.split("/")
    user_id = user_id_components[-1]
    role_arn = data_dict['userIdentity']['sessionContext']['sessionIssuer']['arn']
    role_components = role_arn.split("/")
    role_name = role_components[-1]
    resource_date = data_dict['eventTime']
    
    resource_role_tags = list()
    resource_role_tags = get_role_tags(role_name)

    resource_parameter_tags = list()
    resource_parameter_tags = get_ssm_parameter_tags(role_name, user_id)

    resource_tags = list()
    resource_tags = resource_role_tags + resource_parameter_tags

    created_by = dict()
    created_by['Key'] = 'Created by'
    created_by['Value'] = user_id
    resource_tags.append(created_by)

    roleName = dict()
    roleName['Key'] = 'Role Name'
    roleName['Value'] = role_name
    resource_tags.append(roleName)

    date_created = dict()
    date_created['Key'] = 'Date created'
    date_created['Value'] = resource_date
    resource_tags.append(date_created)
    
    if 'instancesSet' in data_dict['responseElements']:
        for item in data_dict['responseElements']['instancesSet']['items']:
            resource_id = item['instanceId']
            if set_resource_tags(resource_id, resource_tags):    
                return {
                    'statusCode': 200,
                    'Resource ID': resource_id,
                    'body': json.dumps(resource_tags)
                }
            else:
                return {
                    'statusCode': 500,
                    'No tags applied to Resource ID': resource_id,
                    'Lambda function name': context.function_name,
                    'Lambda function version': context.function_version
                }
    else:
        return {
            'statusCode': 200,
            'No resources to tag': event['id']
        }

