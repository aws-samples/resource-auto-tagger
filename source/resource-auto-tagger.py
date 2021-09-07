"""AWS Lambda resource tagger for new Amazon EC2 instances & attached EBS volumes.

   Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
   SPDX-License-Identifier: MIT-0

   Amazon EventBridge triggers this AWS Lambda function when AWS CloudTrail detects
   a RunInstances API event initiated by IAM users and IAM assumed roles.
   This Lambda function extracts relevant information
   from that API event to retrieve resource tags assigned to the IAM role,
   IAM user & SSM parameters.  Next, this Lambda applies the retrieved tags to the newly created
   Amazon EC2 instances & their attached EBS volumes listed in the CloudTrail event.
"""

import json
import logging

import boto3
import botocore

logging.getLogger().setLevel(logging.INFO)
log = logging.getLogger(__name__)

# Instantiate Boto3 clients & resources for every AWS service API called
iam_client = boto3.client("iam")
ssm_client = boto3.client("ssm")
ec2_client = boto3.client("ec2")
ec2_resource = boto3.resource("ec2")


def get_iam_role_tags(role_name):
    """Get resource tags assigned to a specified IAM role.

    Args:
        role_name: IAM role name of entity creating the EC2 instance.

    Returns:
        Returns a list of key:string,value:string resource tag dictionaries
        assigned to the role or return None if no tags assigned

    Raises:
        AWS Python API "Boto3" returned errors
    """
    try:
        response = iam_client.list_role_tags(RoleName=role_name)
        return response.get("Tags")
    except botocore.exceptions.ClientError as error:
        log.error(f"Boto3 API returned error:  {error}")
        return None


def get_iam_user_tags(iam_user_name):
    """Get resource tags assigned to a specified IAM user.

    Args:
        iam_user_name: IAM user who created the EC2 instance.

    Returns:
        Returns a list of key:string,value:string resource tag dictionaries
        assigned to the IAM user or return None if no tags assigned
        to the user.

    Raises:
        AWS Python API "Boto3" returned client errors
    """
    try:
        response = iam_client.list_user_tags(UserName=iam_user_name)
        return response.get("Tags")
    except botocore.exceptions.ClientError as error:
        log.error(f"Boto3 API returned error: {error}")
        return None


def get_ssm_parameter_tags(iam_user_name=None, role_name=None, user_id=None):
    """Get resource tags stored in AWS SSM Parameter Store.

    Args:
        iam_user_name: IAM user creating the EC2 instance
        role_name: IAM role name of entity creating the EC2 instance
        user_id: ID of user assuming the IAM role

    Returns:
        Returns a list of key:string,value:string resource tag dictionaries
        Returns None if no resource tags found

    Raises:
        AWS Python API "Boto3" returned client errors
    """
    if iam_user_name:
        path_string = f"/auto-tag/{iam_user_name}/tag"
    elif role_name and user_id:
        path_string = f"/auto-tag/{role_name}/{user_id}/tag"
    else:
        path_string = ""
    if path_string:
        try:
            get_parameter_response = ssm_client.get_parameters_by_path(
                Path=path_string, Recursive=True, WithDecryption=True
            )
            if get_parameter_response.get("Parameters"):
                tag_list = []
                for parameter in get_parameter_response.get("Parameters"):
                    path_components = parameter["Name"].split("/")
                    tag_key = path_components[-1]
                    tag_list.append({"Key": tag_key, "Value": parameter.get("Value")})
                return tag_list
            else:
                return None
        except botocore.exceptions.ClientError as error:
            log.error(f"Boto3 API returned error: {error}")
            return None
    else:
        return None


# Apply resource tags to EC2 instances & attached EBS volumes
def set_ec2_instance_attached_vols_tags(ec2_instance_id, resource_tags):
    """Applies a list of passed resource tags to the Amazon EC2 instance.
       Also applies the same resource tags to EBS volumes attached to instance.

    Args:
        ec2_instance_id: EC2 instance identifier
        resource_tags: a list of key:string,value:string resource tag dictionaries

    Returns:
        Returns True if tag application successful and False if not

    Raises:
        AWS Python API "Boto3" returned client errors
    """
    try:
        response = ec2_client.create_tags(
            Resources=[ec2_instance_id], Tags=resource_tags
        )
        response = ec2_client.describe_volumes(
            Filters=[{"Name": "attachment.instance-id", "Values": [ec2_instance_id]}]
        )
        try:
            for volume in response.get("Volumes"):
                ec2_vol = ec2_resource.Volume(volume["VolumeId"])
                vol_tags = ec2_vol.create_tags(Tags=resource_tags)
            return True
        except botocore.exceptions.ClientError as error:
            log.error(f"Boto3 API returned error: {error}")
            log.error(f"No Tags Applied To: {volume['VolumeId']}")
            return False
    except botocore.exceptions.ClientError as error:
        log.error(f"Boto3 API returned error: {error}")
        log.error(f"No Tags Applied To: {ec2_instance_id}")
        return False


def cloudtrail_event_parser(event):
    """Extract list of new EC2 instance attributes, creation date, IAM role name,
    SSO User ID from the AWS CloudTrail resource creation event.

    Args:
        event: a cloudtrail event in python dictionary format

    Returns a dictionary containing these keys and their values:
        iam_user_name: the user name of the IAM user
        instances_set: list of EC2 instances & parameter dictionaries
        resource_date: date the EC2 instance was created
        role_name: IAM role name used by entity creating the EC2 instance
        user_id: ID of user assuming the IAM role & taking this action

    Raises:
        none
    """
    returned_event_fields = {}

    # Check if an IAM user created these EC2 instances & get that user
    if event.get("detail").get("userIdentity").get("type") == "IAMUser":
        returned_event_fields["iam_user_name"] = (
            event.get("detail").get("userIdentity").get("userName", "")
        )

    # Get the assumed IAM role name used to create the new EC2 instance(s)
    if event.get("detail").get("userIdentity").get("type") == "AssumedRole":
        # Check if optional Cloudtrail sessionIssuer field indicates assumed role credential type
        # If so, extract the IAM role named used during EC2 instance creation
        if (
            event.get("detail")
            .get("userIdentity")
            .get("sessionContext")
            .get("sessionIssuer")
            .get("type")
            == "Role"
        ):
            role_arn = (
                event.get("detail")
                .get("userIdentity")
                .get("sessionContext")
                .get("sessionIssuer")
                .get("arn")
            )
            role_components = role_arn.split("/")
            returned_event_fields["role_name"] = role_components[-1]
            # Get the user ID who assumed the IAM role
            if event.get("detail").get("userIdentity").get("arn"):
                user_id_arn = event.get("detail").get("userIdentity").get("arn")
                user_id_components = user_id_arn.split("/")
                returned_event_fields["user_id"] = user_id_components[-1]
            else:
                returned_event_fields["user_id"] = ""
        else:
            returned_event_fields["role_name"] = ""

    # Extract & return the list of new EC2 instance(s) and their parameters
    returned_event_fields["instances_set"] = (
        event.get("detail").get("responseElements").get("instancesSet")
    )

    # Extract the date & time of the EC2 instance creation
    returned_event_fields["resource_date"] = event.get("detail").get("eventTime")

    return returned_event_fields


def lambda_handler(event, context):
    resource_tags = []

    # Parse the passed CloudTrail event and extract pertinent EC2 launch fields
    event_fields = cloudtrail_event_parser(event)

    # Check for IAM User initiated event & get any associated resource tags
    if event_fields.get("iam_user_name"):
        resource_tags.append(
            {"Key": "IAM User Name", "Value": event_fields["iam_user_name"]}
        )
        iam_user_resource_tags = get_iam_user_tags(event_fields["iam_user_name"])
        if iam_user_resource_tags:
            resource_tags += iam_user_resource_tags
        ssm_parameter_resource_tags = get_ssm_parameter_tags(
            iam_user_name=event_fields["iam_user_name"]
        )
        if ssm_parameter_resource_tags:
            resource_tags += ssm_parameter_resource_tags

    # Check for event date & time in returned CloudTrail event field
    # and append as resource tag
    if event_fields.get("resource_date"):
        resource_tags.append(
            {"Key": "Date created", "Value": event_fields["resource_date"]}
        )

    # Check for IAM assumed role initiated event & get any associated resource tags
    if event_fields.get("role_name"):
        resource_tags.append(
            {"Key": "IAM Role Name", "Value": event_fields["role_name"]}
        )
        iam_role_resource_tags = get_iam_role_tags(event_fields["role_name"])
        if iam_role_resource_tags:
            resource_tags += iam_role_resource_tags
        if event_fields.get("user_id"):
            resource_tags.append(
                {"Key": "Created by", "Value": event_fields["user_id"]}
            )
            ssm_parameter_resource_tags = get_ssm_parameter_tags(
                role_name=event_fields["role_name"], user_id=event_fields["user_id"]
            )
            if ssm_parameter_resource_tags:
                resource_tags += ssm_parameter_resource_tags

    # Tag EC2 instances listed in the CloudTrail event
    if event_fields.get("instances_set"):
        for item in event_fields.get("instances_set").get("items"):
            ec2_instance_id = item.get("instanceId")
            if set_ec2_instance_attached_vols_tags(ec2_instance_id, resource_tags):
                log.info("'statusCode': 200")
                log.info(f"'Resource ID': {ec2_instance_id}")
                log.info(f"'body': {json.dumps(resource_tags)}")

            else:
                log.info("'statusCode': 500")
                log.info(f"'No tags applied to Resource ID': {ec2_instance_id}")
                log.info(f"'Lambda function name': {context.function_name}")
                log.info(f"'Lambda function version': {context.function_version}")
    else:
        log.info("'statusCode': 200")
        log.info(f"'No Amazon EC2 resources to tag': 'Event ID: {event.get('id')}'")
