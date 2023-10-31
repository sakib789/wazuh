#!/usr/bin/env python3

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
#
#
# Error Codes:
#   1 - Unknown
#   2 - SIGINT
#   3 - Invalid credentials to access AWS service
#   4 - boto3 module missing
#   5 - Unexpected error accessing SQLite DB
#   6 - Unable to create SQLite DB
#   7 - Unexpected error querying/working with objects in S3
#   8 - Failed to decompress file
#   9 - Failed to parse file
#   10 - pyarrow module missing
#   11 - Unable to connect to Wazuh
#   12 - Invalid type of bucket
#   13 - Unexpected error sending message to Wazuh
#   14 - Empty bucket
#   15 - Invalid endpoint URL
#   16 - Throttling error
#   17 - Invalid key format
#   18 - Invalid prefix
#   19 - The server datetime and datetime of the AWS environment differ
#   20 - Unable to find SQS
#   21 - Failed fetch/delete from SQS
#   22 - Invalid region
#   23 - Profile not found

import signal
import sys

# Local imports
import buckets_s3
import services
import subscribers
from aws_tools import (aws_logger, get_script_arguments, get_aws_config_params, ALL_REGIONS,
                       SECURITY_LAKE_IAM_ROLE_AUTHENTICATION_URL, arg_validate_security_lake_auth_params, handler)


def main(argv):
    # Parse arguments
    options = get_script_arguments()

    # Get logging level from argument
    log_lvl = options.debug

    # Set logging level
    aws_logger.set_level(log_level=log_lvl)

    try:
        if options.logBucket:
            if options.type.lower() == 'cloudtrail':
                bucket_type = buckets_s3.cloudtrail.AWSCloudTrailBucket
            elif options.type.lower() == 'vpcflow':
                bucket_type = buckets_s3.vpcflow.AWSVPCFlowBucket
            elif options.type.lower() == 'config':
                bucket_type = buckets_s3.config.AWSConfigBucket
            elif options.type.lower() == 'custom':
                bucket_type = buckets_s3.aws_bucket.AWSCustomBucket
            elif options.type.lower() == 'guardduty':
                bucket_type = buckets_s3.guardduty.AWSGuardDutyBucket
            elif options.type.lower() == 'cisco_umbrella':
                bucket_type = buckets_s3.umbrella.CiscoUmbrella
            elif options.type.lower() == 'waf':
                bucket_type = buckets_s3.waf.AWSWAFBucket
            elif options.type.lower() == 'alb':
                bucket_type = buckets_s3.load_balancers.AWSALBBucket
            elif options.type.lower() == 'clb':
                bucket_type = buckets_s3.load_balancers.AWSCLBBucket
            elif options.type.lower() == 'nlb':
                bucket_type = buckets_s3.load_balancers.AWSNLBBucket
            elif options.type.lower() == 'server_access':
                bucket_type = buckets_s3.server_access.AWSServerAccess
            else:
                raise Exception("Invalid type of bucket")
            import pydevd_pycharm
            pydevd_pycharm.settrace('172.30.0.1', port=55555, stdoutToServer=True, stderrToServer=True)
            bucket = bucket_type(reparse=options.reparse, access_key=options.access_key,
                                 secret_key=options.secret_key,
                                 profile=options.aws_profile,
                                 iam_role_arn=options.iam_role_arn,
                                 bucket=options.logBucket,
                                 only_logs_after=options.only_logs_after,
                                 skip_on_error=options.skip_on_error,
                                 account_alias=options.aws_account_alias,
                                 prefix=options.trail_prefix,
                                 suffix=options.trail_suffix,
                                 delete_file=options.deleteFile,
                                 aws_organization_id=options.aws_organization_id,
                                 region=options.regions[0] if options.regions else None,
                                 discard_field=options.discard_field,
                                 discard_regex=options.discard_regex,
                                 sts_endpoint=options.sts_endpoint,
                                 service_endpoint=options.service_endpoint,
                                 iam_role_duration=options.iam_role_duration
                                 )
            # check if bucket is empty or credentials are wrong
            bucket.check_bucket()
            bucket.iter_bucket(options.aws_account_id, options.regions)
        elif options.service:
            if options.service.lower() == 'inspector':
                service_type = services.inspector.AWSInspector
            elif options.service.lower() == 'cloudwatchlogs':
                service_type = services.cloudwatchlogs.AWSCloudWatchLogs
            else:
                raise Exception("Invalid type of service")

            if not options.regions:
                aws_config = get_aws_config_params()

                profile = options.aws_profile or "default"

                if aws_config.has_option(profile, "region"):
                    options.regions.append(aws_config.get(profile, "region"))
                else:
                    aws_logger.warning("No regions were specified, trying to get events from all regions")
                    options.regions = ALL_REGIONS

            for region in options.regions:
                try:
                    service_type.check_region(region)
                except ValueError:
                    aws_logger.error(f"The region '{region}' is not a valid one.")
                    exit(22)

                aws_logger.debug('Getting alerts from "{}" region.'.format(region))

                service = service_type(reparse=options.reparse,
                                       access_key=options.access_key,
                                       secret_key=options.secret_key,
                                       profile=options.aws_profile,
                                       iam_role_arn=options.iam_role_arn,
                                       only_logs_after=options.only_logs_after,
                                       region=region,
                                       aws_log_groups=options.aws_log_groups,
                                       remove_log_streams=options.deleteLogStreams,
                                       discard_field=options.discard_field,
                                       discard_regex=options.discard_regex,
                                       sts_endpoint=options.sts_endpoint,
                                       service_endpoint=options.service_endpoint,
                                       iam_role_duration=options.iam_role_duration
                                       )
                service.get_alerts()
        elif options.subscriber:
            if options.subscriber.lower() == "security_lake":
                if options.aws_profile:
                    aws_logger.error(
                        "The AWS Security Lake integration does not make use of the Profile authentication "
                        f"method. Check the available ones for it in "
                        f"{SECURITY_LAKE_IAM_ROLE_AUTHENTICATION_URL}")
                    sys.exit(3)
                arg_validate_security_lake_auth_params(options.external_id,options.queue,options.iam_role_arn)
                bucket_handler = subscribers.s3_log_handler.AWSSLSubscriberBucket
                asl_queue = subscribers.sqs_queue.AWSSQSQueue(
                    external_id=options.external_id,
                    iam_role_arn=options.iam_role_arn,
                    iam_role_duration=options.iam_role_duration,
                    profile=None,
                    sts_endpoint=options.sts_endpoint,
                    service_endpoint=options.service_endpoint,
                    name=options.queue,
                    bucket_handler=bucket_handler,
                    message_processor=subscribers.sqs_message_processor.AWSSSecLakeMessageProcessor
                )
            elif options.subscriber.lower() == "buckets":
                bucket_handler = subscribers.s3_log_handler.AWSSubscriberBucket
                asl_queue = subscribers.sqs_queue.AWSSQSQueue(
                    iam_role_arn=options.iam_role_arn,
                    iam_role_duration=options.iam_role_duration,
                    profile=options.aws_profile,
                    sts_endpoint=options.sts_endpoint,
                    service_endpoint=options.service_endpoint,
                    name=options.queue,
                    skip_on_error=options.skip_on_error,
                    discard_field=options.discard_field,
                    discard_regex=options.discard_regex,
                    bucket_handler=bucket_handler,
                    message_processor=subscribers.sqs_message_processor.AWSS3MessageProcessor)
            else:
                raise Exception("Invalid type of subscriber")
            asl_queue.sync_events()
    except Exception as err:
        aws_logger.error("Error: {}".format(err))
        sys.exit(12)


if __name__ == '__main__':
    try:
        aws_logger.debug('Args: {args}'.format
                         (args=str(sys.argv)))
        signal.signal(signal.SIGINT, handler)
        main(sys.argv[1:])
        sys.exit(0)
    except Exception as e:
        aws_logger.error("Unknown error: {}".format(e))
        sys.exit(1)
