# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import csv
import io
import json
import re
import sys
from os import path

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
from aws_tools import aws_logger

try:
    import pyarrow.parquet as pq
except ImportError:
    aws_logger('Pyarrow module is required.')
    sys.exit(10)

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
import wazuh_integration


# Classes
class AWSS3LogHandler:
    def obtain_logs(self, bucket: str, log_path: str) -> list:
        """Fetch a file from a bucket and obtain a list of events from it.

        Parameters
        ----------
        bucket : str
            Bucket to get the file from.
        log_path : str
            Relative path of the file inside the bucket.

        Returns
        -------
        list[dict]
            List of extracted events to send to Wazuh.
        """
        raise NotImplementedError

    def process_file(self, message_body: dict) -> None:
        """Parse an SQS message body, obtain the events associated, and send them to Analysisd.

        Parameters
        ----------
        message_body : dict
            An SQS message received from the queue.
        """
        raise NotImplementedError


class AWSSubscriberBucket(wazuh_integration.WazuhIntegration, AWSS3LogHandler):
    """Class for processing events from AWS S3 buckets.

    Attributes
    ----------
    profile : str
        AWS profile.
    iam_role_arn : str
        IAM Role.
    """
    def __init__(self, service_endpoint: str = None, sts_endpoint: str = None, profile: str = None, **kwargs):
        wazuh_integration.WazuhIntegration.__init__(self, access_key=None,
                                                    secret_key=None,
                                                    profile=profile,
                                                    service_name='s3',
                                                    service_endpoint=service_endpoint,
                                                    sts_endpoint=sts_endpoint,
                                                    **kwargs)

    @staticmethod
    def _process_jsonl(file: io.TextIOWrapper) -> list[dict]:
        """Process JSON objects present in a JSONL file.

        Parameters
        ----------
        file : io.TextIOWrapper
            File object.
        Returns
        -------
        list[dict]
            List of events from the file.
        """
        json_list = list(file)
        result = []
        for json_item in json_list:
            x = json.loads(json_item)
            result.append(dict(x))
        return result

    @staticmethod
    def _json_event_generator(data: str):
        """Obtain events from string of JSON objects.

        Parameters
        ----------
        data : str
            String of JSON data.
        Yields
        -------
        dict
            Extracted JSON event.
        """
        decoder = json.JSONDecoder()
        while data:
            json_data, json_index = decoder.raw_decode(data)
            data = data[json_index:]
            yield json_data

    @staticmethod
    def _remove_none_fields(event: dict):
        """Remove None fields from events.

        Parameters
        ----------
        event : dict
            Event to send to Analysisd.
        """
        for key, value in list(event.items()):
            if isinstance(value, dict):
                AWSSubscriberBucket._remove_none_fields(event[key])
            elif value is None:
                del event[key]

    @staticmethod
    def is_csv(file: io.TextIOWrapper) -> bool:
        """Determine if the given file is a CSV according to its headers.

        Parameters
        ----------
        file : io.TextIOWrapper
            File object.

        Returns
        -------
        bool
            Whether a file contains csv data or not.
        """
        # Read the first line (header row) from the file
        header_row = file.readline().strip()
        file.seek(0)
        # Define the regex pattern for invalid CSV header characters
        not_header_pattern = re.compile(r'.*\d+.*')
        # Check if the header row matches the regex pattern
        return not bool(not_header_pattern.match(header_row))

    def obtain_logs(self, bucket: str, log_path: str) -> list[dict]:
        """Fetch a file from a bucket and obtain a list of events from it.

        Parameters
        ----------
        bucket : str
            Bucket to get the file from.
        log_path : str
            Relative path of the file inside the bucket.

        Returns
        -------
        list[dict]
            List of extracted events to send to Wazuh.
        """

        with self.decompress_file(bucket, log_key=log_path) as f:
            try:
                if log_path.endswith('.jsonl.gz'):
                    return self._process_jsonl(file=f)

                return [dict(event.get('detail', event), source="custom")
                        for event in self._json_event_generator(f.read())]

            except (json.JSONDecodeError, AttributeError):
                aws_logger.debug("+++ Log file does not contain JSON objects. Trying with other formats.")
                f.seek(0)
                if self.is_csv(f):
                    aws_logger.debug("+++ Log file is CSV formatted.")
                    dialect = csv.Sniffer().sniff(f.read(1024))
                    f.seek(0)
                    reader = csv.DictReader(f, dialect=dialect)
                    return [dict({k: v for k, v in row.items() if v is not None},
                                 source='custom') for row in reader]
                else:
                    aws_logger.debug("+++ Data in the file does not seem to be CSV. Trying with plain text.")
                    try:
                        return [dict(full_log=event, source="custom") for event in f.read().splitlines()]
                    except OSError:
                        aws_logger.error(f"Data in the file does not seem to be plain text either.")
                        sys.exit(9)

    def process_file(self, message_body: dict) -> None:
        """Parse an SQS message, obtain the events associated, and send them to Analysisd.

        Parameters
        ----------
        message_body : dict
            An SQS message received from the queue.
        """

        log_path = message_body['log_path']
        bucket_path = message_body['bucket_path']

        msg = {
            'integration': 'aws',
            'aws': {
                'log_info': {
                    'log_file': log_path,
                    's3bucket': bucket_path
                }
            }
        }
        formatted_logs = self.obtain_logs(bucket=bucket_path, log_path=log_path)
        for log in formatted_logs:
            self._remove_none_fields(log)
            if 'full_log' in log:
                # The processed logs origin is a plain text log file
                if re.match(self.discard_regex, log['full_log']):
                    aws_logger.debug(f'+++ The "{self.discard_regex.pattern}" regex found a match. '
                                     'The event will be skipped.')
                    continue
            elif self.event_should_be_skipped(log):
                aws_logger.debug(f'+++ The "{self.discard_regex.pattern}" regex found a match '
                                 f'in the "{self.discard_field}" '
                                 'field. The event will be skipped.')
                continue

            msg['aws'].update(log)
            self.send_msg(msg)


class AWSSLSubscriberBucket(wazuh_integration.WazuhIntegration, AWSS3LogHandler):
    """Class for processing AWS Security Lake events from S3.

    Attributes
    ----------
    access_key : str
        AWS access key id.
    secret_key : str
        AWS secret access key.
    profile : str
        AWS profile.
    iam_role_arn : str
        IAM Role.
    """

    def __init__(self, service_endpoint: str = None, sts_endpoint: str = None, profile: str = None, **kwargs):
        wazuh_integration.WazuhIntegration.__init__(self, access_key=None,
                                                    secret_key=None,
                                                    profile=profile,
                                                    service_name='s3',
                                                    service_endpoint=service_endpoint,
                                                    sts_endpoint=sts_endpoint,
                                                    **kwargs)

    def obtain_logs(self, bucket: str, log_path: str) -> list:
        """Fetch a parquet file from a bucket and obtain a list of the events it contains.

        Parameters
        ----------
        bucket : str
            Bucket to get the file from.
        log_path : str
            Relative path of the file inside the bucket.

        Returns
        -------
        events : list
            Events contained inside the parquet file.
        """
        aws_logger.debug(f'Processing file {log_path} in {bucket}')
        events = []
        try:
            raw_parquet = io.BytesIO(self.client.get_object(Bucket=bucket, Key=log_path)['Body'].read())
        except Exception as e:
            aws_logger.error(f'Could not get the parquet file {log_path} in {bucket}: {e}')
            sys.exit(21)
        pfile = pq.ParquetFile(raw_parquet)
        for i in pfile.iter_batches():
            for j in i.to_pylist():
                events.append(json.dumps(j))
        aws_logger.debug(f'Found {len(events)} events in file {log_path}')
        return events

    def process_file(self, message_body: dict) -> None:
        """Parse an SQS message, obtain the events associated, and send them to Analysisd.

        Parameters
        ----------
        message_body : dict
            An SQS message received from the queue.
        """
        events_in_file = self.obtain_logs(bucket=message_body['bucket_path'],
                                          log_path=message_body['log_path'])
        for event in events_in_file:
            self.send_msg(event, dump_json=False)
        aws_logger.debug(f'{len(events_in_file)} events sent to Analysisd')
