"""Offline unit tests for scanner/audit.py: AWS and Cloudflare are mocked, no credentials needed."""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

import requests
from botocore.exceptions import ClientError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scanner'))
import audit  # noqa: E402


class FakePaginator:
    def __init__(self, fn):
        self.fn = fn

    def paginate(self, **kwargs):
        return [self.fn(kwargs)]


def denied(operation):
    def fn(kwargs):
        raise ClientError({'Error': {'Code': 'UnauthorizedOperation', 'Message': 'denied'}}, operation)
    return fn


def fake_ec2(instances=(), sgs=(), volume_calls=None, deny=()):
    """Build an EC2 client mock. `deny` lists paginator names that raise AccessDenied."""
    volume_calls = [] if volume_calls is None else volume_calls

    def volumes(kwargs):
        volume_calls.append(kwargs)
        return {'Volumes': [{'VolumeId': 'vol-1', 'Encrypted': True}]}

    handlers = {
        'describe_instances': lambda kw: {'Reservations': [{'Instances': list(instances)}]},
        'describe_security_groups': lambda kw: {'SecurityGroups': list(sgs)},
        'describe_volumes': volumes,
    }
    client = mock.Mock()
    client.get_paginator.side_effect = lambda name: FakePaginator(
        denied(name) if name in deny else handlers[name])
    return client


def instance(n, tokens='required'):
    return {'InstanceId': f'i-{n}', 'MetadataOptions': {'HttpTokens': tokens}}


def by_control(results, control):
    return [r for r in results if r['control'] == control]


class SecurityGroupExposureTest(unittest.TestCase):
    def test_wide_and_narrow_sources(self):
        cases = {
            'open-v4': ({'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}, True),
            'half-internet': ({'IpRanges': [{'CidrIp': '0.0.0.0/1'}]}, True),
            'open-v6': ({'Ipv6Ranges': [{'CidrIpv6': '::/0'}]}, True),
            'prefix-list': ({'PrefixListIds': [{'PrefixListId': 'pl-1'}]}, True),
            'private-range': ({'IpRanges': [{'CidrIp': '10.0.0.0/16'}]}, False),
            'sg-reference': ({'UserIdGroupPairs': [{'GroupId': 'sg-1'}]}, False),
        }
        for name, (permission, exposed) in cases.items():
            with self.subTest(name):
                self.assertEqual(bool(audit.sg_exposure(permission)), exposed)


class AwsChecksTest(unittest.TestCase):
    def run_checks(self, **kwargs):
        with mock.patch('boto3.client', return_value=fake_ec2(**kwargs)):
            return audit.aws_checks('us-east-1', 'vpc-1')

    def test_imdsv2_pass_and_fail(self):
        results = by_control(self.run_checks(instances=[instance(1), instance(2, 'optional')]), 'IMDSv2')
        self.assertEqual([r['status'] for r in results], ['PASS', 'FAIL'])

    def test_no_instances_skips_volume_lookup(self):
        calls = []
        results = self.run_checks(volume_calls=calls)
        self.assertEqual(calls, [])
        self.assertEqual(by_control(results, 'EBS encryption')[0]['status'], 'NOT_TESTED')

    def test_volume_filter_chunks_at_200(self):
        calls = []
        self.run_checks(instances=[instance(n) for n in range(250)], volume_calls=calls)
        self.assertEqual([len(c['Filters'][0]['Values']) for c in calls], [200, 50])

    def test_only_live_instances_requested(self):
        seen = []
        with mock.patch.object(FakePaginator, 'paginate', autospec=True,
                               side_effect=lambda self, **kw: seen.append(kw) or [self.fn(kw)]):
            self.run_checks()
        filters = {f['Name']: f['Values'] for f in seen[0]['Filters']}
        self.assertEqual(filters['vpc-id'], ['vpc-1'])
        self.assertNotIn('terminated', filters['instance-state-name'])
        self.assertIn('running', filters['instance-state-name'])

    def test_permission_error_becomes_error_finding(self):
        results = self.run_checks(instances=[instance(1)], deny=('describe_security_groups',))
        sg = by_control(results, 'No unrestricted inbound rules')
        self.assertEqual(sg[0]['status'], 'ERROR')
        self.assertIn('UnauthorizedOperation', sg[0]['evidence'])
        # Other checks still ran.
        self.assertEqual(by_control(results, 'EBS encryption')[0]['status'], 'PASS')


def cf_response(payload=None, http_error=None):
    resp = mock.Mock()
    resp.raise_for_status.side_effect = http_error
    resp.json.return_value = payload
    return resp


class CloudflareChecksTest(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, {'CLOUDFLARE_API_TOKEN': 'test-token'})
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_checks(self, responses):
        def fake_get(url, **kwargs):
            return next(v for k, v in responses.items() if k in url)
        with mock.patch('requests.get', side_effect=fake_get):
            return audit.cf_checks('zone-1', 'lab.example.com')

    def ok(self, result):
        return cf_response({'success': True, 'result': result})

    def test_all_pass(self):
        results = self.run_checks({
            'dns_records': self.ok([{'type': 'CNAME', 'proxied': True, 'content': 'abc.cfargotunnel.com'}]),
            'min_tls_version': self.ok({'value': '1.2'}),
            'always_use_https': self.ok({'value': 'on'}),
        })
        self.assertEqual([r['status'] for r in results], ['PASS', 'PASS', 'PASS'])

    def test_unproxied_record_and_old_tls_fail(self):
        results = self.run_checks({
            'dns_records': self.ok([{'type': 'CNAME', 'proxied': False, 'content': 'abc.cfargotunnel.com'}]),
            'min_tls_version': self.ok({'value': '1.0'}),
            'always_use_https': self.ok({'value': 'off'}),
        })
        self.assertEqual([r['status'] for r in results], ['FAIL', 'FAIL', 'FAIL'])

    def test_api_failures_become_error_findings(self):
        results = self.run_checks({
            'dns_records': cf_response(http_error=requests.HTTPError('403 Forbidden')),
            'min_tls_version': cf_response({'success': False, 'errors': [{'code': 9109}]}),
            'always_use_https': self.ok({'value': 'on'}),
        })
        self.assertEqual([r['status'] for r in results], ['ERROR', 'ERROR', 'PASS'])

    def test_missing_token(self):
        with mock.patch.dict(os.environ, clear=True):
            results = audit.cf_checks('zone-1', 'lab.example.com')
        self.assertEqual(results[0]['status'], 'ERROR')


class MainTest(unittest.TestCase):
    def run_main(self, args, ec2):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, 'out.json')
            with mock.patch('boto3.client', return_value=ec2), \
                    mock.patch.object(sys, 'argv', ['audit.py', *args, '--output', out]), \
                    mock.patch('builtins.print'), \
                    self.assertRaises(SystemExit) as exit_info:
                audit.main()
            report = json.load(open(out)) if os.path.exists(out) else None
        return exit_info.exception.code, report

    def test_exit_0_when_all_pass(self):
        code, report = self.run_main(['--vpc', 'vpc-1'], fake_ec2(instances=[instance(1)]))
        self.assertEqual(code, 0)
        self.assertEqual(report['vpc'], 'vpc-1')

    def test_exit_1_on_fail(self):
        code, _ = self.run_main(['--vpc', 'vpc-1'], fake_ec2(instances=[instance(1, 'optional')]))
        self.assertEqual(code, 1)

    def test_exit_2_on_error_and_report_still_written(self):
        code, report = self.run_main(['--vpc', 'vpc-1'], fake_ec2(deny=('describe_instances',)))
        self.assertEqual(code, 2)
        self.assertTrue(any(r['status'] == 'ERROR' for r in report['findings']))

    def test_zone_without_hostname_rejected(self):
        with mock.patch.object(sys, 'argv', ['audit.py', '--vpc', 'v', '--zone', 'z', '--output', 'x']), \
                mock.patch('sys.stderr'), self.assertRaises(SystemExit) as exit_info:
            audit.main()
        self.assertEqual(exit_info.exception.code, 2)


if __name__ == '__main__':
    unittest.main()
