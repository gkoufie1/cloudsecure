import argparse
import datetime
import ipaddress
import json
import os
import sys

import boto3
import requests
from botocore.exceptions import BotoCoreError, ClientError

CF_API = 'https://api.cloudflare.com/client/v4/zones/'
# Prefixes this short or shorter are treated as "unrestricted" (covers 0.0.0.0/0, 0.0.0.0/1, ::/0 ...).
WIDE_V4_PREFIX = 8
WIDE_V6_PREFIX = 16
LIVE_STATES = ['pending', 'running', 'stopping', 'stopped']


def finding(platform, resource, control, passed, evidence):
    return dict(platform=platform, resource=resource, control=control,
                status='PASS' if passed else 'FAIL', evidence=evidence)


def error(platform, resource, control, exc):
    return dict(platform=platform, resource=resource, control=control,
                status='ERROR', evidence=f'{type(exc).__name__}: {exc}')


def is_wide(cidr, max_prefix):
    try:
        return ipaddress.ip_network(cidr, strict=False).prefixlen <= max_prefix
    except ValueError:
        return False


def sg_exposure(permission):
    """Return the unrestricted sources in one inbound rule."""
    sources = [r['CidrIp'] for r in permission.get('IpRanges', []) if is_wide(r.get('CidrIp', ''), WIDE_V4_PREFIX)]
    sources += [r['CidrIpv6'] for r in permission.get('Ipv6Ranges', []) if is_wide(r.get('CidrIpv6', ''), WIDE_V6_PREFIX)]
    # Prefix lists can hold any CIDR; flag them so they get reviewed rather than silently passing.
    sources += ['prefix-list:' + p['PrefixListId'] for p in permission.get('PrefixListIds', [])]
    return sources


def aws_checks(region, vpc):
    ec2 = boto3.client('ec2', region_name=region)
    results, instance_ids = [], []

    try:
        pages = ec2.get_paginator('describe_instances').paginate(Filters=[
            {'Name': 'vpc-id', 'Values': [vpc]},
            {'Name': 'instance-state-name', 'Values': LIVE_STATES},
        ])
        for page in pages:
            for reservation in page['Reservations']:
                for instance in reservation['Instances']:
                    instance_ids.append(instance['InstanceId'])
                    tokens = instance.get('MetadataOptions', {}).get('HttpTokens', 'unknown')
                    results.append(finding('AWS', instance['InstanceId'], 'IMDSv2', tokens == 'required', tokens))
    except (ClientError, BotoCoreError) as exc:
        results.append(error('AWS', vpc, 'IMDSv2', exc))

    try:
        for page in ec2.get_paginator('describe_security_groups').paginate(Filters=[{'Name': 'vpc-id', 'Values': [vpc]}]):
            for sg in page['SecurityGroups']:
                exposed = [s for p in sg['IpPermissions'] for s in sg_exposure(p)]
                results.append(finding('AWS', sg['GroupId'], 'No unrestricted inbound rules', not exposed,
                                       {'unrestricted_sources': exposed}))
    except (ClientError, BotoCoreError) as exc:
        results.append(error('AWS', vpc, 'No unrestricted inbound rules', exc))

    if not instance_ids:
        results.append(dict(platform='AWS', resource=vpc, control='EBS encryption', status='NOT_TESTED',
                            evidence='No live instances in VPC'))
        return results
    try:
        # The attachment.instance-id filter accepts at most 200 values per call.
        for i in range(0, len(instance_ids), 200):
            chunk = instance_ids[i:i + 200]
            for page in ec2.get_paginator('describe_volumes').paginate(
                    Filters=[{'Name': 'attachment.instance-id', 'Values': chunk}]):
                for vol in page['Volumes']:
                    results.append(finding('AWS', vol['VolumeId'], 'EBS encryption', vol['Encrypted'], vol['Encrypted']))
    except (ClientError, BotoCoreError) as exc:
        results.append(error('AWS', vpc, 'EBS encryption', exc))
    return results


def cf_checks(zone, hostname):
    token = os.environ.get('CLOUDFLARE_API_TOKEN')
    if not token:
        return [dict(platform='Cloudflare', resource=zone, control='Cloudflare checks', status='ERROR',
                     evidence='CLOUDFLARE_API_TOKEN is not set')]
    headers = {'Authorization': 'Bearer ' + token}

    def get(path, params=None):
        r = requests.get(CF_API + zone + '/' + path, headers=headers, params=params, timeout=20)
        r.raise_for_status()
        data = r.json()
        if not data.get('success'):
            raise RuntimeError('Cloudflare API returned failure: ' + json.dumps(data.get('errors', [])))
        return data['result']

    results = []
    control = 'Proxied tunnel DNS'
    try:
        records = get('dns_records', {'name': hostname})
        passed = any(r['proxied'] and r['type'] == 'CNAME' and r['content'].endswith('.cfargotunnel.com') for r in records)
        results.append(finding('Cloudflare', hostname, control, passed,
                               [{'type': r['type'], 'proxied': r['proxied']} for r in records]))
    except (requests.RequestException, RuntimeError, KeyError, ValueError) as exc:
        results.append(error('Cloudflare', hostname, control, exc))

    for setting, allowed in [('min_tls_version', {'1.2', '1.3'}), ('always_use_https', {'on'})]:
        try:
            value = get('settings/' + setting)['value']
            results.append(finding('Cloudflare', zone, setting, value in allowed, value))
        except (requests.RequestException, RuntimeError, KeyError, ValueError) as exc:
            results.append(error('Cloudflare', zone, setting, exc))
    return results


def main():
    p = argparse.ArgumentParser(description='CloudSecure lab evidence scanner')
    p.add_argument('--region', default='us-east-1', help='AWS region; must match the Terraform region variable')
    p.add_argument('--vpc', required=True)
    p.add_argument('--zone')
    p.add_argument('--hostname')
    p.add_argument('--output', required=True)
    a = p.parse_args()
    if bool(a.zone) != bool(a.hostname):
        p.error('--zone and --hostname must be given together')

    results = aws_checks(a.region, a.vpc)
    if a.zone:
        results.extend(cf_checks(a.zone, a.hostname))
    else:
        results.append(dict(platform='Cloudflare', status='NOT_TESTED', control='Cloudflare checks', resource='',
                            evidence='No zone/hostname supplied'))

    with open(a.output, 'w') as f:
        json.dump({'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                   'region': a.region, 'vpc': a.vpc, 'findings': results}, f, indent=2)

    counts = {s: sum(r['status'] == s for r in results) for s in ('PASS', 'FAIL', 'ERROR', 'NOT_TESTED')}
    print(f'Wrote {a.output}: ' + ', '.join(f'{k}={v}' for k, v in counts.items()))
    # Exit 0 = all tested checks passed, 1 = at least one FAIL, 2 = at least one ERROR (no FAIL).
    sys.exit(1 if counts['FAIL'] else 2 if counts['ERROR'] else 0)


if __name__ == '__main__':
    main()
