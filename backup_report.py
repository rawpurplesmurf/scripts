#!/usr/bin/env python3
import boto3
import csv
from datetime import datetime, timedelta, timezone

def get_account_id_and_region():
    session = boto3.session.Session()
    region = session.region_name or 'us-east-1'
    sts = session.client('sts')
    account = sts.get_caller_identity()['Account']
    return account, region

def get_ec2_backup_summary(account, region):
    ec2 = boto3.client('ec2', region_name=region)
    paginator = ec2.get_paginator('describe_instances')
    filters = [{'Name': 'tag-key', 'Values': ['cpm_backup']}]

    rows = []
    for page in paginator.paginate(Filters=filters):
        for reservation in page['Reservations']:
            for inst in reservation['Instances']:
                inst_id = inst['InstanceId']
                tag_value = next(
                    (t['Value'] for t in inst.get('Tags', []) if t['Key'] == 'cpm_backup'),
                    ''
                )
                vol_ids = [
                    bdm['Ebs']['VolumeId']
                    for bdm in inst.get('BlockDeviceMappings', [])
                    if 'Ebs' in bdm
                ]
                if not vol_ids:
                    # still emit instance row even if no volumes
                    rows.append({
                        'InstanceId': inst_id,
                        'BackupTagValue': tag_value,
                        'VolumeId': '',
                        'SizeGiB': '',
                        'Arn': ''
                    })
                else:
                    vol_resp = ec2.describe_volumes(VolumeIds=vol_ids)
                    for vol in vol_resp['Volumes']:
                        vid = vol['VolumeId']
                        size = vol['Size']
                        arn = f"arn:aws:ec2:{region}:{account}:volume/{vid}"
                        rows.append({
                            'InstanceId': inst_id,
                            'BackupTagValue': tag_value,
                            'VolumeId': vid,
                            'SizeGiB': size,
                            'Arn': arn
                        })
    return rows

def get_rds_backup_summary(region):
    rds = boto3.client('rds', region_name=region)
    paginator = rds.get_paginator('describe_db_instances')
    cutoff = datetime.now(timezone.utc) - timedelta(days=7)

    rows = []
    for page in paginator.paginate():
        for db in page['DBInstances']:
            arn = db['DBInstanceArn']
            tags = rds.list_tags_for_resource(ResourceName=arn)['TagList']
            tag_value = next((t['Value'] for t in tags if t['Key'] == 'cpm_backup'), '')
            if not tag_value:
                continue

            inst_id = db['DBInstanceIdentifier']
            engine = db['Engine']
            snaps = rds.describe_db_snapshots(
                DBInstanceIdentifier=inst_id,
                SnapshotType='manual'
            )['DBSnapshots']
            for snap in snaps:
                if snap['SnapshotCreateTime'] >= cutoff:
                    rows.append({
                        'DBInstanceArn':      arn,
                        'BackupTagValue':     tag_value,
                        'Engine':             engine,
                        'SnapshotIdentifier': snap['DBSnapshotIdentifier'],
                        'SnapshotCreateTime': snap['SnapshotCreateTime'].isoformat(),
                        'AllocatedStorageGiB': snap['AllocatedStorage'],
                        'SnapshotArn':        snap['DBSnapshotArn']
                    })
    return rows

def get_efs_backup_summary(region):
    efs = boto3.client('efs', region_name=region)
    backup = boto3.client('backup', region_name=region)
    paginator = efs.get_paginator('describe_file_systems')

    rows = []
    for page in paginator.paginate():
        for fs in page['FileSystems']:
            fs_id = fs['FileSystemId']
            fs_arn = fs['FileSystemArn']
            tags = efs.list_tags_for_resource(FileSystemId=fs_id).get('Tags', [])
            tag_value = next((t['Value'] for t in tags if t['Key'] == 'cpm_backup'), '')
            if not tag_value:
                continue

            rps = backup.list_recovery_points_by_resource(ResourceArn=fs_arn).get('RecoveryPoints', [])
            recent = sorted(rps, key=lambda x: x['CreationDate'], reverse=True)[:2]
            for rp in recent:
                rows.append({
                    'FileSystemArn':      fs_arn,
                    'BackupTagValue':     tag_value,
                    'RecoveryPointArn':   rp['RecoveryPointArn'],
                    'CreationDate':       rp['CreationDate'].isoformat(),
                    'BackupSizeInBytes':  rp.get('BackupSizeInBytes', '')
                })
    return rows

def write_csv(filename, fieldnames, rows):
    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f'→ Wrote {len(rows)} rows to {filename}')

def main():
    account, region = get_account_id_and_region()

    ec2_rows = get_ec2_backup_summary(account, region)
    rds_rows = get_rds_backup_summary(region)
    efs_rows = get_efs_backup_summary(region)

    write_csv(
        'ec2_backup_summary.csv',
        ['InstanceId','BackupTagValue','VolumeId','SizeGiB','Arn'],
        ec2_rows
    )
    write_csv(
        'rds_backup_summary.csv',
        ['DBInstanceArn','BackupTagValue','Engine','SnapshotIdentifier','SnapshotCreateTime','AllocatedStorageGiB','SnapshotArn'],
        rds_rows
    )
    write_csv(
        'efs_backup_summary.csv',
        ['FileSystemArn','BackupTagValue','RecoveryPointArn','CreationDate','BackupSizeInBytes'],
        efs_rows
    )

if __name__ == '__main__':
    main()

