#!/usr/bin/env python3
"""
Script pour configurer:
1. S3 Replication de polystudens3 vers polystudents3-back
2. CloudTrail pour logger les modifications/suppressions d'objets
"""
import boto3
import json
import time
from botocore.exceptions import ClientError


class S3ReplicationCloudTrail:
    def __init__(self, source_bucket, destination_bucket, region='us-east-1'):
        """
        Initialise le gestionnaire de replication et CloudTrail
        
        Args:
            source_bucket: Bucket source
            destination_bucket: Bucket destination pour la réplication
            region: Région AWS
        """
        self.source_bucket = source_bucket
        self.destination_bucket = destination_bucket
        self.region = region
        self.s3_client = boto3.client('s3', region_name=region)
        self.iam_client = boto3.client('iam')
        self.cloudtrail = boto3.client('cloudtrail', region_name=region)
        self.sts_client = boto3.client('sts')
        self.account_id = self.sts_client.get_caller_identity()['Account']
    
    def create_destination_bucket(self):
        """Crée le bucket de destination pour la réplication"""
        try:
            print(f"\nCréation du bucket de destination: {self.destination_bucket}...")
            
            if self.region == 'us-east-1':
                self.s3_client.create_bucket(Bucket=self.destination_bucket)
            else:
                self.s3_client.create_bucket(
                    Bucket=self.destination_bucket,
                    CreateBucketConfiguration={'LocationConstraint': self.region}
                )
            
            print(f"Bucket {self.destination_bucket} créé!")
            
            # Activer le versioning (requis pour la réplication)
            self.s3_client.put_bucket_versioning(
                Bucket=self.destination_bucket,
                VersioningConfiguration={'Status': 'Enabled'}
            )
            print(f"Versioning activé sur {self.destination_bucket}")
            
            # Bloquer les accès publics
            self.s3_client.put_public_access_block(
                Bucket=self.destination_bucket,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            print(f"Accès publics bloqués sur {self.destination_bucket}")
            
            # Activer l'encryption
            self.s3_client.put_bucket_encryption(
                Bucket=self.destination_bucket,
                ServerSideEncryptionConfiguration={
                    'Rules': [{
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'AES256'
                        },
                        'BucketKeyEnabled': True
                    }]
                }
            )
            print(f"Encryption activée sur {self.destination_bucket}")
            
            return True
            
        except ClientError as e:
            if 'BucketAlreadyOwnedByYou' in str(e):
                print(f" Le bucket {self.destination_bucket} existe déjà")
                return True
            else:
                print(f" Erreur: {e}")
                return False
    
    def create_replication_role(self):
        """Crée le rôle IAM pour la réplication S3"""
        try:
            role_name = f"S3ReplicationRole-{self.source_bucket}"
            
            print(f"\n Création du rôle IAM pour la réplication...")
            
            # Trust policy
            trust_policy = {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "s3.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }]
            }
            
            try:
                response = self.iam_client.create_role(
                    RoleName=role_name,
                    AssumeRolePolicyDocument=json.dumps(trust_policy),
                    Description='Role for S3 bucket replication',
                    Tags=[
                        {'Key': 'Purpose', 'Value': 'S3Replication'},
                        {'Key': 'ManagedBy', 'Value': 'Python-Boto3'}
                    ]
                )
                role_arn = response['Role']['Arn']
                print(f" Rôle créé: {role_arn}")
            except ClientError as e:
                if 'EntityAlreadyExists' in str(e):
                    response = self.iam_client.get_role(RoleName=role_name)
                    role_arn = response['Role']['Arn']
                    print(f" Rôle existant: {role_arn}")
                else:
                    raise
            
            # Policy pour la réplication
            policy_name = "S3ReplicationPolicy"
            replication_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:GetReplicationConfiguration",
                            "s3:ListBucket"
                        ],
                        "Resource": f"arn:aws:s3:::{self.source_bucket}"
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:GetObjectVersionForReplication",
                            "s3:GetObjectVersionAcl",
                            "s3:GetObjectVersionTagging"
                        ],
                        "Resource": f"arn:aws:s3:::{self.source_bucket}/*"
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:ReplicateObject",
                            "s3:ReplicateDelete",
                            "s3:ReplicateTags"
                        ],
                        "Resource": f"arn:aws:s3:::{self.destination_bucket}/*"
                    }
                ]
            }
            
            try:
                self.iam_client.put_role_policy(
                    RoleName=role_name,
                    PolicyName=policy_name,
                    PolicyDocument=json.dumps(replication_policy)
                )
                print(f" Policy attachée au rôle")
            except ClientError as e:
                print(f" Erreur lors de l'ajout de la policy: {e}")
            
            # Attendre que le rôle soit disponible
            time.sleep(10)
            
            return role_arn
            
        except ClientError as e:
            print(f" Erreur lors de la création du rôle: {e}")
            return None
    
    def enable_source_bucket_versioning(self):
        """Active le versioning sur le bucket source (requis pour la réplication)"""
        try:
            print(f"\n Activation du versioning sur {self.source_bucket}...")
            
            self.s3_client.put_bucket_versioning(
                Bucket=self.source_bucket,
                VersioningConfiguration={'Status': 'Enabled'}
            )
            
            print(f" Versioning activé!")
            return True
            
        except ClientError as e:
            print(f" Erreur: {e}")
            return False
    
    def configure_replication(self, role_arn):
        """Configure la réplication du bucket source vers le bucket destination"""
        try:
            print(f"\n Configuration de la réplication...")
            print(f"   Source: {self.source_bucket}")
            print(f"   Destination: {self.destination_bucket}")
            
            replication_config = {
                'Role': role_arn,
                'Rules': [{
                    'ID': 'ReplicateAll',
                    'Priority': 1,
                    'Status': 'Enabled',
                    'Filter': {},
                    'Destination': {
                        'Bucket': f'arn:aws:s3:::{self.destination_bucket}',
                        'ReplicationTime': {
                            'Status': 'Enabled',
                            'Time': {'Minutes': 15}
                        },
                        'Metrics': {
                            'Status': 'Enabled',
                            'EventThreshold': {'Minutes': 15}
                        }
                    },
                    'DeleteMarkerReplication': {'Status': 'Enabled'}
                }]
            }
            
            self.s3_client.put_bucket_replication(
                Bucket=self.source_bucket,
                ReplicationConfiguration=replication_config
            )
            
            print(f"Réplication configurée avec succès!")
            return True
            
        except ClientError as e:
            print(f"Erreur lors de la configuration: {e}")
            return False
    
    def create_cloudtrail_bucket(self):
        """Crée un bucket pour stocker les logs CloudTrail"""
        try:
            trail_bucket = f"{self.source_bucket}-cloudtrail-logs"
            
            print(f"\n Création du bucket CloudTrail: {trail_bucket}...")
            
            try:
                if self.region == 'us-east-1':
                    self.s3_client.create_bucket(Bucket=trail_bucket)
                else:
                    self.s3_client.create_bucket(
                        Bucket=trail_bucket,
                        CreateBucketConfiguration={'LocationConstraint': self.region}
                    )
                print(f"Bucket créé: {trail_bucket}")
            except ClientError as e:
                if 'BucketAlreadyOwnedByYou' in str(e):
                    print(f" Bucket existant: {trail_bucket}")
                else:
                    raise
            
            # Policy pour CloudTrail
            bucket_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AWSCloudTrailAclCheck",
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudtrail.amazonaws.com"},
                        "Action": "s3:GetBucketAcl",
                        "Resource": f"arn:aws:s3:::{trail_bucket}"
                    },
                    {
                        "Sid": "AWSCloudTrailWrite",
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudtrail.amazonaws.com"},
                        "Action": "s3:PutObject",
                        "Resource": f"arn:aws:s3:::{trail_bucket}/AWSLogs/{self.account_id}/*",
                        "Condition": {
                            "StringEquals": {
                                "s3:x-amz-acl": "bucket-owner-full-control"
                            }
                        }
                    }
                ]
            }
            
            self.s3_client.put_bucket_policy(
                Bucket=trail_bucket,
                Policy=json.dumps(bucket_policy)
            )
            print(f"Bucket policy configurée")
            
            return trail_bucket
            
        except ClientError as e:
            print(f" Erreur: {e}")
            return None
    
    def enable_cloudtrail(self, trail_bucket):
        """Active CloudTrail pour logger les événements S3"""
        try:
            trail_name = f"{self.source_bucket}-data-events"
            
            print(f"\n Configuration de CloudTrail...")
            
            # Créer le trail
            try:
                response = self.cloudtrail.create_trail(
                    Name=trail_name,
                    S3BucketName=trail_bucket,
                    IncludeGlobalServiceEvents=False,
                    IsMultiRegionTrail=False,
                    EnableLogFileValidation=True,
                    TagsList=[
                        {'Key': 'Purpose', 'Value': 'S3DataEvents'},
                        {'Key': 'ManagedBy', 'Value': 'Python-Boto3'}
                    ]
                )
                trail_arn = response['TrailARN']
                print(f" Trail créé: {trail_arn}")
            except ClientError as e:
                if 'TrailAlreadyExists' in str(e):
                    print(f" Trail existant: {trail_name}")
                    response = self.cloudtrail.describe_trails(
                        trailNameList=[trail_name]
                    )
                    trail_arn = response['trailList'][0]['TrailARN']
                else:
                    raise
            
            # Configurer les data events pour S3
            print(f" Configuration des data events S3...")
            
            self.cloudtrail.put_event_selectors(
                TrailName=trail_name,
                EventSelectors=[{
                    'ReadWriteType': 'WriteOnly',  # Seulement les modifications/suppressions
                    'IncludeManagementEvents': False,
                    'DataResources': [{
                        'Type': 'AWS::S3::Object',
                        'Values': [
                            f'arn:aws:s3:::{self.source_bucket}/*'
                        ]
                    }]
                }]
            )
            
            print(f" Data events configurés (WriteOnly)")
            
            # Démarrer le trail
            self.cloudtrail.start_logging(Name=trail_name)
            print(f" CloudTrail démarré!")
            
            return trail_name
            
        except ClientError as e:
            print(f" Erreur: {e}")
            return None
    
    def setup_complete_configuration(self):
        """Configure complètement la réplication et CloudTrail"""
        print("=" * 60)
        print(" CONFIGURATION S3 REPLICATION + CLOUDTRAIL")
        print("=" * 60)
        
        # Étape 1: Créer le bucket de destination
        if not self.create_destination_bucket():
            return False
        
        # Étape 2: Activer le versioning sur le bucket source
        if not self.enable_source_bucket_versioning():
            return False
        
        # Étape 3: Créer le rôle IAM
        role_arn = self.create_replication_role()
        if not role_arn:
            return False
        
        # Étape 4: Configurer la réplication
        if not self.configure_replication(role_arn):
            return False
        
        # Étape 5: Créer le bucket CloudTrail
        trail_bucket = self.create_cloudtrail_bucket()
        if not trail_bucket:
            return False
        
        # Étape 6: Activer CloudTrail
        trail_name = self.enable_cloudtrail(trail_bucket)
        if not trail_name:
            return False
        
        # Résumé
        print("\n" + "=" * 60)
        print(" CONFIGURATION TERMINÉE")
        print("=" * 60)
        
        print(f"\n S3 REPLICATION:")
        print(f"   Source Bucket: {self.source_bucket}")
        print(f"   Destination Bucket: {self.destination_bucket}")
        print(f"   IAM Role: {role_arn}")
        print(f"   Status: Enabled")
        
        print(f"\n CLOUDTRAIL:")
        print(f"   Trail Name: {trail_name}")
        print(f"   Log Bucket: {trail_bucket}")
        print(f"   Events: Write Only (modifications/suppressions)")
        print(f"   Status: Logging")
        
        print(f"\n VÉRIFICATION:")
        print(f"   Console S3: https://s3.console.aws.amazon.com/s3/buckets/{self.source_bucket}")
        print(f"   Console CloudTrail: https://console.aws.amazon.com/cloudtrail/home?region={self.region}")
        
        print(f"\n Note: La réplication peut prendre quelques minutes")
        
        return True
    
    def verify_replication(self):
        """Vérifie la configuration de réplication"""
        try:
            print("\n Vérification de la réplication...")
            
            response = self.s3_client.get_bucket_replication(
                Bucket=self.source_bucket
            )
            
            print(f" Réplication configurée!")
            print(f"\n Configuration:")
            
            for rule in response['ReplicationConfiguration']['Rules']:
                print(f"\n   Rule ID: {rule['ID']}")
                print(f"   Status: {rule['Status']}")
                print(f"   Destination: {rule['Destination']['Bucket']}")
                print(f"   Delete Markers: {rule.get('DeleteMarkerReplication', {}).get('Status', 'N/A')}")
            
            return True
            
        except ClientError as e:
            if 'ReplicationConfigurationNotFoundError' in str(e):
                print(f" Aucune configuration de réplication trouvée")
            else:
                print(f" Erreur: {e}")
            return False
    
    def verify_cloudtrail(self):
        """Vérifie la configuration de CloudTrail"""
        try:
            trail_name = f"{self.source_bucket}-data-events"
            
            print("\n Vérification de CloudTrail...")
            
            response = self.cloudtrail.get_trail_status(Name=trail_name)
            
            print(f" CloudTrail trouvé!")
            print(f"\n Status:")
            print(f"   Logging: {response['IsLogging']}")
            print(f"   Latest Delivery: {response.get('LatestDeliveryTime', 'N/A')}")
            
            # Event selectors
            selectors = self.cloudtrail.get_event_selectors(TrailName=trail_name)
            print(f"\n Event Selectors:")
            for selector in selectors['EventSelectors']:
                print(f"   Read/Write Type: {selector['ReadWriteType']}")
                for resource in selector['DataResources']:
                    print(f"   Resource Type: {resource['Type']}")
                    for value in resource['Values']:
                        print(f"   Resource: {value}")
            
            return True
            
        except ClientError as e:
            print(f" Erreur: {e}")
            return False


def test_replication(source_bucket, region='us-east-1'):
    """Teste la réplication en uploadant un fichier"""
    try:
        print("\n Test de la réplication...")
        
        s3_client = boto3.client('s3', region_name=region)
        
        # Upload un fichier de test
        test_key = 'test-replication.txt'
        test_content = f'Test file created at {time.time()}'
        
        print(f" Upload du fichier de test: {test_key}")
        s3_client.put_object(
            Bucket=source_bucket,
            Key=test_key,
            Body=test_content.encode('utf-8'),
            ServerSideEncryption='AES256'
        )
        
        print(f" Fichier uploadé!")
        print(f"  Attendez 5-10 minutes pour que la réplication se fasse")
        print(f" Vérifiez le bucket de destination dans la console S3")
        
    except ClientError as e:
        print(f" Erreur: {e}")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Configure S3 Replication and CloudTrail'
    )
    parser.add_argument(
        'action',
        choices=['setup', 'verify', 'test'],
        help='Action to perform'
    )
    parser.add_argument(
        '--source-bucket',
        required=True,
        help='Source S3 bucket name'
    )
    parser.add_argument(
        '--destination-bucket',
        help='Destination S3 bucket name (default: source-bucket + -back)'
    )
    parser.add_argument(
        '--region',
        default='us-east-1',
        help='AWS Region'
    )
    
    args = parser.parse_args()
    
    # Destination bucket par défaut
    if not args.destination_bucket:
        # Remplacer "s3" par "ts3" pour obtenir "polystudents3-back"
        args.destination_bucket = args.source_bucket.replace('polystudens3', 'polystudents3-back')
    
    manager = S3ReplicationCloudTrail(
        source_bucket=args.source_bucket,
        destination_bucket=args.destination_bucket,
        region=args.region
    )
    
    if args.action == 'setup':
        manager.setup_complete_configuration()
    
    elif args.action == 'verify':
        manager.verify_replication()
        manager.verify_cloudtrail()
    
    elif args.action == 'test':
        test_replication(args.source_bucket, args.region)


if __name__ == '__main__':
    main()