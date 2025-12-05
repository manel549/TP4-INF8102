#!/usr/bin/env python3
"""
Script pour créer et configurer un bucket S3 avec encryption et sécurité
Basé sur l'exemple polystudens3
"""
import boto3
import json
import sys
from botocore.exceptions import ClientError


class S3BucketCreator:
    def __init__(self, bucket_name, region='us-east-1'):
        """
        Initialise le créateur de bucket S3
        
        Args:
            bucket_name: Nom du bucket S3 (doit être unique globalement)
            region: Région AWS (défaut: us-east-1)
        """
        self.bucket_name = bucket_name
        self.region = region
        self.s3_client = boto3.client('s3', region_name=region)
        
    def create_bucket(self):
        """Crée le bucket S3"""
        try:
            print(f" Création du bucket S3: {self.bucket_name}")
            
            if self.region == 'us-east-1':
                # Pour us-east-1, pas besoin de LocationConstraint
                self.s3_client.create_bucket(Bucket=self.bucket_name)
            else:
                # Pour les autres régions
                self.s3_client.create_bucket(
                    Bucket=self.bucket_name,
                    CreateBucketConfiguration={'LocationConstraint': self.region}
                )
            
            print(f" Bucket '{self.bucket_name}' créé avec succès!")
            return True
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'BucketAlreadyOwnedByYou':
                print(f"ℹLe bucket '{self.bucket_name}' existe déjà et vous appartient.")
                return True
            elif error_code == 'BucketAlreadyExists':
                print(f"Erreur: Le bucket '{self.bucket_name}' existe déjà (appartient à quelqu'un d'autre).")
                return False
            else:
                print(f"Erreur lors de la création du bucket: {e}")
                return False
    
    def enable_versioning(self):
        """Active le versioning sur le bucket"""
        try:
            print(f"Activation du versioning...")
            
            self.s3_client.put_bucket_versioning(
                Bucket=self.bucket_name,
                VersioningConfiguration={'Status': 'Enabled'}
            )
            
            print("Versioning activé!")
            return True
            
        except ClientError as e:
            print(f"Erreur lors de l'activation du versioning: {e}")
            return False
    
    def enable_encryption(self, encryption_type='AES256'):
        """
        Active l'encryption par défaut sur le bucket
        
        Args:
            encryption_type: 'AES256' (SSE-S3) ou 'aws:kms' (SSE-KMS)
        """
        try:
            print(f"Activation de l'encryption ({encryption_type})...")
            
            if encryption_type == 'AES256':
                encryption_config = {
                    'Rules': [{
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'AES256'
                        },
                        'BucketKeyEnabled': True
                    }]
                }
            else:  # aws:kms
                encryption_config = {
                    'Rules': [{
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'aws:kms'
                        },
                        'BucketKeyEnabled': True
                    }]
                }
            
            self.s3_client.put_bucket_encryption(
                Bucket=self.bucket_name,
                ServerSideEncryptionConfiguration=encryption_config
            )
            
            print("Encryption activée!")
            return True
            
        except ClientError as e:
            print(f"Erreur lors de l'activation de l'encryption: {e}")
            return False
    
    def block_public_access(self):
        """Bloque tous les accès publics au bucket"""
        try:
            print(f"Blocage des accès publics...")
            
            self.s3_client.put_public_access_block(
                Bucket=self.bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            
            print("Accès publics bloqués!")
            return True
            
        except ClientError as e:
            print(f"Erreur lors du blocage des accès publics: {e}")
            return False
    
    def enable_logging(self, target_bucket=None, target_prefix='logs/'):
        """
        Active le logging du bucket
        
        Args:
            target_bucket: Bucket de destination pour les logs (si None, utilise le même bucket)
            target_prefix: Préfixe pour les logs
        """
        try:
            print(f"Activation du logging...")
            
            if target_bucket is None:
                target_bucket = self.bucket_name
            
            self.s3_client.put_bucket_logging(
                Bucket=self.bucket_name,
                BucketLoggingStatus={
                    'LoggingEnabled': {
                        'TargetBucket': target_bucket,
                        'TargetPrefix': target_prefix
                    }
                }
            )
            
            print("Logging activé!")
            return True
            
        except ClientError as e:
            print(f"Erreur lors de l'activation du logging: {e}")
            return False
    
    def add_lifecycle_policy(self):
        """Ajoute une politique de cycle de vie (exemple: suppression après 90 jours)"""
        try:
            print(f"Ajout de la politique de cycle de vie...")
            
            lifecycle_config = {
                'Rules': [
                    {
                        'Id': 'DeleteOldVersions',
                        'Status': 'Enabled',
                        'NoncurrentVersionExpiration': {
                            'NoncurrentDays': 90
                        }
                    },
                    {
                        'Id': 'TransitionToIA',
                        'Status': 'Enabled',
                        'Transitions': [
                            {
                                'Days': 30,
                                'StorageClass': 'STANDARD_IA'
                            },
                            {
                                'Days': 90,
                                'StorageClass': 'GLACIER'
                            }
                        ]
                    }
                ]
            }
            
            self.s3_client.put_bucket_lifecycle_configuration(
                Bucket=self.bucket_name,
                LifecycleConfiguration=lifecycle_config
            )
            
            print("Politique de cycle de vie ajoutée!")
            return True
            
        except ClientError as e:
            print(f"Ereur lors de l'ajout de la politique de cycle de vie: {e}")
            return False
    
    def add_bucket_policy(self, policy_type='deny_insecure_transport'):
        """
        Ajoute une politique de sécurité au bucket
        
        Args:
            policy_type: Type de politique ('deny_insecure_transport', 'enforce_encryption')
        """
        try:
            print(f"Ajout de la bucket policy...")
            
            account_id = boto3.client('sts').get_caller_identity()['Account']
            
            if policy_type == 'deny_insecure_transport':
                # Refuse les connexions non-HTTPS
                policy = {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "DenyInsecureTransport",
                            "Effect": "Deny",
                            "Principal": "*",
                            "Action": "s3:*",
                            "Resource": [
                                f"arn:aws:s3:::{self.bucket_name}",
                                f"arn:aws:s3:::{self.bucket_name}/*"
                            ],
                            "Condition": {
                                "Bool": {
                                    "aws:SecureTransport": "false"
                                }
                            }
                        }
                    ]
                }
            elif policy_type == 'enforce_encryption':
                # Force l'encryption lors de l'upload
                policy = {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "DenyUnencryptedObjectUploads",
                            "Effect": "Deny",
                            "Principal": "*",
                            "Action": "s3:PutObject",
                            "Resource": f"arn:aws:s3:::{self.bucket_name}/*",
                            "Condition": {
                                "StringNotEquals": {
                                    "s3:x-amz-server-side-encryption": "AES256"
                                }
                            }
                        }
                    ]
                }
            
            self.s3_client.put_bucket_policy(
                Bucket=self.bucket_name,
                Policy=json.dumps(policy)
            )
            
            print("Bucket policy ajoutée!")
            return True
            
        except ClientError as e:
            print(f"Erreur lors de l'ajout de la bucket policy: {e}")
            return False
    
    def add_tags(self, tags):
        """
        Ajoute des tags au bucket
        
        Args:
            tags: Dictionnaire de tags {'Key': 'Value'}
        """
        try:
            print(f"Ajout des tags...")
            
            tag_set = [{'Key': k, 'Value': v} for k, v in tags.items()]
            
            self.s3_client.put_bucket_tagging(
                Bucket=self.bucket_name,
                Tagging={'TagSet': tag_set}
            )
            
            print("Tags ajoutés!")
            return True
            
        except ClientError as e:
            print(f"Erreur lors de l'ajout des tags: {e}")
            return False
    
    def get_bucket_info(self):
        """Récupère et affiche les informations du bucket"""
        try:
            print("\n" + "=" * 60)
            print(f"INFORMATIONS DU BUCKET: {self.bucket_name}")
            print("=" * 60)
            
            # Location
            try:
                location = self.s3_client.get_bucket_location(Bucket=self.bucket_name)
                region = location['LocationConstraint'] or 'us-east-1'
                print(f"\n Région: {region}")
            except:
                pass
            
            # Versioning
            try:
                versioning = self.s3_client.get_bucket_versioning(Bucket=self.bucket_name)
                status = versioning.get('Status', 'Disabled')
                print(f"Versioning: {status}")
            except:
                pass
            
            # Encryption
            try:
                encryption = self.s3_client.get_bucket_encryption(Bucket=self.bucket_name)
                algo = encryption['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm']
                print(f"Encryption: {algo}")
            except:
                print(f"Encryption: Non configurée")
            
            # Public Access Block
            try:
                public_access = self.s3_client.get_public_access_block(Bucket=self.bucket_name)
                config = public_access['PublicAccessBlockConfiguration']
                print(f"Accès public bloqué: {config['BlockPublicAcls']}")
            except:
                pass
            
            # Tags
            try:
                tags = self.s3_client.get_bucket_tagging(Bucket=self.bucket_name)
                print(f"\n Tags:")
                for tag in tags['TagSet']:
                    print(f"   - {tag['Key']}: {tag['Value']}")
            except:
                print(f" Tags: Aucun")
            
            print("\n" + "=" * 60)
            
        except ClientError as e:
            print(f" Erreur lors de la récupération des informations: {e}")
    
    def setup_secure_bucket(self, enable_lifecycle=False):
        """
        Configure un bucket S3 complet et sécurisé
        
        Args:
            enable_lifecycle: Active ou non les politiques de cycle de vie
        """
        print("\n" + "=" * 60)
        print(" CONFIGURATION DU BUCKET S3 SÉCURISÉ")
        print("=" * 60 + "\n")
        
        # Étape 1: Créer le bucket
        if not self.create_bucket():
            return False
        
        print()
        
        # Étape 2: Bloquer les accès publics
        self.block_public_access()
        print()
        
        # Étape 3: Activer l'encryption
        self.enable_encryption('AES256')
        print()
        
        # Étape 4: Activer le versioning
        self.enable_versioning()
        print()
        
        # Étape 5: Ajouter une bucket policy
        self.add_bucket_policy('deny_insecure_transport')
        print()
        
        # Étape 6: Ajouter des tags
        tags = {
            'Environment': 'Development',
            'Project': 'PolyStudent',
            'ManagedBy': 'Python-Boto3',
            'Security': 'High'
        }
        self.add_tags(tags)
        print()
        
        # Étape 7 (optionnel): Politique de cycle de vie
        if enable_lifecycle:
            self.add_lifecycle_policy()
            print()
        
        # Afficher les informations finales
        self.get_bucket_info()
        
        print("\n Configuration complète du bucket terminée avec succès!")
        print(f"\n URL du bucket: https://s3.console.aws.amazon.com/s3/buckets/{self.bucket_name}")
        
        return True


def delete_bucket(bucket_name, region='us-east-1'):
    """
    Supprime un bucket S3 (le bucket doit être vide)
    
    Args:
        bucket_name: Nom du bucket à supprimer
        region: Région AWS
    """
    s3_client = boto3.client('s3', region_name=region)
    s3_resource = boto3.resource('s3', region_name=region)
    
    print(f" Suppression du bucket: {bucket_name}")
    print("  ATTENTION: Cette opération va supprimer le bucket et tout son contenu!")
    
    confirmation = input("Tapez 'yes' pour confirmer: ")
    if confirmation.lower() != 'yes':
        print(" Suppression annulée.")
        return
    
    try:
        # Vider le bucket d'abord
        bucket = s3_resource.Bucket(bucket_name)
        
        print(" Suppression de tous les objets...")
        bucket.object_versions.all().delete()
        
        print(" Suppression du bucket...")
        s3_client.delete_bucket(Bucket=bucket_name)
        
        print(" Bucket supprimé avec succès!")
        
    except ClientError as e:
        print(f" Erreur lors de la suppression: {e}")


def list_buckets():
    """Liste tous les buckets S3"""
    s3_client = boto3.client('s3')
    
    print(" Liste des buckets S3:")
    print("-" * 60)
    
    try:
        response = s3_client.list_buckets()
        
        if response['Buckets']:
            for bucket in response['Buckets']:
                print(f"\n {bucket['Name']}")
                print(f"   Créé le: {bucket['CreationDate']}")
        else:
            print("Aucun bucket trouvé.")
            
    except ClientError as e:
        print(f" Erreur: {e}")


def main():
    """Fonction principale"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Créer et gérer des buckets S3 sécurisés avec Python'
    )
    parser.add_argument(
        'action',
        choices=['create', 'delete', 'list', 'info'],
        help='Action à effectuer'
    )
    parser.add_argument(
        '--bucket-name',
        help='Nom du bucket S3 (doit être unique globalement)'
    )
    parser.add_argument(
        '--region',
        default='us-east-1',
        help='Région AWS (défaut: us-east-1)'
    )
    parser.add_argument(
        '--with-lifecycle',
        action='store_true',
        help='Activer les politiques de cycle de vie'
    )
    
    args = parser.parse_args()
    
    if args.action in ['create', 'delete', 'info'] and not args.bucket_name:
        print(" Erreur: --bucket-name est requis pour cette action")
        sys.exit(1)
    
    if args.action == 'create':
        creator = S3BucketCreator(args.bucket_name, args.region)
        creator.setup_secure_bucket(enable_lifecycle=args.with_lifecycle)
        
    elif args.action == 'delete':
        delete_bucket(args.bucket_name, args.region)
        
    elif args.action == 'list':
        list_buckets()
        
    elif args.action == 'info':
        creator = S3BucketCreator(args.bucket_name, args.region)
        creator.get_bucket_info()


if __name__ == '__main__':
    main()