#!/usr/bin/env python3
"""
Script pour ajouter VPC Flow Logs au VPC existant
Flow Logs captures seulement les paquets REJETÉS et les envoie au bucket S3
"""
import boto3
import json
import time
from botocore.exceptions import ClientError


class VPCFlowLogsManager:
    def __init__(self, vpc_id, s3_bucket_name, region='us-east-1'):
        """
        Initialise le gestionnaire de Flow Logs
        
        Args:
            vpc_id: ID du VPC
            s3_bucket_name: Nom du bucket S3 pour les logs
            region: Région AWS
        """
        self.vpc_id = vpc_id
        self.s3_bucket_name = s3_bucket_name
        self.region = region
        self.ec2_client = boto3.client('ec2', region_name=region)
        self.s3_client = boto3.client('s3', region_name=region)
        self.sts_client = boto3.client('sts', region_name=region)
        self.account_id = self.sts_client.get_caller_identity()['Account']
    
    def create_s3_bucket_policy_for_flowlogs(self):
        """Ajoute la policy nécessaire au bucket S3 pour recevoir les Flow Logs"""
        try:
            print(f" Configuration de la bucket policy pour les Flow Logs...")
            
            # Policy qui permet au service VPC Flow Logs d'écrire dans le bucket
            bucket_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AWSLogDeliveryWrite",
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "delivery.logs.amazonaws.com"
                        },
                        "Action": "s3:PutObject",
                        "Resource": f"arn:aws:s3:::{self.s3_bucket_name}/vpc-flow-logs/*",
                        "Condition": {
                            "StringEquals": {
                                "s3:x-amz-acl": "bucket-owner-full-control",
                                "aws:SourceAccount": self.account_id
                            },
                            "ArnLike": {
                                "aws:SourceArn": f"arn:aws:logs:{self.region}:{self.account_id}:*"
                            }
                        }
                    },
                    {
                        "Sid": "AWSLogDeliveryAclCheck",
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "delivery.logs.amazonaws.com"
                        },
                        "Action": "s3:GetBucketAcl",
                        "Resource": f"arn:aws:s3:::{self.s3_bucket_name}",
                        "Condition": {
                            "StringEquals": {
                                "aws:SourceAccount": self.account_id
                            },
                            "ArnLike": {
                                "aws:SourceArn": f"arn:aws:logs:{self.region}:{self.account_id}:*"
                            }
                        }
                    },
                    {
                        "Sid": "DenyInsecureTransport",
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "s3:*",
                        "Resource": [
                            f"arn:aws:s3:::{self.s3_bucket_name}",
                            f"arn:aws:s3:::{self.s3_bucket_name}/*"
                        ],
                        "Condition": {
                            "Bool": {
                                "aws:SecureTransport": "false"
                            }
                        }
                    }
                ]
            }
            
            self.s3_client.put_bucket_policy(
                Bucket=self.s3_bucket_name,
                Policy=json.dumps(bucket_policy)
            )
            
            print("Bucket policy configurée!")
            return True
            
        except ClientError as e:
            print(f"Erreur lors de la configuration de la bucket policy: {e}")
            return False
    
    def enable_flow_logs(self, traffic_type='REJECT'):
        """
        Active les VPC Flow Logs
        
        Args:
            traffic_type: Type de trafic à capturer (ACCEPT, REJECT, ALL)
                         Par défaut: REJECT (seulement les paquets rejetés)
        """
        try:
            print(f"\n Activation des VPC Flow Logs...")
            print(f"   VPC ID: {self.vpc_id}")
            print(f"   S3 Bucket: {self.s3_bucket_name}")
            print(f"   Traffic Type: {traffic_type} (rejected packets only)")
            
            # Créer les Flow Logs
            response = self.ec2_client.create_flow_logs(
                ResourceType='VPC',
                ResourceIds=[self.vpc_id],
                TrafficType=traffic_type,
                LogDestinationType='s3',
                LogDestination=f"arn:aws:s3:::{self.s3_bucket_name}/vpc-flow-logs/",
                LogFormat='${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status}',
                TagSpecifications=[
                    {
                        'ResourceType': 'vpc-flow-log',
                        'Tags': [
                            {'Key': 'Name', 'Value': f'{self.vpc_id}-flowlogs'},
                            {'Key': 'Environment', 'Value': 'polystudent'},
                            {'Key': 'ManagedBy', 'Value': 'Python-Boto3'}
                        ]
                    }
                ]
            )
            
            if response['Unsuccessful']:
                print(f"Erreur lors de la création des Flow Logs:")
                for error in response['Unsuccessful']:
                    print(f"   {error['Error']['Message']}")
                return False
            
            flow_log_id = response['FlowLogIds'][0]
            print(f"Flow Logs créés avec succès!")
            print(f"   Flow Log ID: {flow_log_id}")
            
            return flow_log_id
            
        except ClientError as e:
            print(f" Erreur lors de l'activation des Flow Logs: {e}")
            return False
    
    def verify_flow_logs(self):
        """Vérifie que les Flow Logs sont bien configurés"""
        try:
            print(f"\n Vérification des Flow Logs...")
            
            response = self.ec2_client.describe_flow_logs(
                Filters=[
                    {'Name': 'resource-id', 'Values': [self.vpc_id]}
                ]
            )
            
            if not response['FlowLogs']:
                print(" Aucun Flow Log trouvé pour ce VPC")
                return False
            
            print(f" Flow Logs trouvés: {len(response['FlowLogs'])}")
            
            for fl in response['FlowLogs']:
                print(f"\n Flow Log Details:")
                print(f"   ID: {fl['FlowLogId']}")
                print(f"   Status: {fl['FlowLogStatus']}")
                print(f"   Traffic Type: {fl['TrafficType']}")
                print(f"   Destination: {fl.get('LogDestination', 'N/A')}")
                print(f"   Created: {fl['CreationTime']}")
            
            return True
            
        except ClientError as e:
            print(f" Erreur lors de la vérification: {e}")
            return False
    
    def setup_complete_flowlogs(self):
        """Configure complètement les Flow Logs"""
        print("=" * 60)
        print(" CONFIGURATION DES VPC FLOW LOGS")
        print("=" * 60)
        
        # Étape 1: Configurer la bucket policy
        if not self.create_s3_bucket_policy_for_flowlogs():
            print("\n Échec de la configuration de la bucket policy")
            return False
        
        # Étape 2: Activer les Flow Logs (REJECT only)
        flow_log_id = self.enable_flow_logs(traffic_type='REJECT')
        if not flow_log_id:
            print("\n Échec de l'activation des Flow Logs")
            return False
        
        # Étape 3: Vérifier
        time.sleep(2)  # Attendre un peu
        self.verify_flow_logs()
        
        print("\n" + "=" * 60)
        print(" Configuration des Flow Logs terminée!")
        print("=" * 60)
        print(f"\n Les logs des paquets REJETÉS seront disponibles dans:")
        print(f"   s3://{self.s3_bucket_name}/vpc-flow-logs/")
        print(f"\n Note: Les premiers logs peuvent prendre 10-15 minutes à apparaître")
        
        return True


def get_vpc_id_from_stack(stack_name='PolyStudentVpcStack', region='us-east-1'):
    """Récupère le VPC ID depuis une stack CloudFormation"""
    try:
        cf_client = boto3.client('cloudformation', region_name=region)
        response = cf_client.describe_stacks(StackName=stack_name)
        
        outputs = response['Stacks'][0]['Outputs']
        for output in outputs:
            if output['OutputKey'] == 'VPCId':
                return output['OutputValue']
        
        return None
    except:
        return None


def list_vpcs(region='us-east-1'):
    """Liste tous les VPCs disponibles"""
    ec2_client = boto3.client('ec2', region_name=region)
    
    print("\n VPCs disponibles:")
    print("-" * 60)
    
    response = ec2_client.describe_vpcs()
    
    for vpc in response['Vpcs']:
        vpc_id = vpc['VpcId']
        cidr = vpc['CidrBlock']
        name = 'N/A'
        
        if 'Tags' in vpc:
            for tag in vpc['Tags']:
                if tag['Key'] == 'Name':
                    name = tag['Value']
                    break
        
        print(f"VPC ID: {vpc_id}")
        print(f"  Name: {name}")
        print(f"  CIDR: {cidr}")
        print()


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Configure VPC Flow Logs to capture rejected packets to S3'
    )
    parser.add_argument(
        '--vpc-id',
        help='VPC ID (ex: vpc-xxxxx)'
    )
    parser.add_argument(
        '--stack-name',
        default='PolyStudentVpcStack',
        help='CloudFormation stack name to get VPC ID'
    )
    parser.add_argument(
        '--bucket-name',
        required=True,
        help='S3 bucket name for Flow Logs (ex: polystudens3-tp4)'
    )
    parser.add_argument(
        '--region',
        default='us-east-1',
        help='AWS Region'
    )
    parser.add_argument(
        '--list-vpcs',
        action='store_true',
        help='List all available VPCs'
    )
    
    args = parser.parse_args()
    
    if args.list_vpcs:
        list_vpcs(args.region)
        return
    
    # Obtenir le VPC ID
    vpc_id = args.vpc_id
    
    if not vpc_id:
        print(" Recherche du VPC ID depuis la stack CloudFormation...")
        vpc_id = get_vpc_id_from_stack(args.stack_name, args.region)
        
        if vpc_id:
            print(f" VPC ID trouvé: {vpc_id}")
        else:
            print(" VPC ID non trouvé. Utilisez --vpc-id ou --list-vpcs")
            return
    
    # Configurer les Flow Logs
    manager = VPCFlowLogsManager(vpc_id, args.bucket_name, args.region)
    manager.setup_complete_flowlogs()


if __name__ == '__main__':
    main()