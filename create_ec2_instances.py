#!/usr/bin/env python3
"""
Script pour créer des instances EC2 avec IAM Role LabRole et CloudWatch Alarms
2 instances publiques (AZ1, AZ2) et 2 instances privées (AZ1, AZ2)
"""
import boto3
import time
from botocore.exceptions import ClientError


class EC2InstanceManager:
    def __init__(self, region='us-east-1'):
        """Initialise le gestionnaire d'instances EC2"""
        self.region = region
        self.ec2_client = boto3.client('ec2', region_name=region)
        self.ec2_resource = boto3.resource('ec2', region_name=region)
        self.cloudwatch = boto3.client('cloudwatch', region_name=region)
        self.iam_client = boto3.client('iam', region_name=region)
        self.cf_client = boto3.client('cloudformation', region_name=region)
    
    def get_vpc_resources_from_stack(self, stack_name='PolyStudentVpcStack'):
        """Récupère les ressources VPC depuis la stack CloudFormation"""
        try:
            print(f" Récupération des ressources VPC depuis {stack_name}...")
            
            response = self.cf_client.describe_stacks(StackName=stack_name)
            outputs = response['Stacks'][0]['Outputs']
            
            resources = {}
            for output in outputs:
                key = output['OutputKey']
                value = output['OutputValue']
                resources[key] = value
            
            print(f"Ressources récupérées!")
            return resources
            
        except ClientError as e:
            print(f"Erreur: {e}")
            return None
    
    def verify_iam_role(self, role_name='LabRole'):
        """Vérifie que le rôle IAM existe"""
        try:
            print(f"\n Vérification du rôle IAM: {role_name}...")
            
            self.iam_client.get_role(RoleName=role_name)
            print(f" Rôle {role_name} trouvé!")
            return True
            
        except ClientError as e:
            if 'NoSuchEntity' in str(e):
                print(f"Le rôle {role_name} n'existe pas!")
                print(f" Créez le rôle dans IAM ou utilisez un autre rôle avec --iam-role")
                return False
            else:
                print(f" Erreur: {e}")
                return False
    
    def get_latest_ami(self, ami_name_pattern='amzn2-ami-hvm-*-x86_64-gp2'):
        """Récupère la dernière AMI Amazon Linux 2"""
        try:
            print(f"\n Recherche de l'AMI la plus récente...")
            
            response = self.ec2_client.describe_images(
                Owners=['amazon'],
                Filters=[
                    {'Name': 'name', 'Values': [ami_name_pattern]},
                    {'Name': 'state', 'Values': ['available']},
                    {'Name': 'architecture', 'Values': ['x86_64']},
                    {'Name': 'root-device-type', 'Values': ['ebs']}
                ]
            )
            
            # Trier par date de création
            images = sorted(response['Images'], 
                          key=lambda x: x['CreationDate'], 
                          reverse=True)
            
            if images:
                ami_id = images[0]['ImageId']
                ami_name = images[0]['Name']
                print(f" AMI trouvée: {ami_id} ({ami_name})")
                return ami_id
            else:
                print(" Aucune AMI trouvée")
                return None
                
        except ClientError as e:
            print(f" Erreur: {e}")
            return None
    
    def create_instance(self, subnet_id, security_group_id, instance_name, 
                       iam_role, ami_id, instance_type='t2.micro'):
        """Crée une instance EC2"""
        try:
            print(f"\n  Création de l'instance: {instance_name}...")
            
            # User data pour installer CloudWatch agent
            user_data = """#!/bin/bash
yum update -y
yum install -y amazon-cloudwatch-agent
echo "Instance {instance_name} ready" > /tmp/status.txt
"""
            
            response = self.ec2_resource.create_instances(
                ImageId=ami_id,
                InstanceType=instance_type,
                MinCount=1,
                MaxCount=1,
                NetworkInterfaces=[{
                    'SubnetId': subnet_id,
                    'DeviceIndex': 0,
                    'AssociatePublicIpAddress': True if 'Public' in instance_name else False,
                    'Groups': [security_group_id]
                }],
                IamInstanceProfile={'Name': iam_role},
                UserData=user_data.format(instance_name=instance_name),
                TagSpecifications=[{
                    'ResourceType': 'instance',
                    'Tags': [
                        {'Key': 'Name', 'Value': instance_name},
                        {'Key': 'Environment', 'Value': 'polystudent'},
                        {'Key': 'ManagedBy', 'Value': 'Python-Boto3'}
                    ]
                }],
                Monitoring={'Enabled': True}  # Enable detailed monitoring
            )
            
            instance = response[0]
            instance_id = instance.id
            
            print(f" Instance créée: {instance_id}")
            print(f"   En attente du démarrage...")
            
            # Attendre que l'instance soit running
            instance.wait_until_running()
            instance.reload()
            
            print(f" Instance {instance_id} est maintenant running!")
            
            return instance_id
            
        except ClientError as e:
            print(f" Erreur lors de la création: {e}")
            return None
    
    def create_cloudwatch_alarm(self, instance_id, instance_name, 
                                threshold=1000, period=60):
        """
        Crée une alarme CloudWatch pour surveiller les paquets entrants
        
        Args:
            instance_id: ID de l'instance
            instance_name: Nom de l'instance
            threshold: Seuil en paquets/sec (défaut: 1000)
            period: Période en secondes (défaut: 60)
        """
        try:
            print(f"\n Création de l'alarme CloudWatch pour {instance_name}...")
            
            alarm_name = f"{instance_name}-HighIngressPackets"
            
            self.cloudwatch.put_metric_alarm(
                AlarmName=alarm_name,
                ComparisonOperator='GreaterThanThreshold',
                EvaluationPeriods=1,
                MetricName='NetworkPacketsIn',
                Namespace='AWS/EC2',
                Period=period,
                Statistic='Average',
                Threshold=threshold,
                ActionsEnabled=True,
                AlarmDescription=f'Alarm when ingress packets exceed {threshold} pkts/sec',
                Dimensions=[
                    {
                        'Name': 'InstanceId',
                        'Value': instance_id
                    }
                ],
                Unit='Count',
                TreatMissingData='notBreaching',
                Tags=[
                    {'Key': 'Name', 'Value': alarm_name},
                    {'Key': 'Instance', 'Value': instance_name},
                    {'Key': 'ManagedBy', 'Value': 'Python-Boto3'}
                ]
            )
            
            print(f" Alarme créée: {alarm_name}")
            print(f" Seuil: {threshold} paquets/sec (moyenne sur {period}s)")
            
            return alarm_name
            
        except ClientError as e:
            print(f" Erreur lors de la création de l'alarme: {e}")
            return None
    
    def create_all_instances(self, vpc_resources, iam_role='LabRole', 
                           instance_type='t2.micro', alarm_threshold=1000):
        """Crée toutes les instances EC2 (2 publiques, 2 privées)"""
        
        print("\n" + "=" * 60)
        print(" CRÉATION DES INSTANCES EC2")
        print("=" * 60)
        
        # Vérifier le rôle IAM
        if not self.verify_iam_role(iam_role):
            return False
        
        # Obtenir l'AMI
        ami_id = self.get_latest_ami()
        if not ami_id:
            return False
        
        instances = []
        
        # Configuration des instances
        instance_configs = [
            {
                'name': 'polystudent-public-az1',
                'subnet_key': 'PublicSubnet1Id',
                'sg_key': 'SecurityGroupAZ1',
                'type': 'public'
            },
            {
                'name': 'polystudent-public-az2',
                'subnet_key': 'PublicSubnet2Id',
                'sg_key': 'SecurityGroupAZ2',
                'type': 'public'
            },
            {
                'name': 'polystudent-private-az1',
                'subnet_key': 'PrivateSubnet1Id',
                'sg_key': 'SecurityGroupAZ1',
                'type': 'private'
            },
            {
                'name': 'polystudent-private-az2',
                'subnet_key': 'PrivateSubnet2Id',
                'sg_key': 'SecurityGroupAZ2',
                'type': 'private'
            }
        ]
        
        # Créer chaque instance
        for config in instance_configs:
            subnet_id = vpc_resources.get(config['subnet_key'])
            sg_id = vpc_resources.get(config['sg_key'])
            
            if not subnet_id or not sg_id:
                print(f" Ressources manquantes pour {config['name']}")
                continue
            
            instance_id = self.create_instance(
                subnet_id=subnet_id,
                security_group_id=sg_id,
                instance_name=config['name'],
                iam_role=iam_role,
                ami_id=ami_id,
                instance_type=instance_type
            )
            
            if instance_id:
                # Créer l'alarme CloudWatch
                alarm_name = self.create_cloudwatch_alarm(
                    instance_id=instance_id,
                    instance_name=config['name'],
                    threshold=alarm_threshold
                )
                
                instances.append({
                    'name': config['name'],
                    'id': instance_id,
                    'type': config['type'],
                    'alarm': alarm_name
                })
        
        # Résumé
        print("\n" + "=" * 60)
        print(" RÉSUMÉ DES INSTANCES CRÉÉES")
        print("=" * 60)
        
        for inst in instances:
            print(f"\n  {inst['name']} ({inst['type'].upper()})")
            print(f"   Instance ID: {inst['id']}")
            print(f"   Alarme CloudWatch: {inst['alarm']}")
        
        print("\n" + "=" * 60)
        print(" Toutes les instances ont été créées avec succès!")
        print("=" * 60)
        print(f"\n IAM Role: {iam_role}")
        print(f" CloudWatch Alarm Threshold: {alarm_threshold} pkts/sec")
        print(f"\n Vérifiez les instances dans la console EC2:")
        print(f"   https://console.aws.amazon.com/ec2/v2/home?region={self.region}#Instances:")
        
        return instances
    
    def get_instance_info(self, instance_ids):
        """Récupère les informations détaillées des instances"""
        try:
            response = self.ec2_client.describe_instances(InstanceIds=instance_ids)
            
            print("\n" + "=" * 60)
            print(" INFORMATIONS DES INSTANCES")
            print("=" * 60)
            
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    name = 'N/A'
                    for tag in instance.get('Tags', []):
                        if tag['Key'] == 'Name':
                            name = tag['Value']
                            break
                    
                    print(f"\n  {name}")
                    print(f"   Instance ID: {instance['InstanceId']}")
                    print(f"   State: {instance['State']['Name']}")
                    print(f"   Type: {instance['InstanceType']}")
                    print(f"   Private IP: {instance.get('PrivateIpAddress', 'N/A')}")
                    print(f"   Public IP: {instance.get('PublicIpAddress', 'N/A')}")
                    print(f"   Subnet: {instance['SubnetId']}")
                    print(f"   IAM Profile: {instance.get('IamInstanceProfile', {}).get('Arn', 'N/A')}")
            
        except ClientError as e:
            print(f" Erreur: {e}")


def list_instances(region='us-east-1'):
    """Liste toutes les instances EC2"""
    ec2_client = boto3.client('ec2', region_name=region)
    
    print("\n Instances EC2 existantes:")
    print("-" * 60)
    
    response = ec2_client.describe_instances()
    
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            name = 'N/A'
            for tag in instance.get('Tags', []):
                if tag['Key'] == 'Name':
                    name = tag['Value']
                    break
            
            print(f"\nInstance: {name}")
            print(f"  ID: {instance['InstanceId']}")
            print(f"  State: {instance['State']['Name']}")
            print(f"  Type: {instance['InstanceType']}")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Create EC2 instances with IAM Role and CloudWatch Alarms'
    )
    parser.add_argument(
        'action',
        choices=['create', 'list', 'info'],
        help='Action to perform'
    )
    parser.add_argument(
        '--stack-name',
        default='PolyStudentVpcStack',
        help='CloudFormation stack name'
    )
    parser.add_argument(
        '--iam-role',
        default='LabRole',
        help='IAM role name (default: LabRole)'
    )
    parser.add_argument(
        '--instance-type',
        default='t2.micro',
        help='EC2 instance type (default: t2.micro)'
    )
    parser.add_argument(
        '--alarm-threshold',
        type=int,
        default=1000,
        help='CloudWatch alarm threshold in pkts/sec (default: 1000)'
    )
    parser.add_argument(
        '--region',
        default='us-east-1',
        help='AWS Region'
    )
    parser.add_argument(
        '--instance-ids',
        nargs='+',
        help='Instance IDs for info command'
    )
    
    args = parser.parse_args()
    
    manager = EC2InstanceManager(region=args.region)
    
    if args.action == 'create':
        # Récupérer les ressources VPC
        vpc_resources = manager.get_vpc_resources_from_stack(args.stack_name)
        
        if not vpc_resources:
            print(" Impossible de récupérer les ressources VPC")
            return
        
        # Créer les instances
        manager.create_all_instances(
            vpc_resources=vpc_resources,
            iam_role=args.iam_role,
            instance_type=args.instance_type,
            alarm_threshold=args.alarm_threshold
        )
    
    elif args.action == 'list':
        list_instances(args.region)
    
    elif args.action == 'info':
        if not args.instance_ids:
            print(" Veuillez spécifier --instance-ids")
            return
        manager.get_instance_info(args.instance_ids)


if __name__ == '__main__':
    main()