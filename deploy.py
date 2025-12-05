#!/usr/bin/env python3
"""
Script pour déployer l'infrastructure VPC à partir du fichier vpc.yml
"""
import boto3
import time
import sys
from botocore.exceptions import ClientError


def deploy_cloudformation_stack(stack_name, template_file, parameters=None):
    """
    Déploie ou met à jour une stack CloudFormation
    
    Args:
        stack_name: Nom de la stack CloudFormation
        template_file: Chemin vers le fichier YAML template
        parameters: Liste de paramètres (optionnel)
    """
    
    # Créer le client CloudFormation
    cf_client = boto3.client('cloudformation')
    
    # Lire le fichier template
    try:
        with open(template_file, 'r') as f:
            template_body = f.read()
    except FileNotFoundError:
        print(f"Erreur: Le fichier {template_file} n'existe pas!")
        sys.exit(1)
    
    # Préparer les paramètres
    if parameters is None:
        parameters = []
    
    print(f" Déploiement de la stack: {stack_name}")
    print(f" Template: {template_file}")
    print("-" * 60)
    
    try:
        # Vérifier si la stack existe déjà
        try:
            cf_client.describe_stacks(StackName=stack_name)
            stack_exists = True
            print(f"ℹLa stack {stack_name} existe déjà. Mise à jour en cours...")
            operation = "update"
        except ClientError as e:
            if 'does not exist' in str(e):
                stack_exists = False
                print(f"ℹCréation d'une nouvelle stack: {stack_name}")
                operation = "create"
            else:
                raise
        
        # Créer ou mettre à jour la stack
        if operation == "create":
            response = cf_client.create_stack(
                StackName=stack_name,
                TemplateBody=template_body,
                Parameters=parameters,
                Capabilities=['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM'],
                OnFailure='ROLLBACK'
            )
            stack_id = response['StackId']
            print(f"Stack créée avec succès!")
            print(f"Stack ID: {stack_id}")
            
        else:  # update
            try:
                response = cf_client.update_stack(
                    StackName=stack_name,
                    TemplateBody=template_body,
                    Parameters=parameters,
                    Capabilities=['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM']
                )
                stack_id = response['StackId']
                print(f" Mise à jour de la stack lancée!")
                print(f"Stack ID: {stack_id}")
            except ClientError as e:
                if 'No updates are to be performed' in str(e):
                    print(" Aucune modification détectée. La stack est déjà à jour.")
                    return
                else:
                    raise
        
        # Attendre que la stack soit créée/mise à jour
        print("\n Attente de la fin du déploiement...")
        print("   (Cela peut prendre 5-10 minutes à cause des NAT Gateways)")
        
        waiter_name = 'stack_create_complete' if operation == 'create' else 'stack_update_complete'
        waiter = cf_client.get_waiter(waiter_name)
        
        try:
            waiter.wait(
                StackName=stack_name,
                WaiterConfig={
                    'Delay': 15,  # Vérifier toutes les 15 secondes
                    'MaxAttempts': 120  # Maximum 30 minutes
                }
            )
        except Exception as e:
            print(f"\n Erreur lors du déploiement: {e}")
            print("\n Événements de la stack:")
            print_stack_events(cf_client, stack_name)
            sys.exit(1)
        
        print("\n Déploiement terminé avec succès!")
        
        # Afficher les outputs
        print("\n" + "=" * 60)
        print(" OUTPUTS DE LA STACK")
        print("=" * 60)
        
        stack_info = cf_client.describe_stacks(StackName=stack_name)
        outputs = stack_info['Stacks'][0].get('Outputs', [])
        
        if outputs:
            for output in outputs:
                print(f"\n{output['OutputKey']}:")
                print(f"  Value: {output['OutputValue']}")
                if 'Description' in output:
                    print(f"  Description: {output['Description']}")
        else:
            print("Aucun output disponible.")
        
        print("\n" + "=" * 60)
        
    except ClientError as e:
        print(f"\n Erreur AWS: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n Erreur inattendue: {e}")
        sys.exit(1)


def print_stack_events(cf_client, stack_name, limit=10):
    """Affiche les derniers événements de la stack"""
    try:
        events = cf_client.describe_stack_events(StackName=stack_name)
        print("\nDerniers événements:")
        for event in events['StackEvents'][:limit]:
            timestamp = event['Timestamp'].strftime('%Y-%m-%d %H:%M:%S')
            status = event['ResourceStatus']
            resource = event.get('LogicalResourceId', 'N/A')
            reason = event.get('ResourceStatusReason', '')
            print(f"  [{timestamp}] {resource}: {status}")
            if reason:
                print(f"    Raison: {reason}")
    except Exception as e:
        print(f"Impossible de récupérer les événements: {e}")


def delete_stack(stack_name):
    """Supprime une stack CloudFormation"""
    cf_client = boto3.client('cloudformation')
    
    print(f"Suppression de la stack: {stack_name}")
    print(" ATTENTION: Cela va supprimer toutes les ressources!")
    
    confirmation = input("Tapez 'yes' pour confirmer: ")
    if confirmation.lower() != 'yes':
        print("Suppression annulée.")
        return
    
    try:
        cf_client.delete_stack(StackName=stack_name)
        print("Suppression en cours...")
        
        waiter = cf_client.get_waiter('stack_delete_complete')
        waiter.wait(
            StackName=stack_name,
            WaiterConfig={'Delay': 15, 'MaxAttempts': 120}
        )
        
        print("Stack supprimée avec succès!")
        
    except ClientError as e:
        print(f"Erreur lors de la suppression: {e}")
        sys.exit(1)


def list_stacks():
    """Liste toutes les stacks CloudFormation"""
    cf_client = boto3.client('cloudformation')
    
    print("Liste des stacks CloudFormation:")
    print("-" * 60)
    
    try:
        response = cf_client.list_stacks(
            StackStatusFilter=[
                'CREATE_COMPLETE',
                'UPDATE_COMPLETE',
                'UPDATE_ROLLBACK_COMPLETE'
            ]
        )
        
        if response['StackSummaries']:
            for stack in response['StackSummaries']:
                print(f"\nNom: {stack['StackName']}")
                print(f"  Status: {stack['StackStatus']}")
                print(f"  Créée: {stack['CreationTime']}")
        else:
            print("Aucune stack active trouvée.")
            
    except ClientError as e:
        print(f" Erreur: {e}")


def main():
    """Fonction principale"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Déploie ou gère une infrastructure VPC AWS via CloudFormation'
    )
    parser.add_argument(
        'action',
        choices=['deploy', 'delete', 'list'],
        help='Action à effectuer (deploy, delete, ou list)'
    )
    parser.add_argument(
        '--stack-name',
        default='PolyStudentVpcStack',
        help='Nom de la stack CloudFormation (défaut: PolyStudentVpcStack)'
    )
    parser.add_argument(
        '--template',
        default='vpc.yml',
        help='Chemin vers le fichier template YAML (défaut: vpc.yml)'
    )
    parser.add_argument(
        '--environment',
        default='polystudent',
        help='Nom de l\'environnement (défaut: polystudent)'
    )
    
    args = parser.parse_args()
    
    if args.action == 'deploy':
        parameters = [
            {
                'ParameterKey': 'EnvironmentName',
                'ParameterValue': args.environment
            }
        ]
        
        deploy_cloudformation_stack(
            stack_name=args.stack_name,
            template_file=args.template,
            parameters=parameters
        )
        
    elif args.action == 'delete':
        delete_stack(args.stack_name)
        
    elif args.action == 'list':
        list_stacks()


if __name__ == '__main__':
    main()