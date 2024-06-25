#!/usr/bin/env bash

HASH="$(git rev-parse --short HEAD)"
LAYER_NAME="${ENVIRONMENT}-peerbook"
CLUSTER_NAME="${ENVIRONMENT}-peerbook"

echo "Preparing docker compose"
sed -e "s/\${AWS_REGION}/${AWS_REGION}/g; s/\${AWS_ACCOUNT_ID}/${AWS_ACCOUNT_ID}/g; s/\${HASH}/${HASH}/g; s/\${LAYER_NAME}/${LAYER_NAME}/g" docker-compose.${ENVIRONMENT}.template.yml >docker-compose.yml

if [ "${ENVIRONMENT}" = "staging" ]; then
    # If in the staging environment, deploy directly to an EC2 instance using AWS CLI via SSM
    # Define the instance ID for the EC2 instance
    INSTANCE_ID="i-0c951da757bd3d175"
    PUBLIC_IP=$(aws ec2 describe-instances --instance-ids "${INSTANCE_ID}" --query "Reservations[*].Instances[*].PublicIpAddress" --output text)

    sed -e "s/\${PUBLIC_IP}/${PUBLIC_IP}/g" docker-compose.yml >docker-compose.yml
    # Upload docker-compose.yml to an S3 bucket
    BUCKET_NAME="peerbook-staging"
    aws s3 cp docker-compose.yml s3://${BUCKET_NAME}/docker-compose.yml

    # Command to execute on the EC2 instance
    RUN_COMMANDS="aws s3 cp s3://${BUCKET_NAME}/docker-compose.yml .; \
                  docker compose down; \
                  docker compose up -d"

    # Execute commands via SSM
    aws ssm send-command \
        --instance-ids "${INSTANCE_ID}" \
        --document-name "AWS-RunShellScript" \
        --parameters commands="${RUN_COMMANDS}" workingDirectory="/tmp" \
        --comment "Peerbook deployment via SSM on staging" \
        --output json

    if [ "$?" != "0" ]; then
        echo "Deployment to EC2 via SSM failed"
        exit 1
    fi
else
    echo "Preparing ecs params"
    sed -e "s/\${AWS_REGION}/${AWS_REGION}/g; s/\${AWS_ACCOUNT_ID}/${AWS_ACCOUNT_ID}/g; s/\${ENVIRONMENT}/${ENVIRONMENT}/g" ecs-params.template.yml >ecs-params.yml

    ecs-cli compose --project-name "${CLUSTER_NAME}" \
      service up \
      --create-log-groups \
      --cluster-config "${CLUSTER_NAME}" \
      --cluster "${CLUSTER_NAME}" \
      --target-groups "targetGroupArn=arn:aws:elasticloadbalancing:${AWS_REGION}:${AWS_ACCOUNT_ID}:targetgroup/${TARGET_GROUP_ID},containerName=api,containerPort=17777" \
      --region "${AWS_REGION}" \
      --deployment-min-healthy-percent 100 \
      --deployment-max-percent 200 \
      --timeout 10

    if [ "$?" = "1" ]; then
      echo "Deploy failed"
      exit 1
    fi
fi
