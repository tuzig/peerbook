#!/usr/bin/env bash

VERSION="$(git rev-parse --short HEAD)"
LAYER_NAME="staging-peerbook"
ENVIRONMENT="staging"

echo "Preparing docker compose"
sed -e "s/\${AWS_REGION}/${AWS_REGION}/g; s/\${AWS_ACCOUNT_ID}/${AWS_ACCOUNT_ID}/g; s/\${VERSION}/${VERSION}/g; s/\${LAYER_NAME}/${LAYER_NAME}/g" docker-compose.template.yml >docker-compose.yml

echo "Preparing ecs params"
sed -e "s/\${AWS_REGION}/${AWS_REGION}/g; s/\${AWS_ACCOUNT_ID}/${AWS_ACCOUNT_ID}/g; s/\${ENVIRONMENT}/${ENVIRONMENT}/g" ecs-params.template.yml >ecs-params.yml

ecs-cli compose --project-name tools \
  service up \
  --create-log-groups \
  --cluster-config "${LAYER_NAME}" \
  --cluster "${LAYER_NAME}" \
  --target-groups "targetGroupArn=arn:aws:elasticloadbalancing:${AWS_REGION}:${AWS_ACCOUNT_ID}:targetgroup/${TARGET_GROUP_ID},containerName=api,containerPort=17777" \
  --region "${AWS_REGION}" \
  --deployment-min-healthy-percent 100 \
  --deployment-max-percent 200 \
  --timeout 5

if [ "$?" = "1" ]; then
  echo "Deploy failed"
  exit 1
fi
