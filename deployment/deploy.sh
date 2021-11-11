#!/usr/bin/env bash

HASH="$(git rev-parse --short HEAD)"
LAYER_NAME="${ENVIRONMENT}-peerbook"
CLUSTER_NAME="${ENVIRONMENT}-peerbook"

echo "Preparing docker compose"
sed -e "s/\${AWS_REGION}/${AWS_REGION}/g; s/\${AWS_ACCOUNT_ID}/${AWS_ACCOUNT_ID}/g; s/\${HASH}/${HASH}/g; s/\${LAYER_NAME}/${LAYER_NAME}/g" docker-compose.template.yml >docker-compose.yml

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
