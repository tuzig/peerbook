#!/usr/bin/env bash
set -e

HASH=$(git rev-parse --short HEAD)
GIT_TAG=$(git tag -l | tail -1)

echo "git tag is: ${GIT_TAG}"

ECR_HOST="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
ECR_URL="${ECR_HOST}/${ENVIRONMENT}/peerbook"

if [ -z "${AWS_REGION+unset}" ]; then
    echo "AWS_REGION must be set to push the image"
    exit 1
else
    echo "Login into ECR"
    aws ecr get-login-password --region "${AWS_REGION}" | docker login --username AWS --password-stdin "${ECR_HOST}"
    echo "Uploading images to ecr ${ECR_URL}"
fi

build() {
    docker build -t "server:${HASH}" -f deployment/Dockerfile .
}

push() {
    local app=server
    docker tag "${app}:${HASH}" "${ECR_URL}/${app}:${HASH}"

    if [ "${GIT_TAG}" != "" ]; then
      docker tag "${app}:${HASH}" "${ECR_URL}/${app}:${GIT_TAG}"
    fi

    docker push --all-tags "${ECR_URL}/${app}"
}

build
push
