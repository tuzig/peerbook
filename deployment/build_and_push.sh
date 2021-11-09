#!/usr/bin/env bash
set -e

VERSION=$(git rev-parse --short HEAD)
ECR_HOST="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
ECR_URL="${ECR_HOST}/peerbook"

if [ -z "${AWS_REGION+unset}" ]; then
    echo "AWS_REGION must be set to push the image"
    exit 1
else
    echo "Login into ECR"
    aws ecr get-login-password --region "${AWS_REGION}" | docker login --username AWS --password-stdin "${ECR_HOST}"
    echo "Uploading images to ecr ${ECR_URL}"
fi

build() {
    docker build -t base_image .
    docker build -t "server:${VERSION}" -f deployment/Dockerfile.prod .
}

push() {
    local app=server
    docker tag "${app}":"${VERSION}" "${ECR_URL}"/"${app}":"${VERSION}"
    docker push "${ECR_URL}"/"${app}":"${VERSION}"
}

build
push
