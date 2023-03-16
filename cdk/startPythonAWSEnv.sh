#!/bin/bash
echo "##########################################################"
echo " A docker image for python  development: "
echo "For cdk... once started do in /app:"
echo "  python3 -m venv .venv"
echo "  source .venv/bin/activate"
echo "  pip install -r requirements.txt"
name="aws-python"
port=5000
if [[ $# != 0 ]]
then
    name=$1
    port=$2
fi

docker run --rm --name $name -v $(pwd):/app -it  -v ~/.aws:/root/.aws -e AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN=$AWS_SESSION_TOKEN -p $port:$port jbcodeforce/aws-python bash 
