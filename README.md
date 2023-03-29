# Remote access to AWS services from a k8s cluster (over the internet)

This is a simple code example to illustrate how to access AWS services from a remote Kubernetes Cluster running outside of AWS.

Update 03/27/2023.

Audiance: Beginner developer or CRE.

## Problems

There are two requirements:

1. We want to access ECR to get an image scheduled to a Kubernetes cluster running in another cloud (or on-premises) 
2. Access AWS services from a running app within the same Kubernetes cluster. 

So the first problem is to demonstrate, how to access to the ECR repository to download the container image so the pod can be created:

![](./docs/diagrams/general-concept.drawio.png)

The second challenge is to demonstrate how to access any AWS service, like S3, from pods running on remote Kubernetes. 

All communications are over public internet, therefore low latency is not part of the equation.

## Demonstration preparation

Start by cloning this repository.

As a pre-requisite you can build a docker image from the [simple python program](https://github.com/jbcodeforce/aws-remote-svc-acccess-from-k8s/blob/main/src/app.py) which will be deployed on your Kubernetes cluster. When executed the pod will list the S3 buckets in your AWS account. The code is using environment variables to get credentials to access AWS and IAM role identify. Those variables are defined as Secret in k8s.

You can prepare the demonstration using the set of elements from this repository but read the next sections for more details.

* We assume you have AWS CLI installed and you configured your access to AWS via `aws configure`. You should set the temporary access token, access key id and access key secret in environment variables

  ```sh
  export AWS_ACCESS_KEY_ID=AS....EM
  export AWS_SECRET_ACCESS_KEY=fE.....lN
  export AWS_SESSION_TOKEN=IQoJ......v02SJ
  ```

* If you want to use a IaC approach run CDK to create IAM user, Policy, ECR repository. For that you could use the script and docker image (`jbcodeforce/aws-python` from public dockerhub registry):

  ```sh
  # under cdk folder, start an isolated environemt with AWS CLI, CDK, and some python goodies:
  ./startPythonAWSEnv.sh
  # Verify you can see your S3 buckets
  aws s3 ls
  # in the shell use cdk CLI as:
  cdk deploy
  ```

  This should generate a CloudFormation template named `EcrAccessSample` and then the resources in IAM and policy matching the description in next section.

* Add access key and secret for the `ecruser` with the `Application running outside AWS` choice. Download the csv file on your computer.
* Build the image with the name of the ECR repository: (change `your_aws_account_id` below)

  ```sh
  cd src
  docker build -t your_aws_account_id.dkr.ecr.us-west-2.amazonaws.com/s3bucketlist .
  ```

* Login to docker: (change `your_aws_account_id` below)

  ```sh
  aws ecr get-login-password --region us-west-2 | docker login --username AWS --password-stdin  your_aws_account_id.dkr.ecr.us-west-2.amazonaws.com

  ```

* Push the image that we will use later to test kubernetes to S3 connection: (change `your_aws_account_id` below)

  ```sh
  docker push your_aws_account_id.dkr.ecr.us-west-2.amazonaws.com/s3bucketlist
  ```


## ECR remote access

Recall that ECR has the following components: A registry that is private and unique to an account, and then repositories to include a set of OCI (Open Container Initiative) images. Each image may have multiple version.

![](./docs/diagrams/ecr-components.drawio.png)

Any client must authenticate to Amazon ECR private registries as an AWS user before it can push and pull images. Access control policies must be defined to grant access to private repositories via API.

Amazon ECR provides several managed policies to control user access. It uses resource-based permissions.

Amazon ECR repository policies and IAM policies are used when determining which actions a specific user or role may perform on a repository.

Any users must get permission to make calls to the `ecr:GetAuthorizationToken` API through an IAM policy before they can authenticate to a registry and push or pull any images from any Amazon ECR repository. 

The IAM Policy looks like:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "ecrauthorization",
            "Effect": "Allow",
            "Action": "ecr:GetAuthorizationToken",
            "Resource": "*"
        }
    ]
}
```

Once added be sure to authorize push and pull actions on the image repository you want the user to access (see next session for repository policy).

### ECR access using IAM user

Using AWS CLI, Docker and AWS account, we can download a container image from our private registry. The following diagram illustrates what we can do:

![](./docs/diagrams/ecr-from-laptop.drawio.png)

A developer or CI/CD pipeline can push image to the registry/repository using the docker CLI, but he/she needs to be authenticated. An authentication token is used to access any Amazon ECR registry that your IAM principal has access to and is valid for 12 hours. 

1. If not done by using the CDK in previous section, create a IAM user: `ecruser` and attach the ECR policy created above to it:

    ![](./docs/images/ecruser.jpg)

    We can add an access key to the created user, so we can test the next steps with AWS CLI.

1. Get the authorization token

    An authorization token represents the IAM authentication credentials which can be used to access any Amazon ECR registry that our IAM principal has access to. The authorization token is valid for 12 hours. To obtain an authorization token, we must use the `GetAuthorizationToken` API operation, It retrieves a base64-encoded authorization token containing the username "AWS" and an encoded password.

    The AWS CLI provides a `get-login-password` command to simplify this authentication process. This command returns a temporary access token. 

    Here is an example to use a logged admin user (who created the ECR registry):

    ```sh
    # use a specific IAM user: like `ecruser` using the access key and secret key
    aws configure 
    aws ecr get-login-password --region us-west-2 | docker login --username AWS --password-stdin your_aws_account_id.dkr.ecr.us-west-2.amazonaws.com
    # The following command should fail
    docker pull <accountID>.dkr.ecr.us-west-2.amazonaws.com/s3bucketlist
    # with error like
    # denied: User: arn:aws:iam::40...:user/ecruser is not authorized to perform: ecr:BatchGetImage on resource...
    ```

1. If not done previously, add one ECR repository policy to authorize the `ecruser` user to pull the expected image. This may be done in the ECR AWS console, repositories view, and `add permissions` to the selected repository:

    ```json
    {
    "Version": "2012-10-17",
    "Statement": [
        {
        "Sid": "new statement",
        "Effect": "Allow",
        "Principal": {
            "AWS": "arn:aws:iam::4....:user/ecruser"
        },
        "Action": [
            "ecr:BatchCheckLayerAvailability",
            "ecr:BatchGetImage",
            "ecr:GetDownloadUrlForLayer",
            "ecr:ListImages"
        ]
        }
    ]
    }
    ```

    [See policy examples in the product documentation](https://docs.aws.amazon.com/AmazonECR/latest/userguide/repository-policy-examples.html).

1. Now pulling image should work:

    ```sh
     docker pull <accountID>.dkr.ecr.us-west-2.amazonaws.com/s3bucketlist
     ```

### ECR access with code

To make HTTPS call to AWS services, we need to get temporary security credentials from the AWS Security Token Service (AWS STS).

* Example of calling ECR API to get the list of tags for a repository, using a temporary authorization token:

```sh
TOKEN=$(aws ecr get-authorization-token --output text --query 'authorizationData[].authorizationToken') 
curl -i -H "Authorization: Basic $TOKEN" https://<myaccountID>.dkr.ecr.us-west-2.amazonaws.com/v2/s3bucketlist/tags/list
```


### ECR access from remote Kubernetes

To access a remote registry, Kubernetes cluster uses the Secret of `kubernetes.io/dockerconfigjson` type to authenticate to the remote registry and to pull a private image from. The secret can be defined in any namespace. The `.dockerconfigjson` is the base64 encrypted version of the docker `config.json` file, which includes the path to the AWS ECR registry:

```json
{
	"auths": {
		"40.....dkr.ecr.us-west-2.amazonaws.com": {},
		"https://index.docker.io/v1/": {}
	}

```

* The command to encrypt the docker config file:

```sh
cat ~/.docker/config.json| base64
```

Here is the secret with the generated string as `.data.dockerconfigjson`:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: aws-ecr
  namespace: your-ns
data:
  .dockerconfigjson: Um....
type: kubernetes.io/dockerconfigjson
```

* A better solution is to use `kubectl`, combined with Temporary Authorization Token:

```sh
export REGISTRY_SERVER=https://403.....dkr.ecr.us-west-2.amazonaws.com
export TOKEN=$(aws ecr get-authorization-token --output text --query 'authorizationData[].authorizationToken') 
export EMAIL=your-email
kubectl create secret docker-registry aws-ecr --docker-server=$REGISTRY_SERVER --docker-username=AWS --docker-password=$TOKEN --docker-email=$EMAIL
```

This secret will work for 12 hours. If your security requirements do not enforce changing the token as often then use the IAM user with access key and secret to create this Kubernetes Secret:

```sh
export PWD=secret-key-of-iam-user
export EMAIL=your-email
kubectl create secret docker-registry awsecr --docker-server=$REGISTRY_SERVER --docker-username=ecruser --docker-password=$PWD --docker-email=$EMAIL
```

* Verify it with

```sh
kubectl describe secret aws-ecr

Name:         aws-ecr
Namespace:    default
Labels:       <none>
Annotations:  <none>

Type:  kubernetes.io/dockerconfigjson

Data
====
.dockerconfigjson:  298 bytes
```

You can even verify the configuration with

```sh
kubectl get secret aws-ecr -o json | jq '.data.".dockerconfigjson"' | base64 --decode
```

See [Kubernetes documentation](https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/).

Once done, define a `pod.yaml` or a deployment.yaml file with the image name referencing the full path to the ECR private registry.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: tenant
spec:
  containers:
  - name: private-reg-container
    image: 40....dkr.ecr.us-west-2.amazonaws.com/s3bucketlist:latest
  imagePullSecrets:
  - name: aws-ecr
```

The `imagePullSecrets` element references the Secret name to get the credentials from.

Try these with [killercoda - kubernetes](https://killercoda.com/kubernetes) or Minikube.

The pod.yaml file in the `src` directory present a template and can be deployed using:

```sh
kubectl apply -f pod.yaml
kubectl get pods
kubectl logs jb-s3-bucket-ls
```

## Other things to consider

* If we need to use image encryption then the public KMS key needs to be in the Kubernetes cluster to be able to decrypt the image.

## Access from pod to S3

This is the second example on how to access AWS resources from a running pod inside of a remote Kubernetes platform, not running on AWS.

Basically the pod will use environment variables with access key, secret and temporary token. Those are saved in another secret and loaded inside the pod via a declaration like:

```yaml
    envFrom:
    - secretRef:
        name: s3-bucket-secret
```

and the secret is built with the following template or the kubectl CLI.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: aws-creds
type: Opaque
data:
  AWS_ACCESS_KEY_ID:
  AWS_SECRET_ACCESS_KEY:
  AWS_SESSION_TOKEN: 
```

Which could be created with the command:

```sh
kubectl create secret generic s3-bucket-secret --from-literal=AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID --from-literal=AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY --from-literal=AWS_SESSION_TOKEN=$AWS_SESSION_TOKEN
``` 




The main approach is to use the [IAM Role Anywhere](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html) capability to get the temporary token.