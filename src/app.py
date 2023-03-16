import boto3, os




if __name__ == "__main__":
    AWS_ACCESS_KEY_ID=os.environ.get("AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY=os.environ.get("AWS_SECRET_ACCESS_KEY")
    AWS_SESSION_TOKEN=os.environ.get("AWS_SESSION_TOKEN")
    print(" Welcome to Python app to test S3 access v1.0.0")
    print(AWS_ACCESS_KEY_ID)
    s3 = boto3.resource('s3')
    # Print out bucket names
    for bucket in s3.buckets.all():
        print(bucket.name)