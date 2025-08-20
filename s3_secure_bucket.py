#!/usr/bin/env python3
"""
Create a secure S3 bucket with:
- Block Public Access (all 4 protections)
- Default encryption (SSE-S3)
- Object Ownership = BucketOwnerEnforced (disables ACLs)
- HTTPS/TLS-only bucket policy
- Helper functions to generate presigned GET/PUT URLs

Usage:
  export AWS_REGION=us-east-1
  python s3_secure_bucket.py my-unique-bucket-name-123

Requires:
  pip install boto3
"""
import json
import os
import sys
import time
import botocore
import boto3

REGION = os.getenv("AWS_REGION", "us-east-1")

def ensure_bucket_exists(s3_client, bucket_name: str):
    # Create bucket (region handling for us-east-1 vs others)
    try:
        if REGION == "us-east-1":
            s3_client.create_bucket(Bucket=bucket_name)
        else:
            s3_client.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={"LocationConstraint": REGION},
            )
        # Wait until exists
        waiter = s3_client.get_waiter("bucket_exists")
        waiter.wait(Bucket=bucket_name)
        print(f"[OK] Created bucket: {bucket_name}")
    except botocore.exceptions.ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            print(f"[SKIP] Bucket already exists: {bucket_name} ({code})")
        else:
            raise

def set_block_public_access(s3_client, bucket_name: str):
    s3_client.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    print("[OK] Block Public Access enabled (all)")

def set_default_encryption(s3_client, bucket_name: str):
    # SSE-S3 (AES256). New S3 uploads are encrypted by default, but we set it explicitly.
    s3_client.put_bucket_encryption(
        Bucket=bucket_name,
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )
    print("[OK] Default encryption set to SSE-S3 (AES256)")

def disable_acls_bucket_owner_enforced(s3_client, bucket_name: str):
    # Enforce bucket-owner ownership and disable ACLs
    s3_client.put_bucket_ownership_controls(
        Bucket=bucket_name,
        OwnershipControls={"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]},
    )
    print("[OK] Object Ownership set to BucketOwnerEnforced (ACLs disabled)")

def put_tls_only_bucket_policy(s3_client, bucket_name: str):
    # Deny any non-HTTPS requests using aws:SecureTransport
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyInsecureTransport",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": [
                    f"arn:aws:s3:::{bucket_name}",
                    f"arn:aws:s3:::{bucket_name}/*",
                ],
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            }
        ],
    }
    s3_client.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))
    print("[OK] Bucket policy enforces HTTPS/TLS only")

def create_presigned_urls(s3_client, bucket_name: str, key: str, expires: int = 900):
    get_url = s3_client.generate_presigned_url(
        "get_object",
        Params={"Bucket": bucket_name, "Key": key},
        ExpiresIn=expires,
    )
    put_url = s3_client.generate_presigned_url(
        "put_object",
        Params={"Bucket": bucket_name, "Key": key},
        ExpiresIn=expires,
    )
    return get_url, put_url

def main():
    if len(sys.argv) != 2:
        print("Usage: python s3_secure_bucket.py <bucket-name>")
        sys.exit(2)
    bucket_name = sys.argv[1]

    session = boto3.Session(region_name=REGION)
    s3_client = session.client("s3")

    ensure_bucket_exists(s3_client, bucket_name)
    # Some settings depend on bucket existence, so small wait helps in brand-new accounts
    time.sleep(2)

    set_block_public_access(s3_client, bucket_name)
    set_default_encryption(s3_client, bucket_name)
    disable_acls_bucket_owner_enforced(s3_client, bucket_name)
    put_tls_only_bucket_policy(s3_client, bucket_name)

    # Demo presigned URLs
    demo_key = "uploads/example.txt"
    get_url, put_url = create_presigned_urls(s3_client, bucket_name, demo_key, expires=900)
    print("\n[DEMO] Presigned URLs (valid ~15 minutes):")
    print(f"PUT  → {put_url}")
    print(f"GET  → {get_url}")

if __name__ == "__main__":
    main()