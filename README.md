# Secure S3 Bucket Bootstrapper

`s3_secure_bucket.py` creates an **opinionated, secure-by-default** Amazon S3 bucket and prints **presigned GET/PUT URLs** for temporary, credential-less file exchange.

## Executive Summary

**Goal:** provision an S3 bucket that is safe for inbound/outbound file transfers without exposing data publicly.

**Controls applied automatically:**
- **Block Public Access (all 4 settings)**
- **Default at-rest encryption (SSE-S3 / AES256)**
- **Object Ownership = BucketOwnerEnforced (disables ACLs)**
- **HTTPS/TLS-only bucket policy**
- **Short-lived presigned URLs** for GET/PUT to a demo key

---

## How it Works (Flow)

```
You run script
   └─> Create bucket (region-aware) ── wait for existence
       ├─> Sleep 2 seconds (helps with brand-new AWS accounts)
       ├─> Enable Block Public Access (BPA)
       ├─> Set default encryption (SSE-S3/AES256)
       ├─> Enforce BucketOwnerEnforced (no ACLs)
       ├─> Attach TLS-only bucket policy (deny non-HTTPS)
       └─> Generate presigned GET/PUT for uploads/example.txt (15 min)
```

---

## Security Objectives & Mapping

| Objective | Control | Why it matters |
|---|---|---|
| Prevent public exposure | Block Public Access | Central kill-switch against public ACLs/policies |
| Encrypt data at rest | SSE-S3 (AES256) | Compliance baseline; protects stored objects |
| Predictable ownership | BucketOwnerEnforced | Disables ACLs; avoids cross-account “who owns this object?” bugs |
| Encrypt in transit | TLS-only bucket policy | Denies plain HTTP requests |
| Least-privilege sharing | Presigned URLs | Temporary, scoped URL access without IAM users |

---

## Prerequisites

- Python 3.8+
- `boto3` and `botocore`  
  ```bash
  pip install boto3
  ```
- AWS credentials configured (profile, env vars, or instance role) with the **minimum** permissions listed below.

### Minimum IAM Permissions

Attach to the identity that runs the script (tighten as needed):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect":"Allow","Action":[
      "s3:CreateBucket","s3:GetBucketLocation","s3:PutPublicAccessBlock",
      "s3:PutBucketEncryption","s3:PutBucketOwnershipControls","s3:PutBucketPolicy",
      "s3:GetBucketPolicy","s3:ListBucket"
    ],"Resource":"*"},
    {"Effect":"Allow","Action":[ "s3:PutObject","s3:GetObject" ],"Resource":"arn:aws:s3:::*/*"}
  ]
}
```

> If you later switch to **SSE-KMS**, also grant `kms:GenerateDataKey` and `kms:Decrypt` on the chosen CMK.

---

## Usage

```bash
export AWS_REGION=us-east-1
python s3_secure_bucket.py <your-unique-bucket-name>
```

- Bucket names are **globally unique** and DNS-compatible (lowercase, no underscores, etc.).
- If the name is taken by another account, the script should **fail** (see “Hardening & Extensions” below for a small improvement).

**Output:** the script prints **one PUT and one GET presigned URL** valid for ~15 minutes for the key `uploads/example.txt`.

### Quick sanity test

```bash
# Upload a file via the presigned PUT
echo "hello" > example.txt
curl -T example.txt "https://…PUT_URL…"

# Download via the presigned GET and compare
curl -o out.txt "https://…GET_URL…"
diff example.txt out.txt
```

---

## What the Script Configures (Deep Dive)

1. **Bucket creation**  
   Handles the `us-east-1` "no LocationConstraint" special case. Waits until the bucket exists. If the bucket already exists and is owned by you, it continues; if owned by someone else, subsequent operations will fail with AccessDenied.

2. **Post-creation wait**  
   Adds a 2-second sleep after bucket creation to help settings apply reliably in brand-new AWS accounts.

3. **Block Public Access (BPA)**  
   Turns on all four BPA toggles to stop both public ACLs and public policies from taking effect.

4. **Default Bucket Encryption**  
   Sets SSE-S3 (AWS-managed keys, `AES256`) so new objects encrypt by default even if clients don't specify headers.

5. **BucketOwnerEnforced (Ownership Controls)**  
   Disables object ACLs entirely. Objects are always owned by the bucket owner. This avoids cross-account ACL surprises and simplifies permissions (IAM & bucket policies only).

6. **TLS-only policy**  
   Attaches a bucket policy that **denies any request** where `aws:SecureTransport` is `false` (i.e., not using HTTPS).

7. **Presigned URLs**  
   Generates temporary URLs for `get_object` and `put_object` specifically for the key `uploads/example.txt`. The URLs embed a SigV4 signature and expiration (default 15 minutes); no AWS account is required to use them before they expire.

---

## Operational Notes

- **Idempotency:** safe to re-run on **your** existing bucket; settings are just (re)applied. The script prints `[SKIP] Bucket already exists` if you own it, or errors with `BucketAlreadyExists` if someone else owns it.
- **Headers with presign:** if an uploader sets headers (e.g., `Content-Type`), those must be **included in the presign** or the request will be rejected.
- **ACLs disabled:** clients must **not** send `x-amz-acl` (some old SDK defaults); with BucketOwnerEnforced, such PUTs fail.
- **Region handling:** The script uses `boto3.Session` with explicit region configuration from `AWS_REGION` environment variable (defaults to `us-east-1`).

---

## Compliance & Alternatives

- **SSE-S3 (current default):** lowest friction and cost. Meets many baseline requirements.
- **SSE-KMS (recommended for stricter regimes):** swap to a CMK for key separation, revocation, and audit controls. Requires additional IAM and KMS policy work (see snippet below).

---

## Hardening & Extensions (optional)

### 1) Fail fast if the bucket name is taken by someone else
```python
# replace the except block in ensure_bucket_exists()
except botocore.exceptions.ClientError as e:
    code = e.response.get("Error", {}).get("Code")
    if code == "BucketAlreadyOwnedByYou":
        print(f"[SKIP] Bucket already exists and is yours: {bucket_name}")
    elif code == "BucketAlreadyExists":
        print(f"[ERROR] Bucket name is taken by another account: {bucket_name}")
        sys.exit(1)
    else:
        raise
```

### 2) Enable Versioning (and optionally MFA Delete)
```python
s3_client.put_bucket_versioning(
    Bucket=bucket_name,
    VersioningConfiguration={"Status": "Enabled"}
)
```

### 3) Lifecycle management (cost + hygiene)
```python
s3_client.put_bucket_lifecycle_configuration(
    Bucket=bucket_name,
    LifecycleConfiguration={
      "Rules":[
        {"ID":"abort-multipart","Status":"Enabled",
         "AbortIncompleteMultipartUpload":{"DaysAfterInitiation":7}},
        {"ID":"transition-ia","Status":"Enabled","Filter":{"Prefix":""},
         "Transitions":[{"Days":30,"StorageClass":"STANDARD_IA"}]}
      ]
    }
)
```

### 4) Server access logs / CloudTrail data events
Log access to a **separate, locked logging bucket** for audits and investigations.

### 5) SSE-KMS default encryption (replace SSE-S3 step)
```python
s3_client.put_bucket_encryption(
  Bucket=bucket_name,
  ServerSideEncryptionConfiguration={
    "Rules":[{"ApplyServerSideEncryptionByDefault":{
      "SSEAlgorithm":"aws:kms",
      "KMSMasterKeyID":"arn:aws:kms:REGION:ACCOUNT_ID:key/KEY_ID"
    }}]
  }
)
```
> Ensure: bucket policy and IAM allow S3 to use the CMK; principals that **GET** objects also need `kms:Decrypt`.

### 6) Network scoping (VPC endpoints)
If uploads occur from inside your VPC, restrict access using `aws:SourceVpce` or source IP conditions in the bucket policy.

---

## Testing Checklist

- [ ] Re-run script on the same bucket (idempotent, no drift).
- [ ] Upload via presigned PUT, download via presigned GET, verify bytes match.
- [ ] Attempt HTTP (non-TLS) request ⇒ **denied**.
- [ ] Attempt a public ACL or bucket policy ⇒ **ineffective** due to BPA.
- [ ] (If enabled) Delete an object and confirm you can restore prior version.
- [ ] (If KMS) Validate both PUT and GET work with CMK permissions in place.

---

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| `BucketAlreadyExists` then `AccessDenied` on later calls | Name taken by another account | Use a different bucket name; add “fail fast” code above |
| Presigned PUT fails with `SignatureDoesNotMatch` | Headers/body mismatch vs presign | Include same `Content-Type` (and any headers) when presigning and uploading |
| Client PUT fails with `InvalidRequest: ACLs are not supported` | Client adds `x-amz-acl` | Remove ACL headers; BucketOwnerEnforced disables ACLs |
| GET/PUT works over HTTPS but HTTP returns `AccessDenied` | TLS-only policy is working | Use HTTPS |
| `AccessDenied` on GET with SSE-KMS | Missing `kms:Decrypt` | Grant decrypt rights on the CMK to the caller |

---

## Appendix: TLS-Only Bucket Policy (applied by script)

```json
{
  "Version":"2012-10-17",
  "Statement":[
    {
      "Sid":"DenyInsecureTransport",
      "Effect":"Deny",
      "Principal":"*",
      "Action":"s3:*",
      "Resource":[
        "arn:aws:s3:::<BUCKET>",
        "arn:aws:s3:::<BUCKET>/*"
      ],
      "Condition":{"Bool":{"aws:SecureTransport":"false"}}
    }
  ]
}
```

---

## Notes on Presigned URLs

- **Expiration:** configurable; default 900 seconds here. SigV4 URLs can go up to 7 days (SDK-specific).
- **Scope:** presigned **PUT** grants write to exactly one key; **GET** grants read to that key only.
- **No credentials exposure:** recipients don’t need AWS accounts.

---

### License & Warranty

This script and documentation are provided “as is” without warranty. Validate against your organization’s security baseline and compliance standards before production use.
