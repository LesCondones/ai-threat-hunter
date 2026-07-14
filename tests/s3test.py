import sys
import boto3
from botocore.exceptions import ClientError, ProfileNotFound

# Configuration Constants
BUCKET_NAME = "threat-intelligence-memory"
REGION = "us-east-1"  # Swap with your actual AWS region if different


def verify_vector_connection():
    print(f"[*] Initializing connection to S3 Vectors in {REGION}...")

    try:
        # 1. Initialize the specialized client
        # Note: If using a custom local profile, pass session = boto3.Session(profile_name='your-profile')
        client = boto3.client("s3vectors", region_name=REGION)

        print(f"[*] Querying vector indexes inside bucket: '{BUCKET_NAME}'...")

        # 2. Call the read-only index lister
        response = client.list_indexes(vectorBucketName=BUCKET_NAME)

        # 3. Parse and display results
        indexes = response.get("vectorIndexes", [])

        if not indexes:
            print(
                f"[!] Connection working, but no active indexes were found in '{BUCKET_NAME}'."
            )
            return True

        print(
            f"\n[+] SUCCESS! Successfully communicated with S3 Vectors. Found {len(indexes)} index(es):"
        )
        print("-" * 60)
        for idx in indexes:
            print(f" • Name:      {idx.get('name')}")
            print(f"   Status:    {idx.get('status')}")
            print(f"   Dimension: {idx.get('dimension')}")
            print(f"   Metric:    {idx.get('distanceMetric')}")
            print("-" * 60)

        return True

    except ProfileNotFound:
        print("[X] ERROR: The specified AWS profile could not be found.")
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_msg = e.response["Error"]["Message"]

        if error_code == "AccessDeniedException":
            print(f"\n[X] IAM PERMISSION DENIED ({error_code}):")
            print(
                f"    Your current IAM credentials do not have 's3vectors:ListIndexes' permissions"
            )
            print(f"    for the target resource bucket '{BUCKET_NAME}'.")
        elif error_code == "ResourceNotFoundException":
            print(f"\n[X] RESOURCE NOT FOUND ({error_code}):")
            print(
                f"    The vector bucket '{BUCKET_NAME}' does not exist in the '{REGION}' region."
            )
        else:
            print(f"\n[X] AWS API ERROR ({error_code}): {error_msg}")

    except AttributeError:
        print(f"\n[X] ENVIRONMENT ERROR:")
        print(
            "    Your local 'boto3' library doesn't recognize the 's3vectors' service footprint."
        )
        print(
            "    Fix this by upgrading your libraries: pip install --upgrade boto3 botocore"
        )
    except Exception as e:
        print(f"\n[X] UNEXPECTED SYSTEM ERROR: {str(e)}")

    return False


if __name__ == "__main__":
    success = verify_vector_connection()
    sys.exit(0 if success else 1)
