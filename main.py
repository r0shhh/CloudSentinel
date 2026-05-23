from scanners.s3_scanner import list_buckets, check_public_access_block, check_bucket_encryption

def run_s3_checks():
    buckets = list_buckets()

    if not buckets:
        print("No S3 buckets found.")
        return
    print(f"Scanning {len(buckets)} bucket(s)...\n")

    for bucket in buckets:
        name = bucket['Name']
        print(f"Bucket: {name}")

        result = check_public_access_block(name)
        print(f" [Public Access Block] {result['status']}")
        if result['issues']:
            for issue in result['issues']:
                print(f"   ! {issue}")

        result = check_bucket_encryption(name)
        print(f" [Encryption] {result['status']}")
        if result['issues']:
            for issue in result['issues']:
                print(f"   ! {issue}")

        print() 

if __name__ == "__main__":
    run_s3_checks()                       