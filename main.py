from scanners.s3_scanner import list_buckets, check_public_access_block, check_bucket_encryption
from scanners.iam_scanner import list_iam_users, check_user_mfa, check_access_key_age, check_admin_privileges

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
        print(f"[Public Access Block] {result['status']}")
        if result['issues']:
            for issue in result['issues']:
                print(f"   ! {issue}")

        result = check_bucket_encryption(name)
        print(f"[Encryption] {result['status']}")
        if result['issues']:
            for issue in result['issues']:
                print(f"   ! {issue}")

        print() 


def run_iam_checks(): 
    users = list_iam_users()

    if not users:
        print("No IAM users found.")
    else:
        print(f"Found {len(users)} user(s):")
        for user in users:
            print (f"- {user['UserName']}")
            
            result = check_user_mfa(user['UserName'])
            print(f"[MFA] {result['status']} ")
            if result['issues']:
                for issue in result['issues']:
                    print(f"! {issue}")

            result = check_access_key_age(user['UserName'])
            print(f"[Access Key Age] {result['status']}")
            if result['issues']:
                for issue in result['issues']:
                    print(f"! {issue}")

            result = check_admin_privileges(user['UserName'])
            print(f"[Admin Privileges] {result['status']}")
            if result['issues']:
                for issue in result['issues']:
                    print(f"! {issue}")          

if __name__ == "__main__":
    run_s3_checks()                       
    run_iam_checks()