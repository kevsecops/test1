"""
main.py — Entry point for the SAST demo application.

Imports and calls all vulnerable modules so SAST tools can trace
the full call graph. The application is intentionally broken in
multiple ways — DO NOT run in production.
"""
from app.command_injection import (
    calculate,
    compress_file,
    get_file_info,
    ping_host,
    run_script,
)
from app.crypto_issues import (
    encrypt_des,
    generate_session_token,
    hash_password_md5,
    hash_password_sha1,
    verify_token_insecure,
)
from app.insecure_deserialization import (
    deserialize_user_data,
    load_yaml_file,
    parse_config,
)
from app.misc_issues import (
    admin_only,
    authenticate,
    connect_to_db,
    decode_token,
    read_config,
    write_temp_data,
)
from app.sql_injection import (
    delete_user,
    find_user_by_id,
    find_user_by_name,
    list_users_sorted,
)


def main():
    print("=== SAST Demo — Python ===")

    # SQL injection demo
    print(find_user_by_name("alice' OR '1'='1"))
    print(find_user_by_id("1 OR 1=1"))
    delete_user("admin'--")
    list_users_sorted("name; DROP TABLE users--")

    # Command injection demo
    ping_host("127.0.0.1; cat /etc/passwd")
    compress_file("file.txt; rm -rf /")
    print(get_file_info(".; ls /"))
    print(calculate("__import__('os').system('id')"))
    run_script("import os; os.system('whoami')")

    # Crypto issues demo
    print(hash_password_md5("password123"))
    print(hash_password_sha1("password123"))
    encrypt_des(b"secret!!")
    print(generate_session_token())
    print(verify_token_insecure("abc", "abc"))

    # Insecure deserialization demo
    parse_config("key: value")

    # Misc issues demo
    print(read_config("/etc/app.conf"))
    authenticate("admin", "admin123")
    admin_only(True)
    tmp = write_temp_data("sensitive data")
    print(tmp)
    decode_token("eyJ...")

    print("=== Demo complete ===")


if __name__ == "__main__":
    main()
