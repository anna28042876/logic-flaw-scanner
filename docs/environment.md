# Environment

## Docker Target Applications

| Application  | Image                              | Port  |
|-------------|-------------------------------------|-------|
| Juice Shop  | bkimminich/juice-shop:v19.2.1      | 3000  |
| DVWA        | vulnerables/web-dvwa:1.9           | 8080  |

## Notes
- Juice Shop version pinned to avoid mid-project vulnerability patches
- DVWA version pinned for same reason
- DVWA security level: Low (primary), Medium (secondary), Impossible (false-positive control)

# DVWA Accounts
- admin / password (default)
- user_a / CHANGE_ME_USER_A (user_id: 6, created via MySQL)
- user_b / CHANGE_ME_USER_B (user_id: 7, created via MySQL)
- MySQL access confirmed using password: vulnerables
