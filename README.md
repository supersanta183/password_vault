# password_vault

A password manager that secures passwords behind RSA encryption using OAEP padding. The login for the password manager is a 12-word seedphrase or a password, that has been used for seeding the RSA keypair.
The seedphrase is stored in memory when logging in, so it can be used to decrypt passwords as long as logged in. Seedphrase is then dropped from memory once logged out.

Current functionality:
- store one encrypted password for each service/website
- login using 12-word seedphrase
- login using password
- generate passwords

future functionality:
- possibility for more than one password for each service
- signatures for encrypted passwords, so Oliver doesn't mess with it
- possibility to save passwords even when program is shut down
