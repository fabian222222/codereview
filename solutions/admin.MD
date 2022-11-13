# Login By pass

## Problem:

In this code, we can see the creation of database with some datas in it. Three tables are created which are users, sessions and articles. Then, we insert user in this table. The values are very simple, "admin" for the login, "admin123" for the password. Even if people don't know these informations, they can just force it by trying random and simple logs. When making a password for the admin user, we need to make sure to not put a common password that can be found in this list for example :[Common List](https://github.com/nixawk/fuzzdb/blob/master/bruteforce/passwds/default_devices_users%2Bpasswords.txt).

## Solution:

In order to avoid a bruteforce login:

- Insert logs with more complexitude
- Generate secure passwords for every account we create by default.
