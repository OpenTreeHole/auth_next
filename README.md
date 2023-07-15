# Open Tree Hole Auth Next

Next Generation of Auth microservice integrated with [Kong Gateway](https://github.com/Kong/kong) for registration and
issuing tokens

## Features

- White-listed email registration
- Anonymous: Shamir encrypted email and random identity
- issue and revoke JWT tokens

## Usage

### Configurations

Environment Variables

|           Name            |     Default     |         Valid values         |                                 Description                                  |
|:-------------------------:|:---------------:|:----------------------------:|:----------------------------------------------------------------------------:|
|           MODE            |       dev       | dev, production, test, bench |                          if dev, log gorm debug sql                          |
|          DB_URL           |                 |                              |                 Database DSN, required in "production" mode                  |
|         KONG_URL          |                 |                              |         if STANDALONE is false, required to connect to kong gateway          |
|         REDIS_URL         |                 |                              |                       if not set, use go-cache instead                       |
|     NOTIFICATION_URL      |                 |                              |                   if not set, no notification will be sent                   |
|      EMAIL_WHITELIST      |                 |                              |           use ',' to separate emails; if not set, allow all emails           |
| EMAIL_SERVER_NO_REPLY_URL |                 |                              | required in "production" mode; if not set, unable to send verification email |
|       EMAIL_DOMAIN        |                 |                              | required in "production" mode; if not set, unable to send verification email |
|         EMAIL_DEV         | dev@fduhole.com |                              |                      send email if shamir update failed                      |
|      SHAMIR_FEATURE       |      true       |                              |   if enabled, check email shamir encryption when users register and login    |
|        STANDALONE         |      false      |                              |          if not set, this application not required to set KONG_URL           |
| VERIFICATION_CODE_EXPIRES |       10        |           integers           |                  register verification code expiration time                  |
|         SITE_NAME         | Open Tree Hole  |                              |                      title prefix of verification email                      |

File settings, required in production mode

|       Env Name       |             Default Path              | Default |                          Description                          |
|:--------------------:|:-------------------------------------:|:-------:|:-------------------------------------------------------------:|
|   IDENTIFIER_SALT    |   /var/run/secrets/identifier_salt    | 123456  |  hash salt for encrypting email; required in production mode  |
| REGISTER_APIKEY_SEED | /var/run/secrets/register_apikey_seed |         | register apikey; if not set, disable apikey register function |
|      KONG_TOKEN      |      /var/run/secrets/kong_token      |         |                        kong api token                         |

### Debug Development Prerequisite

1. set STANDALONE environment to true
2. if `SHAMIR_FEATURE` set true, it will create table `shamir_public_key` automatically, and insert default shamir private keys defined in ./data/*-private.key

### Production Deploy Prerequisite

1. Kong Gateway deployed, see https://docs.konghq.com/gateway/latest/

2. Prepare mysql/sqlite database, if `SHAMIR_FEATURE` set true or default

Create table `shamir_public_key`

```mysql
CREATE TABLE `shamir_public_key`
(
    `id`                 bigint   NOT NULL AUTO_INCREMENT,
    `identity_name`      longtext NOT NULL,
    `armored_public_key` longtext NOT NULL,
    PRIMARY KEY (`id`)
);
```

Insert at least 7 PGP key administrator info into this table

`identity_name`: PGP identity name or `uid`, including username, ( comment ) and < email >

`armored_public_key`: the public key begin with `-----BEGIN PGP PUBLIC KEY BLOCK-----` and end
with `-----END PGP PUBLIC KEY BLOCK-----`

### Docker Deploy

This project continuously integrates with docker. Go check it out if you don't have docker locally installed.

Note: this docker image use MODE `production` as default, please check your configuration when deploying.

```shell
docker run -d -p 8000:8000 opentreehole/auth_next
```

or use [docker compose](./docker-compose.yml)

For api documentation, please open http://localhost:8000/docs after running app

## Badge

[![stars](https://img.shields.io/github/stars/OpenTreeHole/auth_next)](https://github.com/OpenTreeHole/auth_next/stargazers)
[![issues](https://img.shields.io/github/issues/OpenTreeHole/auth_next)](https://github.com/OpenTreeHole/auth_next/issues)
[![pull requests](https://img.shields.io/github/issues-pr/OpenTreeHole/auth_next)](https://github.com/OpenTreeHole/auth_next/pulls)

[![standard-readme compliant](https://img.shields.io/badge/readme%20style-standard-brightgreen.svg?style=flat-square)](https://github.com/RichardLitt/standard-readme)

### Powered by

![Go](https://img.shields.io/badge/go-%2300ADD8.svg?style=for-the-badge&logo=go&logoColor=white)
![Swagger](https://img.shields.io/badge/-Swagger-%23Clojure?style=for-the-badge&logo=swagger&logoColor=white)

## Contributing

Feel free to dive in! [Open an issue](https://github.com/OpenTreeHole/auth_next/issues/new)
or [Submit PRs](https://github.com/OpenTreeHole/auth_next/compare).

### Contributors

This project exists thanks to all the people who contribute.

<a href="https://github.com/OpenTreeHole/auth_next/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=OpenTreeHole/auth_next"  alt="contributors"/>
</a>

## Licence

[![license](https://img.shields.io/github/license/OpenTreeHole/auth_next)](https://github.com/OpenTreeHole/auth_next/blob/master/LICENSE)
© OpenTreeHole
