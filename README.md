# Open Tree Hole Auth Next

Next Generation of Auth microservice integrated with [Kong Gateway](https://github.com/Kong/kong) for registration and issuing tokens

## Features

- White-listed email registration
- Anonymous: Shamir encrypted email and random identity
- issue and revoke JWT tokens

## Usage

### Prerequisite

1. Kong Gateway deployed, see https://docs.konghq.com/gateway/latest/

2. Prepare mysql/sqlite database, if `SHAMIR_FEATURE` set true or default

Create table `shamir_public_key`

```mysql
CREATE TABLE `shamir_public_key` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `identity_name` longtext NOT NULL,
  `armored_public_key` longtext NOT NULL,
  PRIMARY KEY (`id`)
);
```

Insert at least 7 PGP key administrator info into this table

`identity_name`: PGP identity name or `uid`, including username, ( comment ) and < email >

`armored_public_key`: the public key begin with `-----BEGIN PGP PUBLIC KEY BLOCK-----` and end with `-----END PGP PUBLIC KEY BLOCK-----`

3. Environment variables

`MODE` optional

This variable controls info logger and user authorization. 

one of `production`, `dev`, `test` or `bench`. 

default: `dev`.

`DB_URL` **required**

This variable specified the dsn for database connecting.

format: `username:password@tcp(hostname:port)/database?parseTime=true&loc=[Timezone]`

eg: `auth:auth@tcp(mysql:3306)/auth?parseTime=true&loc=Asia%2FShanghai`

`KONG_URL` **required**

This variable specified the Kong Gateway Url

eg: `http://kong:8001`

`REDIS_URL` optional

This variable specified redis url for verification code storage and other cache fields.

If not set, use local memory cache powered by [go-cache](https://github.com/patrickmn/go-cache).

`EMAIL_WHITELIST` optional

This variable is the email whitelist checked when user register, seperated by comma.

eg: `qq.com,gmail.com,hotmail.com`

if not set, mean allowing all email address.

`EMAIL_SERVER_NO_REPLY_URL` **required**

This variable specified smtp server url for sending verification code email.

format: `smtps://username:password@stmp_host:port`

eg: `smtps://no-reply:xxx@smtp.feishu.cn:465`

`EMAIL_DOMAIN` **required**

This variable specified the sending email domain name and will send email from `username@domain`.

eg: `fduhole.com`

`SHAMIR_FEATURE` optional

This variable is set to open or close shamir feature.

default: `true`

`VERIFICATION_CODE_EXPIRES` optional

verification code expire time in minute.

default: `10`

`SITE_NAME` optional

Send site name when sending verification code email

default: `Open Tree Hole`

4. Environment variables to load data from file

> These files must exist, otherwise the program will panic.

`IDENTIFIER_SALT`

A base64 encrypted secret for encrypting user email into identifier.

default: `/var/run/secrets/identifier_salt`

`PROVISION_KEY`

For oauth, set empty if not needed

default: `/var/run/secrets/provision_key`

`REGISTER_APIKEY_SEED`

For apikey register and login

default: `/var/run/secrets/register_apikey_seed`

`KONG_TOKEN`

Kong basic auth token, set empty if not needed.

default: `/var/run/secrets/kong_token`

### Deploy

This project continuously integrates with docker. Go check it out if you don't have docker locally installed.

```shell
docker run -d -p 8000:8000 opentreehole/auth_next
```

or use docker-compose file: 

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

Feel free to dive in! [Open an issue](https://github.com/OpenTreeHole/auth_next/issues/new) or [Submit PRs](https://github.com/OpenTreeHole/auth_next/compare).

### Contributors

This project exists thanks to all the people who contribute.

<a href="https://github.com/OpenTreeHole/auth_next/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=OpenTreeHole/auth_next"  alt="contributors"/>
</a>

## Licence

[![license](https://img.shields.io/github/license/OpenTreeHole/auth_next)](https://github.com/OpenTreeHole/auth_next/blob/master/LICENSE)
© OpenTreeHole
