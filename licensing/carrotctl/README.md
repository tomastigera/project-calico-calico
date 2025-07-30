# carrotctl

Tigera licensing and entitlement commandline tool

![carrotctl](./carrabbit.png) <!-- .element height="20%" width="20%" -->

## Setup 

Download the `carrotctl` binary from the releases page on Github.

Update the `example.env` file with the database access information and credentials.
Then source the file by `source ./example.env`

Note: you don't need to do that for a local dev setup where DB is on the same host. 

# Using carrotctl

`carrotctl` can generate and retrieve licenses.

For v2.1 we basically have 2 major features:

1. Generate license (`carrotctl generate`)
2. Retrieve license (`carrotctl list` and `carrotctl retrieve`)

## Generate a new license

### Usage

Spec for `carrotctl generate` is:

```
Generate Calico Enterprise license file and store the fields in the database

Usage:
  carrotctl generate [flags]

Aliases:
  generate, gen, gen-lic, generate-license, make-me-a-license

Flags:
      --certificate string   Licensing intermediate certificate path (default "./tigera.io_certificate.pem")
  -c, --customer string      Customer name
      --debug                Print debug logs while generating this license
  -e, --expiry string        License expiration date in MM/DD/YYYY format. Expires at the end of the day cluster local timezone.
  -g, --graceperiod int      Number of days the cluster will keep working after the license expires (default 90)
  -h, --help                 help for generate
  -n, --nodes int            Number of nodes customer is licensed for. If not specified, it'll be an unlimited nodes license.
  -p, --package string       License Package and feature selection to be assigned to a license (default "cnx|all")
      --signing-key string   Private key path to sign the license content (default "./tigera.io_private_key.pem")
```

If none of the flags are passed then it will interactively ask the user to enter the data.

In order to select a license package type one of the following values must be set:
- `cloud|community`
- `cloud|pro`
- `cloud|starter`
- `cnx|all`

### Examples

#### Default fields:

```
carrotctl generate --customer happy-carrot-inc --expiry 3/14/2022
Confirm the license information:
_________________________________________________________________________
Customer name:                  happy-carrot-inc
Number of nodes:                Unlimited (site license)
License term expiration date:   2022-03-14 23:59:59 -0700 PDT
Features:                       [cnx all]
Checkin interval:               Offline license
Grace period (days):            90
License ID (auto-generated):    b2e8c974-a987-4004-b1bc-a739e6ad6272
________________________________________________________________________

Is the license information correct? [y/N]
y
Customer 'happy-carrot-inc-license.yaml' not found in company database.  Create new company? [y/N]
y

Created license file 'happy-carrot-inc-license.yaml'
```

## Retrieve a license from database

`carrotctl list --customer=boxy-box-inc` will list all key license fields for all the licenses issued for a customer name matching `boxy-box-inc*`

To list all customers and their licenses, use `carrotctl list --all` command.

It will list `LicenseID` for each license issued for that customer, which can be used to retrieve the
license with `carrotctl retrieve --license-id=<license-id>` command.

Each license has a unique ID (LICENSEID), even if it is for the same customer.

### Usage

List licenses for a specific or all customers

```
List licenses

Usage:
  carrotctl list licenses for a specific or all customers [flags]

Aliases:
  list, list, list-licenses

Flags:
      --all               List all companies and their licenses
  -c, --customer string   Customer name
  -h, --help              help for list
```

Re-generate a license listed in the list command

```
Retrieve a license

Usage:
  carrotctl retrieve a previously generated license from the database [flags]

Aliases:
  retrieve, retrieve, retrieve-license

Flags:
  -h, --help                help for retrieve
  -i, --license-id string   License ID
```

### Example

- List all customers and their licenses (this could take a while if there's a lot of customers and licenses in the database)

```
carrotctl list --all
COMPANY                    LICENSE_ID                                 NODES          EXPIRY                          FEATURES
ayyyyyyyyyyyyyyoooooooo    e971637d-19df-4f0f-8f8d-2a1f73887b33       Unlimited      2020-03-05 00:00:00 +0000 UTC   cnx|all
Box                        f012f6b8-579a-4c2d-b16b-74e3c882cb07       Unlimited      2020-03-05 00:00:00 +0000 UTC   cnx|all
Box                        37d8927b-a90b-4df5-b59d-00a4d72b5a89       Unlimited      2020-03-05 00:00:00 +0000 UTC   cnx|all
boxy                       57b415fd-cb48-4c4f-b12d-693e4466c42c       Unlimited      2020-03-05 00:00:00 +0000 UTC   cnx|all
weetabix-inc               f9fb8c9d-6d12-4ab7-80dd-201ec2289faa       Unlimited      2021-07-08 00:00:00 +0000 UTC   cnx|all
weetabix-inc               137ca41f-62f6-4862-8329-b3056db5ba87       Unlimited      2021-07-08 00:00:00 +0000 UTC   cnx|all
```

- List all the licenses issued for customer `weetabix-inc`

```
carrotctl list --customer weetabix-inc
COMPANY                    LICENSE_ID                                 NODES          EXPIRY                          FEATURES
weetabix-inc               f9fb8c9d-6d12-4ab7-80dd-201ec2289faa       Unlimited      2021-07-08 00:00:00 +0000 UTC   cnx|all
weetabix-inc               137ca41f-62f6-4862-8329-b3056db5ba87       Unlimited      2021-07-08 00:00:00 +0000 UTC   cnx|all

```

- Re-generate the license.yaml for the second license from database:

```
carrotctl retrieve --license-id=f9fb8c9d-6d12-4ab7-80dd-201ec2289faa

Created license file 'f9fb8c9d-6d12-4ab7-80dd-201ec2289faa-license.yaml'
```

# Building

## DB setup

To develop the tool, you'll need to set up a suitable license database to test against.
Do NOT run on the official AWS instance: it will interact with the real license database.

```
# Install mariadb; you may need to consult your distribution's instructions.
pacman -Sy mysql
sudo systemctl start mysqld

# Create the tables and user
mysql -u root -p < datastore/db.sql
```

### Checking the DB

Consult the internet for SQL documentation, but as a quickstart:

```
mysql -u root -p
USE tigera_backoffice;
SELECT * FROM companies;
SELECT (id, nodes, company_id, expiry) FROM licenses;
SELECT (jwt) FROM licenses WHERE company_id=2;
```

### Wiping the DB
```
mysql -u root << EOF
USE tigera_backoffice;
DROP TABLE licenses;
DROP TABLE companies;
EOF
```

## Building

With dep installed (`go get -u github.com/golang/dep/cmd/dep`), run the following.

```
dep ensure
go build -o dist/carrotctl ./carrotctl
```

## Testing

You can run generate like the following.  It'll pick up the certificates in the repo.
```
dist/carrotctl generate -c tigera -e 01/01/2019 -n 10
```
