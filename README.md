## AWS Utils Library

[![Go Report Card](https://goreportcard.com/badge/github.com/florianakos/aws-utils)](https://goreportcard.com/report/github.com/florianakos/aws-utils) [![Build Status](https://travis-ci.org/florianakos/aws-utils.svg?branch=master)](https://travis-ci.org/florianakos/aws-utils)

This is a simple Go library that wraps the "AWS GO SDK" library to provide some useful functions that create or modify AWS resources.

### Example Usage: ###

```go
awsutils.CreateEC2KeyPair("aws_region", "key_name")
```
The above code creates a new KeyPair and saves the secret key to ``~/.ssh/ `` directory on UNIX systems. It returns an error if something went wrong.


```go
awsutils.ListAllEC2KeyPairs("aws_region")
```
The above code returns a array of pointers to ec2.KeyPairInfo or an error if something goes wrong while querying the region for all security keys available.


```go
awsutils.DeleteEC2KeyPair("aws_region", "keypair_name")
```
The above code deletes a key in the specifid region if it exists, otherwise gives an error.


```go
awsutils.CreateSecurityGroupForSSH("aws_region", "group_name", "group_description")
```
The above code creates a security group with name and description unless the name already exists. It returns a string which contains the sgID of the newly create security group or an error if something went wrong.

```go
awsutils.ListAllSecurityGroups("aws_region", "sgID")
```
The above function lists all security groups in a region if the "sgID" string was empty, otherwise lists all info about the security group with the given ID.

```go
awsutils.OpenSession("public_ec2_IP", "name_of_secret_key.pem")
```

The above code can be used to initiate a session in the terminal and switch to it interactively.

The library assumes that the secret key used for login is available in the ``"~/.ssh"`` directory.
