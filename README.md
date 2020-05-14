## AWS Utils Library

[![Go Report Card](https://goreportcard.com/badge/github.com/florianakos/awshelper)](https://goreportcard.com/report/github.com/florianakos/awshelper) [![Build Status](https://travis-ci.org/florianakos/awshelper.svg?branch=master)](https://travis-ci.org/florianakos/awshelper)

This is a simple Go library that wraps the "AWS GO SDK" library to provide some useful functions that create or modify AWS resources.

### Example Usage: ###

```go
awshelper.CreateEC2KeyPair("aws_region", "key_name")
```
The above code creates a new KeyPair and saves the secret key to ``~/.ssh/ `` directory on UNIX systems. It returns an error if something went wrong.


```go
awshelper.ListAllEC2KeyPairs("aws_region")
```
The above code returns a array of pointers to ec2.KeyPairInfo or an error if something goes wrong while querying the region for all security keys available.


```go
awshelper.DeleteEC2KeyPair("aws_region", "keypair_name")
```
The above code deletes a key in the specifid region if it exists, otherwise gives an error.


```go
awshelper.CreateSecurityGroupForSSH("aws_region", "group_name", "group_description")
```
The above code creates a security group with name and description unless the name already exists. It returns a string which contains the sgID of the newly create security group or an error if something went wrong.

```go
awshelper.ListAllSecurityGroups("aws_region", "sgID")
```
The above function lists all security groups in a region if the "sgID" string was empty, otherwise lists all info about the security group with the given ID.
