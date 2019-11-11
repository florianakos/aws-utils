package awshelper

import (
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"io/ioutil"
	"os/user"
)

// AllRegions is a vsriable that stores all possible AWS regions
var AllRegions = []string{
	"us-east-2",      //US East (Ohio)
	"us-east-1",      //US East (N. Virginia)
	"us-west-1",      //US West (N. California)
	"us-west-2",      //US West (Oregon)
	"ap-south-1",     //Asia Pacific (Mumbai)
	"ap-northeast-3", //Asia Pacific (Osaka-Local)
	"ap-northeast-2", //Asia Pacific (Seoul)
	"ap-southeast-1", //Asia Pacific (Singapore)
	"ap-southeast-2", //Asia Pacific (Sydney)
	"ap-northeast-1", //Asia Pacific (Tokyo)
	"ca-central-1",   //Canada (Central)
	"cn-north-1",     //China (Beijing)
	"cn-northwest-1", //China (Ningxia)
	"eu-central-1",   //EU (Frankfurt)
	"eu-west-1",      //EU (Ireland)
	"eu-west-2",      //EU (London)
	"eu-west-3",      //EU (Paris)
	"sa-east-1",      //South America (São Paulo)
	"us-gov-east-1",  //AWS GovCloud (US-East)
	"us-gov-west-1",  //AWS GovCloud (US)
}

// checks if the supplied string is a valud AWS EC2 region name
func isValidEC2Region(compare string) bool {

	for _, value := range AllRegions {
		if value == compare {
			return true
		}
	}
	return false

}

// helper function to validate region and open SVC session to EC2
func openServiceClientEC2(region string) (*ec2.EC2, error) {

	// validate region string
	if !isValidEC2Region(region) {
		return nil, errors.New("Invalid region name!")
	}
	// open session in region
	sess, err := session.NewSession(&aws.Config{Region: aws.String(region)})
	// check erros if any, otherwise return the session pointer
	if err != nil {
		return nil, err
	}
	return ec2.New(sess), nil
}

// CreateEC2KeyPair creates a new AWS SSH Secret key and puts the secret content in a file in ~/.ssh/ dir
func CreateEC2KeyPair(region string, keyname string) error {

	usr, err := user.Current()
	if err != nil {
		return errors.New("Unable to determine UNIX user HOME directory!")
	}

	svc, err := openServiceClientEC2(region)
	if err != nil {
		return err
	}

	newKey, err := svc.CreateKeyPair(&ec2.CreateKeyPairInput{KeyName: aws.String(keyname)})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok && aerr.Code() == "InvalidKeyPair.Duplicate" {
			return errors.New("Keypair already exists with that name in that region!")
		}
		return errors.New("Unable to create keypair!")
	}

	err = ioutil.WriteFile(usr.HomeDir+"/.ssh/"+keyname+".pem",
		[]byte(*newKey.KeyMaterial), 0600)
	if err != nil {
		return errors.New("Error writing secret key to file!")
	}

	return nil
}

// ListAllEC2KeyPairs is a function to list all AWS KeyPairs in region specified
func ListAllEC2KeyPairs(region string) ([]*ec2.KeyPairInfo, error) {

	svc, err := openServiceClientEC2(region)
	if err != nil {
		return nil, err
	}
	result, err := svc.DescribeKeyPairs(nil)
	if err != nil {
		return nil, fmt.Errorf("Unable to get key pairs, %v", err)
	}
	return result.KeyPairs, nil
}

// DeleteEC2KeyPair is a function to delete specified key in specified region
func DeleteEC2KeyPair(region string, keyname string) error {

	svc, err := openServiceClientEC2(region)
	if err != nil {
		return err
	}
	_, err = svc.DeleteKeyPair(&ec2.DeleteKeyPairInput{
		KeyName: aws.String(keyname),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok && aerr.Code() == "InvalidKeyPair.Duplicate" {
			return fmt.Errorf("Key pair %q does not exist.", keyname)
		}
		return fmt.Errorf("Unable to delete key pair: %s, %v.", keyname, err)
	}
	return nil

}

// CreateSecurityGroupForSSH is a function to create security group that allows SSN through on TCP/22
// returns (string, error) that point to SG-ID and error if any during execution
func CreateSecurityGroupForSSH(region string, name string, description string) (string, error) {

	if len(name) == 0 || len(description) == 0 {
		return "", errors.New("Invalid Group name or Group Description supplied")
	}

	svc, err := openServiceClientEC2(region)
	if err != nil {
		return "", err
	}

	// Get a list of VPCs so we can associate the group with the first VPC.
	availableVPCs, err := svc.DescribeVpcs(nil)
	if err != nil {
		return "", fmt.Errorf("Unable to describe VPCs, %v", err)
	}
	if len(availableVPCs.Vpcs) == 0 {
		return "", errors.New("No VPCs found to associate security group with.")
	}
	vpcID := aws.StringValue(availableVPCs.Vpcs[0].VpcId)

	// Create the security group with the VPC, name and description.
	createSGResult, err := svc.CreateSecurityGroup(&ec2.CreateSecurityGroupInput{
		GroupName:   aws.String(name),
		Description: aws.String(description),
		VpcId:       aws.String(vpcID),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case "InvalidVpcID.NotFound":
				return "", fmt.Errorf("Unable to find VPC with ID %q.", vpcID)
			case "InvalidGroup.Duplicate":
				return "", fmt.Errorf("Security group %q already exists.", name)
			}
		}
		return "", fmt.Errorf("Unable to create security group %q, %v", name, err)
	}

	newSGID := createSGResult.GroupId

	// authorize the created security group for SSH ingress
	_, err = svc.AuthorizeSecurityGroupIngress(&ec2.AuthorizeSecurityGroupIngressInput{
		GroupName: aws.String(name),
		IpPermissions: []*ec2.IpPermission{
			(&ec2.IpPermission{}).
				SetIpProtocol("tcp").
				SetFromPort(22).
				SetToPort(22).
				SetIpRanges([]*ec2.IpRange{
					(&ec2.IpRange{}).
						SetCidrIp("0.0.0.0/0"),
				}),
		},
	})
	if err != nil {
		return "", fmt.Errorf("Unable to set security group %q ingress, %v", name, err)
	}
	// return SG-ID and nil error
	return *newSGID, nil

}

// ListAllSecurityGroups is a function to list all security groups, if sgID is "" then it lists all in the region
func ListAllSecurityGroups(region string, sgID string) ([]*ec2.SecurityGroup, error) {

	svc, err := openServiceClientEC2(region)
	if err != nil {
		return nil, err
	}

	result, err := svc.DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{
		GroupIds: aws.StringSlice([]string{sgID}),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case "InvalidGroupId.Malformed":
				fallthrough
			case "InvalidGroup.NotFound":
				return nil, fmt.Errorf("%s.", aerr.Message())
			}
		}
		return nil, fmt.Errorf("Unable to get descriptions for security groups, %v", err)
	}
	return result.SecurityGroups, nil

}
