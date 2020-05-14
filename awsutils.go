package awsutils

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os/user"
	"strconv"
	"time"

	"github.com/Arafatk/glot"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	_ "github.com/aws/aws-sdk-go/aws/awserr" //
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatch"
	"github.com/aws/aws-sdk-go/service/ec2"
	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
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

// it is helper function to validate region and open SVC session to EC2
func openServiceClientEC2(region string) (*ec2.EC2, error) {

	// validate region string
	if !isValidEC2Region(region) {
		return nil, errors.New("invalid region name")
	}
	// open session in region
	sess, err := session.NewSessionWithOptions(session.Options{
		Profile: "personal-aws",
		Config: aws.Config{
			Region: aws.String(region),
		},
	})
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
		return errors.New("unable to determine UNIX user HOME directory")
	}

	svc, err := openServiceClientEC2(region)
	if err != nil {
		return err
	}

	newKey, err := svc.CreateKeyPair(&ec2.CreateKeyPairInput{KeyName: aws.String(keyname)})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok && aerr.Code() == "InvalidKeyPair.Duplicate" {
			return errors.New("keypair already exists with that name in that region")
		}
		return errors.New("unable to create keypair")
	}

	err = ioutil.WriteFile(usr.HomeDir+"/.ssh/"+keyname+".pem",
		[]byte(*newKey.KeyMaterial), 0600)
	if err != nil {
		return errors.New("error writing secret key to file")
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
		return nil, fmt.Errorf("unable to get key pairs, %v", err)
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
			return fmt.Errorf("key pair %q does not exist", keyname)
		}
		return fmt.Errorf("unable to delete key pair: %s, %v", keyname, err)
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
		return "", errors.New("no VPCs found to associate security group with")
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
				return "", fmt.Errorf("unable to find VPC with ID %q", vpcID)
			case "InvalidGroup.Duplicate":
				return "", fmt.Errorf("security group %q already exists", name)
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
				return nil, fmt.Errorf("%s", aerr.Message())
			}
		}
		return nil, fmt.Errorf("unable to get descriptions for security groups, %v", err)
	}
	return result.SecurityGroups, nil

}

// GetAmazonImageID is a function storing ami IDs anre returning then based on region
func GetAmazonImageID(region string) string {
	AMIs := make(map[string]string)

	AMIs["eu-central-1"] = "ami-001d09d44e27bbb7c" //"ami-0ec1ba09723e5bfac"
	// AMIs["eu-west-1"] = "ami-00035f41c82244dab"
	// AMIs["eu-west-2"] = "ami-0b0a60c0a2bd40612"
	// AMIs["eu-west-3"] = "ami-08182c55a1c188dee"
	// AMIs["us-east-1"] = "ami-0ac019f4fcb7cb7e6"
	// AMIs["us-east-2"] = "ami-0f65671a86f061fcd"
	// AMIs["us-west-1"] = "ami-063aa838bd7631e0b"
	// AMIs["us-west-2"] = "ami-0bbe6b35405ecebdb"
	// AMIs["ca-central-1"] = "ami-0427e8367e3770df1"
	// AMIs["ap-northeast-1"] = "ami-07ad4b1c3af1ea214"
	// AMIs["ap-northeast-2"] = "ami-06e7b9c5e0c4dd014"
	// AMIs["ap-southeast-1"] = "ami-0c5199d385b432989"
	// AMIs["ap-southeast-2"] = "ami-07a3bd4944eb120a0"
	// AMIs["ap-south-1"] = "ami-0d773a3b7bb2bb1c1"
	// AMIs["sa-east-1"] = "ami-03c6239555bb12112"

	return AMIs[region]
}

// GetSecurityGroupID is a func that returns SG ID basedo n region
func GetSecurityGroupID(region string) string {
	sgIDs := make(map[string]string)

	sgIDs["eu-central-1"] = "sg-0df229a56b6b67832"
	// sgIDs["eu-west-1"] = ""
	// sgIDs["eu-west-2"] = ""
	// sgIDs["eu-west-3"] = ""
	// sgIDs["us-east-1"] = ""
	// sgIDs["us-east-2"] = ""
	// sgIDs["us-west-1"] = ""
	// sgIDs["us-west-2"] = ""
	// sgIDs["ca-central-1"] = ""
	// sgIDs["ap-northeast-1"] = ""
	// sgIDs["ap-northeast-2"] = ""
	// sgIDs["ap-southeast-1"] = ""
	// sgIDs["ap-southeast-2"] = ""
	// sgIDs["ap-south-1"] = ""
	// sgIDs["sa-east-1"] = ""

	return sgIDs[region]
}

// GetKeyPairs returns EC2 key pairs from given account for given region
func GetKeyPairs(region string) ([]string, error) {
	fmt.Println("Getting keys...")
	keys := make([]string, 0)
	sess, err := session.NewSessionWithOptions(session.Options{
		Profile: "personal-aws",
		Config: aws.Config{
			Region: aws.String(region),
		},
	})
	if err != nil {
		return nil, err
	}
	svc := ec2.New(sess)
	result, err := svc.DescribeKeyPairs(nil)
	if err != nil {
		return keys, err
	}
	for _, pair := range result.KeyPairs {
		keys = append(keys, fmt.Sprintf("%s", *pair.KeyName))
	}
	return keys, nil
}

// PlotGraph is for plotting graphs
func PlotGraph(region string, instanceID string, data []Metric) {
	dimensions := 2
	persist := false
	debug := false

	plot1, _ := glot.NewPlot(dimensions, persist, debug)
	plot1.SetTitle(instanceID + " - " + region)
	plot1.SetYrange(0, 100)
	plot1.AddPointGroup(data[0].MetricName, "lines", data[0].Values)
	plot1.SavePlot(instanceID + "_" + data[0].MetricName + ".png")

	plot2, _ := glot.NewPlot(dimensions, persist, debug)
	plot2.SetTitle(instanceID + " - " + region)
	plot2.AddPointGroup(data[1].MetricName, "lines", data[1].Values)
	plot2.SavePlot(instanceID + "_" + data[1].MetricName + ".png")
}

// CreateInstance is for creating EC2 instances for given region, keypair, SG and AMI-ID
func CreateInstance(region string, keypair string, sgparam string, amid string) (string, error) {
	// Create Amazon AWS Session in the specified region
	sess, err := session.NewSessionWithOptions(session.Options{
		Profile: "personal-aws",
		Config: aws.Config{
			Region: aws.String(region),
		},
	})
	if err != nil {
		return "", err
	}
	// Create Amazon AWS Service client using the session
	svc := ec2.New(sess)

	sgID := sgparam //FloSec2 in London
	//sgID := "sg-0d1e241f54b384e14"  //FloSec in Frankfurt
	sgArray := make([]*string, 1)
	sgArray[0] = &sgID

	runResult, err := svc.RunInstances(&ec2.RunInstancesInput{
		// An Amazon Linux AMI ID for t2.micro instances in the us-west-2 region
		ImageId: aws.String(amid), // LONDON
		//ImageId:      aws.String("ami-0bdf93799014acdc4"),  // FRANKFURT
		InstanceType:     aws.String("t2.xlarge"),
		KeyName:          aws.String(keypair),
		SecurityGroupIds: sgArray,
		MinCount:         aws.Int64(1),
		MaxCount:         aws.Int64(1),
	})

	if err != nil {
		//fmt.Println("Could not create instance", err)
		return "", err
	}

	newInstanceID := *runResult.Instances[0].InstanceId
	//fmt.Println("Created instance", newInstanceID)
	return newInstanceID, nil
}

// TagInstance is a helper function to tag a newly created instance
func TagInstance(region string, instanceid string, nametag string) error {

	sess, err := session.NewSessionWithOptions(session.Options{
		Profile: "personal-aws",
		Config: aws.Config{
			Region: aws.String(region),
		},
	})
	if err != nil {
		//fmt.Println("Error creating session ", err)
		return err
	}

	svc := ec2.New(sess)

	// Add tags to the created instance
	_, errtag := svc.CreateTags(&ec2.CreateTagsInput{
		Resources: []*string{&instanceid},
		Tags: []*ec2.Tag{
			{
				Key:   aws.String("Name"),
				Value: aws.String(nametag),
			},
		},
	})

	if errtag != nil {
		//log.Println("Could not create tags for instance", runResult.Instances[0].InstanceId, errtag)
		return errtag
	}
	//fmt.Println("Instance was successfully tagged.")
	return nil
}

// StartInstance is helper func to start instance in region with given InstanceID
func StartInstance(region string, instanceID string) error {
	sess, err := session.NewSessionWithOptions(session.Options{
		Profile: "personal-aws",
		Config: aws.Config{
			Region: aws.String(region),
		},
	})
	if err != nil {
		//fmt.Println("Error creating session ", err)
		return err
	}

	svc := ec2.New(sess)

	input := &ec2.StartInstancesInput{
		InstanceIds: []*string{
			aws.String(instanceID),
		},
		DryRun: aws.Bool(false),
	}
	_, err = svc.StartInstances(input)
	return err
}

// StopInstance is helper func to stop instance with given ID in given region
func StopInstance(region string, instanceID string) error {
	sess, err := session.NewSessionWithOptions(session.Options{
		Profile: "personal-aws",
		Config: aws.Config{
			Region: aws.String(region),
		},
	})
	if err != nil {
		return err
	}

	svc := ec2.New(sess)

	input := &ec2.StopInstancesInput{
		InstanceIds: []*string{
			aws.String(instanceID),
		},
		DryRun: aws.Bool(false),
	}
	_, err = svc.StopInstances(input)
	return err
}

// TerminateInstanceByID is helper func to terminate instance by ID
func TerminateInstanceByID(region string, instanceID string) error {
	sess, err := session.NewSessionWithOptions(session.Options{
		Profile: "personal-aws",
		Config: aws.Config{
			Region: aws.String(region),
		},
	})
	if err != nil {
		return err
	}

	svc := ec2.New(sess)

	input := &ec2.TerminateInstancesInput{
		InstanceIds: []*string{
			aws.String(instanceID),
		},
		DryRun: aws.Bool(false),
	}
	_, err = svc.TerminateInstances(input)
	return err
}

func convertToFloatArray(input []int) []float64 {
	var output []float64
	for _, v := range input {
		output = append(output, float64(v))
	}
	return output
}

// RenderGraphs is helper func to render graphs
func RenderGraphs(metricArray []Metric) {
	if err := ui.Init(); err != nil {
		fmt.Printf("failed to initialize termui: %v", err)
		panic(err)
	}
	defer ui.Close()

	CPUData, NetworkData := metricArray[0].Values, metricArray[1].Values

	sl0 := widgets.NewSparkline()
	sl0.Data = convertToFloatArray(CPUData)
	sl0.LineColor = ui.ColorGreen

	// single
	slg0 := widgets.NewSparklineGroup(sl0)
	slg0.Title = "CPU Usage"
	slg0.SetRect(0, 0, 40, 15)

	sl1 := widgets.NewSparkline()
	sl1.Data = convertToFloatArray(NetworkData)
	sl1.LineColor = ui.ColorGreen

	// single
	slg1 := widgets.NewSparklineGroup(sl1)
	slg1.Title = "Network I/O"
	slg1.SetRect(0, 50, 40, 15)

	ui.Render(slg0, slg1)

	uiEvents := ui.PollEvents()
	for {
		e := <-uiEvents
		switch e.ID {
		case "q", "<C-c>":
			return
		}
	}
}

var counter int64

func buildMetricDataQuery(metricname, instanceID string) *cloudwatch.MetricDataQuery {
	counter++
	return &cloudwatch.MetricDataQuery{
		Id: aws.String("id" + strconv.FormatInt(counter, 10)),
		MetricStat: &cloudwatch.MetricStat{
			Period: aws.Int64(60),
			Stat:   aws.String("Average"),
			Metric: &cloudwatch.Metric{
				MetricName: aws.String(metricname),
				Dimensions: []*cloudwatch.Dimension{
					{
						Name:  aws.String("InstanceId"),
						Value: aws.String(instanceID),
					},
				},
				Namespace: aws.String("AWS/EC2"),
			},
		},
	}
}

// Metric struct to hold CW metrics data
type Metric struct {
	Region     string
	InstanceID string
	MetricName string
	Values     []int
}

// GetCloudWatchMetrics to help get metrics for given Instance ID
func GetCloudWatchMetrics(region string, instanceID string) []Metric {
	counter = 0
	sess, err := session.NewSessionWithOptions(session.Options{
		Profile: "personal-aws",
		Config: aws.Config{
			Region: aws.String(region),
		},
	})
	if err != nil {
		fmt.Println(err)
	}
	cw := cloudwatch.New(sess)

	dataInput := &cloudwatch.GetMetricDataInput{
		StartTime: aws.Time(time.Now().Add(-480 * time.Minute)),
		EndTime:   aws.Time(time.Now()),
		MetricDataQueries: []*cloudwatch.MetricDataQuery{
			buildMetricDataQuery("CPUUtilization", instanceID),
			buildMetricDataQuery("NetworkPacketsOut", instanceID),
		},
	}

	dataOutput, err := cw.GetMetricData(dataInput)
	if err != nil {
		log.Fatal("error GetMetricStatistics: ", err)
	}
	data := *dataOutput

	return []Metric{
		saveMetric(region, instanceID, data.MetricDataResults[0]),
		saveMetric(region, instanceID, data.MetricDataResults[1]),
	}
}

func roundUp(val float64) int {
	if val > 0 {
		return int(val + 1.0)
	}
	return int(val)
}

func saveMetric(region string, instanceID string, source *cloudwatch.MetricDataResult) Metric {
	data := make([]int, 0)

	for i := len(source.Values); i > 0; i-- {
		data = append(data, roundUp(*source.Values[i-1]))
	}

	return Metric{
		Region:     region,
		InstanceID: instanceID,
		MetricName: *source.Label,
		Values:     data,
	}
}
