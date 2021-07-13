package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iotdeviceadvisor"
	"github.com/aws/aws-sdk-go-v2/service/iotdeviceadvisor/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"go.uber.org/zap"
)

var (
	appBinary          = os.Getenv("APP_BINARY")        // Absolute path to device application
	appArgsStr         = os.Getenv("APP_ARGS")          // Args to deive application if any
	cfg_key            = os.Getenv("CONFIG_PARAM_KEY")  // Parameter store key name for configuration
	isDeviceAdvisorRun = os.Getenv("DEVICEADVISOR_RUN") // Is it a device advisor run? TRUE/FALSE
	clientCertPath     = os.Getenv("CLIENT_CERT_PATH")
	clientPubKeyPath   = os.Getenv("CLIENT_CERT_KEY_PATH")
	clientPvtKeyPath   = os.Getenv("CLIENT_PRIVATE_KEY_PATH")
	envVars            = []string{}
	logLevel           = os.Getenv("LOG_LEVEL") // DEBUG or nothing. Defaults to INFO
	log                *zap.SugaredLogger
)

type Configuration struct {
	IoTEndpoint           string
	DeviceAdvisorEndpoint string
	DeviceAdvisorSuiteID  string
	Thing                 Thing
}

type Thing struct {
	Name string
	ARN  string
	Cert Certificate
}

type Certificate struct {
	ID     string
	ARN    string
	PEM    string
	PubKey string
	Pvtkey string
}

func main() {
	var logger *zap.Logger
	if logLevel == "DEBUG" {
		logger, _ = zap.NewDevelopment()
	} else {
		logger, _ = zap.NewProduction()
	}
	log = logger.Sugar()
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithDefaultRegion("us-west-2"))
	if err != nil {
		log.Fatalf("could not load aws config: %v", err)
	}
	ssmclient := ssm.NewFromConfig(cfg)
	gpo, err := ssmclient.GetParameter(ctx, &ssm.GetParameterInput{Name: &cfg_key, WithDecryption: true})
	if err != nil {
		log.Fatalf("could not get config from param store: %s, err: %v", cfg_key, err)
	}
	config := Configuration{}
	err = json.Unmarshal([]byte(*gpo.Parameter.Value), &config)
	if err != nil {
		log.Fatalf("could not unmarshall into object: %v", err)
	}

	err = ioutil.WriteFile(clientCertPath, []byte(config.Thing.Cert.PEM), 0644)
	if err != nil {
		log.Fatalf("could not write cert: %v", err)
	}
	err = ioutil.WriteFile(clientPubKeyPath, []byte(config.Thing.Cert.PubKey), 0644)
	if err != nil {
		log.Fatalf("could not write pubKey: %v", err)
	}
	err = ioutil.WriteFile(clientPvtKeyPath, []byte(config.Thing.Cert.Pvtkey), 0644)
	if err != nil {
		log.Fatalf("could not write pvtKey: %v", err)
	}
	log.Debug("wrote all certificates")

	envVars = append(envVars, fmt.Sprintf("CLIENT_IDENTIFIER=%q", config.Thing.Name))

	errChan := make(chan error)
	if isDeviceAdvisorRun == "TRUE" {
		log.Debugf("isDeviceAdvisorRun=%s", isDeviceAdvisorRun)
		go startDeviceAdvisor(ctx, cfg, config, errChan)
		envVars = append(envVars, fmt.Sprintf("AWS_IOT_ENDPOINT=%s", config.DeviceAdvisorEndpoint))
	} else {
		envVars = append(envVars, fmt.Sprintf("AWS_IOT_ENDPOINT=%s", config.IoTEndpoint))
	}
	go runApp(envVars, errChan)
	err = <-errChan
	if err != nil {
		log.Fatalf("error :( %v", err)
	}
}

func runApp(env []string, errChan chan<- error) {
	log.Debug("entering runApp")
	appArgs := strings.Split(appArgsStr, " ")
	cmd := exec.Command(appBinary, appArgs...)
	cmd.Env = append(env, os.Environ()...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	err := cmd.Run()
	log.Debug("exiting runApp")
	errChan <- err
}

func startDeviceAdvisor(ctx context.Context, cfg aws.Config, config Configuration, errChan chan<- error) {
	log.Debug("entering startDeviceAdvisor")
	idaclient := iotdeviceadvisor.NewFromConfig(cfg)

	start := time.Now()
	sro, err := idaclient.StartSuiteRun(ctx, &iotdeviceadvisor.StartSuiteRunInput{
		SuiteDefinitionId: &config.DeviceAdvisorSuiteID,
		SuiteRunConfiguration: &types.SuiteRunConfiguration{
			PrimaryDevice: &types.DeviceUnderTest{
				CertificateArn: &config.Thing.Cert.ARN,
				ThingArn:       &config.Thing.ARN,
			},
		},
	})
	if err != nil {
		errChan <- fmt.Errorf("could not start DA run: %v", err)
		return
	}

	timeout := 10 * time.Minute
	retry_interval := 3 * time.Second
	stillRunning := true
	for (time.Since(start) < timeout) && stillRunning {
		time.Sleep(retry_interval)
		gsro, err := idaclient.GetSuiteRun(ctx, &iotdeviceadvisor.GetSuiteRunInput{
			SuiteDefinitionId: &config.DeviceAdvisorSuiteID,
			SuiteRunId:        sro.SuiteRunId,
		})
		if err != nil {
			errChan <- fmt.Errorf("could not get DA run deets: %v", err)
			return
		}
		stillRunning = isRunning(gsro.Status)

		if testPassed(gsro.Status) {
			stillRunning = false
			errChan <- nil
		}
		if testFailed(gsro.Status) {
			stillRunning = false
			errChan <- fmt.Errorf("device advisor did not pass: %+v", gsro.TestResult)
		}
	}
	if stillRunning {
		errChan <- fmt.Errorf("device advisor timeout after %s", timeout)
	}
	log.Debug("exiting startDeviceAdvisor")
}

func isRunning(status types.SuiteRunStatus) bool {
	r := []types.SuiteRunStatus{
		types.SuiteRunStatusPending,
		types.SuiteRunStatusRunning,
		types.SuiteRunStatusStopping,
	}
	for _, s := range r {
		if status == s {
			return true
		}
	}
	return false
}

func testPassed(status types.SuiteRunStatus) bool {
	return status == types.SuiteRunStatusPass
}

func testFailed(status types.SuiteRunStatus) bool {
	failStatuses := []types.SuiteRunStatus{
		types.SuiteRunStatusFail,
		types.SuiteRunStatusCanceled,
		types.SuiteRunStatusStopped,
		types.SuiteRunStatusPassWithWarnings,
		types.SuiteRunStatusError,
	}
	for _, s := range failStatuses {
		if status == s {
			return true
		}
	}
	return false
}
