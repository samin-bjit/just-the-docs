## Security Tools

### PHPStan

PHPStan is a static analysis system for PHP projects. It scans your entire codebase and looks for both obvious and tricky bugs, even in rarely executed if statements that aren’t covered by tests. It can be run on your machine and in CI to prevent bugs from reaching your customers in production. PHPStan is open-source, free, and offers extensions for popular frameworks like Symfony, Laravel, or Doctrine. It also understands code that takes advantage of magic methods and properties.

### OWASP Dependency Check

OWASP Dependency Check is a Software Composition Analysis (SCA) tool that detects publicly disclosed vulnerabilities contained within a project’s dependencies. It does this by determining if there is a Common Platform Enumeration (CPE) identifier for a given dependency. If found, it generates a report linking to the associated CVE entries. Dependency Check can be used to scan applications (and their dependent libraries) to identify any known vulnerable components. It helps address the problem of using known vulnerable components in applications, which can pose security risks.

### OWASP ZAP

OWASP ZAP (Zed Attack Proxy) is the world’s most widely used web app scanner. It is a free and open-source tool actively maintained by a dedicated international team of volunteers. ZAP helps identify security vulnerabilities in web applications by scanning them for potential weaknesses. It provides a range of options for security automation and has add-ons contributed by the community to extend its functionality.

## CodeCommit Configuration

Step 1: Create an IAM User with AWSCodeCommitPowerUser policy.

![codecommit-IAM-user-permission.png](.\assets\codecommit-IAM-user-permission.png)

Step 2: Create Repositories

![codecommit-repositories.png](.\assets\codecommit-repositories.png)

Step 3: Add your SSH keys to the newly created user in Step 1 security credentials. Up to 5 SSH can be added per IAM user.

![Vaccine-SCM-user-IAM-Global.png](.\assets\Vaccine-SCM-user-IAM-Global.png)

![Vaccine-SCM-user-SSH-Keys.png](.\assets\Vaccine-SCM-user-SSH-Keys.png)

Step 4: Again under Security Credentials for HTTPS access to your repositories you need to generate git credentials for your account. 

![Vaccine-SCM-user-IAM-HTTPS-Git-Cred.png](.\assets\Vaccine-SCM-user-IAM-HTTPS-Git-Cred.png)

Step 5: Copy the username and password that IAM generated for you, either by showing, copying, and then pasting this information into a secure file on your local computer, or by choosing Download credentials to download this information as a .CSV file. You need this information to connect to CodeCommit.

Step 6: Check your connection by cloning one of the repositories.

----

## ECR (Elastic Container Registry) Setup

Step 1: Go over to ECR and create a private repository with a name of your choosing.

![Elastic-Container-Registry-Create-Repository.png](.\assets\Elastic-Container-Registry-Create-Repository.png)

Step 2: Next, go to Permissions>Edit JSON Policy and delete the default and set the following permissions for the repository

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": [
        "ecr:BatchGetImage",
        "ecr:DescribeImages",
        "ecr:GetDownloadUrlForLayer",
        "ecr:PullImage"
      ]
    }
  ]
}
```

----

## S3 Bucket Configuration

Step 1: Go over to S3 and create a private bucket for the project. Check if the settings matches the following screenshots and keep the defaults for rest of the configurations.

![](.\assets\S3-bucket-1.png)

![](.\assets\S3-bucket-2.png)

![](.\assets\S3-bucket-3.png) 

## Terraform Setup

We need terraform to setup an EKS and RDS cluster for this project. Follow the steps below to setup terraform:

**For Ubuntu/Debian:**

Step 1: Install  `gnupg`, `software-properties-common`, and `curl` packages by running the following commands.

```bash
sudo apt-get update && sudo apt-get install -y gnupg software-properties-common
```

Step 2:  Install HashiCorp GPG Key.

```bash
wget -O- https://apt.releases.hashicorp.com/gpg | \
gpg --dearmor | \
sudo tee /usr/share/keyrings/hashicorp-archive-keyring.gpg
```

Step 3: Add the HashiCorp repository to your package manager.

```bash
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] \
https://apt.releases.hashicorp.com $(lsb_release -cs) main" | \
sudo tee /etc/apt/sources.list.d/hashicorp.list
```

Step 4: Update packages and install Terraform.

```bash
sudo apt update && sudo apt-get install terraform
```

**For RHEL:**

Step 1: Install `yum-utils` package.

```bash
sudo yum install -y yum-utils
```

Step 2: Use `yum-config-manager` to add HashiCorp repository to your package manager.

```bash
sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/RHEL/hashicorp.repo`
```

Step 3: Finally, install terraform from the newly added repository.

```bash
sudo yum -y install terraform
```

### AWS CLI setup

For various tasks in this project we will need to interact with AWS services and resources from our local machine. Therefore, we need to install AWS CLI and configure it properly in our system. Follow the steps below for installing and configuring the AWS CLI.

> **Note:** If you are using an EC2 instance with Amazon linux images aws cli should already be installed in the system. In that case, skip the installtions steps.

**Step 1:**  Make sure `curl` and `unzip` is installed in the system.

**For Ubuntu/Debian:**

```bash
sudo apt update && sudo apt-get install -y curl unzip
```

**For RHEL:**

```bash
sudo yum install -y curl unzip
```

**Step 2:** Download the install script for aws-cli

```bash
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
```

**Step 3:** Unzip and run the install script.

```bash
unzip awscliv2.zip
sudo ./aws/install
```

**Step 4:** Run the following command to check the version of installed aws cli:

```bash
aws --version
```

**Step 5:** Run the following command to start configuring AWS CLI.

```bash
aws configure
```

**Step 6:** For configuring the aws cli you will need an Access key and Secret access key pair associated with your account. If you don't have an access key, login to your aws account and go to security credentials.

![aws-security-credentials.png](assets/aws-security-credentials.png)

![](assets/account-access-key.png)

Create an access key for aws command line interface. Download the access key after generation and save it in a safe place because the secret key can't be obtained later.

**Step 7:** Use the access key and secret access kye to configure the AWS CLI. The configuration should look like the image below.

![aws-cli-configuration.png](assets/aws-cli-configuration.png)

## Kubectl setup

To interact with the EKS cluster we would need to setup `kubectl`. Follow the steps below:

**Step 1:** Run the following command to download kubectl binary.

```bash
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
```

**Step 2:**  Afterwards, run the following command to install kubectl as the root user.

```bash
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
```

**Step 3:** Check `kubectl` is working by running a version check

```bash
kubectl version --client
```

## EKS and RDS Cluster Provisioning with Terraform

Assuming you have already installed and setup `terraform`, `aws-cli` & `kubectl` we can provision the EKS and RDS Cluster using the provided terraform code.

**Step 1:** Clone the terraform code repo

```bash
git clone https://github.com/samin-bjit/AWS_DevSecOps_Infra_Monitor_Configs.git
```
**Step 2:** Go to `terraform` directory and open and edit `variables.tf` file. Change the region to your current one.

**Step 3:** Next, run the following command to intiate the backend.

```bash
terraform init
```

**Step 4:** Next, run the following command to generate a plan before provisioning

```bash
terraform plan
```

**Step 5:** Thoroughly check the plan and run the following command to apply and start the provisioning process.

```bash
terraform apply -auto-approve
```

**Step 6:** After provisioning is completed. you should see the cluster name and region. Now, we need to get the `kubeconfig` file to communicate with the EKS control-plane. We can do so with the help of `aws-cli`. Run the following command to update the kubeconfig file.

```bash
aws eks update-kubeconfig --name <eks-cluster-name> --region <aws-region-name>
```

**Step 7:** Check if the `kubectl` can communicate with the cluster by running the following coommand:

```bash
kubectl cluster-info
```

**Step 8:** We can check cluster is functioning properly by going to the `AWS Console` `>` `Elastic Kuberntetes Service` `>` `Clusters`.

![vaccination-system-eks-Clusters-EKS.png](assets/vaccination-system-eks-Clusters-EKS.png)

**Step 9:** Head over to `RDS` > `Databases` and there should be a RDS instance with the name `vaccination-rds`.

# PHPStan OWASP Dependency-Check & OWASP ZAP integration

## PHPStan

**Step 1:** First, go over to CodeBuild and create a project.

![](assets/Build-projects-CodePipeline-ap-southeast-1.png)

**Step 2:** Next, give the project a name and setup your source. We are using CodeCommit as our source for our project.

![](assets/Create-build-choose-source.png)

**Step 3:** Afterwards, we have to choose the runtime environment for the building process. We will use `Amazon Linux 2` as our build runtime OS. Set the environment configuration as the image below.

![](assets/Create-build-project-choose-env.png)

**Step 4:** Now, specify the name for the buildspec file we will be using to run the PHPStan scan inside a CodeBuild conatainer. We named the file for this project `buildspec-phpstan.yml`. See the image below for reference

![](assets/Create-build-project-buildspec-name.png)

The following is the content of the `buildspec-phpstan.yml` file.

```yaml
version: 0.2
phases:
  install:
    runtime-versions:
      php: 8.2
    commands:
      - echo "installing phpstan"
      - composer require --dev phpstan/phpstan
      - echo "completed installing phpstan"
  build:
    commands:
      - echo "phpstan scan starting......"
      - vendor/bin/phpstan analyse  --error-format=json --level=1 -c phpstan.neon --memory-limit=3G --xdebug > vendor/phpstan-results.json || true
      - echo "phpstan scan completed. Analysing the results......"
  post_build:
    commands:
      - phpstan_fileerrors=$(cat vendor/phpstan-results.json | jq -r '.totals.file_errors')
      - echo "phpstan errors count is "  $phpstan_fileerrors
      - | 
        if [ $phpstan_fileerrors -gt 0 ]; then     
          jq "{ \"messageType\": \"CodeScanReport\", \"reportType\": \"PHPStan\", \"createdAt\": $(date +\"%Y-%m-%dT%H:%M:%S.%3NZ\"), \"productName\": \"VMS Registration Service\", \"companyName\": \"DevSecOps\", \"source_repository\": env.CODEBUILD_SOURCE_REPO_URL, \"source_branch\": env.CODEBUILD_SOURCE_VERSION, \"build_id\": env.CODEBUILD_BUILD_ID, \"source_commitid\": env.CODEBUILD_RESOLVED_SOURCE_VERSION, \"report\": . }" vendor/phpstan-results.json > payload.json
          echo "There are some errors/vulnerabilities reported in the phpstan scan. Stopping the build process.";
          cat payload.json
          aws lambda invoke --function-name ImportVulToSecurityHub --payload fileb://payload.json phpstan_scan_report.json && echo "LAMBDA_SUCCEDED" || echo "LAMBDA_FAILED";
          cat phpstan_scan_report.json
          echo " completed gathering the phpstan report";
          # exit 1;
        else
          echo "no vulnerabilities found in phpstan scan"
        fi     
artifacts:
  type: zip
  files: 
    - '**/*'
```

**Step 5:** Next, configure the logs for this CodeBuild project. We opted for S3 logs for our project.

![](assets/Create-build-project-codebuild-logs.png)

**Step 6:** Now all we need to do is to add the CodeBuild project to our existing pipeline. In order to do so, go over to your pipeline and add a new stage if you need and add an action group right after the Source stage.

**Step 7:** Give the action a name and choose CodeBuild as the action provider.

![](assets/phpstan-create-action.png)

**Step 8:** Set input artifact to SourceArtifact and choose the project you created in the above steps then create the action.

![](assets/phpstan-create-action-inputartifact.png)

## OWASP Dependency Scan

**Step 1:** Follow the PHPStan steps for creating the build project. The __*buildspec*__ file name for this build project should be set to `buildspec-dependency-check.yml`

The following is the content of the `buildspec-dependency-check.yml` file

```yaml
version: 0.2
phases:
  install:
    commands:
      - echo "install phase....."
  pre_build:
    commands:
      - composer install
      - wget https://github.com/jeremylong/DependencyCheck/releases/download/v8.4.0/dependency-check-8.4.0-release.zip
      - unzip dependency-check-8.4.0-release.zip
      - rm dependency-check-8.4.0-release.zip
      - chmod -R 775 $CODEBUILD_SRC_DIR/dependency-check/bin/dependency-check.sh
      - echo "stage pre_build completed"
  build:
    commands: 
      - cd dependency-check/bin
      - $CODEBUILD_SRC_DIR/dependency-check/bin/dependency-check.sh --format JSON --prettyPrint --enableExperimental --scan $CODEBUILD_SRC_DIR --exclude '$CODEBUILD_SRC_DIR/depedency-check/'
      - echo "OWASP dependency check analysis status is completed..."; 
      - high_risk_dependency=$( cat dependency-check-report.json | grep -c "HIGHEST" )
  post_build:
    commands:
      - | 
        jq "{ \"messageType\": \"CodeScanReport\", \"reportType\": \"OWASP-Dependency-Check\", \
        \"createdAt\": $(date +\"%Y-%m-%dT%H:%M:%S.%3NZ\"), \"source_repository\": env.CODEBUILD_SOURCE_REPO_URL, \
        \"productName\": \"VMS Registration Service\", \"companyName\": \"DevSecOps\", \
        \"source_branch\": env.CODEBUILD_SOURCE_VERSION, \
        \"build_id\": env.CODEBUILD_BUILD_ID, \
        \"source_commitid\": env.CODEBUILD_RESOLVED_SOURCE_VERSION, \
        \"report\": . }" dependency-check-report.json > payload.json
      - |
        if [ $high_risk_dependency -gt 0 ]; then
          echo "there are high or medium alerts.. failing the build"
          cat payload.json
          aws lambda invoke --function-name ImportVulToSecurityHub --payload fileb://payload.json dependency-check-report.json && echo "LAMBDA_SUCCEDED" || echo "LAMBDA_FAILED";
          cat dependency-check-report.json
          # exit 1; 
        fi
artifacts:
  type: zip
  files: '**/*'
```

**Step 2:** Next Follow the same process as the PHPStan to create an action group inside your existing pipeline for integrating the build project.

## OWASP ZAP (Zed Attack Proxy)

**Step 1:** Create another build project just like PHPStan and dependency check. The __*buildspec*__ file name should be set to `buildspec-owasp-zap.yml` this time around.

The following is what's inside the `buildspec-owasp-zap.yml`

```yaml
version: 0.2

phases:
  install:
    commands:
      - echo Installing app dependencies and Kubectl tool for K8s...
      - curl -o kubectl https://amazon-eks.s3.us-west-2.amazonaws.com/1.18.9/2020-11-02/bin/linux/amd64/kubectl   
      - chmod +x ./kubectl
      - mkdir -p $HOME/bin && cp ./kubectl $HOME/bin/kubectl && export PATH=$PATH:$HOME/bin
      - echo 'export PATH=$PATH:$HOME/bin' >> $HOME/.bashrc
      - source $HOME/.bashrc
      - echo 'Check kubectl version'
      - kubectl version --short --client 
  build:
    commands:
      - echo Logging into Amazon EKS...
      - aws eks --region $AWS_DEFAULT_REGION update-kubeconfig --name $AWS_CLUSTER_NAME
      - echo check config 
      - kubectl config view --minify
      - echo check kubectl access
      - kubectl get svc -n vaccination-system-dev
      - ALB_URL=$(kubectl get svc -n vaccination-system-dev -o json | jq -r ".items[].status.loadBalancer.ingress[0].hostname")
      - echo $ALB_URL
      - echo Starting OWASP Zed Attack Proxy active scanning...
      - chmod 777 $PWD
      - mkdir -p /zap/wrk
      - chmod 777 /zap/wrk
      - docker --version
      - docker pull docker.io/owasp/zap2docker-stable
      - docker run -v $(pwd):/zap/wrk/:rw -t owasp/zap2docker-stable zap-baseline.py -t http://$ALB_URL -J owaspresult.json || true
  post_build:
    commands:
      - ls -lrt $CODEBUILD_SRC_DIR
      - cat owaspresult.json
      - |
        jq "{ \"messageType\": \"CodeScanReport\", \"reportType\": \"OWASP-Zap\", \
        \"createdAt\": $(date +\"%Y-%m-%dT%H:%M:%S.%3NZ\"), \"source_repository\": env.CODEBUILD_SOURCE_REPO_URL, \
        \"productName\": \"VMS Registration Service\", \"companyName\": \"DevSecOps\", \
        \"source_branch\": env.CODEBUILD_SOURCE_VERSION, \
        \"build_id\": env.CODEBUILD_BUILD_ID, \
        \"source_commitid\": env.CODEBUILD_RESOLVED_SOURCE_VERSION, \
        \"report\": . }" owaspresult.json > payload.json
        aws lambda invoke --function-name ImportVulToSecurityHub --payload fileb://payload.json owaspresult.json && echo "LAMBDA_SUCCEDED" || echo "LAMBDA_FAILED";

     # - if [ $high_alerts != 0 ] || [ $medium_alerts != 0 ]; then echo "there are high or medium alerts.. failing the build" && exit 1; else exit 0; fi
artifacts:
  type: zip
  files: '**/*'
```

**Step 2:** Create action group in your pipeline for this project but create it inside a stage after deployment. This scan is only for the services that have an LoadBalancer attached to it.

## Security Scan Logs collection with AWS Lambda

**Step 1:** First, create a lambda function named `ImportVulToSecurityHub`. Setting the name to the aforementioned value is crucial because inside each security tools scan buildspec file we will be invoking the function by name.

![](assets/Create-function-Lambda.png)

**Step 2:** Set `Python 3.9` as the runtime and `x86_64` as the architechture.

![](assets/Create-function-Lambda-1.png)


**Step 3:** Next, make sure that a new role is created along with the function

![](assets/Create-function-Lambda-2.png)

**Step 4:** Modify the new Lambda role and add `AmazonS3FullAccess` and `AWSSecurityHubFullAccess` policies.

![](assets/Create-function-Lambda-3.png)

**Step 5:** Go into the lambda function you just created and click on **Upload From** and choose **.zip file** option. 

![](assets/Create-function-Lambda-4.png)

This should import the codes into two files one named `lambda_function.py` and another `securityhub.py`

The content of `lambda_function.py` is as follows

```python
import os
import json
import logging
import boto3
import securityhub
from datetime import datetime, timezone

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

FINDING_TITLE = "CodeAnalysis"
FINDING_DESCRIPTION_TEMPLATE = "Summarized report of code scan with {0}"
FINDING_TYPE_TEMPLATE = "{0} code scan"
BEST_PRACTICES_PHP = "https://aws.amazon.com/developer/language/php/"
BEST_PRACTICES_OWASP = "https://owasp.org/www-project-top-ten/"
report_url = "https://aws.amazon.com"

def process_message(event):
    """ Process Lambda Event """
    if event['messageType'] == 'CodeScanReport':
        account_id = boto3.client('sts').get_caller_identity().get('Account')
        region = os.environ['AWS_REGION']
        created_at = event['createdAt']
        source_repository = event['source_repository']
        source_branch = event['source_branch']
        source_commitid = event['source_commitid']
        build_id = event['build_id']
        report_type = event['reportType']
        product_name = event['productName']
        company_name = event['companyName']
        finding_type = FINDING_TYPE_TEMPLATE.format(report_type)
        generator_id = f"{report_type.lower()}-{source_repository}-{source_branch}"
        ### upload to S3 bucket
        s3 = boto3.client('s3')
        s3bucket = os.environ['BUCKET_NAME']
        key = f"reports/{event['reportType']}/{build_id}-{created_at}.json"
        s3.put_object(Bucket=s3bucket, Body=json.dumps(event), Key=key, ServerSideEncryption='aws:kms')
        report_url = f"https://s3.console.aws.amazon.com/s3/object/{s3bucket}/{key}?region={region}"
                
        ### OWASP SCA scanning report parsing
        if event['reportType'] == 'OWASP-Dependency-Check':
            severity = 50
            FINDING_TITLE = "OWASP Dependecy Check Analysis"
            dep_pkgs = len(event['report']['dependencies'])
            for i in range(dep_pkgs):
                if "packages" in event['report']['dependencies'][i]:
                    confidence = event['report']['dependencies'][i]['packages'][0]['confidence']
                    url = event['report']['dependencies'][i]['packages'][0]['url']
                    finding_id = f"{i}-{report_type.lower()}-{build_id}"
                    finding_description = f"Package: {event['report']['dependencies'][i]['packages'][0]['id']}, \nConfidence: {confidence}, \nURL: {url}"
                    created_at = datetime.now(timezone.utc).isoformat()
                    ### find the vulnerability severity level
                    if confidence == "HIGHEST":
                        normalized_severity = 80
                    else:
                        normalized_severity = 50
                    securityhub.import_finding_to_sh(i, account_id, region, created_at, source_repository, source_branch, source_commitid, build_id, report_url, finding_id, generator_id, normalized_severity, severity, finding_type, FINDING_TITLE, finding_description, BEST_PRACTICES_OWASP, product_name, company_name)

        ### PHPStan SAST scanning report parsing
        if event['reportType'] == 'PHPStan':
            severity = 50
            FINDING_TITLE = "PHPStan StaticCode Analysis"
            report_count = event['report']['totals']['file_errors']
            for i in range(report_count):
                for filename in event['report']['files']:
                    finding_id = f"{i}-{report_type.lower()}-{build_id}"
                    finding_description = f"Message: {event['report']['files'][filename]['messages'][0]['message']}, \nfile: {filename}, line: {event['report']['files'][filename]['messages'][0]['line']}"
                    created_at = datetime.now(timezone.utc).isoformat()
                    normalized_severity = 60                   
                    ### find the vulnerability severity level
                    is_ignorable = f"{event['report']['files'][filename]['messages'][0]['ignorable']}"
                    if is_ignorable == "true":
                        normalized_severity = 30
                    else:
                        normalized_severity = 60
                    ### Calling Securityhub function to post the findings
                    securityhub.import_finding_to_sh(i, account_id, region, created_at, source_repository, source_branch, source_commitid, build_id, report_url, finding_id, generator_id, normalized_severity, severity, finding_type, FINDING_TITLE, finding_description, BEST_PRACTICES_OWASP, product_name, company_name)
        
        ### SonarQube SAST scanning report parsing
        elif event['reportType'] == 'SONAR-QUBE':           
            severity = 50
            FINDING_TITLE = "SonarQube StaticCode Analysis"         
            report_count = event['report']['total']
            for i in range(report_count):
                finding_id = f"{i}-{report_type.lower()}-{source_repository}-{source_branch}-{build_id}"
                finding_description = f"{event['report']['issues'][i]['type']}-{event['report']['issues'][i]['message']}-{i}, component: {event['report']['issues'][i]['component']}"
                created_at = datetime.now(timezone.utc).isoformat()
                report_severity = event['report']['issues'][i]['severity']
                ### find the vulnerability severity level
                if report_severity == 'MAJOR':
                    normalized_severity = 70
                elif report_severity == 'BLOCKER':
                    normalized_severity = 90
                elif report_severity == 'CRITICAL':
                    normalized_severity = 90
                else:
                    normalized_severity= 20
                ### Calling Securityhub function to post the findings
                    securityhub.import_finding_to_sh(i, account_id, region, created_at, source_repository, source_branch, source_commitid, build_id, report_url, finding_id, generator_id, normalized_severity, severity, finding_type, FINDING_TITLE, finding_description, BEST_PRACTICES_OWASP, product_name, company_name)
        
        ### OWASP Zap SAST scanning report parsing
        elif event['reportType'] == 'OWASP-Zap':  
            severity = 50
            FINDING_TITLE = "OWASP ZAP DynamicCode Analysis"
            alert_ct = event['report']['site'][0]['alerts']
            alert_count = len(alert_ct)
            for alertno in range(alert_count):
                risk_desc = event['report']['site'][0]['alerts'][alertno]['riskdesc']
                riskletters = risk_desc[0:3]
                ### find the vulnerability severity level
                if riskletters == 'Hig':
                    normalized_severity = 70
                elif riskletters == 'Med':
                    normalized_severity = 60
                elif riskletters == 'Low' or riskletters == 'Inf':  
                    normalized_severity = 30
                else:
                    normalized_severity = 90                                       
                instances = len(event['report']['site'][0]['alerts'][alertno]['instances'])
                finding_description = f"{alertno}-Vulerability:{event['report']['site'][0]['alerts'][alertno]['alert']}-Total occurances of this issue:{instances}"
                finding_id = f"{alertno}-{report_type.lower()}-{build_id}"
                created_at = datetime.now(timezone.utc).isoformat()
                ### Calling Securityhub function to post the findings
                securityhub.import_finding_to_sh(alertno, account_id, region, created_at, source_repository, source_branch, source_commitid, build_id, report_url, finding_id, generator_id, normalized_severity, severity, finding_type, FINDING_TITLE, finding_description, BEST_PRACTICES_OWASP, product_name, company_name)
        else:
            print("Invalid report type was provided")                
    else:
        logger.error("Report type not supported:")

def lambda_handler(event, context):
    """ Lambda entrypoint """
    try:
        logger.info("Starting function")
        return process_message(event)
    except Exception as error:
        logger.error("Error {}".format(error))
        raise

```

The following is the content of `securityhub.py` file

```python
import sys
import logging
sys.path.insert(0, "external")
import boto3

logger = logging.getLogger(__name__)

securityhub = boto3.client('securityhub')

# This function import agregated report findings to securityhub 
def import_finding_to_sh(count: int, account_id: str, region: str, created_at: str, source_repository: str,
    source_branch: str, source_commitid: str, build_id: str, report_url: str, finding_id: str, generator_id: str,
                         normalized_severity: str, severity: str, finding_type: str, finding_title: str, finding_description: str, best_practices_cfn: str, product_name: str, company_name: str): 
    print("called securityhub.py..................")
    new_findings = []
    new_findings.append({
        "SchemaVersion": "2018-10-08",
        "Id": finding_id,
        "ProductArn": "arn:aws:securityhub:{0}:{1}:product/{1}/default".format(region, account_id),
        "GeneratorId": generator_id,
        "AwsAccountId": account_id,
        "ProductName": product_name,
        "CompanyName": company_name,
        "Types": [
            "Software and Configuration Checks/AWS Security Best Practices/{0}".format(
                finding_type)
        ],
        "CreatedAt": created_at,
        "UpdatedAt": created_at,
        "Severity": {
            "Normalized": normalized_severity,
        },
        "Title":  f"{count}-{finding_title}",
        "Description": f"{finding_description}",
        'Remediation': {
            'Recommendation': {
                'Text': 'For directions on PHP AWS Best practices, please click this link',
                'Url': best_practices_cfn
            }
        },
        'SourceUrl': report_url,
        'Resources': [
            {
                'Id': build_id,
                'Type': "CodeBuild",
                'Partition': "aws",
                'Region': region
            }
        ],
    })
    ### post the security vulnerability findings to AWS SecurityHub
    response = securityhub.batch_import_findings(Findings=new_findings)
    if response['FailedCount'] > 0:
        logger.error("Error importing finding: " + response)
        raise Exception("Failed to import finding: {}".format(response['FailedCount']))
```

**Step 6:** Go over to **Configuration** and then **Environment Variables** and add a new variable with the key `BUCKET_NAME` and value set to the S3 bucket you choose to store your scan logs to. See the image below for reference.

![](assets/Create-function-Lambda-5.png)

**Step 7:** Finally, Deploy the function


# Monitoring with Prometheus and Grafana

**Step 1:** Install `Helm3` in the system

```bash
curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
chmod 700 get_helm.sh
./get_helm.sh
```

**Step 2:** Next, install the `prometheus-community/kube-prometheus-stack` helm chart by running the following command(Assuming you have `kubectl` and kubeconfig configured). This will install a complete monitoring stack that includes `Prometheus`, `Grafana`, `Alertmanager`, `Node Exporter`, `Kube State Metrics` and `Prometheus Operator`.

```bash
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm install kube-prometheus-stack prometheus-community/kube-prometheus-stack -n prometheus --create-namespace
```

**Step 3:** Afterwards, check all the monitoring pods are up and running.

```bash
kubectl get pods -n prometheus
```

**Step 5:** Now by default the services that serves as the endpoint to the tools are defined as `ClusterIP` services. If we wnat to access them we need to perform port forwarding in order to access them.

```bash
nohup kubectl port-forward -n prometheus svc/kube-prometheus-stack-prometheus 85:9090 --address 0.0.0.0 &>/dev/null &
nohup kubectl port-forward -n prometheus svc/kube-prometheus-stack-grafana 86:80 --address 0.0.0.0 &>/dev/null &
nohup kubectl port-forward -n prometheus svc/kube-prometheus-stack-alertmanager 87:9093 --address 0.0.0.0 &>/dev/null &
```
**Step 6:** If the commands in the above step executed properly, we can view `Prometheus` at ['http://localhost:85'](http://localhost:85), `Grafana` at ['http://localhost:86'](http://localhost:86) and `AlertManager` at ['http://localhost:87'](http://localhost:87).


**Step 7:** Once all the pods are ready and running without any errors and the services are accessible, we can start applying our prometheus configurations. Go to the `prometheus` folder and apply each configurations.

```bash
kubectl apply -f PrometheusRule.yaml
kubectl apply -f AlertmanagerSecret.yaml
```

**Step 8:** Finally, perform a restart on the prometheus and alertmanager instances so that they get the updated configuration quickly.

```bash
kubectl -n prometheus rollout restart statefulset prometheus-kube-prometheus-stack-prometheus alertmanager-kube-prometheus-stack-alertmanager
```

# Autoscaling with metrics server

**Step 1:** Since we have defined a `HorizontalPodAutoscaler` for all of our deployments, it needs a metrics API endpoint to scale up/down depending on the metrics. We need to install the `metrics-server` in the same namespace as our deployments. Run the command below to install the `metrics-server` using helm.

```bash
helm repo add metrics-server https://kubernetes-sigs.github.io/metrics-server/
helm install metrics-server metrics-server/metrics-server -n prometheus
```

















AWS EKS Setup



Configure the following in the machine you are going to access the cluster:  

- AWS CLI

- AWS IAM Authenticator

- Kubectl

Run the following command to get kubeconfig file for the new cluster:

Linux:

aws eks –region $(terraform output -raw region) update-kubeconfig --name $(terraform output -raw cluster_name)

Windows:

set region_code=region-code

set cluster_name=my-cluster

set account_id=111122223333

for /f "tokens=*" %%a in ('aws eks describe-cluster --region %region_code% --name %cluster_name% --query "cluster.endpoint" --output text') do set cluster_endpoint=%%a

for /f "tokens=*" %%a in ('aws eks describe-cluster --region %region_code% --name %cluster_name% --query "cluster.certificateAuthority.data" --output text') do set certificate_data=%%a

aws eks update-kubeconfig --region %region_code% --name %cluster_name%

aws eks –region ap-southeast-1 update-kubeconfig –name vaccination-system-eks

# AWS Load balancer Controller Configuration

## Create Identity provider

Step 1: Copy OpenIDConnect URL from EKS overview

![](https://lh4.googleusercontent.com/YI_Psh2E5PnaP_0jw7h9osFx3NQvRpNSA-MpV4K2KwPlztBVxIlX5hYnHDuZiVUcHKshspD6X4Qxa2Qy_sRSnrxR2UTCbshRxbfHo4sOzUTV0f3ijs4yYJzO_CpVVwsqh_gdwcXiECmXzeX6PbHfUbPgqv3hjHEA)

Step 2: Go to IAM console>Identity Provider and create a OpenID Connect provider using the connector provider URL copied in the earlier step. Use sts.amazonaws.com as the audience.![](https://lh4.googleusercontent.com/YDHbuMepmIUFaH1lM2_SiVtfemCNQhv_x8MA6_He5W_XwdwtmaHpGx0sCU-ECRy2Uml4dSM54VujP9BjHG_uQ_lwcXP99pAwRNIpy04AHspSOixiydRBZ8vg-QZqMIA7EZThDDxN9PoktoaTBvgLIpRAB7_qDUt1)

Step 3: Now create an IAM policy from AWS load balancer controller documentation for the version you are using. I am using v2.6.1 in this project.  
https://github.com/kubernetes-sigs/aws-load-balancer-controller/blob/v2.6.1/docs/install/iam_policy.json
