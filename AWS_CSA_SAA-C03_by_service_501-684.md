# AWS SAA-C03 Questions Grouped by AWS Service

## Table of Contents

- [AWS Backup](#aws-backup)
- [AWS Certificate Manager (ACM)](#aws-certificate-manager-acm)
- [AWS Config & CloudTrail](#aws-config-and-cloudtrail)
- [AWS DMS / SCT](#aws-dms-sct)
- [AWS Direct Connect & VPN](#aws-direct-connect-and-vpn)
- [AWS Global Accelerator](#aws-global-accelerator)
- [AWS Glue](#aws-glue)
- [AWS KMS](#aws-kms)
- [AWS Lake Formation](#aws-lake-formation)
- [AWS Lambda](#aws-lambda)
- [AWS Organizations / IAM Identity Center (SSO)](#aws-organizations-iam-identity-center-sso)
- [AWS Secrets Manager](#aws-secrets-manager)
- [AWS Snow Family](#aws-snow-family)
- [AWS Systems Manager](#aws-systems-manager)
- [AWS WAF & Shield](#aws-waf-and-shield)
- [Amazon API Gateway](#amazon-api-gateway)
- [Amazon Athena](#amazon-athena)
- [Amazon Aurora](#amazon-aurora)
- [Amazon CloudFront](#amazon-cloudfront)
- [Amazon CloudWatch & EventBridge](#amazon-cloudwatch-and-eventbridge)
- [Amazon DynamoDB](#amazon-dynamodb)
- [Amazon EBS](#amazon-ebs)
- [Amazon EC2 / Auto Scaling](#amazon-ec2-auto-scaling)
- [Amazon EFS](#amazon-efs)
- [Amazon FSx](#amazon-fsx)
- [Amazon Kinesis](#amazon-kinesis)
- [Amazon Macie / Rekognition / Comprehend](#amazon-macie-rekognition-comprehend)
- [Amazon OpenSearch Service](#amazon-opensearch-service)
- [Amazon QuickSight](#amazon-quicksight)
- [Amazon RDS](#amazon-rds)
- [Amazon Redshift](#amazon-redshift)
- [Amazon Route 53](#amazon-route-53)
- [Amazon S3](#amazon-s3)
- [Amazon SNS](#amazon-sns)
- [Amazon SQS](#amazon-sqs)
- [Amazon VPC](#amazon-vpc)
- [Elastic Load Balancing (ALB/NLB/GWLB)](#elastic-load-balancing-albnlbgwlb)
- [General / Architecture](#general-architecture)


## AWS Backup

### Question #508

A company has migrated multiple Microsoft Windows Server workloads to Amazon EC2 instances that run in the us-west-1 Region. The company manually backs up the workloads to create an image as needed. In the event of a natural disaster in the us-west-1 Region, the company wants to recover workloads quickly in the us-west-2 Region. The company wants no more than 24 hours of data loss on the EC2 instances. The company also wants to automate any backups of the EC2 instances. Which solutions will meet these requirements with the LEAST administrative effort? (Choose two.)

- A. Create an Amazon EC2-backed Amazon Machine Image (AMI) lifecycle policy to create a backup based on tags. Schedule the backup to run twice daily. Copy the image on demand.

- B. Create an Amazon EC2-backed Amazon Machine Image (AMI) lifecycle policy to create a backup based on tags. Schedule the backup to run twice daily. Configure the copy to the us-west-2 Region.

- C. Create backup vaults in us-west-1 and in us-west-2 by using AWS Backup. Create a backup plan for the EC2 instances based on tag values. Create an AWS Lambda function to run as a scheduled job to copy the backup data to us-west-2.

- D. Create a backup vault by using AWS Backup. Use AWS Backup to create a backup plan for the EC2 instances based on tag values. Dene the destination for the copy as us-west-2. Specify the backup schedule to run twice daily.

E. Create a backup vault by using AWS Backup. Use AWS Backup to create a backup plan for the EC2 instances based on tag values. Specify the backup schedule to run twice daily. Copy on demand to us-west-2.

**Correct:** B, D
**Why:** AMI lifecycle with cross‑Region copy and AWS Backup cross‑Region backups both automate twice‑daily backups within the 24‑hour RPO.

**Incorrect:**
- A: On‑demand copies add manual steps.
- C: Lambda copy adds unnecessary custom code.
- E: On‑demand copies add manual steps.


---

---

### Question #512

A company uses AWS Organizations with resources tagged by account. The company also uses AWS Backup to back up its AWS infrastructure resources. The company needs to back up all AWS resources. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use AWS Cong to identify all untagged resources. Tag the identied resources programmatically. Use tags in the backup plan.

- B. Use AWS Cong to identify all resources that are not running. Add those resources to the backup vault.

- C. Require all AWS account owners to review their resources to identify the resources that need to be backed up.

- D. Use Amazon Inspector to identify all noncompliant resources.

**Correct:** A
**Why:** Use AWS Config to find untagged resources and tag them programmatically so tag‑based AWS Backup plans cover all resources.

**Incorrect:**
- B: Not aligned with comprehensive, automated backups.
- C: Not aligned with comprehensive, automated backups.
- D: Not aligned with comprehensive, automated backups.


---

---

### Question #602

A company's infrastructure consists of hundreds of Amazon EC2 instances that use Amazon Elastic Block Store (Amazon EBS) storage. A solutions architect must ensure that every EC2 instance can be recovered after a disaster. What should the solutions architect do to meet this requirement with the LEAST amount of effort?

- A. Take a snapshot of the EBS storage that is attached to each EC2 instance. Create an AWS CloudFormation template to launch new EC2 instances from the EBS storage.

- B. Take a snapshot of the EBS storage that is attached to each EC2 instance. Use AWS Elastic Beanstalk to set the environment based on the EC2 template and attach the EBS storage.

- C. Use AWS Backup to set up a backup plan for the entire group of EC2 instances. Use the AWS Backup API or the AWS CLI to speed up the restore process for multiple EC2 instances.

- D. Create an AWS Lambda function to take a snapshot of the EBS storage that is attached to each EC2 instance and copy the Amazon Machine Images (AMIs). Create another Lambda function to perform the restores with the copied AMIs and attach the EBS storage.

**Correct:** C
**Why:** AWS Backup can centrally back up and restore fleets of EC2/EBS with minimal effort.

**Incorrect:**
- A: Custom snapshots/scripts/Beanstalk add operational complexity.
- B: Custom snapshots/scripts/Beanstalk add operational complexity.
- D: Custom snapshots/scripts/Beanstalk add operational complexity.


---

---

### Question #618

A company wants to use Amazon FSx for Windows File Server for its Amazon EC2 instances that have an SMB file share mounted as a volume in the us-east-1 Region. The company has a recovery point objective (RPO) of 5 minutes for planned system maintenance or unplanned service disruptions. The company needs to replicate the file system to the us-west-2 Region. The replicated data must not be deleted by any user for 5 years. Which solution will meet these requirements?

- A. Create an FSx for Windows File Server file system in us-east-1 that has a Single-AZ 2 deployment type. Use AWS Backup to create a daily backup plan that includes a backup rule that copies the backup to us-west-2. Configure AWS Backup Vault Lock in compliance mode for a target vault in us-west-2. Configure a minimum duration of 5 years.

- B. Create an FSx for Windows File Server file system in us-east-1 that has a Multi-AZ deployment type. Use AWS Backup to create a daily backup plan that includes a backup rule that copies the backup to us-west-2. Configure AWS Backup Vault Lock in governance mode for a target vault in us-west-2. Configure a minimum duration of 5 years.

- C. Create an FSx for Windows File Server file system in us-east-1 that has a Multi-AZ deployment type. Use AWS Backup to create a daily backup plan that includes a backup rule that copies the backup to us-west-2. Configure AWS Backup Vault Lock in compliance mode for a target vault in us-west-2. Configure a minimum duration of 5 years.

- D. Create an FSx for Windows File Server file system in us-east-1 that has a Single-AZ 2 deployment type. Use AWS Backup to create a daily backup plan that includes a backup rule that copies the backup to us-west-2. Configure AWS Backup Vault Lock in governance mode for a target vault in us-west-2. Configure a minimum duration of 5 years.

**Correct:** C
**Why:** Multi‑AZ FSx for Windows for primary; copy backups to us‑west‑2 with AWS Backup and enable Vault Lock compliance mode for 5‑year immutability.

**Incorrect:**
- A: Single‑AZ reduces availability.
- B: Governance mode can be bypassed by privileged users; compliance mode is required for WORM.
- D: Single‑AZ reduces availability.


---

---

### Question #635

A company uses Amazon FSx for NetApp ONTAP in its primary AWS Region for CIFS and NFS file shares. Applications that run on Amazon EC2 instances access the file shares. The company needs a storage disaster recovery (DR) solution in a secondary Region. The data that is replicated in the secondary Region needs to be accessed by using the same protocols as the primary Region. Which solution will meet these requirements with the LEAST operational overhead?

- A. Create an AWS Lambda function to copy the data to an Amazon S3 bucket. Replicate the S3 bucket to the secondary Region.

- B. Create a backup of the FSx for ONTAP volumes by using AWS Backup. Copy the volumes to the secondary Region. Create a new FSx for ONTAP instance from the backup.

- C. Create an FSx for ONTAP instance in the secondary Region. Use NetApp SnapMirror to replicate data from the primary Region to the secondary Region.

- D. Create an Amazon Elastic File System (Amazon EFS) volume. Migrate the current data to the volume. Replicate the volume to the secondary Region.

**Correct:** C
**Why:** FSx for NetApp ONTAP supports SMB/NFS; use SnapMirror for cross‑Region replication with the same protocols on failover.

**Incorrect:**
- A: Lambda + S3 is not a file service and loses protocol semantics.
- B: Backup/restore increases RTO and ops.
- D: EFS is NFS only, not SMB.


---

## AWS Certificate Manager (ACM)

### Question #521

A retail company has several businesses. The IT team for each business manages its own AWS account. Each team account is part of an organization in AWS Organizations. Each team monitors its product inventory levels in an Amazon DynamoDB table in the team's own AWS account. The company is deploying a central inventory reporting application into a shared AWS account. The application must be able to read items from all the teams' DynamoDB tables. Which authentication option will meet these requirements MOST securely?

- A. Integrate DynamoDB with AWS Secrets Manager in the inventory application account. Configure the application to use the correct secret from Secrets Manager to authenticate and read the DynamoDB table. Schedule secret rotation for every 30 days.

- B. In every business account, create an IAM user that has programmatic access. Configure the application to use the correct IAM user access key ID and secret access key to authenticate and read the DynamoDB table. Manually rotate IAM access keys every 30 days.

- C. In every business account, create an IAM role named BU_ROLE with a policy that gives the role access to the DynamoDB table and a trust policy to trust a specic role in the inventory application account. In the inventory account, create a role named APP_ROLE that allows access to the STS AssumeRole API operation. Configure the application to use APP_ROLE and assume the crossaccount role BU_ROLE to read the DynamoDB table.

- D. Integrate DynamoDB with AWS Certicate Manager (ACM). Generate identity certicates to authenticate DynamoDB. Configure the application to use the correct certicate to authenticate and read the DynamoDB table.

**Correct:** C
**Why:** Cross‑account role assumption (STS AssumeRole) is the most secure way to access each account’s DynamoDB table.

**Incorrect:**
- A: Long‑lived credentials or ACM are not appropriate.
- B: Long‑lived credentials or ACM are not appropriate.
- D: Long‑lived credentials or ACM are not appropriate.


---

---

### Question #532

A company has a workload in an AWS Region. Customers connect to and access the workload by using an Amazon API Gateway REST API. The company uses Amazon Route 53 as its DNS provider. The company wants to provide individual and secure URLs for all customers. Which combination of steps will meet these requirements with the MOST operational eciency? (Choose three.)

- A. Register the required domain in a registrar. Create a wildcard custom domain name in a Route 53 hosted zone and record in the zone that points to the API Gateway endpoint.

- B. Request a wildcard certicate that matches the domains in AWS Certicate Manager (ACM) in a different Region.

- C. Create hosted zones for each customer as required in Route 53. Create zone records that point to the API Gateway endpoint.

- D. Request a wildcard certicate that matches the custom domain name in AWS Certicate Manager (ACM) in the same Region.

E. Create multiple API endpoints for each customer in API Gateway.

F. Create a custom domain name in API Gateway for the REST API. Import the certicate from AWS Certicate Manager (ACM).

**Correct:** A, D, F
**Why:** Use a wildcard custom domain in Route 53, request a matching wildcard ACM cert in the same Region, and create a custom domain in API Gateway with that cert.

**Incorrect:**
- B: Wrong Region for ACM, per‑customer hosted zones, or multiple API endpoints add overhead.
- C: Wrong Region for ACM, per‑customer hosted zones, or multiple API endpoints add overhead.
- E: Wrong Region for ACM, per‑customer hosted zones, or multiple API endpoints add overhead.


---

---

### Question #571

A company is creating a REST API. The company has strict requirements for the use of TLS. The company requires TLSv1.3 on the API endpoints. The company also requires a specic public third-party certicate authority (CA) to sign the TLS certicate. Which solution will meet these requirements?

- A. Use a local machine to create a certicate that is signed by the third-party CImport the certicate into AWS Certicate Manager (ACM). Create an HTTP API in Amazon API Gateway with a custom domain. Configure the custom domain to use the certicate.

- B. Create a certicate in AWS Certicate Manager (ACM) that is signed by the third-party CA. Create an HTTP API in Amazon API Gateway with a custom domain. Configure the custom domain to use the certicate.

- C. Use AWS Certicate Manager (ACM) to create a certicate that is signed by the third-party CA. Import the certicate into AWS Certicate Manager (ACM). Create an AWS Lambda function with a Lambda function URL. Configure the Lambda function URL to use the certicate.

- D. Create a certicate in AWS Certicate Manager (ACM) that is signed by the third-party CA. Create an AWS Lambda function with a Lambda function URL. Configure the Lambda function URL to use the certicate.

**Correct:** A
**Why:** Import a certificate signed by the required third-party CA into ACM and use it on an API Gateway custom domain. ACM cannot issue third‑party CA certs directly; importing meets the TLS policy needs.

**Incorrect:**
- B: ACM cannot create a certificate that is signed by an external third-party CA; you must import it.
- C: Lambda function URLs cannot use externally issued certs via ACM like this; also not an API endpoint replacement.
- D: Lambda URLs plus ACM do not fulfill the REST API requirement or TLS policy at the edge.


---

---

### Question #577

A company uses an Amazon CloudFront distribution to serve content pages for its website. The company needs to ensure that clients use a TLS certicate when accessing the company's website. The company wants to automate the creation and renewal of the TLS certicates. Which solution will meet these requirements with the MOST operational eciency?

- A. Use a CloudFront security policy to create a certicate.

- B. Use a CloudFront origin access control (OAC) to create a certicate.

- C. Use AWS Certicate Manager (ACM) to create a certicate. Use DNS validation for the domain.

- D. Use AWS Certicate Manager (ACM) to create a certicate. Use email validation for the domain.

**Correct:** C
**Why:** Use ACM with DNS validation for automatic renewal and simple management of certificates used by CloudFront.

**Incorrect:**
- A: CloudFront policies and OAC do not create TLS certificates.
- B: CloudFront policies and OAC do not create TLS certificates.
- D: Email validation works but is more operationally intensive than DNS validation.


---

---

### Question #644

An international company has a subdomain for each country that the company operates in. The subdomains are formatted as example.com, country1.example.com, and country2.example.com. The company's workloads are behind an Application Load Balancer. The company wants to encrypt the website data that is in transit. Which combination of steps will meet these requirements? (Choose two.)

- A. Use the AWS Certicate Manager (ACM) console to request a public certicate for the apex top domain example com and a wildcard certicate for *.example.com.

- B. Use the AWS Certicate Manager (ACM) console to request a private certicate for the apex top domain example.com and a wildcard certicate for *.example.com.

- C. Use the AWS Certicate Manager (ACM) console to request a public and private certicate for the apex top domain example.com.

- D. Validate domain ownership by email address. Switch to DNS validation by adding the required DNS records to the DNS provider.

E. Validate domain ownership for the domain by adding the required DNS records to the DNS provider.

**Correct:** A, E
**Why:** Request a public cert for example.com and a wildcard for *.example.com in ACM; validate via DNS records.

**Incorrect:**
- B: Private certs or mixed public/private are not needed for public websites.
- C: Private certs or mixed public/private are not needed for public websites.
- D: Email validation is more manual vs. DNS validation.


---

## AWS Config & CloudTrail

### Question #512

A company uses AWS Organizations with resources tagged by account. The company also uses AWS Backup to back up its AWS infrastructure resources. The company needs to back up all AWS resources. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use AWS Cong to identify all untagged resources. Tag the identied resources programmatically. Use tags in the backup plan.

- B. Use AWS Cong to identify all resources that are not running. Add those resources to the backup vault.

- C. Require all AWS account owners to review their resources to identify the resources that need to be backed up.

- D. Use Amazon Inspector to identify all noncompliant resources.

**Correct:** A
**Why:** Use AWS Config to find untagged resources and tag them programmatically so tag‑based AWS Backup plans cover all resources.

**Incorrect:**
- B: Not aligned with comprehensive, automated backups.
- C: Not aligned with comprehensive, automated backups.
- D: Not aligned with comprehensive, automated backups.


---

---

### Question #524

A company wants to analyze and troubleshoot Access Denied errors and Unauthorized errors that are related to IAM permissions. The company has AWS CloudTrail turned on. Which solution will meet these requirements with the LEAST effort?

- A. Use AWS Glue and write custom scripts to query CloudTrail logs for the errors.

- B. Use AWS Batch and write custom scripts to query CloudTrail logs for the errors.

- C. Search CloudTrail logs with Amazon Athena queries to identify the errors.

- D. Search CloudTrail logs with Amazon QuickSight. Create a dashboard to identify the errors.

**Correct:** C
**Why:** Query CloudTrail logs directly with Athena to find AccessDenied/Unauthorized events—lowest effort.

**Incorrect:**
- A: Glue/Batch/QuickSight add unnecessary development overhead.
- B: Glue/Batch/QuickSight add unnecessary development overhead.
- D: Glue/Batch/QuickSight add unnecessary development overhead.


---

---

### Question #534

A company wants to build a logging solution for its multiple AWS accounts. The company currently stores the logs from all accounts in a centralized account. The company has created an Amazon S3 bucket in the centralized account to store the VPC flow logs and AWS CloudTrail logs. All logs must be highly available for 30 days for frequent analysis, retained for an additional 60 days for backup purposes, and deleted 90 days after creation. Which solution will meet these requirements MOST cost-effectively?

- A. Transition objects to the S3 Standard storage class 30 days after creation. Write an expiration action that directs Amazon S3 to delete objects after 90 days.

- B. Transition objects to the S3 Standard-Infrequent Access (S3 Standard-IA) storage class 30 days after creation. Move all objects to the S3 Glacier Flexible Retrieval storage class after 90 days. Write an expiration action that directs Amazon S3 to delete objects after 90 days.

- C. Transition objects to the S3 Glacier Flexible Retrieval storage class 30 days after creation. Write an expiration action that directs Amazon S3 to delete objects after 90 days.

- D. Transition objects to the S3 One Zone-Infrequent Access (S3 One Zone-IA) storage class 30 days after creation. Move all objects to the S3 Glacier Flexible Retrieval storage class after 90 days. Write an expiration action that directs Amazon S3 to delete objects after 90 days.

**Correct:** C
**Why:** Keep logs in Standard for 30 days, then transition to Glacier Flexible Retrieval until day 90, then expire—lowest cost for retention/restore needs.

**Incorrect:**
- A: Other tiering mixes are less cost‑effective or contradict the 90‑day deletion.
- B: Other tiering mixes are less cost‑effective or contradict the 90‑day deletion.
- D: Other tiering mixes are less cost‑effective or contradict the 90‑day deletion.


---

---

### Question #560

A company's solutions architect is designing an AWS multi-account solution that uses AWS Organizations. The solutions architect has organized the company's accounts into organizational units (OUs). The solutions architect needs a solution that will identify any changes to the OU hierarchy. The solution also needs to notify the company's operations team of any changes. Which solution will meet these requirements with the LEAST operational overhead?

- A. Provision the AWS accounts by using AWS Control Tower. Use account drift notications to identify the changes to the OU hierarchy.

- B. Provision the AWS accounts by using AWS Control Tower. Use AWS Cong aggregated rules to identify the changes to the OU hierarchy.

- C. Use AWS Service Catalog to create accounts in Organizations. Use an AWS CloudTrail organization trail to identify the changes to the OU hierarchy.

- D. Use AWS CloudFormation templates to create accounts in Organizations. Use the drift detection operation on a stack to identify the changes to the OU hierarchy.

**Correct:** C
**Why:** An organization trail in AWS CloudTrail records changes to AWS Organizations (including OU hierarchy). Pairing account creation via Service Catalog is incidental; the key is CloudTrail org trail plus notifications for changes.

**Incorrect:**
- A: Control Tower drift notifications relate to account/VPC baselines, not specifically OU hierarchy changes.
- B: AWS Config rules don’t natively report OU hierarchy changes; CloudTrail does.
- D: CloudFormation drift detection applies to stacks, not Organizations OU structure.


---

---

### Question #569

An Amazon EventBridge rule targets a third-party API. The third-party API has not received any incoming trac. A solutions architect needs to determine whether the rule conditions are being met and if the rule's target is being invoked. Which solution will meet these requirements?

- A. Check for metrics in Amazon CloudWatch in the namespace for AWS/Events.

- B. Review events in the Amazon Simple Queue Service (Amazon SQS) dead-letter queue.

- C. Check for the events in Amazon CloudWatch Logs.

- D. Check the trails in AWS CloudTrail for the EventBridge events.

**Correct:** A
**Why:** CloudWatch provides AWS/Events metrics (e.g., Invocations, MatchedEvents, DeliveryToTargetFailures) to verify rule matching and target invocation.

**Incorrect:**
- B: DLQ is relevant if a target supports and you configured one; not inherent for third-party API targets.
- C: CloudWatch Logs may be used if target logs there, but the primary signal for EventBridge rule evaluation is CloudWatch metrics.
- D: CloudTrail logs API calls, not internal EventBridge rule evaluations and target invocations.


---

---

### Question #615

A company runs a critical, customer-facing application on Amazon Elastic Kubernetes Service (Amazon EKS). The application has a microservices architecture. The company needs to implement a solution that collects, aggregates, and summarizes metrics and logs from the application in a centralized location. Which solution meets these requirements?

- A. Run the Amazon CloudWatch agent in the existing EKS cluster. View the metrics and logs in the CloudWatch console.

- B. Run AWS App Mesh in the existing EKS cluster. View the metrics and logs in the App Mesh console.

- C. Configure AWS CloudTrail to capture data events. Query CloudTrail by using Amazon OpenSearch Service.

- D. Configure Amazon CloudWatch Container Insights in the existing EKS cluster. View the metrics and logs in the CloudWatch console.

**Correct:** D
**Why:** CloudWatch Container Insights provides cluster‑wide metrics and logs aggregation for EKS with centralized dashboards.

**Incorrect:**
- A: Agent alone lacks curated EKS insights.
- B: App Mesh is a service mesh, not a logging/metrics aggregator.
- C: CloudTrail data events are not application metrics/logs.


---

---

### Question #616

A company has deployed its newest product on AWS. The product runs in an Auto Scaling group behind a Network Load Balancer. The company stores the product’s objects in an Amazon S3 bucket. The company recently experienced malicious attacks against its systems. The company needs a solution that continuously monitors for malicious activity in the AWS account, workloads, and access patterns to the S3 bucket. The solution must also report suspicious activity and display the information on a dashboard. Which solution will meet these requirements?

- A. Configure Amazon Macie to monitor and report ndings to AWS Cong.

- B. Configure Amazon Inspector to monitor and report ndings to AWS CloudTrail.

- C. Configure Amazon GuardDuty to monitor and report ndings to AWS Security Hub.

- D. Configure AWS Cong to monitor and report ndings to Amazon EventBridge.

**Correct:** C
**Why:** GuardDuty continuously monitors account, workload, and S3 access for threats; Security Hub aggregates and dashboards findings.

**Incorrect:**
- A: Macie focuses on sensitive data discovery, not threat detection.
- B: Inspector is for vulnerability assessment, not S3 access/threat patterns.
- D: Config tracks resource configuration, not threat activity.


---

---

### Question #619

A solutions architect is designing a security solution for a company that wants to provide developers with individual AWS accounts through AWS Organizations, while also maintaining standard security controls. Because the individual developers will have AWS account root user-level access to their own accounts, the solutions architect wants to ensure that the mandatory AWS CloudTrail configuration that is applied to new developer accounts is not modied. Which action meets these requirements?

- A. Create an IAM policy that prohibits changes to CloudTrail. and attach it to the root user.

- B. Create a new trail in CloudTrail from within the developer accounts with the organization trails option enabled.

- C. Create a service control policy (SCP) that prohibits changes to CloudTrail, and attach it the developer accounts.

- D. Create a service-linked role for CloudTrail with a policy condition that allows changes only from an Amazon Resource Name (ARN) in the management account.

**Correct:** C
**Why:** An SCP can deny CloudTrail modifications across developer accounts, even for root, preserving mandatory settings.

**Incorrect:**
- A: You cannot attach IAM policies to root, and IAM can be bypassed by root.
- B: Trails created within accounts can still be altered without an SCP guardrail.
- D: Service‑linked roles don’t enforce org‑level immutability.


---

---

### Question #653

A company maintains an Amazon RDS database that maps users to cost centers. The company has accounts in an organization in AWS Organizations. The company needs a solution that will tag all resources that are created in a specic AWS account in the organization. The solution must tag each resource with the cost center ID of the user who created the resource. Which solution will meet these requirements?

- A. Move the specic AWS account to a new organizational unit (OU) in Organizations from the management account. Create a service control policy (SCP) that requires all existing resources to have the correct cost center tag before the resources are created. Apply the SCP to the new OU.

- B. Create an AWS Lambda function to tag the resources after the Lambda function looks up the appropriate cost center from the RDS database. Configure an Amazon EventBridge rule that reacts to AWS CloudTrail events to invoke the Lambda function.

- C. Create an AWS CloudFormation stack to deploy an AWS Lambda function. Configure the Lambda function to look up the appropriate cost center from the RDS database and to tag resources. Create an Amazon EventBridge scheduled rule to invoke the CloudFormation stack.

- D. Create an AWS Lambda function to tag the resources with a default value. Configure an Amazon EventBridge rule that reacts to AWS CloudTrail events to invoke the Lambda function when a resource is missing the cost center tag.

**Correct:** B
**Why:** Use EventBridge (CloudTrail events) to invoke Lambda that tags new resources after looking up the creator’s cost center in RDS.

**Incorrect:**
- A: SCPs cannot inject tags pre‑creation; they can only allow/deny.
- C: Re‑deploying a stack on a schedule won’t tag arbitrary resources created outside CloudFormation.
- D: Default tags without lookup won’t meet correctness.


---

---

### Question #665

A company has customers located across the world. The company wants to use automation to secure its systems and network infrastructure. The company's security team must be able to track and audit all incremental changes to the infrastructure. Which solution will meet these requirements?

- A. Use AWS Organizations to set up the infrastructure. Use AWS Cong to track changes.

- B. Use AWS CloudFormation to set up the infrastructure. Use AWS Cong to track changes.

- C. Use AWS Organizations to set up the infrastructure. Use AWS Service Catalog to track changes.

- D. Use AWS CloudFormation to set up the infrastructure. Use AWS Service Catalog to track changes.

**Correct:** B
**Why:** CloudFormation provides IaC for automated builds; AWS Config tracks and audits incremental configuration changes.

**Incorrect:**
- A: Organizations/Service Catalog don’t audit infra changes like Config does.
- C: Organizations/Service Catalog don’t audit infra changes like Config does.
- D: Organizations/Service Catalog don’t audit infra changes like Config does.


---

---

### Question #676

A company's application uses Network Load Balancers, Auto Scaling groups, Amazon EC2 instances, and databases that are deployed in an Amazon VPC. The company wants to capture information about trac to and from the network interfaces in near real time in its Amazon VPC. The company wants to send the information to Amazon OpenSearch Service for analysis. Which solution will meet these requirements?

- A. Create a log group in Amazon CloudWatch Logs. Configure VPC Flow Logs to send the log data to the log group. Use Amazon Kinesis Data Streams to stream the logs from the log group to OpenSearch Service.

- B. Create a log group in Amazon CloudWatch Logs. Configure VPC Flow Logs to send the log data to the log group. Use Amazon Kinesis Data Firehose to stream the logs from the log group to OpenSearch Service.

- C. Create a trail in AWS CloudTrail. Configure VPC Flow Logs to send the log data to the trail. Use Amazon Kinesis Data Streams to stream the logs from the trail to OpenSearch Service.

- D. Create a trail in AWS CloudTrail. Configure VPC Flow Logs to send the log data to the trail. Use Amazon Kinesis Data Firehose to stream the logs from the trail to OpenSearch Service.

**Correct:** B
**Why:** Send VPC Flow Logs to CloudWatch Logs, then stream to OpenSearch Service with Kinesis Data Firehose for near real‑time analysis.

**Incorrect:**
- A: Data Streams adds custom consumer management; Firehose is simpler.
- C: CloudTrail is not used for VPC Flow Logs delivery.
- D: CloudTrail is not used for VPC Flow Logs delivery.


---

---

### Question #682

A company needs a solution to enforce data encryption at rest on Amazon EC2 instances. The solution must automatically identify noncompliant resources and enforce compliance policies on ndings. Which solution will meet these requirements with the LEAST administrative overhead?

- A. Use an IAM policy that allows users to create only encrypted Amazon Elastic Block Store (Amazon EBS) volumes. Use AWS Cong and AWS Systems Manager to automate the detection and remediation of unencrypted EBS volumes.

- B. Use AWS Key Management Service (AWS KMS) to manage access to encrypted Amazon Elastic Block Store (Amazon EBS) volumes. Use AWS Lambda and Amazon EventBridge to automate the detection and remediation of unencrypted EBS volumes.

- C. Use Amazon Macie to detect unencrypted Amazon Elastic Block Store (Amazon EBS) volumes. Use AWS Systems Manager Automation rules to automatically encrypt existing and new EBS volumes.

- D. Use Amazon inspector to detect unencrypted Amazon Elastic Block Store (Amazon EBS) volumes. Use AWS Systems Manager Automation rules to automatically encrypt existing and new EBS volumes.

**Correct:** A
**Why:** Enforce encrypted EBS creation via IAM, and use AWS Config with Systems Manager Automation to detect and remediate unencrypted volumes automatically.

**Incorrect:**
- B: Lambda + EventBridge is more custom ops; KMS alone doesn’t enforce encryption.
- C: Macie/Inspector do not detect EBS encryption compliance.
- D: Macie/Inspector do not detect EBS encryption compliance.


---

## AWS DMS / SCT

### Question #527

A company has a regional subscription-based streaming service that runs in a single AWS Region. The architecture consists of web servers and application servers on Amazon EC2 instances. The EC2 instances are in Auto Scaling groups behind Elastic Load Balancers. The architecture includes an Amazon Aurora global database cluster that extends across multiple Availability Zones. The company wants to expand globally and to ensure that its application has minimal downtime. Which solution will provide the MOST fault tolerance?

- A. Extend the Auto Scaling groups for the web tier and the application tier to deploy instances in Availability Zones in a second Region. Use an Aurora global database to deploy the database in the primary Region and the second Region. Use Amazon Route 53 health checks with a failover routing policy to the second Region.

- B. Deploy the web tier and the application tier to a second Region. Add an Aurora PostgreSQL cross-Region Aurora Replica in the second Region. Use Amazon Route 53 health checks with a failover routing policy to the second Region. Promote the secondary to primary as needed.

- C. Deploy the web tier and the application tier to a second Region. Create an Aurora PostgreSQL database in the second Region. Use AWS Database Migration Service (AWS DMS) to replicate the primary database to the second Region. Use Amazon Route 53 health checks with a failover routing policy to the second Region.

- D. Deploy the web tier and the application tier to a second Region. Use an Amazon Aurora global database to deploy the database in the primary Region and the second Region. Use Amazon Route 53 health checks with a failover routing policy to the second Region. Promote the secondary to primary as needed.

**Correct:** D
**Why:** Deploy app tiers in a second Region and use Aurora Global Database plus Route 53 failover for maximal fault tolerance.

**Incorrect:**
- A: Less integrated or slower replication and more manual promotion.
- B: Less integrated or slower replication and more manual promotion.
- C: Less integrated or slower replication and more manual promotion.


---

---

### Question #539

A company wants to use the AWS Cloud to improve its on-premises disaster recovery (DR) configuration. The company's core production business application uses Microsoft SQL Server Standard, which runs on a virtual machine (VM). The application has a recovery point objective (RPO) of 30 seconds or fewer and a recovery time objective (RTO) of 60 minutes. The DR solution needs to minimize costs wherever possible. Which solution will meet these requirements?

- A. Configure a multi-site active/active setup between the on-premises server and AWS by using Microsoft SQL Server Enterprise with Always On availability groups.

- B. Configure a warm standby Amazon RDS for SQL Server database on AWS. Configure AWS Database Migration Service (AWS DMS) to use change data capture (CDC).

- C. Use AWS Elastic Disaster Recovery congured to replicate disk changes to AWS as a pilot light.

- D. Use third-party backup software to capture backups every night. Store a secondary set of backups in Amazon S3.

**Correct:** C
**Why:** AWS Elastic Disaster Recovery provides near‑continuous replication (low RPO) and quick spin‑up (RTO ≤ 60 min) at low standby cost.

**Incorrect:**
- A: SQL Server Enterprise AOAG is costly.
- B: Warm standby RDS incurs ongoing cost and may not meet RPO.
- D: Nightly backups miss the 30‑second RPO.


---

---

### Question #540

A company has an on-premises server that uses an Oracle database to process and store customer information. The company wants to use an AWS database service to achieve higher availability and to improve application performance. The company also wants to ooad reporting from its primary database system. Which solution will meet these requirements in the MOST operationally ecient way?

- A. Use AWS Database Migration Service (AWS DMS) to create an Amazon RDS DB instance in multiple AWS Regions. Point the reporting functions toward a separate DB instance from the primary DB instance.

- B. Use Amazon RDS in a Single-AZ deployment to create an Oracle database. Create a read replica in the same zone as the primary DB instance. Direct the reporting functions to the read replica.

- C. Use Amazon RDS deployed in a Multi-AZ cluster deployment to create an Oracle database. Direct the reporting functions to use the reader instance in the cluster deployment.

- D. Use Amazon RDS deployed in a Multi-AZ instance deployment to create an Amazon Aurora database. Direct the reporting functions to the reader instances.

**Correct:** C
**Why:** RDS Oracle Multi‑AZ cluster improves availability; use the reader for reporting offload with minimal ops.

**Incorrect:**
- A: Multi‑Region primaries/Single‑AZ/engine change add cost or complexity.
- B: Multi‑Region primaries/Single‑AZ/engine change add cost or complexity.
- D: Multi‑Region primaries/Single‑AZ/engine change add cost or complexity.


---

---

### Question #547

A company has data collection sensors at different locations. The data collection sensors stream a high volume of data to the company. The company wants to design a platform on AWS to ingest and process high-volume streaming data. The solution must be scalable and support data collection in near real time. The company must store the data in Amazon S3 for future reporting. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use Amazon Kinesis Data Firehose to deliver streaming data to Amazon S3.

- B. Use AWS Glue to deliver streaming data to Amazon S3.

- C. Use AWS Lambda to deliver streaming data and store the data to Amazon S3.

- D. Use AWS Database Migration Service (AWS DMS) to deliver streaming data to Amazon S3.

**Correct:** A
**Why:** Kinesis Data Firehose ingests high‑volume streams and delivers to S3 with near real‑time buffering and minimal ops.

**Incorrect:**
- B: Glue/Lambda/DMS are not the best fit for streaming ingestion at scale.
- C: Glue/Lambda/DMS are not the best fit for streaming ingestion at scale.
- D: Glue/Lambda/DMS are not the best fit for streaming ingestion at scale.


---

---

### Question #565

A company has an on-premises MySQL database that handles transactional data. The company is migrating the database to the AWS Cloud. The migrated database must maintain compatibility with the company's applications that use the database. The migrated database also must scale automatically during periods of increased demand. Which migration solution will meet these requirements?

- A. Use native MySQL tools to migrate the database to Amazon RDS for MySQL. Configure elastic storage scaling.

- B. Migrate the database to Amazon Redshift by using the mysqldump utility. Turn on Auto Scaling for the Amazon Redshift cluster.

- C. Use AWS Database Migration Service (AWS DMS) to migrate the database to Amazon Aurora. Turn on Aurora Auto Scaling.

- D. Use AWS Database Migration Service (AWS DMS) to migrate the database to Amazon DynamoDB. Configure an Auto Scaling policy.

**Correct:** C
**Why:** Migrate with AWS DMS to Amazon Aurora (MySQL-compatible). Aurora Auto Scaling (e.g., readers, and with Aurora Serverless v2 if adopted) provides automatic scaling to meet demand while maintaining compatibility.

**Incorrect:**
- A: RDS for MySQL with elastic storage scaling does not auto scale compute to handle demand spikes.
- B: Redshift is a data warehouse, not a transactional DB replacement.
- D: DynamoDB is NoSQL and not MySQL-compatible for existing apps.


---

---

### Question #588

An ecommerce company wants a disaster recovery solution for its Amazon RDS DB instances that run Microsoft SQL Server Enterprise Edition. The company's current recovery point objective (RPO) and recovery time objective (RTO) are 24 hours. Which solution will meet these requirements MOST cost-effectively?

- A. Create a cross-Region read replica and promote the read replica to the primary instance.

- B. Use AWS Database Migration Service (AWS DMS) to create RDS cross-Region replication.

- C. Use cross-Region replication every 24 hours to copy native backups to an Amazon S3 bucket.

- D. Copy automatic snapshots to another Region every 24 hours.

**Correct:** D
**Why:** Copy automatic snapshots cross‑Region every 24 hours to meet 24‑hour RPO/RTO at the lowest cost.

**Incorrect:**
- A: Cross‑Region read replica costs more and is overkill for 24‑hour objectives.
- B: DMS is for migration/replication at higher cost/complexity.
- C: Native backups to S3 and custom replication add ops overhead.


---

---

### Question #607

A company has migrated a two-tier application from its on-premises data center to the AWS Cloud. The data tier is a Multi-AZ deployment of Amazon RDS for Oracle with 12 TB of General Purpose SSD Amazon Elastic Block Store (Amazon EBS) storage. The application is designed to process and store documents in the database as binary large objects (blobs) with an average document size of 6 MB. The database size has grown over time, reducing the performance and increasing the cost of storage. The company must improve the database performance and needs a solution that is highly available and resilient. Which solution will meet these requirements MOST cost-effectively?

- A. Reduce the RDS DB instance size. Increase the storage capacity to 24 TiB. Change the storage type to Magnetic.

- B. Increase the RDS DB instance size. Increase the storage capacity to 24 TiChange the storage type to Provisioned IOPS.

- C. Create an Amazon S3 bucket. Update the application to store documents in the S3 bucket. Store the object metadata in the existing database.

- D. Create an Amazon DynamoDB table. Update the application to use DynamoDB. Use AWS Database Migration Service (AWS DMS) to migrate data from the Oracle database to DynamoDB.

**Correct:** C
**Why:** Offload large blobs to S3 and keep only metadata in RDS to reduce DB size/cost and improve performance.

**Incorrect:**
- A: Increasing size/IOPS increases cost and doesn’t address bloated storage from blobs.
- B: Increasing size/IOPS increases cost and doesn’t address bloated storage from blobs.
- D: DynamoDB migration is unnecessary and higher effort.


---

---

### Question #629

A company runs a production database on Amazon RDS for MySQL. The company wants to upgrade the database version for security compliance reasons. Because the database contains critical data, the company wants a quick solution to upgrade and test functionality without losing any data. Which solution will meet these requirements with the LEAST operational overhead?

- A. Create an RDS manual snapshot. Upgrade to the new version of Amazon RDS for MySQL.

- B. Use native backup and restore. Restore the data to the upgraded new version of Amazon RDS for MySQL.

- C. Use AWS Database Migration Service (AWS DMS) to replicate the data to the upgraded new version of Amazon RDS for MySQL.

- D. Use Amazon RDS Blue/Green Deployments to deploy and test production changes.

**Correct:** D
**Why:** RDS Blue/Green Deployments enable quick, low‑risk upgrades and testing without data loss and with minimal downtime.

**Incorrect:**
- A: Snapshot/restore, native backup/restore, or DMS add downtime/ops overhead.
- B: Snapshot/restore, native backup/restore, or DMS add downtime/ops overhead.
- C: Snapshot/restore, native backup/restore, or DMS add downtime/ops overhead.


---

## AWS Direct Connect & VPN

### Question #504

A company needs to connect several VPCs in the us-east-1 Region that span hundreds of AWS accounts. The company's networking team has its own AWS account to manage the cloud network. What is the MOST operationally ecient solution to connect the VPCs?

- A. Set up VPC peering connections between each VPC. Update each associated subnet’s route table

- B. Configure a NAT gateway and an internet gateway in each VPC to connect each VPC through the internet

- C. Create an AWS Transit Gateway in the networking team’s AWS account. Configure static routes from each VPC.

- D. Deploy VPN gateways in each VPC. Create a transit VPC in the networking team’s AWS account to connect to each VPC.

**Correct:** C
**Why:** Transit Gateway in a central networking account scales to hundreds of VPCs with simple routing.

**Incorrect:**
- A: Peering/internet/VPN transit VPCs add heavy ops.
- B: Peering/internet/VPN transit VPCs add heavy ops.
- D: Peering/internet/VPN transit VPCs add heavy ops.


---

---

### Question #558

A company has two VPCs that are located in the us-west-2 Region within the same AWS account. The company needs to allow network trac between these VPCs. Approximately 500 GB of data transfer will occur between the VPCs each month. What is the MOST cost-effective solution to connect these VPCs?

- A. Implement AWS Transit Gateway to connect the VPCs. Update the route tables of each VPC to use the transit gateway for inter-VPC communication.

- B. Implement an AWS Site-to-Site VPN tunnel between the VPCs. Update the route tables of each VPC to use the VPN tunnel for inter-VPC communication.

- C. Set up a VPC peering connection between the VPCs. Update the route tables of each VPC to use the VPC peering connection for inter-VPC communication.

- D. Set up a 1 GB AWS Direct Connect connection between the VPCs. Update the route tables of each VPC to use the Direct Connect connection for inter-VPC communication.

**Correct:** C
**Why:** VPC peering within the same account/Region is simplest and most cost-effective for 500 GB/month, with low operational overhead.

**Incorrect:**
- A: Transit Gateway adds unnecessary cost/complexity for two VPCs.
- B: Site-to-Site VPN incurs data transfer charges and adds latency/overhead.
- D: Direct Connect is for on-prem to AWS, not VPC-to-VPC, and is cost-inefficient here.


---

---

### Question #572

A company runs an application on AWS. The application receives inconsistent amounts of usage. The application uses AWS Direct Connect to connect to an on-premises MySQL-compatible database. The on-premises database consistently uses a minimum of 2 GiB of memory. The company wants to migrate the on-premises database to a managed AWS service. The company wants to use auto scaling capabilities to manage unexpected workload increases. Which solution will meet these requirements with the LEAST administrative overhead?

- A. Provision an Amazon DynamoDB database with default read and write capacity settings.

- B. Provision an Amazon Aurora database with a minimum capacity of 1 Aurora capacity unit (ACU).

- C. Provision an Amazon Aurora Serverless v2 database with a minimum capacity of 1 Aurora capacity unit (ACU).

- D. Provision an Amazon RDS for MySQL database with 2 GiB of memory.

**Correct:** C
**Why:** Aurora Serverless v2 (MySQL-compatible) supports automatic, fine-grained scaling with minimal admin overhead; a 1 ACU minimum covers the 2 GiB baseline.

**Incorrect:**
- A: DynamoDB is not MySQL-compatible.
- B: Provisioned Aurora (non-serverless) requires capacity management.
- D: RDS for MySQL is managed but does not auto scale compute to absorb unexpected spikes.


---

---

### Question #610

A company deploys Amazon EC2 instances that run in a VPC. The EC2 instances load source data into Amazon S3 buckets so that the data can be processed in the future. According to compliance laws, the data must not be transmitted over the public internet. Servers in the company's on- premises data center will consume the output from an application that runs on the EC2 instances. Which solution will meet these requirements?

- A. Deploy an interface VPC endpoint for Amazon EC2. Create an AWS Site-to-Site VPN connection between the company and the VPC.

- B. Deploy a gateway VPC endpoint for Amazon S3. Set up an AWS Direct Connect connection between the on-premises network and the VPC.

- C. Set up an AWS Transit Gateway connection from the VPC to the S3 buckets. Create an AWS Site-to-Site VPN connection between the company and the VPC.

- D. Set up proxy EC2 instances that have routes to NAT gateways. Configure the proxy EC2 instances to fetch S3 data and feed the application instances.

**Correct:** B
**Why:** Use an S3 gateway endpoint for private access from EC2 to S3 and Direct Connect for private on‑prem access to VPC‑hosted outputs.

**Incorrect:**
- A: Do not provide private S3 access end‑to‑end without traversing the internet.
- C: Do not provide private S3 access end‑to‑end without traversing the internet.
- D: Do not provide private S3 access end‑to‑end without traversing the internet.


---

---

### Question #612

A company has an application that runs on Amazon EC2 instances in a private subnet. The application needs to process sensitive information from an Amazon S3 bucket. The application must not use the internet to connect to the S3 bucket. Which solution will meet these requirements?

- A. Configure an internet gateway. Update the S3 bucket policy to allow access from the internet gateway. Update the application to use the new internet gateway.

- B. Configure a VPN connection. Update the S3 bucket policy to allow access from the VPN connection. Update the application to use the new VPN connection.

- C. Configure a NAT gateway. Update the S3 bucket policy to allow access from the NAT gateway. Update the application to use the new NAT gateway.

- D. Configure a VPC endpoint. Update the S3 bucket policy to allow access from the VPC endpoint. Update the application to use the new VPC endpoint.

**Correct:** D
**Why:** Use an S3 VPC endpoint and bucket policy to allow access only via the endpoint. No internet path is used.

**Incorrect:**
- A: These traverse the internet or are unnecessary.
- B: These traverse the internet or are unnecessary.
- C: These traverse the internet or are unnecessary.


---

---

### Question #659

A company is relocating its data center and wants to securely transfer 50 TB of data to AWS within 2 weeks. The existing data center has a Site-to- Site VPN connection to AWS that is 90% utilized. Which AWS service should a solutions architect use to meet these requirements?

- A. AWS DataSync with a VPC endpoint

- B. AWS Direct Connect

- C. AWS Snowball Edge Storage Optimized

- D. AWS Storage Gateway

**Correct:** C
**Why:** Snowball Edge Storage Optimized transfers 50 TB securely within 2 weeks without saturating the VPN.

**Incorrect:**
- A: DataSync over congested VPN may miss the window.
- B: Direct Connect cannot be provisioned that quickly typically.
- D: Storage Gateway is not a bulk one‑time transfer solution.


---

---

### Question #667

A company is moving its data and applications to AWS during a multiyear migration project. The company wants to securely access data on Amazon S3 from the company's AWS Region and from the company's on-premises location. The data must not traverse the internet. The company has established an AWS Direct Connect connection between its Region and its on-premises location. Which solution will meet these requirements?

- A. Create gateway endpoints for Amazon S3. Use the gateway endpoints to securely access the data from the Region and the on-premises location.

- B. Create a gateway in AWS Transit Gateway to access Amazon S3 securely from the Region and the on-premises location.

- C. Create interface endpoints for Amazon S3. Use the interface endpoints to securely access the data from the Region and the on-premises location.

- D. Use an AWS Key Management Service (AWS KMS) key to access the data securely from the Region and the on-premises location.

**Correct:** C
**Why:** S3 interface endpoints (PrivateLink) allow private S3 access inside a VPC. Over Direct Connect private VIF, on‑prem can reach those endpoints without internet.

**Incorrect:**
- A: Gateway endpoints are not reachable from on‑prem.
- B: Transit Gateway does not provide S3 service access.
- D: KMS keys don’t provide network‑private access.


---

## AWS Global Accelerator

### Question #502

A company runs a website that uses a content management system (CMS) on Amazon EC2. The CMS runs on a single EC2 instance and uses an Amazon Aurora MySQL Multi-AZ DB instance for the data tier. Website images are stored on an Amazon Elastic Block Store (Amazon EBS) volume that is mounted inside the EC2 instance. Which combination of actions should a solutions architect take to improve the performance and resilience of the website? (Choose two.)

- A. Move the website images into an Amazon S3 bucket that is mounted on every EC2 instance

- B. Share the website images by using an NFS share from the primary EC2 instance. Mount this share on the other EC2 instances.

- C. Move the website images onto an Amazon Elastic File System (Amazon EFS) file system that is mounted on every EC2 instance.

- D. Create an Amazon Machine Image (AMI) from the existing EC2 instance. Use the AMI to provision new instances behind an Application Load Balancer as part of an Auto Scaling group. Configure the Auto Scaling group to maintain a minimum of two instances. Configure an accelerator in AWS Global Accelerator for the website

E. Create an Amazon Machine Image (AMI) from the existing EC2 instance. Use the AMI to provision new instances behind an Application Load Balancer as part of an Auto Scaling group. Configure the Auto Scaling group to maintain a minimum of two instances. Configure an Amazon CloudFront distribution for the website.

**Correct:** C, E
**Why:** Move images to EFS for shared, scalable storage; use ALB+Auto Scaling behind a CloudFront distribution for performance and resilience.

**Incorrect:**
- A: S3 mounted or EC2 NFS via a primary instance are not ideal.
- B: S3 mounted or EC2 NFS via a primary instance are not ideal.
- D: Global Accelerator is unnecessary for origin performance here.


---

---

### Question #530

A company has an online gaming application that has TCP and UDP multiplayer gaming capabilities. The company uses Amazon Route 53 to point the application trac to multiple Network Load Balancers (NLBs) in different AWS Regions. The company needs to improve application performance and decrease latency for the online game in preparation for user growth. Which solution will meet these requirements?

- A. Add an Amazon CloudFront distribution in front of the NLBs. Increase the Cache-Control max-age parameter.

- B. Replace the NLBs with Application Load Balancers (ALBs). Configure Route 53 to use latency-based routing.

- C. Add AWS Global Accelerator in front of the NLBs. Configure a Global Accelerator endpoint to use the correct listener ports.

- D. Add an Amazon API Gateway endpoint behind the NLBs. Enable API caching. Override method caching for the different stages.

**Correct:** C
**Why:** Global Accelerator improves global TCP/UDP performance with anycast IPs in front of NLBs.

**Incorrect:**
- A: CloudFront/ALB/API Gateway are not suited for arbitrary TCP/UDP improvements.
- B: CloudFront/ALB/API Gateway are not suited for arbitrary TCP/UDP improvements.
- D: CloudFront/ALB/API Gateway are not suited for arbitrary TCP/UDP improvements.


---

---

### Question #647

A gaming company is building an application with Voice over IP capabilities. The application will serve trac to users across the world. The application needs to be highly available with an automated failover across AWS Regions. The company wants to minimize the latency of users without relying on IP address caching on user devices. What should a solutions architect do to meet these requirements?

- A. Use AWS Global Accelerator with health checks.

- B. Use Amazon Route 53 with a geolocation routing policy.

- C. Create an Amazon CloudFront distribution that includes multiple origins.

- D. Create an Application Load Balancer that uses path-based routing.

**Correct:** A
**Why:** Global Accelerator provides anycast IPs, health checks, and automatic multi‑Region failover without relying on DNS caching.

**Incorrect:**
- B: Route 53 relies on DNS caching/TTL.
- C: CloudFront is for HTTP(S), not generic VoIP/UDP or bi‑directional traffic patterns.
- D: ALB routes within a Region only.


---

## AWS Glue

### Question #501

A company wants to ingest customer payment data into the company's data lake in Amazon S3. The company receives payment data every minute on average. The company wants to analyze the payment data in real time. Then the company wants to ingest the data into the data lake. Which solution will meet these requirements with the MOST operational eciency?

- A. Use Amazon Kinesis Data Streams to ingest data. Use AWS Lambda to analyze the data in real time.

- B. Use AWS Glue to ingest data. Use Amazon Kinesis Data Analytics to analyze the data in real time.

- C. Use Amazon Kinesis Data Firehose to ingest data. Use Amazon Kinesis Data Analytics to analyze the data in real time.

- D. Use Amazon API Gateway to ingest data. Use AWS Lambda to analyze the data in real time.

**Correct:** C
**Why:** Kinesis Data Firehose provides fully managed ingestion to S3; Kinesis Data Analytics analyzes the stream in real time with minimal ops.

**Incorrect:**
- A: Lambda analysis is more custom and operationally heavier than KDA for streaming analytics.
- B: Glue/API Gateway are not optimal for continuous real‑time ingestion/analysis.
- D: Glue/API Gateway are not optimal for continuous real‑time ingestion/analysis.


---

---

### Question #524

A company wants to analyze and troubleshoot Access Denied errors and Unauthorized errors that are related to IAM permissions. The company has AWS CloudTrail turned on. Which solution will meet these requirements with the LEAST effort?

- A. Use AWS Glue and write custom scripts to query CloudTrail logs for the errors.

- B. Use AWS Batch and write custom scripts to query CloudTrail logs for the errors.

- C. Search CloudTrail logs with Amazon Athena queries to identify the errors.

- D. Search CloudTrail logs with Amazon QuickSight. Create a dashboard to identify the errors.

**Correct:** C
**Why:** Query CloudTrail logs directly with Athena to find AccessDenied/Unauthorized events—lowest effort.

**Incorrect:**
- A: Glue/Batch/QuickSight add unnecessary development overhead.
- B: Glue/Batch/QuickSight add unnecessary development overhead.
- D: Glue/Batch/QuickSight add unnecessary development overhead.


---

---

### Question #547

A company has data collection sensors at different locations. The data collection sensors stream a high volume of data to the company. The company wants to design a platform on AWS to ingest and process high-volume streaming data. The solution must be scalable and support data collection in near real time. The company must store the data in Amazon S3 for future reporting. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use Amazon Kinesis Data Firehose to deliver streaming data to Amazon S3.

- B. Use AWS Glue to deliver streaming data to Amazon S3.

- C. Use AWS Lambda to deliver streaming data and store the data to Amazon S3.

- D. Use AWS Database Migration Service (AWS DMS) to deliver streaming data to Amazon S3.

**Correct:** A
**Why:** Kinesis Data Firehose ingests high‑volume streams and delivers to S3 with near real‑time buffering and minimal ops.

**Incorrect:**
- B: Glue/Lambda/DMS are not the best fit for streaming ingestion at scale.
- C: Glue/Lambda/DMS are not the best fit for streaming ingestion at scale.
- D: Glue/Lambda/DMS are not the best fit for streaming ingestion at scale.


---

---

### Question #557

A solutions architect manages an analytics application. The application stores large amounts of semistructured data in an Amazon S3 bucket. The solutions architect wants to use parallel data processing to process the data more quickly. The solutions architect also wants to use information that is stored in an Amazon Redshift database to enrich the data. Which solution will meet these requirements?

- A. Use Amazon Athena to process the S3 data. Use AWS Glue with the Amazon Redshift data to enrich the S3 data.

- B. Use Amazon EMR to process the S3 data. Use Amazon EMR with the Amazon Redshift data to enrich the S3 data.

- C. Use Amazon EMR to process the S3 data. Use Amazon Kinesis Data Streams to move the S3 data into Amazon Redshift so that the data can be enriched.

- D. Use AWS Glue to process the S3 data. Use AWS Lake Formation with the Amazon Redshift data to enrich the S3 data.

**Correct:** B
**Why:** Amazon EMR supports large-scale parallel processing on S3 data and can integrate with Amazon Redshift to enrich S3 data with Redshift data (e.g., via Spark connectors/JDBC).

**Incorrect:**
- A: Athena + Glue can join, but enriching with Redshift data is more direct and scalable with EMR compute.
- C: Kinesis Data Streams is for streaming ingestion, not enriching S3 batch data with Redshift.
- D: Glue can process S3 data, but enrichment specifically with Redshift is better served by EMR’s flexible engines.


---

---

### Question #598

A research company uses on-premises devices to generate data for analysis. The company wants to use the AWS Cloud to analyze the data. The devices generate .csv files and support writing the data to an SMB file share. Company analysts must be able to use SQL commands to query the data. The analysts will run queries periodically throughout the day. Which combination of steps will meet these requirements MOST cost-effectively? (Choose three.)

- A. Deploy an AWS Storage Gateway on premises in Amazon S3 File Gateway mode.

- B. Deploy an AWS Storage Gateway on premises in Amazon FSx File Gateway made.

- C. Set up an AWS Glue crawler to create a table based on the data that is in Amazon S3.

- D. Set up an Amazon EMR cluster with EMR File System (EMRFS) to query the data that is in Amazon S3. Provide access to analysts.

E. Set up an Amazon Redshift cluster to query the data that is in Amazon S3. Provide access to analysts.

F. Setup Amazon Athena to query the data that is in Amazon S3. Provide access to analysts.

**Correct:** A, C, F
**Why:** Use S3 File Gateway to land CSVs in S3 over SMB, crawl with Glue to build schema, and query with Athena using SQL on demand.

**Incorrect:**
- B: FSx File Gateway presents FSx, not S3.
- D: EMR/Redshift add cost/ops for periodic ad‑hoc queries.
- E: EMR/Redshift add cost/ops for periodic ad‑hoc queries.


---

---

### Question #603

A company recently migrated to the AWS Cloud. The company wants a serverless solution for large-scale parallel on-demand processing of a semistructured dataset. The data consists of logs, media files, sales transactions, and IoT sensor data that is stored in Amazon S3. The company wants the solution to process thousands of items in the dataset in parallel. Which solution will meet these requirements with the MOST operational eciency?

- A. Use the AWS Step Functions Map state in Inline mode to process the data in parallel.

- B. Use the AWS Step Functions Map state in Distributed mode to process the data in parallel.

- C. Use AWS Glue to process the data in parallel.

- D. Use several AWS Lambda functions to process the data in parallel.

**Correct:** B
**Why:** Step Functions Distributed Map processes thousands to millions of items in parallel serverlessly with high efficiency.

**Incorrect:**
- A: Inline Map is limited for large-scale fan‑out.
- C: Glue/Lambda alone are less scalable or require orchestration for very large parallelism.
- D: Glue/Lambda alone are less scalable or require orchestration for very large parallelism.


---

---

### Question #672

A marketing company receives a large amount of new clickstream data in Amazon S3 from a marketing campaign. The company needs to analyze the clickstream data in Amazon S3 quickly. Then the company needs to determine whether to process the data further in the data pipeline. Which solution will meet these requirements with the LEAST operational overhead?

- A. Create external tables in a Spark catalog. Configure jobs in AWS Glue to query the data.

- B. Configure an AWS Glue crawler to crawl the data. Configure Amazon Athena to query the data.

- C. Create external tables in a Hive metastore. Configure Spark jobs in Amazon EMR to query the data.

- D. Configure an AWS Glue crawler to crawl the data. Configure Amazon Kinesis Data Analytics to use SQL to query the data.

**Correct:** B
**Why:** Run an AWS Glue crawler to catalog the S3 data, then use Amazon Athena to query immediately with SQL and minimal ops.

**Incorrect:**
- A: Spark catalog setup adds unnecessary overhead for a quick assessment.
- C: EMR + Hive metastore increases cost/ops for ad‑hoc queries.
- D: Kinesis Data Analytics is for streaming SQL, not batch S3 analysis.


---

## AWS KMS

### Question #529

A company is migrating its workloads to AWS. The company has transactional and sensitive data in its databases. The company wants to use AWS Cloud solutions to increase security and reduce operational overhead for the databases. Which solution will meet these requirements?

- A. Migrate the databases to Amazon EC2. Use an AWS Key Management Service (AWS KMS) AWS managed key for encryption.

- B. Migrate the databases to Amazon RDS Configure encryption at rest.

- C. Migrate the data to Amazon S3 Use Amazon Macie for data security and protection

- D. Migrate the database to Amazon RDS. Use Amazon CloudWatch Logs for data security and protection.

**Correct:** B
**Why:** RDS is managed, supports encryption at rest/in transit, and reduces operational overhead for transactional/sensitive data.

**Incorrect:**
- A: EC2/CloudWatch Logs/Macie alone do not meet the database requirements.
- C: EC2/CloudWatch Logs/Macie alone do not meet the database requirements.
- D: EC2/CloudWatch Logs/Macie alone do not meet the database requirements.


---

---

### Question #535

A company is building an Amazon Elastic Kubernetes Service (Amazon EKS) cluster for its workloads. All secrets that are stored in Amazon EKS must be encrypted in the Kubernetes etcd key-value store. Which solution will meet these requirements?

- A. Create a new AWS Key Management Service (AWS KMS) key. Use AWS Secrets Manager to manage, rotate, and store all secrets in Amazon EKS.

- B. Create a new AWS Key Management Service (AWS KMS) key. Enable Amazon EKS KMS secrets encryption on the Amazon EKS cluster.

- C. Create the Amazon EKS cluster with default options. Use the Amazon Elastic Block Store (Amazon EBS) Container Storage Interface (CSI) driver as an add-on.

- D. Create a new AWS Key Management Service (AWS KMS) key with the alias/aws/ebs alias. Enable default Amazon Elastic Block Store (Amazon EBS) volume encryption for the account.

**Correct:** B
**Why:** Enable EKS KMS secrets encryption with a customer KMS key to encrypt Kubernetes secrets in etcd.

**Incorrect:**
- A: Secrets Manager/EBS encryption don’t encrypt etcd secrets by default.
- C: Secrets Manager/EBS encryption don’t encrypt etcd secrets by default.
- D: Secrets Manager/EBS encryption don’t encrypt etcd secrets by default.


---

---

### Question #550

A company is using AWS Key Management Service (AWS KMS) keys to encrypt AWS Lambda environment variables. A solutions architect needs to ensure that the required permissions are in place to decrypt and use the environment variables. Which steps must the solutions architect take to implement the correct permissions? (Choose two.)

- A. Add AWS KMS permissions in the Lambda resource policy.

- B. Add AWS KMS permissions in the Lambda execution role.

- C. Add AWS KMS permissions in the Lambda function policy.

- D. Allow the Lambda execution role in the AWS KMS key policy.

E. Allow the Lambda resource policy in the AWS KMS key policy.

**Correct:** B, D
**Why:** The Lambda execution role must have KMS permissions, and the KMS key policy must allow that role to use the key for decryption.

**Incorrect:**
- A: Lambda resource/function policies are not where KMS grants are applied; allow the role in the key policy instead.
- C: Lambda resource/function policies are not where KMS grants are applied; allow the role in the key policy instead.
- E: Lambda resource/function policies are not where KMS grants are applied; allow the role in the key policy instead.


---

---

### Question #564

A company is building an ecommerce application and needs to store sensitive customer information. The company needs to give customers the ability to complete purchase transactions on the website. The company also needs to ensure that sensitive customer data is protected, even from database administrators. Which solution meets these requirements?

- A. Store sensitive data in an Amazon Elastic Block Store (Amazon EBS) volume. Use EBS encryption to encrypt the data. Use an IAM instance role to restrict access.

- B. Store sensitive data in Amazon RDS for MySQL. Use AWS Key Management Service (AWS KMS) client-side encryption to encrypt the data.

- C. Store sensitive data in Amazon S3. Use AWS Key Management Service (AWS KMS) server-side encryption to encrypt the data. Use S3 bucket policies to restrict access.

- D. Store sensitive data in Amazon FSx for Windows Server. Mount the file share on application servers. Use Windows file permissions to restrict access.

**Correct:** B
**Why:** To prevent even DBAs from accessing sensitive data, encrypt at the application/client layer before storage (client-side KMS encryption) and store ciphertext in the database.

**Incorrect:**
- A: EBS encryption protects at the volume level; DBAs can still read decrypted data via the DB engine.
- C: S3 is not the right backend for transactional ecommerce data; SSE-KMS also does not prevent privileged DB access.
- D: FSx + Windows permissions doesn’t address app-level transactional storage nor protect from DBAs.


---

---

### Question #613

A company uses Amazon Elastic Kubernetes Service (Amazon EKS) to run a container application. The EKS cluster stores sensitive information in the Kubernetes secrets object. The company wants to ensure that the information is encrypted. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use the container application to encrypt the information by using AWS Key Management Service (AWS KMS).

- B. Enable secrets encryption in the EKS cluster by using AWS Key Management Service (AWS KMS).

- C. Implement an AWS Lambda function to encrypt the information by using AWS Key Management Service (AWS KMS).

- D. Use AWS Systems Manager Parameter Store to encrypt the information by using AWS Key Management Service (AWS KMS).

**Correct:** B
**Why:** EKS secrets encryption with KMS provides at‑rest encryption for Kubernetes secrets with minimal ops.

**Incorrect:**
- A: App/Lambda encryption adds complexity and key handling.
- C: App/Lambda encryption adds complexity and key handling.
- D: Parameter Store is separate from native K8s secrets management.


---

---

### Question #640

A company has an application workow that uses an AWS Lambda function to download and decrypt files from Amazon S3. These files are encrypted using AWS Key Management Service (AWS KMS) keys. A solutions architect needs to design a solution that will ensure the required permissions are set correctly. Which combination of actions accomplish this? (Choose two.)

- A. Attach the kms:decrypt permission to the Lambda function’s resource policy

- B. Grant the decrypt permission for the Lambda IAM role in the KMS key's policy

- C. Grant the decrypt permission for the Lambda resource policy in the KMS key's policy.

- D. Create a new IAM policy with the kms:decrypt permission and attach the policy to the Lambda function.

E. Create a new IAM role with the kms:decrypt permission and attach the execution role to the Lambda function.

**Correct:** B, E
**Why:** Allow the Lambda execution role in the KMS key policy and ensure the function uses an execution role with kms:Decrypt.

**Incorrect:**
- A: Lambda resource policies do not grant KMS decrypt permissions.
- C: Lambda resource policies do not grant KMS decrypt permissions.
- D: Policies attach to roles; attach to the function’s role, not the function object.


---

---

### Question #645

A company is required to use cryptographic keys in its on-premises key manager. The key manager is outside of the AWS Cloud because of regulatory and compliance requirements. The company wants to manage encryption and decryption by using cryptographic keys that are retained outside of the AWS Cloud and that support a variety of external key managers from different vendors. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use AWS CloudHSM key store backed by a CloudHSM cluster.

- B. Use an AWS Key Management Service (AWS KMS) external key store backed by an external key manager.

- C. Use the default AWS Key Management Service (AWS KMS) managed key store.

- D. Use a custom key store backed by an AWS CloudHSM cluster.

**Correct:** B
**Why:** KMS External Key Store (XKS) uses keys retained in external key managers and supports multiple vendor solutions with minimal ops.

**Incorrect:**
- A: CloudHSM/custom key stores keep keys in AWS‑managed HSMs, not external.
- C: AWS‑managed key store does not meet external key retention.
- D: CloudHSM/custom key stores keep keys in AWS‑managed HSMs, not external.


---

---

### Question #663

A company is developing a new application on AWS. The application consists of an Amazon Elastic Container Service (Amazon ECS) cluster, an Amazon S3 bucket that contains assets for the application, and an Amazon RDS for MySQL database that contains the dataset for the application. The dataset contains sensitive information. The company wants to ensure that only the ECS cluster can access the data in the RDS for MySQL database and the data in the S3 bucket. Which solution will meet these requirements?

- A. Create a new AWS Key Management Service (AWS KMS) customer managed key to encrypt both the S3 bucket and the RDS for MySQL database. Ensure that the KMS key policy includes encrypt and decrypt permissions for the ECS task execution role.

- B. Create an AWS Key Management Service (AWS KMS) AWS managed key to encrypt both the S3 bucket and the RDS for MySQL database. Ensure that the S3 bucket policy species the ECS task execution role as a user.

- C. Create an S3 bucket policy that restricts bucket access to the ECS task execution role. Create a VPC endpoint for Amazon RDS for MySQL. Update the RDS for MySQL security group to allow access from only the subnets that the ECS cluster will generate tasks in.

- D. Create a VPC endpoint for Amazon RDS for MySQL. Update the RDS for MySQL security group to allow access from only the subnets that the ECS cluster will generate tasks in. Create a VPC endpoint for Amazon S3. Update the S3 bucket policy to allow access from only the S3 VPC endpoint.

**Correct:** C
**Why:** Restrict S3 bucket access to the ECS task execution role, and tighten RDS access via security groups to only the ECS task subnets; combined, only the ECS tasks can reach data.

**Incorrect:**
- A: KMS encryption alone doesn’t restrict principal network/data access.
- B: KMS encryption alone doesn’t restrict principal network/data access.
- D: There is no VPC endpoint for RDS database connections; S3 endpoint restriction is good, but RDS SG is the right control.


---

---

### Question #667

A company is moving its data and applications to AWS during a multiyear migration project. The company wants to securely access data on Amazon S3 from the company's AWS Region and from the company's on-premises location. The data must not traverse the internet. The company has established an AWS Direct Connect connection between its Region and its on-premises location. Which solution will meet these requirements?

- A. Create gateway endpoints for Amazon S3. Use the gateway endpoints to securely access the data from the Region and the on-premises location.

- B. Create a gateway in AWS Transit Gateway to access Amazon S3 securely from the Region and the on-premises location.

- C. Create interface endpoints for Amazon S3. Use the interface endpoints to securely access the data from the Region and the on-premises location.

- D. Use an AWS Key Management Service (AWS KMS) key to access the data securely from the Region and the on-premises location.

**Correct:** C
**Why:** S3 interface endpoints (PrivateLink) allow private S3 access inside a VPC. Over Direct Connect private VIF, on‑prem can reach those endpoints without internet.

**Incorrect:**
- A: Gateway endpoints are not reachable from on‑prem.
- B: Transit Gateway does not provide S3 service access.
- D: KMS keys don’t provide network‑private access.


---

---

### Question #678

A company stores sensitive data in Amazon S3. A solutions architect needs to create an encryption solution. The company needs to fully control the ability of users to create, rotate, and disable encryption keys with minimal effort for any data that must be encrypted. Which solution will meet these requirements?

- A. Use default server-side encryption with Amazon S3 managed encryption keys (SSE-S3) to store the sensitive data.

- B. Create a customer managed key by using AWS Key Management Service (AWS KMS). Use the new key to encrypt the S3 objects by using server-side encryption with AWS KMS keys (SSE-KMS).

- C. Create an AWS managed key by using AWS Key Management Service (AWS KMS). Use the new key to encrypt the S3 objects by using server-side encryption with AWS KMS keys (SSE-KMS).

- D. Download S3 objects to an Amazon EC2 instance. Encrypt the objects by using customer managed keys. Upload the encrypted objects back into Amazon S3.

**Correct:** B
**Why:** Use a customer managed KMS key with SSE‑KMS for S3 to fully control key creation, rotation, and disabling.

**Incorrect:**
- A: SSE‑S3 uses AWS‑owned keys with no customer control.
- C: AWS managed keys limit control of rotation/disable.
- D: Client‑side EC2 encryption adds operational complexity.


---

---

### Question #681

A company uses Amazon EC2 instances and stores data on Amazon Elastic Block Store (Amazon EBS) volumes. The company must ensure that all data is encrypted at rest by using AWS Key Management Service (AWS KMS). The company must be able to control rotation of the encryption keys. Which solution will meet these requirements with the LEAST operational overhead?

- A. Create a customer managed key. Use the key to encrypt the EBS volumes.

- B. Use an AWS managed key to encrypt the EBS volumes. Use the key to configure automatic key rotation.

- C. Create an external KMS key with imported key material. Use the key to encrypt the EBS volumes.

- D. Use an AWS owned key to encrypt the EBS volumes.

**Correct:** A
**Why:** A customer managed KMS key encrypts EBS volumes with customer‑controlled rotation, meeting requirements with low ops.

**Incorrect:**
- B: AWS managed keys do not give customer control over rotation/disable.
- C: External key material increases complexity without additional benefit here.
- D: AWS owned keys provide no control or visibility.


---

---

### Question #682

A company needs a solution to enforce data encryption at rest on Amazon EC2 instances. The solution must automatically identify noncompliant resources and enforce compliance policies on ndings. Which solution will meet these requirements with the LEAST administrative overhead?

- A. Use an IAM policy that allows users to create only encrypted Amazon Elastic Block Store (Amazon EBS) volumes. Use AWS Cong and AWS Systems Manager to automate the detection and remediation of unencrypted EBS volumes.

- B. Use AWS Key Management Service (AWS KMS) to manage access to encrypted Amazon Elastic Block Store (Amazon EBS) volumes. Use AWS Lambda and Amazon EventBridge to automate the detection and remediation of unencrypted EBS volumes.

- C. Use Amazon Macie to detect unencrypted Amazon Elastic Block Store (Amazon EBS) volumes. Use AWS Systems Manager Automation rules to automatically encrypt existing and new EBS volumes.

- D. Use Amazon inspector to detect unencrypted Amazon Elastic Block Store (Amazon EBS) volumes. Use AWS Systems Manager Automation rules to automatically encrypt existing and new EBS volumes.

**Correct:** A
**Why:** Enforce encrypted EBS creation via IAM, and use AWS Config with Systems Manager Automation to detect and remediate unencrypted volumes automatically.

**Incorrect:**
- B: Lambda + EventBridge is more custom ops; KMS alone doesn’t enforce encryption.
- C: Macie/Inspector do not detect EBS encryption compliance.
- D: Macie/Inspector do not detect EBS encryption compliance.


---

## AWS Lake Formation

### Question #557

A solutions architect manages an analytics application. The application stores large amounts of semistructured data in an Amazon S3 bucket. The solutions architect wants to use parallel data processing to process the data more quickly. The solutions architect also wants to use information that is stored in an Amazon Redshift database to enrich the data. Which solution will meet these requirements?

- A. Use Amazon Athena to process the S3 data. Use AWS Glue with the Amazon Redshift data to enrich the S3 data.

- B. Use Amazon EMR to process the S3 data. Use Amazon EMR with the Amazon Redshift data to enrich the S3 data.

- C. Use Amazon EMR to process the S3 data. Use Amazon Kinesis Data Streams to move the S3 data into Amazon Redshift so that the data can be enriched.

- D. Use AWS Glue to process the S3 data. Use AWS Lake Formation with the Amazon Redshift data to enrich the S3 data.

**Correct:** B
**Why:** Amazon EMR supports large-scale parallel processing on S3 data and can integrate with Amazon Redshift to enrich S3 data with Redshift data (e.g., via Spark connectors/JDBC).

**Incorrect:**
- A: Athena + Glue can join, but enriching with Redshift data is more direct and scalable with EMR compute.
- C: Kinesis Data Streams is for streaming ingestion, not enriching S3 batch data with Redshift.
- D: Glue can process S3 data, but enrichment specifically with Redshift is better served by EMR’s flexible engines.


---

---

### Question #609

A company is building a data analysis platform on AWS by using AWS Lake Formation. The platform will ingest data from different sources such as Amazon S3 and Amazon RDS. The company needs a secure solution to prevent access to portions of the data that contain sensitive information. Which solution will meet these requirements with the LEAST operational overhead?

- A. Create an IAM role that includes permissions to access Lake Formation tables.

- B. Create data lters to implement row-level security and cell-level security.

- C. Create an AWS Lambda function that removes sensitive information before Lake Formation ingests the data.

- D. Create an AWS Lambda function that periodically queries and removes sensitive information from Lake Formation tables.

**Correct:** B
**Why:** Lake Formation row‑level and cell‑level filters natively enforce fine‑grained access to sensitive data with minimal ops.

**Incorrect:**
- A: IAM role alone cannot implement row/cell security at the table data level.
- C: Lambda preprocessing/postprocessing adds complexity and is brittle.
- D: Lambda preprocessing/postprocessing adds complexity and is brittle.


---

## AWS Lambda

### Question #501

A company wants to ingest customer payment data into the company's data lake in Amazon S3. The company receives payment data every minute on average. The company wants to analyze the payment data in real time. Then the company wants to ingest the data into the data lake. Which solution will meet these requirements with the MOST operational eciency?

- A. Use Amazon Kinesis Data Streams to ingest data. Use AWS Lambda to analyze the data in real time.

- B. Use AWS Glue to ingest data. Use Amazon Kinesis Data Analytics to analyze the data in real time.

- C. Use Amazon Kinesis Data Firehose to ingest data. Use Amazon Kinesis Data Analytics to analyze the data in real time.

- D. Use Amazon API Gateway to ingest data. Use AWS Lambda to analyze the data in real time.

**Correct:** C
**Why:** Kinesis Data Firehose provides fully managed ingestion to S3; Kinesis Data Analytics analyzes the stream in real time with minimal ops.

**Incorrect:**
- A: Lambda analysis is more custom and operationally heavier than KDA for streaming analytics.
- B: Glue/API Gateway are not optimal for continuous real‑time ingestion/analysis.
- D: Glue/API Gateway are not optimal for continuous real‑time ingestion/analysis.


---

---

### Question #507

A company has a web application for travel ticketing. The application is based on a database that runs in a single data center in North America. The company wants to expand the application to serve a global user base. The company needs to deploy the application to multiple AWS Regions. Average latency must be less than 1 second on updates to the reservation database. The company wants to have separate deployments of its web platform across multiple Regions. However, the company must maintain a single primary reservation database that is globally consistent. Which solution should a solutions architect recommend to meet these requirements?

- A. Convert the application to use Amazon DynamoDB. Use a global table for the center reservation table. Use the correct Regional endpoint in each Regional deployment.

- B. Migrate the database to an Amazon Aurora MySQL database. Deploy Aurora Read Replicas in each Region. Use the correct Regional endpoint in each Regional deployment for access to the database.

- C. Migrate the database to an Amazon RDS for MySQL database. Deploy MySQL read replicas in each Region. Use the correct Regional endpoint in each Regional deployment for access to the database.

- D. Migrate the application to an Amazon Aurora Serverless database. Deploy instances of the database to each Region. Use the correct Regional endpoint in each Regional deployment to access the database. Use AWS Lambda functions to process event streams in each Region to synchronize the databases.

**Correct:** B
**Why:** Aurora MySQL with cross‑Region Aurora Replicas (Aurora Global Database) keeps a single primary and low‑latency replicas; web tiers use Regional endpoints.

**Incorrect:**
- A: DynamoDB changes the data model.
- C: RDS MySQL cross‑Region replication is slower and less managed.
- D: Serverless with custom sync adds complexity.


---

---

### Question #508

A company has migrated multiple Microsoft Windows Server workloads to Amazon EC2 instances that run in the us-west-1 Region. The company manually backs up the workloads to create an image as needed. In the event of a natural disaster in the us-west-1 Region, the company wants to recover workloads quickly in the us-west-2 Region. The company wants no more than 24 hours of data loss on the EC2 instances. The company also wants to automate any backups of the EC2 instances. Which solutions will meet these requirements with the LEAST administrative effort? (Choose two.)

- A. Create an Amazon EC2-backed Amazon Machine Image (AMI) lifecycle policy to create a backup based on tags. Schedule the backup to run twice daily. Copy the image on demand.

- B. Create an Amazon EC2-backed Amazon Machine Image (AMI) lifecycle policy to create a backup based on tags. Schedule the backup to run twice daily. Configure the copy to the us-west-2 Region.

- C. Create backup vaults in us-west-1 and in us-west-2 by using AWS Backup. Create a backup plan for the EC2 instances based on tag values. Create an AWS Lambda function to run as a scheduled job to copy the backup data to us-west-2.

- D. Create a backup vault by using AWS Backup. Use AWS Backup to create a backup plan for the EC2 instances based on tag values. Dene the destination for the copy as us-west-2. Specify the backup schedule to run twice daily.

E. Create a backup vault by using AWS Backup. Use AWS Backup to create a backup plan for the EC2 instances based on tag values. Specify the backup schedule to run twice daily. Copy on demand to us-west-2.

**Correct:** B, D
**Why:** AMI lifecycle with cross‑Region copy and AWS Backup cross‑Region backups both automate twice‑daily backups within the 24‑hour RPO.

**Incorrect:**
- A: On‑demand copies add manual steps.
- C: Lambda copy adds unnecessary custom code.
- E: On‑demand copies add manual steps.


---

---

### Question #513

A social media company wants to allow its users to upload images in an application that is hosted in the AWS Cloud. The company needs a solution that automatically resizes the images so that the images can be displayed on multiple device types. The application experiences unpredictable trac patterns throughout the day. The company is seeking a highly available solution that maximizes scalability. What should a solutions architect do to meet these requirements?

- A. Create a static website hosted in Amazon S3 that invokes AWS Lambda functions to resize the images and store the images in an Amazon S3 bucket.

- B. Create a static website hosted in Amazon CloudFront that invokes AWS Step Functions to resize the images and store the images in an Amazon RDS database.

- C. Create a dynamic website hosted on a web server that runs on an Amazon EC2 instance. Configure a process that runs on the EC2 instance to resize the images and store the images in an Amazon S3 bucket.

- D. Create a dynamic website hosted on an automatically scaling Amazon Elastic Container Service (Amazon ECS) cluster that creates a resize job in Amazon Simple Queue Service (Amazon SQS). Set up an image-resizing program that runs on an Amazon EC2 instance to process the resize jobs.

**Correct:** A
**Why:** Static site front end in S3 with Lambda resizing on upload provides high availability and scalability with minimal ops; store results in S3.

**Incorrect:**
- B: CloudFront+Step Functions/EC2/ECS add complexity and are less serverless.
- C: CloudFront+Step Functions/EC2/ECS add complexity and are less serverless.
- D: CloudFront+Step Functions/EC2/ECS add complexity and are less serverless.


---

---

### Question #516

A company provides an API interface to customers so the customers can retrieve their nancial information. Е he company expects a larger number of requests during peak usage times of the year. The company requires the API to respond consistently with low latency to ensure customer satisfaction. The company needs to provide a compute host for the API. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use an Application Load Balancer and Amazon Elastic Container Service (Amazon ECS).

- B. Use Amazon API Gateway and AWS Lambda functions with provisioned concurrency.

- C. Use an Application Load Balancer and an Amazon Elastic Kubernetes Service (Amazon EKS) cluster.

- D. Use Amazon API Gateway and AWS Lambda functions with reserved concurrency.

**Correct:** B
**Why:** API Gateway + Lambda with provisioned concurrency delivers consistently low latency with minimal ops.

**Incorrect:**
- A: ALB+ECS/EKS add cluster ops.
- C: ALB+ECS/EKS add cluster ops.
- D: Reserved concurrency controls throughput but doesn’t remove cold starts.


---

---

### Question #522

A company runs container applications by using Amazon Elastic Kubernetes Service (Amazon EKS). The company's workload is not consistent throughout the day. The company wants Amazon EKS to scale in and out according to the workload. Which combination of steps will meet these requirements with the LEAST operational overhead? (Choose two.)

- A. Use an AWS Lambda function to resize the EKS cluster.

- B. Use the Kubernetes Metrics Server to activate horizontal pod autoscaling.

- C. Use the Kubernetes Cluster Autoscaler to manage the number of nodes in the cluster.

- D. Use Amazon API Gateway and connect it to Amazon EKS.

E. Use AWS App Mesh to observe network activity.

**Correct:** B, C
**Why:** Use the Metrics Server for HPA (pods) and the Cluster Autoscaler for node count—low operational overhead.

**Incorrect:**
- A: Lambda/API Gateway/App Mesh are not needed for autoscaling here.
- D: Lambda/API Gateway/App Mesh are not needed for autoscaling here.
- E: Lambda/API Gateway/App Mesh are not needed for autoscaling here.


---

---

### Question #523

A company runs a microservice-based serverless web application. The application must be able to retrieve data from multiple Amazon DynamoDB tables A solutions architect needs to give the application the ability to retrieve the data with no impact on the baseline performance of the application. Which solution will meet these requirements in the MOST operationally ecient way?

- A. AWS AppSync pipeline resolvers

- B. Amazon CloudFront with Lambda@Edge functions

- C. Edge-optimized Amazon API Gateway with AWS Lambda functions

- D. Amazon Athena Federated Query with a DynamoDB connector

**Correct:** A
**Why:** AppSync pipeline resolvers can aggregate data from multiple DynamoDB tables efficiently without impacting baseline performance.

**Incorrect:**
- B: Edge/REST proxy/Athena are less suitable for orchestrated multi‑table reads in a serverless app.
- C: Edge/REST proxy/Athena are less suitable for orchestrated multi‑table reads in a serverless app.
- D: Edge/REST proxy/Athena are less suitable for orchestrated multi‑table reads in a serverless app.


---

---

### Question #528

A data analytics company wants to migrate its batch processing system to AWS. The company receives thousands of small data files periodically during the day through FTP. An on-premises batch job processes the data files overnight. However, the batch job takes hours to nish running. The company wants the AWS solution to process incoming data files as soon as possible with minimal changes to the FTP clients that send the files. The solution must delete the incoming data files after the files have been processed successfully. Processing for each file needs to take 3-8 minutes. Which solution will meet these requirements in the MOST operationally ecient way?

- A. Use an Amazon EC2 instance that runs an FTP server to store incoming files as objects in Amazon S3 Glacier Flexible Retrieval. Configure a job queue in AWS Batch. Use Amazon EventBridge rules to invoke the job to process the objects nightly from S3 Glacier Flexible Retrieval. Delete the objects after the job has processed the objects.

- B. Use an Amazon EC2 instance that runs an FTP server to store incoming files on an Amazon Elastic Block Store (Amazon EBS) volume. Configure a job queue in AWS Batch. Use Amazon EventBridge rules to invoke the job to process the files nightly from the EBS volume. Delete the files after the job has processed the files.

- C. Use AWS Transfer Family to create an FTP server to store incoming files on an Amazon Elastic Block Store (Amazon EBS) volume. Configure a job queue in AWS Batch. Use an Amazon S3 event notification when each file arrives to invoke the job in AWS Batch. Delete the files after the job has processed the files.

- D. Use AWS Transfer Family to create an FTP server to store incoming files in Amazon S3 Standard. Create an AWS Lambda function to process the files and to delete the files after they are processed. Use an S3 event notification to invoke the Lambda function when the files arrive.

**Correct:** D
**Why:** Transfer Family (FTP) to S3 with S3 event → Lambda processes and deletes files as they arrive—near real time, minimal client changes.

**Incorrect:**
- A: Glacier/EBS nightly batches or Batch jobs add latency/ops.
- B: Glacier/EBS nightly batches or Batch jobs add latency/ops.
- C: Glacier/EBS nightly batches or Batch jobs add latency/ops.


---

---

### Question #531

A company needs to integrate with a third-party data feed. The data feed sends a webhook to notify an external service when new data is ready for consumption. A developer wrote an AWS Lambda function to retrieve data when the company receives a webhook callback. The developer must make the Lambda function available for the third party to call. Which solution will meet these requirements with the MOST operational eciency?

- A. Create a function URL for the Lambda function. Provide the Lambda function URL to the third party for the webhook.

- B. Deploy an Application Load Balancer (ALB) in front of the Lambda function. Provide the ALB URL to the third party for the webhook.

- C. Create an Amazon Simple Notification Service (Amazon SNS) topic. Attach the topic to the Lambda function. Provide the public hostname of the SNS topic to the third party for the webhook.

- D. Create an Amazon Simple Queue Service (Amazon SQS) queue. Attach the queue to the Lambda function. Provide the public hostname of the SQS queue to the third party for the webhook.

**Correct:** A
**Why:** Lambda function URLs expose HTTPS endpoints directly for webhook callbacks with minimal ops.

**Incorrect:**
- B: ALB/SNS/SQS add unnecessary components for a simple webhook.
- C: ALB/SNS/SQS add unnecessary components for a simple webhook.
- D: ALB/SNS/SQS add unnecessary components for a simple webhook.


---

---

### Question #541

A company wants to build a web application on AWS. Client access requests to the website are not predictable and can be idle for a long time. Only customers who have paid a subscription fee can have the ability to sign in and use the web application. Which combination of steps will meet these requirements MOST cost-effectively? (Choose three.)

- A. Create an AWS Lambda function to retrieve user information from Amazon DynamoDB. Create an Amazon API Gateway endpoint to accept RESTful APIs. Send the API calls to the Lambda function.

- B. Create an Amazon Elastic Container Service (Amazon ECS) service behind an Application Load Balancer to retrieve user information from Amazon RDS. Create an Amazon API Gateway endpoint to accept RESTful APIs. Send the API calls to the Lambda function.

- C. Create an Amazon Cognito user pool to authenticate users.

- D. Create an Amazon Cognito identity pool to authenticate users.

E. Use AWS Amplify to serve the frontend web content with HTML, CSS, and JS. Use an integrated Amazon CloudFront configuration.

F. Use Amazon S3 static web hosting with PHP, CSS, and JS. Use Amazon CloudFront to serve the frontend web content.

**Correct:** A, C, E
**Why:** Serverless API (API Gateway → Lambda) is cost‑effective for spiky/idle loads; Cognito user pool handles subscription auth; Amplify hosts frontend with integrated CloudFront.

**Incorrect:**
- B: ECS/EC2 PHP or identity pools are unnecessary here.
- D: ECS/EC2 PHP or identity pools are unnecessary here.
- F: ECS/EC2 PHP or identity pools are unnecessary here.


---

---

### Question #547

A company has data collection sensors at different locations. The data collection sensors stream a high volume of data to the company. The company wants to design a platform on AWS to ingest and process high-volume streaming data. The solution must be scalable and support data collection in near real time. The company must store the data in Amazon S3 for future reporting. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use Amazon Kinesis Data Firehose to deliver streaming data to Amazon S3.

- B. Use AWS Glue to deliver streaming data to Amazon S3.

- C. Use AWS Lambda to deliver streaming data and store the data to Amazon S3.

- D. Use AWS Database Migration Service (AWS DMS) to deliver streaming data to Amazon S3.

**Correct:** A
**Why:** Kinesis Data Firehose ingests high‑volume streams and delivers to S3 with near real‑time buffering and minimal ops.

**Incorrect:**
- B: Glue/Lambda/DMS are not the best fit for streaming ingestion at scale.
- C: Glue/Lambda/DMS are not the best fit for streaming ingestion at scale.
- D: Glue/Lambda/DMS are not the best fit for streaming ingestion at scale.


---

---

### Question #550

A company is using AWS Key Management Service (AWS KMS) keys to encrypt AWS Lambda environment variables. A solutions architect needs to ensure that the required permissions are in place to decrypt and use the environment variables. Which steps must the solutions architect take to implement the correct permissions? (Choose two.)

- A. Add AWS KMS permissions in the Lambda resource policy.

- B. Add AWS KMS permissions in the Lambda execution role.

- C. Add AWS KMS permissions in the Lambda function policy.

- D. Allow the Lambda execution role in the AWS KMS key policy.

E. Allow the Lambda resource policy in the AWS KMS key policy.

**Correct:** B, D
**Why:** The Lambda execution role must have KMS permissions, and the KMS key policy must allow that role to use the key for decryption.

**Incorrect:**
- A: Lambda resource/function policies are not where KMS grants are applied; allow the role in the key policy instead.
- C: Lambda resource/function policies are not where KMS grants are applied; allow the role in the key policy instead.
- E: Lambda resource/function policies are not where KMS grants are applied; allow the role in the key policy instead.


---

---

### Question #561

A company's website handles millions of requests each day, and the number of requests continues to increase. A solutions architect needs to improve the response time of the web application. The solutions architect determines that the application needs to decrease latency when retrieving product details from the Amazon DynamoDB table. Which solution will meet these requirements with the LEAST amount of operational overhead?

- A. Set up a DynamoDB Accelerator (DAX) cluster. Route all read requests through DAX.

- B. Set up Amazon ElastiCache for Redis between the DynamoDB table and the web application. Route all read requests through Redis.

- C. Set up Amazon ElastiCache for Memcached between the DynamoDB table and the web application. Route all read requests through Memcached.

- D. Set up Amazon DynamoDB Streams on the table, and have AWS Lambda read from the table and populate Amazon ElastiCache. Route all read requests through ElastiCache.

**Correct:** A
**Why:** DynamoDB Accelerator (DAX) provides microsecond read latency with minimal changes and low operational overhead for read-heavy, latency-sensitive workloads.

**Incorrect:**
- B: ElastiCache layers require cache invalidation strategies and more app changes than DAX for DynamoDB.
- C: ElastiCache layers require cache invalidation strategies and more app changes than DAX for DynamoDB.
- D: Streams + Lambda + ElastiCache is complex and higher overhead.


---

---

### Question #567

A solutions architect is designing a workload that will store hourly energy consumption by business tenants in a building. The sensors will feed a database through HTTP requests that will add up usage for each tenant. The solutions architect must use managed services when possible. The workload will receive more features in the future as the solutions architect adds independent components. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use Amazon API Gateway with AWS Lambda functions to receive the data from the sensors, process the data, and store the data in an Amazon DynamoDB table.

- B. Use an Elastic Load Balancer that is supported by an Auto Scaling group of Amazon EC2 instances to receive and process the data from the sensors. Use an Amazon S3 bucket to store the processed data.

- C. Use Amazon API Gateway with AWS Lambda functions to receive the data from the sensors, process the data, and store the data in a Microsoft SQL Server Express database on an Amazon EC2 instance.

- D. Use an Elastic Load Balancer that is supported by an Auto Scaling group of Amazon EC2 instances to receive and process the data from the sensors. Use an Amazon Elastic File System (Amazon EFS) shared file system to store the processed data.

**Correct:** A
**Why:** API Gateway + Lambda gives a fully managed, serverless, event-driven ingestion and processing path with low overhead and easy future extensibility; store results in DynamoDB.

**Incorrect:**
- B: ELB + EC2 adds operational burden and is not necessary for simple HTTP ingest.
- C: EC2-hosted SQL Server Express increases ops overhead and reduces elasticity.
- D: ELB + EC2 adds operational burden and is not necessary for simple HTTP ingest.


---

---

### Question #571

A company is creating a REST API. The company has strict requirements for the use of TLS. The company requires TLSv1.3 on the API endpoints. The company also requires a specic public third-party certicate authority (CA) to sign the TLS certicate. Which solution will meet these requirements?

- A. Use a local machine to create a certicate that is signed by the third-party CImport the certicate into AWS Certicate Manager (ACM). Create an HTTP API in Amazon API Gateway with a custom domain. Configure the custom domain to use the certicate.

- B. Create a certicate in AWS Certicate Manager (ACM) that is signed by the third-party CA. Create an HTTP API in Amazon API Gateway with a custom domain. Configure the custom domain to use the certicate.

- C. Use AWS Certicate Manager (ACM) to create a certicate that is signed by the third-party CA. Import the certicate into AWS Certicate Manager (ACM). Create an AWS Lambda function with a Lambda function URL. Configure the Lambda function URL to use the certicate.

- D. Create a certicate in AWS Certicate Manager (ACM) that is signed by the third-party CA. Create an AWS Lambda function with a Lambda function URL. Configure the Lambda function URL to use the certicate.

**Correct:** A
**Why:** Import a certificate signed by the required third-party CA into ACM and use it on an API Gateway custom domain. ACM cannot issue third‑party CA certs directly; importing meets the TLS policy needs.

**Incorrect:**
- B: ACM cannot create a certificate that is signed by an external third-party CA; you must import it.
- C: Lambda function URLs cannot use externally issued certs via ACM like this; also not an API endpoint replacement.
- D: Lambda URLs plus ACM do not fulfill the REST API requirement or TLS policy at the edge.


---

---

### Question #573

A company wants to use an event-driven programming model with AWS Lambda. The company wants to reduce startup latency for Lambda functions that run on Java 11. The company does not have strict latency requirements for the applications. The company wants to reduce cold starts and outlier latencies when a function scales up. Which solution will meet these requirements MOST cost-effectively?

- A. Configure Lambda provisioned concurrency.

- B. Increase the timeout of the Lambda functions.

- C. Increase the memory of the Lambda functions.

- D. Configure Lambda SnapStart.

**Correct:** D
**Why:** Lambda SnapStart reduces cold-start latency for Java functions cost‑effectively without the steady cost of provisioned concurrency.

**Incorrect:**
- A: Provisioned concurrency reduces cold starts but costs more continuously.
- B: Increasing timeout does not reduce startup latency.
- C: More memory may improve CPU/throughput but doesn’t fundamentally solve cold-start latency.


---

---

### Question #576

A company is building a RESTful serverless web application on AWS by using Amazon API Gateway and AWS Lambda. The users of this web application will be geographically distributed, and the company wants to reduce the latency of API requests to these users. Which type of endpoint should a solutions architect use to meet these requirements?

- A. Private endpoint

- B. Regional endpoint

- C. Interface VPC endpoint

- D. Edge-optimized endpoint

**Correct:** D
**Why:** Edge-optimized API Gateway endpoints use CloudFront to reduce latency for geographically distributed users.

**Incorrect:**
- A: Private endpoints are for VPC-only access.
- B: Regional endpoints don’t leverage global edge locations.
- C: Interface VPC endpoints are for private access within a VPC, not global latency reduction.


---

---

### Question #579

A company runs an application that uses Amazon RDS for PostgreSQL. The application receives trac only on weekdays during business hours. The company wants to optimize costs and reduce operational overhead based on this usage. Which solution will meet these requirements?

- A. Use the Instance Scheduler on AWS to configure start and stop schedules.

- B. Turn off automatic backups. Create weekly manual snapshots of the database.

- C. Create a custom AWS Lambda function to start and stop the database based on minimum CPU utilization.

- D. Purchase All Upfront reserved DB instances.

**Correct:** A
**Why:** The Instance Scheduler on AWS can start/stop RDS instances on a schedule to reduce cost when idle.

**Incorrect:**
- B: Turning off backups risks data loss and doesn’t optimize running costs.
- C: Custom Lambda adds overhead and brittleness.
- D: Reserved instances charge continuously despite low utilization.


---

---

### Question #587

A company is designing a solution to capture customer activity in different web applications to process analytics and make predictions. Customer activity in the web applications is unpredictable and can increase suddenly. The company requires a solution that integrates with other web applications. The solution must include an authorization step for security purposes. Which solution will meet these requirements?

- A. Configure a Gateway Load Balancer (GWLB) in front of an Amazon Elastic Container Service (Amazon ECS) container instance that stores the information that the company receives in an Amazon Elastic File System (Amazon EFS) file system. Authorization is resolved at the GWLB.

- B. Configure an Amazon API Gateway endpoint in front of an Amazon Kinesis data stream that stores the information that the company receives in an Amazon S3 bucket. Use an AWS Lambda function to resolve authorization.

- C. Configure an Amazon API Gateway endpoint in front of an Amazon Kinesis Data Firehose that stores the information that the company receives in an Amazon S3 bucket. Use an API Gateway Lambda authorizer to resolve authorization.

- D. Configure a Gateway Load Balancer (GWLB) in front of an Amazon Elastic Container Service (Amazon ECS) container instance that stores the information that the company receives on an Amazon Elastic File System (Amazon EFS) file system. Use an AWS Lambda function to resolve authorization.

**Correct:** C
**Why:** API Gateway with a Lambda authorizer provides auth. Kinesis Data Firehose scales ingestion and delivers to S3 with minimal ops overhead.

**Incorrect:**
- A: GWLB + ECS introduces heavy ops complexity for simple event ingestion.
- B: API Gateway to Kinesis Data Streams is viable but requires more scaling/consumer management than Firehose for S3 delivery.
- D: GWLB + ECS introduces heavy ops complexity for simple event ingestion.


---

---

### Question #591

A company runs a container application by using Amazon Elastic Kubernetes Service (Amazon EKS). The application includes microservices that manage customers and place orders. The company needs to route incoming requests to the appropriate microservices. Which solution will meet this requirement MOST cost-effectively?

- A. Use the AWS Load Balancer Controller to provision a Network Load Balancer.

- B. Use the AWS Load Balancer Controller to provision an Application Load Balancer.

- C. Use an AWS Lambda function to connect the requests to Amazon EKS.

- D. Use Amazon API Gateway to connect the requests to Amazon EKS.

**Correct:** B
**Why:** The AWS Load Balancer Controller can provision an ALB for path/host routing to EKS microservices cost‑effectively.

**Incorrect:**
- A: NLB is L4 and not suited for HTTP routing across microservices.
- C: Lambda or API Gateway add unnecessary abstraction and cost.
- D: Lambda or API Gateway add unnecessary abstraction and cost.


---

---

### Question #597

A company hosts an internal serverless application on AWS by using Amazon API Gateway and AWS Lambda. The company’s employees report issues with high latency when they begin using the application each day. The company wants to reduce latency. Which solution will meet these requirements?

- A. Increase the API Gateway throttling limit.

- B. Set up a scheduled scaling to increase Lambda provisioned concurrency before employees begin to use the application each day.

- C. Create an Amazon CloudWatch alarm to initiate a Lambda function as a target for the alarm at the beginning of each day.

- D. Increase the Lambda function memory.

**Correct:** B
**Why:** Schedule provisioned concurrency before users start to eliminate cold starts and reduce latency.

**Incorrect:**
- A: API Gateway throttling limits won’t affect cold starts.
- C: Invoking a warm‑up Lambda is ad‑hoc vs. built‑in provisioned concurrency.
- D: More memory doesn’t eliminate cold starts.


---

---

### Question #600

A company is planning to migrate a TCP-based application into the company's VPC. The application is publicly accessible on a nonstandard TCP port through a hardware appliance in the company's data center. This public endpoint can process up to 3 million requests per second with low latency. The company requires the same level of performance for the new public endpoint in AWS. What should a solutions architect recommend to meet this requirement?

- A. Deploy a Network Load Balancer (NLB). Configure the NLB to be publicly accessible over the TCP port that the application requires.

- B. Deploy an Application Load Balancer (ALB). Configure the ALB to be publicly accessible over the TCP port that the application requires.

- C. Deploy an Amazon CloudFront distribution that listens on the TCP port that the application requires. Use an Application Load Balancer as the origin.

- D. Deploy an Amazon API Gateway API that is congured with the TCP port that the application requires. Configure AWS Lambda functions with provisioned concurrency to process the requests.

**Correct:** A
**Why:** NLB supports millions of requests per second with low latency on arbitrary TCP ports.

**Incorrect:**
- B: ALB is HTTP/HTTPS (L7) and not optimized for raw TCP performance at this scale.
- C: CloudFront/API Gateway do not meet the raw TCP nonstandard port requirement.
- D: CloudFront/API Gateway do not meet the raw TCP nonstandard port requirement.


---

---

### Question #602

A company's infrastructure consists of hundreds of Amazon EC2 instances that use Amazon Elastic Block Store (Amazon EBS) storage. A solutions architect must ensure that every EC2 instance can be recovered after a disaster. What should the solutions architect do to meet this requirement with the LEAST amount of effort?

- A. Take a snapshot of the EBS storage that is attached to each EC2 instance. Create an AWS CloudFormation template to launch new EC2 instances from the EBS storage.

- B. Take a snapshot of the EBS storage that is attached to each EC2 instance. Use AWS Elastic Beanstalk to set the environment based on the EC2 template and attach the EBS storage.

- C. Use AWS Backup to set up a backup plan for the entire group of EC2 instances. Use the AWS Backup API or the AWS CLI to speed up the restore process for multiple EC2 instances.

- D. Create an AWS Lambda function to take a snapshot of the EBS storage that is attached to each EC2 instance and copy the Amazon Machine Images (AMIs). Create another Lambda function to perform the restores with the copied AMIs and attach the EBS storage.

**Correct:** C
**Why:** AWS Backup can centrally back up and restore fleets of EC2/EBS with minimal effort.

**Incorrect:**
- A: Custom snapshots/scripts/Beanstalk add operational complexity.
- B: Custom snapshots/scripts/Beanstalk add operational complexity.
- D: Custom snapshots/scripts/Beanstalk add operational complexity.


---

---

### Question #603

A company recently migrated to the AWS Cloud. The company wants a serverless solution for large-scale parallel on-demand processing of a semistructured dataset. The data consists of logs, media files, sales transactions, and IoT sensor data that is stored in Amazon S3. The company wants the solution to process thousands of items in the dataset in parallel. Which solution will meet these requirements with the MOST operational eciency?

- A. Use the AWS Step Functions Map state in Inline mode to process the data in parallel.

- B. Use the AWS Step Functions Map state in Distributed mode to process the data in parallel.

- C. Use AWS Glue to process the data in parallel.

- D. Use several AWS Lambda functions to process the data in parallel.

**Correct:** B
**Why:** Step Functions Distributed Map processes thousands to millions of items in parallel serverlessly with high efficiency.

**Incorrect:**
- A: Inline Map is limited for large-scale fan‑out.
- C: Glue/Lambda alone are less scalable or require orchestration for very large parallelism.
- D: Glue/Lambda alone are less scalable or require orchestration for very large parallelism.


---

---

### Question #608

A company has an application that serves clients that are deployed in more than 20.000 retail storefront locations around the world. The application consists of backend web services that are exposed over HTTPS on port 443. The application is hosted on Amazon EC2 instances behind an Application Load Balancer (ALB). The retail locations communicate with the web application over the public internet. The company allows each retail location to register the IP address that the retail location has been allocated by its local ISP. The company's security team recommends to increase the security of the application endpoint by restricting access to only the IP addresses registered by the retail locations. What should a solutions architect do to meet these requirements?

- A. Associate an AWS WAF web ACL with the ALB. Use IP rule sets on the ALB to filter trac. Update the IP addresses in the rule to include the registered IP addresses.

- B. Deploy AWS Firewall Manager to manage the ALCongure firewall rules to restrict trac to the ALModify the firewall rules to include the registered IP addresses.

- C. Store the IP addresses in an Amazon DynamoDB table. Configure an AWS Lambda authorization function on the ALB to validate that incoming requests are from the registered IP addresses.

- D. Configure the network ACL on the subnet that contains the public interface of the ALB. Update the ingress rules on the network ACL with entries for each of the registered IP addresses.

**Correct:** A
**Why:** Attach an AWS WAF web ACL to the ALB with IP set rules; update the IP set with registered site IPs to restrict access.

**Incorrect:**
- B: Firewall Manager helps manage WAF across accounts but still relies on WAF/IP sets.
- C: ALB does not support Lambda authorizers; and DynamoDB storage is unnecessary.
- D: Network ACLs are coarse and hard to manage at scale.


---

---

### Question #609

A company is building a data analysis platform on AWS by using AWS Lake Formation. The platform will ingest data from different sources such as Amazon S3 and Amazon RDS. The company needs a secure solution to prevent access to portions of the data that contain sensitive information. Which solution will meet these requirements with the LEAST operational overhead?

- A. Create an IAM role that includes permissions to access Lake Formation tables.

- B. Create data lters to implement row-level security and cell-level security.

- C. Create an AWS Lambda function that removes sensitive information before Lake Formation ingests the data.

- D. Create an AWS Lambda function that periodically queries and removes sensitive information from Lake Formation tables.

**Correct:** B
**Why:** Lake Formation row‑level and cell‑level filters natively enforce fine‑grained access to sensitive data with minimal ops.

**Incorrect:**
- A: IAM role alone cannot implement row/cell security at the table data level.
- C: Lambda preprocessing/postprocessing adds complexity and is brittle.
- D: Lambda preprocessing/postprocessing adds complexity and is brittle.


---

---

### Question #611

A company has an application with a REST-based interface that allows data to be received in near-real time from a third-party vendor. Once received, the application processes and stores the data for further analysis. The application is running on Amazon EC2 instances. The third-party vendor has received many 503 Service Unavailable Errors when sending data to the application. When the data volume spikes, the compute capacity reaches its maximum limit and the application is unable to process all requests. Which design should a solutions architect recommend to provide a more scalable solution?

- A. Use Amazon Kinesis Data Streams to ingest the data. Process the data using AWS Lambda functions.

- B. Use Amazon API Gateway on top of the existing application. Create a usage plan with a quota limit for the third-party vendor.

- C. Use Amazon Simple Notification Service (Amazon SNS) to ingest the data. Put the EC2 instances in an Auto Scaling group behind an Application Load Balancer.

- D. Repackage the application as a container. Deploy the application using Amazon Elastic Container Service (Amazon ECS) using the EC2 launch type with an Auto Scaling group.

**Correct:** A
**Why:** Kinesis Data Streams buffers spikes and decouples producers from consumers; Lambda scales to process without 503s.

**Incorrect:**
- B: API Gateway with quotas throttles the vendor rather than scaling.
- C: SNS is pub/sub and not ideal for high‑throughput buffering + ordering.
- D: ECS on EC2 still faces sudden capacity limits without a buffer.


---

---

### Question #613

A company uses Amazon Elastic Kubernetes Service (Amazon EKS) to run a container application. The EKS cluster stores sensitive information in the Kubernetes secrets object. The company wants to ensure that the information is encrypted. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use the container application to encrypt the information by using AWS Key Management Service (AWS KMS).

- B. Enable secrets encryption in the EKS cluster by using AWS Key Management Service (AWS KMS).

- C. Implement an AWS Lambda function to encrypt the information by using AWS Key Management Service (AWS KMS).

- D. Use AWS Systems Manager Parameter Store to encrypt the information by using AWS Key Management Service (AWS KMS).

**Correct:** B
**Why:** EKS secrets encryption with KMS provides at‑rest encryption for Kubernetes secrets with minimal ops.

**Incorrect:**
- A: App/Lambda encryption adds complexity and key handling.
- C: App/Lambda encryption adds complexity and key handling.
- D: Parameter Store is separate from native K8s secrets management.


---

---

### Question #621

An online photo-sharing company stores its photos in an Amazon S3 bucket that exists in the us-west-1 Region. The company needs to store a copy of all new photos in the us-east-1 Region. Which solution will meet this requirement with the LEAST operational effort?

- A. Create a second S3 bucket in us-east-1. Use S3 Cross-Region Replication to copy photos from the existing S3 bucket to the second S3 bucket.

- B. Create a cross-origin resource sharing (CORS) configuration of the existing S3 bucket. Specify us-east-1 in the CORS rule's AllowedOrigin element.

- C. Create a second S3 bucket in us-east-1 across multiple Availability Zones. Create an S3 Lifecycle rule to save photos into the second S3 bucket.

- D. Create a second S3 bucket in us-east-1. Configure S3 event notications on object creation and update events to invoke an AWS Lambda function to copy photos from the existing S3 bucket to the second S3 bucket.

**Correct:** A
**Why:** S3 Cross‑Region Replication automatically replicates new objects from us‑west‑1 to us‑east‑1 with minimal ops.

**Incorrect:**
- B: CORS is unrelated to replication.
- C: Lifecycle rules do not copy between buckets/Regions.
- D: Lambda copy works but adds unnecessary ops and cost.


---

---

### Question #630

A solutions architect is creating a data processing job that runs once daily and can take up to 2 hours to complete. If the job is interrupted, it has to restart from the beginning. How should the solutions architect address this issue in the MOST cost-effective manner?

- A. Create a script that runs locally on an Amazon EC2 Reserved Instance that is triggered by a cron job.

- B. Create an AWS Lambda function triggered by an Amazon EventBridge scheduled event.

- C. Use an Amazon Elastic Container Service (Amazon ECS) Fargate task triggered by an Amazon EventBridge scheduled event.

- D. Use an Amazon Elastic Container Service (Amazon ECS) task running on Amazon EC2 triggered by an Amazon EventBridge scheduled event.

**Correct:** C
**Why:** ECS Fargate scheduled by EventBridge runs containers up to hours long without managing servers; resilient to interruptions.

**Incorrect:**
- A: A single RI instance is brittle and always on.
- B: Lambda max runtime is insufficient for a 2‑hour job.
- D: ECS on EC2 requires capacity management.


---

---

### Question #635

A company uses Amazon FSx for NetApp ONTAP in its primary AWS Region for CIFS and NFS file shares. Applications that run on Amazon EC2 instances access the file shares. The company needs a storage disaster recovery (DR) solution in a secondary Region. The data that is replicated in the secondary Region needs to be accessed by using the same protocols as the primary Region. Which solution will meet these requirements with the LEAST operational overhead?

- A. Create an AWS Lambda function to copy the data to an Amazon S3 bucket. Replicate the S3 bucket to the secondary Region.

- B. Create a backup of the FSx for ONTAP volumes by using AWS Backup. Copy the volumes to the secondary Region. Create a new FSx for ONTAP instance from the backup.

- C. Create an FSx for ONTAP instance in the secondary Region. Use NetApp SnapMirror to replicate data from the primary Region to the secondary Region.

- D. Create an Amazon Elastic File System (Amazon EFS) volume. Migrate the current data to the volume. Replicate the volume to the secondary Region.

**Correct:** C
**Why:** FSx for NetApp ONTAP supports SMB/NFS; use SnapMirror for cross‑Region replication with the same protocols on failover.

**Incorrect:**
- A: Lambda + S3 is not a file service and loses protocol semantics.
- B: Backup/restore increases RTO and ops.
- D: EFS is NFS only, not SMB.


---

---

### Question #636

A development team is creating an event-based application that uses AWS Lambda functions. Events will be generated when files are added to an Amazon S3 bucket. The development team currently has Amazon Simple Notification Service (Amazon SNS) congured as the event target from Amazon S3. What should a solutions architect do to process the events from Amazon S3 in a scalable way?

- A. Create an SNS subscription that processes the event in Amazon Elastic Container Service (Amazon ECS) before the event runs in Lambda.

- B. Create an SNS subscription that processes the event in Amazon Elastic Kubernetes Service (Amazon EKS) before the event runs in Lambda

- C. Create an SNS subscription that sends the event to Amazon Simple Queue Service (Amazon SQS). Configure the SOS queue to trigger a Lambda function.

- D. Create an SNS subscription that sends the event to AWS Server Migration Service (AWS SMS). Configure the Lambda function to poll from the SMS event.

**Correct:** C
**Why:** Send SNS to SQS, then trigger Lambda from SQS for scalable, durable processing and smoothing spikes.

**Incorrect:**
- A: ECS/EKS add complexity; SNS->Lambda fanout directly may throttle; SQS adds buffering.
- B: ECS/EKS add complexity; SNS->Lambda fanout directly may throttle; SQS adds buffering.
- D: SMS is unrelated.


---

---

### Question #637

A solutions architect is designing a new service behind Amazon API Gateway. The request patterns for the service will be unpredictable and can change suddenly from 0 requests to over 500 per second. The total size of the data that needs to be persisted in a backend database is currently less than 1 GB with unpredictable future growth. Data can be queried using simple key-value requests. Which combination ofAWS services would meet these requirements? (Choose two.)

- A. AWS Fargate

- B. AWS Lambda

- C. Amazon DynamoDB

- D. Amazon EC2 Auto Scaling

E. MySQL-compatible Amazon Aurora

**Correct:** B, C
**Why:** Lambda scales to sudden bursts. DynamoDB provides key‑value storage with <1 GB easily and elastic throughput.

**Incorrect:**
- A: Fargate/ASG/Aurora add ops or are overkill for KB/MB‑scale key‑value.
- D: Fargate/ASG/Aurora add ops or are overkill for KB/MB‑scale key‑value.
- E: Fargate/ASG/Aurora add ops or are overkill for KB/MB‑scale key‑value.


---

---

### Question #638

A company collects and shares research data with the company's employees all over the world. The company wants to collect and store the data in an Amazon S3 bucket and process the data in the AWS Cloud. The company will share the data with the company's employees. The company needs a secure solution in the AWS Cloud that minimizes operational overhead. Which solution will meet these requirements?

- A. Use an AWS Lambda function to create an S3 presigned URL. Instruct employees to use the URL.

- B. Create an IAM user for each employee. Create an IAM policy for each employee to allow S3 access. Instruct employees to use the AWS Management Console.

- C. Create an S3 File Gateway. Create a share for uploading and a share for downloading. Allow employees to mount shares on their local computers to use S3 File Gateway.

- D. Configure AWS Transfer Family SFTP endpoints. Select the custom identity provider options. Use AWS Secrets Manager to manage the user credentials Instruct employees to use Transfer Family.

**Correct:** A
**Why:** Presigned URLs from Lambda provide secure, minimal‑ops upload/download to S3 without managing user accounts or servers.

**Incorrect:**
- B: Per‑employee IAM users add heavy management.
- C: S3 File Gateway is for SMB/NFS; not needed for internet‑scale sharing.
- D: Transfer Family SFTP adds server management and user store overhead.


---

---

### Question #640

A company has an application workow that uses an AWS Lambda function to download and decrypt files from Amazon S3. These files are encrypted using AWS Key Management Service (AWS KMS) keys. A solutions architect needs to design a solution that will ensure the required permissions are set correctly. Which combination of actions accomplish this? (Choose two.)

- A. Attach the kms:decrypt permission to the Lambda function’s resource policy

- B. Grant the decrypt permission for the Lambda IAM role in the KMS key's policy

- C. Grant the decrypt permission for the Lambda resource policy in the KMS key's policy.

- D. Create a new IAM policy with the kms:decrypt permission and attach the policy to the Lambda function.

E. Create a new IAM role with the kms:decrypt permission and attach the execution role to the Lambda function.

**Correct:** B, E
**Why:** Allow the Lambda execution role in the KMS key policy and ensure the function uses an execution role with kms:Decrypt.

**Incorrect:**
- A: Lambda resource policies do not grant KMS decrypt permissions.
- C: Lambda resource policies do not grant KMS decrypt permissions.
- D: Policies attach to roles; attach to the function’s role, not the function object.


---

---

### Question #653

A company maintains an Amazon RDS database that maps users to cost centers. The company has accounts in an organization in AWS Organizations. The company needs a solution that will tag all resources that are created in a specic AWS account in the organization. The solution must tag each resource with the cost center ID of the user who created the resource. Which solution will meet these requirements?

- A. Move the specic AWS account to a new organizational unit (OU) in Organizations from the management account. Create a service control policy (SCP) that requires all existing resources to have the correct cost center tag before the resources are created. Apply the SCP to the new OU.

- B. Create an AWS Lambda function to tag the resources after the Lambda function looks up the appropriate cost center from the RDS database. Configure an Amazon EventBridge rule that reacts to AWS CloudTrail events to invoke the Lambda function.

- C. Create an AWS CloudFormation stack to deploy an AWS Lambda function. Configure the Lambda function to look up the appropriate cost center from the RDS database and to tag resources. Create an Amazon EventBridge scheduled rule to invoke the CloudFormation stack.

- D. Create an AWS Lambda function to tag the resources with a default value. Configure an Amazon EventBridge rule that reacts to AWS CloudTrail events to invoke the Lambda function when a resource is missing the cost center tag.

**Correct:** B
**Why:** Use EventBridge (CloudTrail events) to invoke Lambda that tags new resources after looking up the creator’s cost center in RDS.

**Incorrect:**
- A: SCPs cannot inject tags pre‑creation; they can only allow/deny.
- C: Re‑deploying a stack on a schedule won’t tag arbitrary resources created outside CloudFormation.
- D: Default tags without lookup won’t meet correctness.


---

---

### Question #654

A company recently migrated its web application to the AWS Cloud. The company uses an Amazon EC2 instance to run multiple processes to host the application. The processes include an Apache web server that serves static content. The Apache web server makes requests to a PHP application that uses a local Redis server for user sessions. The company wants to redesign the architecture to be highly available and to use AWS managed solutions. Which solution will meet these requirements?

- A. Use AWS Elastic Beanstalk to host the static content and the PHP application. Configure Elastic Beanstalk to deploy its EC2 instance into a public subnet. Assign a public IP address.

- B. Use AWS Lambda to host the static content and the PHP application. Use an Amazon API Gateway REST API to proxy requests to the Lambda function. Set the API Gateway CORS configuration to respond to the domain name. Configure Amazon ElastiCache for Redis to handle session information.

- C. Keep the backend code on the EC2 instance. Create an Amazon ElastiCache for Redis cluster that has Multi-AZ enabled. Configure the ElastiCache for Redis cluster in cluster mode. Copy the frontend resources to Amazon S3. Configure the backend code to reference the EC2 instance.

- D. Configure an Amazon CloudFront distribution with an Amazon S3 endpoint to an S3 bucket that is congured to host the static content. Configure an Application Load Balancer that targets an Amazon Elastic Container Service (Amazon ECS) service that runs AWS Fargate tasks for the PHP application. Configure the PHP application to use an Amazon ElastiCache for Redis cluster that runs in multiple Availability Zones.

**Correct:** D
**Why:** S3 + CloudFront for static assets; ECS Fargate behind ALB for PHP app; Redis (Multi‑AZ) for sessions meets HA with managed services.

**Incorrect:**
- A: Single EC2 in public subnet is not HA.
- B: Lambda for PHP monolith adds complexity and cold‑start concerns.
- C: Keeping backend on EC2 is not fully managed/HA.


---

---

### Question #657

A company has multiple AWS accounts in an organization in AWS Organizations that different business units use. The company has multiple oces around the world. The company needs to update security group rules to allow new oce CIDR ranges or to remove old CIDR ranges across the organization. The company wants to centralize the management of security group rules to minimize the administrative overhead that updating CIDR ranges requires. Which solution will meet these requirements MOST cost-effectively?

- A. Create VPC security groups in the organization's management account. Update the security groups when a CIDR range update is necessary.

- B. Create a VPC customer managed prex list that contains the list of CIDRs. Use AWS Resource Access Manager (AWS RAM) to share the prex list across the organization. Use the prex list in the security groups across the organization.

- C. Create an AWS managed prex list. Use an AWS Security Hub policy to enforce the security group update across the organization. Use an AWS Lambda function to update the prex list automatically when the CIDR ranges change.

- D. Create security groups in a central administrative AWS account. Create an AWS Firewall Manager common security group policy for the whole organization. Select the previously created security groups as primary groups in the policy.

**Correct:** B
**Why:** Create and share a VPC prefix list via RAM and reference it in security groups; update once to propagate across accounts.

**Incorrect:**
- A: Central SGs in one account don’t propagate automatically.
- C: No such AWS managed prefix list for office CIDRs with auto updates.
- D: Firewall Manager SG policies don’t centrally update IPs without a shared prefix list.


---

---

### Question #661

A company runs applications on AWS that connect to the company's Amazon RDS database. The applications scale on weekends and at peak times of the year. The company wants to scale the database more effectively for its applications that connect to the database. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use Amazon DynamoDB with connection pooling with a target group configuration for the database. Change the applications to use the DynamoDB endpoint.

- B. Use Amazon RDS Proxy with a target group for the database. Change the applications to use the RDS Proxy endpoint.

- C. Use a custom proxy that runs on Amazon EC2 as an intermediary to the database. Change the applications to use the custom proxy endpoint.

- D. Use an AWS Lambda function to provide connection pooling with a target group configuration for the database. Change the applications to use the Lambda function.

**Correct:** B
**Why:** RDS Proxy pools and shares DB connections, improving scalability during surges with minimal app changes.

**Incorrect:**
- A: DynamoDB/Lambda are unrelated to SQL connection pooling.
- C: Custom proxy increases ops burden.
- D: DynamoDB/Lambda are unrelated to SQL connection pooling.


---

---

### Question #669

A company runs its databases on Amazon RDS for PostgreSQL. The company wants a secure solution to manage the master user password by rotating the password every 30 days. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use Amazon EventBridge to schedule a custom AWS Lambda function to rotate the password every 30 days.

- B. Use the modify-db-instance command in the AWS CLI to change the password.

- C. Integrate AWS Secrets Manager with Amazon RDS for PostgreSQL to automate password rotation.

- D. Integrate AWS Systems Manager Parameter Store with Amazon RDS for PostgreSQL to automate password rotation.

**Correct:** C
**Why:** Secrets Manager integrates with RDS to automatically rotate the master password on a schedule with minimal ops.

**Incorrect:**
- A: Custom Lambda is more work.
- B: CLI changes are manual and error‑prone.
- D: Parameter Store lacks built‑in rotation for RDS master passwords.


---

---

### Question #680

A solutions architect needs to copy files from an Amazon S3 bucket to an Amazon Elastic File System (Amazon EFS) file system and another S3 bucket. The files must be copied continuously. New files are added to the original S3 bucket consistently. The copied files should be overwritten only if the source file changes. Which solution will meet these requirements with the LEAST operational overhead?

- A. Create an AWS DataSync location for both the destination S3 bucket and the EFS file system. Create a task for the destination S3 bucket and the EFS file system. Set the transfer mode to transfer only data that has changed.

- B. Create an AWS Lambda function. Mount the file system to the function. Set up an S3 event notification to invoke the function when files are created and changed in Amazon S3. Configure the function to copy files to the file system and the destination S3 bucket.

- C. Create an AWS DataSync location for both the destination S3 bucket and the EFS file system. Create a task for the destination S3 bucket and the EFS file system. Set the transfer mode to transfer all data.

- D. Launch an Amazon EC2 instance in the same VPC as the file system. Mount the file system. Create a script to routinely synchronize all objects that changed in the origin S3 bucket to the destination S3 bucket and the mounted file system.

**Correct:** A
**Why:** AWS DataSync supports continuous copies S3→S3 and S3→EFS with change‑only transfers, minimizing overhead and avoiding unnecessary overwrites.

**Incorrect:**
- B: Lambda + mount is complex and not ideal for continuous, scalable sync.
- C: Transfer all data is inefficient and increases costs.
- D: EC2 + scripts adds ops and reliability risks.


---

---

### Question #682

A company needs a solution to enforce data encryption at rest on Amazon EC2 instances. The solution must automatically identify noncompliant resources and enforce compliance policies on ndings. Which solution will meet these requirements with the LEAST administrative overhead?

- A. Use an IAM policy that allows users to create only encrypted Amazon Elastic Block Store (Amazon EBS) volumes. Use AWS Cong and AWS Systems Manager to automate the detection and remediation of unencrypted EBS volumes.

- B. Use AWS Key Management Service (AWS KMS) to manage access to encrypted Amazon Elastic Block Store (Amazon EBS) volumes. Use AWS Lambda and Amazon EventBridge to automate the detection and remediation of unencrypted EBS volumes.

- C. Use Amazon Macie to detect unencrypted Amazon Elastic Block Store (Amazon EBS) volumes. Use AWS Systems Manager Automation rules to automatically encrypt existing and new EBS volumes.

- D. Use Amazon inspector to detect unencrypted Amazon Elastic Block Store (Amazon EBS) volumes. Use AWS Systems Manager Automation rules to automatically encrypt existing and new EBS volumes.

**Correct:** A
**Why:** Enforce encrypted EBS creation via IAM, and use AWS Config with Systems Manager Automation to detect and remediate unencrypted volumes automatically.

**Incorrect:**
- B: Lambda + EventBridge is more custom ops; KMS alone doesn’t enforce encryption.
- C: Macie/Inspector do not detect EBS encryption compliance.
- D: Macie/Inspector do not detect EBS encryption compliance.


---

---

### Question #683

A company is migrating its multi-tier on-premises application to AWS. The application consists of a single-node MySQL database and a multi-node web tier. The company must minimize changes to the application during the migration. The company wants to improve application resiliency after the migration. Which combination of steps will meet these requirements? (Choose two.)

- A. Migrate the web tier to Amazon EC2 instances in an Auto Scaling group behind an Application Load Balancer.

- B. Migrate the database to Amazon EC2 instances in an Auto Scaling group behind a Network Load Balancer.

- C. Migrate the database to an Amazon RDS Multi-AZ deployment.

- D. Migrate the web tier to an AWS Lambda function.

E. Migrate the database to an Amazon DynamoDB table.

**Correct:** A, C
**Why:** Move the web tier behind an ALB with Auto Scaling for resiliency, and migrate the DB to RDS Multi‑AZ for high availability with minimal app changes.

**Incorrect:**
- B: EC2 DB on NLB is self‑managed and higher ops.
- D: Lambda/DynamoDB require major app changes.
- E: Lambda/DynamoDB require major app changes.


---

## AWS Organizations / IAM Identity Center (SSO)

### Question #512

A company uses AWS Organizations with resources tagged by account. The company also uses AWS Backup to back up its AWS infrastructure resources. The company needs to back up all AWS resources. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use AWS Cong to identify all untagged resources. Tag the identied resources programmatically. Use tags in the backup plan.

- B. Use AWS Cong to identify all resources that are not running. Add those resources to the backup vault.

- C. Require all AWS account owners to review their resources to identify the resources that need to be backed up.

- D. Use Amazon Inspector to identify all noncompliant resources.

**Correct:** A
**Why:** Use AWS Config to find untagged resources and tag them programmatically so tag‑based AWS Backup plans cover all resources.

**Incorrect:**
- B: Not aligned with comprehensive, automated backups.
- C: Not aligned with comprehensive, automated backups.
- D: Not aligned with comprehensive, automated backups.


---

---

### Question #521

A retail company has several businesses. The IT team for each business manages its own AWS account. Each team account is part of an organization in AWS Organizations. Each team monitors its product inventory levels in an Amazon DynamoDB table in the team's own AWS account. The company is deploying a central inventory reporting application into a shared AWS account. The application must be able to read items from all the teams' DynamoDB tables. Which authentication option will meet these requirements MOST securely?

- A. Integrate DynamoDB with AWS Secrets Manager in the inventory application account. Configure the application to use the correct secret from Secrets Manager to authenticate and read the DynamoDB table. Schedule secret rotation for every 30 days.

- B. In every business account, create an IAM user that has programmatic access. Configure the application to use the correct IAM user access key ID and secret access key to authenticate and read the DynamoDB table. Manually rotate IAM access keys every 30 days.

- C. In every business account, create an IAM role named BU_ROLE with a policy that gives the role access to the DynamoDB table and a trust policy to trust a specic role in the inventory application account. In the inventory account, create a role named APP_ROLE that allows access to the STS AssumeRole API operation. Configure the application to use APP_ROLE and assume the crossaccount role BU_ROLE to read the DynamoDB table.

- D. Integrate DynamoDB with AWS Certicate Manager (ACM). Generate identity certicates to authenticate DynamoDB. Configure the application to use the correct certicate to authenticate and read the DynamoDB table.

**Correct:** C
**Why:** Cross‑account role assumption (STS AssumeRole) is the most secure way to access each account’s DynamoDB table.

**Incorrect:**
- A: Long‑lived credentials or ACM are not appropriate.
- B: Long‑lived credentials or ACM are not appropriate.
- D: Long‑lived credentials or ACM are not appropriate.


---

---

### Question #543

A company runs Amazon EC2 instances in multiple AWS accounts that are individually bled. The company recently purchased a Savings Pian. Because of changes in the company’s business requirements, the company has decommissioned a large number of EC2 instances. The company wants to use its Savings Plan discounts on its other AWS accounts. Which combination of steps will meet these requirements? (Choose two.)

- A. From the AWS Account Management Console of the management account, turn on discount sharing from the billing preferences section.

- B. From the AWS Account Management Console of the account that purchased the existing Savings Plan, turn on discount sharing from the billing preferences section. Include all accounts.

- C. From the AWS Organizations management account, use AWS Resource Access Manager (AWS RAM) to share the Savings Plan with other accounts.

- D. Create an organization in AWS Organizations in a new payer account. Invite the other AWS accounts to join the organization from the management account.

E. Create an organization in AWS Organizations in the existing AWS account with the existing EC2 instances and Savings Plan. Invite the other AWS accounts to join the organization from the management account.

**Correct:** A, E
**Why:** Turn on discount sharing in the management account and place accounts under one Organization so Savings Plan discounts can float.

**Incorrect:**
- B: Enabling in a member account, RAM sharing, or moving to a new payer account is not required.
- C: Enabling in a member account, RAM sharing, or moving to a new payer account is not required.
- D: Enabling in a member account, RAM sharing, or moving to a new payer account is not required.


---

---

### Question #548

A company has separate AWS accounts for its nance, data analytics, and development departments. Because of costs and security concerns, the company wants to control which services each AWS account can use. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use AWS Systems Manager templates to control which AWS services each department can use.

- B. Create organization units (OUs) for each department in AWS Organizations. Attach service control policies (SCPs) to the OUs.

- C. Use AWS CloudFormation to automatically provision only the AWS services that each department can use.

- D. Set up a list of products in AWS Service Catalog in the AWS accounts to manage and control the usage of specic AWS services.

**Correct:** B
**Why:** Use Organizations OUs with SCPs to centrally control which services accounts can use.

**Incorrect:**
- A: Systems Manager/CloudFormation/Service Catalog are not primary service blockers.
- C: Systems Manager/CloudFormation/Service Catalog are not primary service blockers.
- D: Systems Manager/CloudFormation/Service Catalog are not primary service blockers.


---

---

### Question #559

A company hosts multiple applications on AWS for different product lines. The applications use different compute resources, including Amazon EC2 instances and Application Load Balancers. The applications run in different AWS accounts under the same organization in AWS Organizations across multiple AWS Regions. Teams for each product line have tagged each compute resource in the individual accounts. The company wants more details about the cost for each product line from the consolidated billing feature in Organizations. Which combination of steps will meet these requirements? (Choose two.)

- A. Select a specic AWS generated tag in the AWS Billing console.

- B. Select a specic user-dened tag in the AWS Billing console.

- C. Select a specic user-dened tag in the AWS Resource Groups console.

- D. Activate the selected tag from each AWS account.

E. Activate the selected tag from the Organizations management account.

**Correct:** B, E
**Why:** Use a specific user-defined cost allocation tag and activate it in the AWS Billing console of the Organizations management (payer) account to surface costs by tag across linked accounts.

**Incorrect:**
- A: AWS-generated tags are limited in usefulness and not aligned to product lines.
- C: Resource Groups is not where cost allocation tags are activated for billing.
- D: Tag activation for consolidated billing is performed in the management account, not individually in each member account.


---

---

### Question #560

A company's solutions architect is designing an AWS multi-account solution that uses AWS Organizations. The solutions architect has organized the company's accounts into organizational units (OUs). The solutions architect needs a solution that will identify any changes to the OU hierarchy. The solution also needs to notify the company's operations team of any changes. Which solution will meet these requirements with the LEAST operational overhead?

- A. Provision the AWS accounts by using AWS Control Tower. Use account drift notications to identify the changes to the OU hierarchy.

- B. Provision the AWS accounts by using AWS Control Tower. Use AWS Cong aggregated rules to identify the changes to the OU hierarchy.

- C. Use AWS Service Catalog to create accounts in Organizations. Use an AWS CloudTrail organization trail to identify the changes to the OU hierarchy.

- D. Use AWS CloudFormation templates to create accounts in Organizations. Use the drift detection operation on a stack to identify the changes to the OU hierarchy.

**Correct:** C
**Why:** An organization trail in AWS CloudTrail records changes to AWS Organizations (including OU hierarchy). Pairing account creation via Service Catalog is incidental; the key is CloudTrail org trail plus notifications for changes.

**Incorrect:**
- A: Control Tower drift notifications relate to account/VPC baselines, not specifically OU hierarchy changes.
- B: AWS Config rules don’t natively report OU hierarchy changes; CloudTrail does.
- D: CloudFormation drift detection applies to stacks, not Organizations OU structure.


---

---

### Question #586

A company has ve organizational units (OUs) as part of its organization in AWS Organizations. Each OU correlates to the ve businesses that the company owns. The company's research and development (R&D) business is separating from the company and will need its own organization. A solutions architect creates a separate new management account for this purpose. What should the solutions architect do next in the new management account?

- A. Have the R&D AWS account be part of both organizations during the transition.

- B. Invite the R&D AWS account to be part of the new organization after the R&D AWS account has left the prior organization.

- C. Create a new R&D AWS account in the new organization. Migrate resources from the prior R&D AWS account to the new R&D AWS account.

- D. Have the R&D AWS account join the new organization. Make the new management account a member of the prior organization.

**Correct:** B
**Why:** Accounts can join a new organization only after leaving the previous one; then invite the R&D account to the new organization.

**Incorrect:**
- A: An account cannot belong to two organizations simultaneously.
- C: Creating a new account and migrating resources is unnecessary overhead.
- D: A management account cannot be a member of another organization.


---

---

### Question #619

A solutions architect is designing a security solution for a company that wants to provide developers with individual AWS accounts through AWS Organizations, while also maintaining standard security controls. Because the individual developers will have AWS account root user-level access to their own accounts, the solutions architect wants to ensure that the mandatory AWS CloudTrail configuration that is applied to new developer accounts is not modied. Which action meets these requirements?

- A. Create an IAM policy that prohibits changes to CloudTrail. and attach it to the root user.

- B. Create a new trail in CloudTrail from within the developer accounts with the organization trails option enabled.

- C. Create a service control policy (SCP) that prohibits changes to CloudTrail, and attach it the developer accounts.

- D. Create a service-linked role for CloudTrail with a policy condition that allows changes only from an Amazon Resource Name (ARN) in the management account.

**Correct:** C
**Why:** An SCP can deny CloudTrail modifications across developer accounts, even for root, preserving mandatory settings.

**Incorrect:**
- A: You cannot attach IAM policies to root, and IAM can be bypassed by root.
- B: Trails created within accounts can still be altered without an SCP guardrail.
- D: Service‑linked roles don’t enforce org‑level immutability.


---

---

### Question #628

A global company runs its applications in multiple AWS accounts in AWS Organizations. The company's applications use multipart uploads to upload data to multiple Amazon S3 buckets across AWS Regions. The company wants to report on incomplete multipart uploads for cost compliance purposes. Which solution will meet these requirements with the LEAST operational overhead?

- A. Configure AWS Cong with a rule to report the incomplete multipart upload object count.

- B. Create a service control policy (SCP) to report the incomplete multipart upload object count.

- C. Configure S3 Storage Lens to report the incomplete multipart upload object count.

- D. Create an S3 Multi-Region Access Point to report the incomplete multipart upload object count.

**Correct:** C
**Why:** S3 Storage Lens provides org‑wide visibility, including incomplete multipart upload metrics, with minimal ops.

**Incorrect:**
- A: Config/SCP/Multi‑Region Access Point do not report incomplete MPU counts.
- B: Config/SCP/Multi‑Region Access Point do not report incomplete MPU counts.
- D: Config/SCP/Multi‑Region Access Point do not report incomplete MPU counts.


---

---

### Question #641

A company wants to monitor its AWS costs for nancial review. The cloud operations team is designing an architecture in the AWS Organizations management account to query AWS Cost and Usage Reports for all member accounts. The team must run this query once a month and provide a detailed analysis of the bill. Which solution is the MOST scalable and cost-effective way to meet these requirements?

- A. Enable Cost and Usage Reports in the management account. Deliver reports to Amazon Kinesis. Use Amazon EMR for analysis.

- B. Enable Cost and Usage Reports in the management account. Deliver the reports to Amazon S3 Use Amazon Athena for analysis.

- C. Enable Cost and Usage Reports for member accounts. Deliver the reports to Amazon S3 Use Amazon Redshift for analysis.

- D. Enable Cost and Usage Reports for member accounts. Deliver the reports to Amazon Kinesis. Use Amazon QuickSight tor analysis.

**Correct:** B
**Why:** CUR to S3 + Athena provides scalable, low‑cost monthly querying across member accounts from the management account.

**Incorrect:**
- A: Kinesis/QuickSight not needed; CUR+Athena is simpler/cheaper.
- C: Enabling CUR per member is unnecessary; centralize in management.
- D: Kinesis/QuickSight not needed; CUR+Athena is simpler/cheaper.


---

---

### Question #653

A company maintains an Amazon RDS database that maps users to cost centers. The company has accounts in an organization in AWS Organizations. The company needs a solution that will tag all resources that are created in a specic AWS account in the organization. The solution must tag each resource with the cost center ID of the user who created the resource. Which solution will meet these requirements?

- A. Move the specic AWS account to a new organizational unit (OU) in Organizations from the management account. Create a service control policy (SCP) that requires all existing resources to have the correct cost center tag before the resources are created. Apply the SCP to the new OU.

- B. Create an AWS Lambda function to tag the resources after the Lambda function looks up the appropriate cost center from the RDS database. Configure an Amazon EventBridge rule that reacts to AWS CloudTrail events to invoke the Lambda function.

- C. Create an AWS CloudFormation stack to deploy an AWS Lambda function. Configure the Lambda function to look up the appropriate cost center from the RDS database and to tag resources. Create an Amazon EventBridge scheduled rule to invoke the CloudFormation stack.

- D. Create an AWS Lambda function to tag the resources with a default value. Configure an Amazon EventBridge rule that reacts to AWS CloudTrail events to invoke the Lambda function when a resource is missing the cost center tag.

**Correct:** B
**Why:** Use EventBridge (CloudTrail events) to invoke Lambda that tags new resources after looking up the creator’s cost center in RDS.

**Incorrect:**
- A: SCPs cannot inject tags pre‑creation; they can only allow/deny.
- C: Re‑deploying a stack on a schedule won’t tag arbitrary resources created outside CloudFormation.
- D: Default tags without lookup won’t meet correctness.


---

---

### Question #657

A company has multiple AWS accounts in an organization in AWS Organizations that different business units use. The company has multiple oces around the world. The company needs to update security group rules to allow new oce CIDR ranges or to remove old CIDR ranges across the organization. The company wants to centralize the management of security group rules to minimize the administrative overhead that updating CIDR ranges requires. Which solution will meet these requirements MOST cost-effectively?

- A. Create VPC security groups in the organization's management account. Update the security groups when a CIDR range update is necessary.

- B. Create a VPC customer managed prex list that contains the list of CIDRs. Use AWS Resource Access Manager (AWS RAM) to share the prex list across the organization. Use the prex list in the security groups across the organization.

- C. Create an AWS managed prex list. Use an AWS Security Hub policy to enforce the security group update across the organization. Use an AWS Lambda function to update the prex list automatically when the CIDR ranges change.

- D. Create security groups in a central administrative AWS account. Create an AWS Firewall Manager common security group policy for the whole organization. Select the previously created security groups as primary groups in the policy.

**Correct:** B
**Why:** Create and share a VPC prefix list via RAM and reference it in security groups; update once to propagate across accounts.

**Incorrect:**
- A: Central SGs in one account don’t propagate automatically.
- C: No such AWS managed prefix list for office CIDRs with auto updates.
- D: Firewall Manager SG policies don’t centrally update IPs without a shared prefix list.


---

---

### Question #665

A company has customers located across the world. The company wants to use automation to secure its systems and network infrastructure. The company's security team must be able to track and audit all incremental changes to the infrastructure. Which solution will meet these requirements?

- A. Use AWS Organizations to set up the infrastructure. Use AWS Cong to track changes.

- B. Use AWS CloudFormation to set up the infrastructure. Use AWS Cong to track changes.

- C. Use AWS Organizations to set up the infrastructure. Use AWS Service Catalog to track changes.

- D. Use AWS CloudFormation to set up the infrastructure. Use AWS Service Catalog to track changes.

**Correct:** B
**Why:** CloudFormation provides IaC for automated builds; AWS Config tracks and audits incremental configuration changes.

**Incorrect:**
- A: Organizations/Service Catalog don’t audit infra changes like Config does.
- C: Organizations/Service Catalog don’t audit infra changes like Config does.
- D: Organizations/Service Catalog don’t audit infra changes like Config does.


---

---

### Question #668

A company created a new organization in AWS Organizations. The organization has multiple accounts for the company's development teams. The development team members use AWS IAM Identity Center (AWS Single Sign-On) to access the accounts. For each of the company's applications, the development teams must use a predened application name to tag resources that are created. A solutions architect needs to design a solution that gives the development team the ability to create resources only if the application name tag has an approved value. Which solution will meet these requirements?

- A. Create an IAM group that has a conditional Allow policy that requires the application name tag to be specied for resources to be created.

- B. Create a cross-account role that has a Deny policy for any resource that has the application name tag.

- C. Create a resource group in AWS Resource Groups to validate that the tags are applied to all resources in all accounts.

- D. Create a tag policy in Organizations that has a list of allowed application names.

**Correct:** D
**Why:** Tag policies in Organizations define allowed values and enforce tag compliance across accounts.

**Incorrect:**
- A: IAM policies can’t enforce allowed tag values at org scale.
- B: Denying any resource with the tag is the opposite of the requirement.
- C: Resource Groups doesn’t enforce creation constraints.


---

## AWS Secrets Manager

### Question #521

A retail company has several businesses. The IT team for each business manages its own AWS account. Each team account is part of an organization in AWS Organizations. Each team monitors its product inventory levels in an Amazon DynamoDB table in the team's own AWS account. The company is deploying a central inventory reporting application into a shared AWS account. The application must be able to read items from all the teams' DynamoDB tables. Which authentication option will meet these requirements MOST securely?

- A. Integrate DynamoDB with AWS Secrets Manager in the inventory application account. Configure the application to use the correct secret from Secrets Manager to authenticate and read the DynamoDB table. Schedule secret rotation for every 30 days.

- B. In every business account, create an IAM user that has programmatic access. Configure the application to use the correct IAM user access key ID and secret access key to authenticate and read the DynamoDB table. Manually rotate IAM access keys every 30 days.

- C. In every business account, create an IAM role named BU_ROLE with a policy that gives the role access to the DynamoDB table and a trust policy to trust a specic role in the inventory application account. In the inventory account, create a role named APP_ROLE that allows access to the STS AssumeRole API operation. Configure the application to use APP_ROLE and assume the crossaccount role BU_ROLE to read the DynamoDB table.

- D. Integrate DynamoDB with AWS Certicate Manager (ACM). Generate identity certicates to authenticate DynamoDB. Configure the application to use the correct certicate to authenticate and read the DynamoDB table.

**Correct:** C
**Why:** Cross‑account role assumption (STS AssumeRole) is the most secure way to access each account’s DynamoDB table.

**Incorrect:**
- A: Long‑lived credentials or ACM are not appropriate.
- B: Long‑lived credentials or ACM are not appropriate.
- D: Long‑lived credentials or ACM are not appropriate.


---

---

### Question #535

A company is building an Amazon Elastic Kubernetes Service (Amazon EKS) cluster for its workloads. All secrets that are stored in Amazon EKS must be encrypted in the Kubernetes etcd key-value store. Which solution will meet these requirements?

- A. Create a new AWS Key Management Service (AWS KMS) key. Use AWS Secrets Manager to manage, rotate, and store all secrets in Amazon EKS.

- B. Create a new AWS Key Management Service (AWS KMS) key. Enable Amazon EKS KMS secrets encryption on the Amazon EKS cluster.

- C. Create the Amazon EKS cluster with default options. Use the Amazon Elastic Block Store (Amazon EBS) Container Storage Interface (CSI) driver as an add-on.

- D. Create a new AWS Key Management Service (AWS KMS) key with the alias/aws/ebs alias. Enable default Amazon Elastic Block Store (Amazon EBS) volume encryption for the account.

**Correct:** B
**Why:** Enable EKS KMS secrets encryption with a customer KMS key to encrypt Kubernetes secrets in etcd.

**Incorrect:**
- A: Secrets Manager/EBS encryption don’t encrypt etcd secrets by default.
- C: Secrets Manager/EBS encryption don’t encrypt etcd secrets by default.
- D: Secrets Manager/EBS encryption don’t encrypt etcd secrets by default.


---

---

### Question #638

A company collects and shares research data with the company's employees all over the world. The company wants to collect and store the data in an Amazon S3 bucket and process the data in the AWS Cloud. The company will share the data with the company's employees. The company needs a secure solution in the AWS Cloud that minimizes operational overhead. Which solution will meet these requirements?

- A. Use an AWS Lambda function to create an S3 presigned URL. Instruct employees to use the URL.

- B. Create an IAM user for each employee. Create an IAM policy for each employee to allow S3 access. Instruct employees to use the AWS Management Console.

- C. Create an S3 File Gateway. Create a share for uploading and a share for downloading. Allow employees to mount shares on their local computers to use S3 File Gateway.

- D. Configure AWS Transfer Family SFTP endpoints. Select the custom identity provider options. Use AWS Secrets Manager to manage the user credentials Instruct employees to use Transfer Family.

**Correct:** A
**Why:** Presigned URLs from Lambda provide secure, minimal‑ops upload/download to S3 without managing user accounts or servers.

**Incorrect:**
- B: Per‑employee IAM users add heavy management.
- C: S3 File Gateway is for SMB/NFS; not needed for internet‑scale sharing.
- D: Transfer Family SFTP adds server management and user store overhead.


---

---

### Question #669

A company runs its databases on Amazon RDS for PostgreSQL. The company wants a secure solution to manage the master user password by rotating the password every 30 days. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use Amazon EventBridge to schedule a custom AWS Lambda function to rotate the password every 30 days.

- B. Use the modify-db-instance command in the AWS CLI to change the password.

- C. Integrate AWS Secrets Manager with Amazon RDS for PostgreSQL to automate password rotation.

- D. Integrate AWS Systems Manager Parameter Store with Amazon RDS for PostgreSQL to automate password rotation.

**Correct:** C
**Why:** Secrets Manager integrates with RDS to automatically rotate the master password on a schedule with minimal ops.

**Incorrect:**
- A: Custom Lambda is more work.
- B: CLI changes are manual and error‑prone.
- D: Parameter Store lacks built‑in rotation for RDS master passwords.


---

## AWS Snow Family

### Question #583

A company has 5 PB of archived data on physical tapes. The company needs to preserve the data on the tapes for another 10 years for compliance purposes. The company wants to migrate to AWS in the next 6 months. The data center that stores the tapes has a 1 Gbps uplink internet connectivity. Which solution will meet these requirements MOST cost-effectively?

- A. Read the data from the tapes on premises. Stage the data in a local NFS storage. Use AWS DataSync to migrate the data to Amazon S3 Glacier Flexible Retrieval.

- B. Use an on-premises backup application to read the data from the tapes and to write directly to Amazon S3 Glacier Deep Archive.

- C. Order multiple AWS Snowball devices that have Tape Gateway. Copy the physical tapes to virtual tapes in Snowball. Ship the Snowball devices to AWS. Create a lifecycle policy to move the tapes to Amazon S3 Glacier Deep Archive.

- D. Configure an on-premises Tape Gateway. Create virtual tapes in the AWS Cloud. Use backup software to copy the physical tape to the virtual tape.

**Correct:** C
**Why:** Use Snowball devices with Tape Gateway to migrate physical tapes to virtual tapes, then lifecycle to S3 Glacier Deep Archive for long-term retention and low cost.

**Incorrect:**
- A: 1 Gbps link and 5 PB over 6 months is impractical and costly.
- B: Direct write to Deep Archive over the network is too slow for 5 PB.
- D: On-premises Tape Gateway alone over 1 Gbps is time‑prohibitive for 5 PB.


---

---

### Question #604

A company will migrate 10 PB of data to Amazon S3 in 6 weeks. The current data center has a 500 Mbps uplink to the internet. Other on-premises applications share the uplink. The company can use 80% of the internet bandwidth for this one-time migration task. Which solution will meet these requirements?

- A. Configure AWS DataSync to migrate the data to Amazon S3 and to automatically verify the data.

- B. Use rsync to transfer the data directly to Amazon S3.

- C. Use the AWS CLI and multiple copy processes to send the data directly to Amazon S3.

- D. Order multiple AWS Snowball devices. Copy the data to the devices. Send the devices to AWS to copy the data to Amazon S3.

**Correct:** D
**Why:** With 500 Mbps and shared bandwidth, 10 PB in 6 weeks is infeasible over network; Snowball provides the needed data transfer speed.

**Incorrect:**
- A: Network transfer would not meet the timeline and could disrupt other apps.
- B: Network transfer would not meet the timeline and could disrupt other apps.
- C: Network transfer would not meet the timeline and could disrupt other apps.


---

---

### Question #626

A company stores its data on premises. The amount of data is growing beyond the company's available capacity. The company wants to migrate its data from the on-premises location to an Amazon S3 bucket. The company needs a solution that will automatically validate the integrity of the data after the transfer. Which solution will meet these requirements?

- A. Order an AWS Snowball Edge device. Configure the Snowball Edge device to perform the online data transfer to an S3 bucket

- B. Deploy an AWS DataSync agent on premises. Configure the DataSync agent to perform the online data transfer to an S3 bucket.

- C. Create an Amazon S3 File Gateway on premises Configure the S3 File Gateway to perform the online data transfer to an S3 bucket

- D. Configure an accelerator in Amazon S3 Transfer Acceleration on premises. Configure the accelerator to perform the online data transfer to an S3 bucket.

**Correct:** B
**Why:** AWS DataSync performs online transfers to S3 with built‑in integrity verification.

**Incorrect:**
- A: Snowball Edge is offline and not needed here.
- C: S3 File Gateway presents SMB/NFS, but DataSync better automates validation at scale.
- D: S3 Transfer Acceleration is for internet uploads, not integrity‑checked migrations.


---

---

### Question #659

A company is relocating its data center and wants to securely transfer 50 TB of data to AWS within 2 weeks. The existing data center has a Site-to- Site VPN connection to AWS that is 90% utilized. Which AWS service should a solutions architect use to meet these requirements?

- A. AWS DataSync with a VPC endpoint

- B. AWS Direct Connect

- C. AWS Snowball Edge Storage Optimized

- D. AWS Storage Gateway

**Correct:** C
**Why:** Snowball Edge Storage Optimized transfers 50 TB securely within 2 weeks without saturating the VPN.

**Incorrect:**
- A: DataSync over congested VPN may miss the window.
- B: Direct Connect cannot be provisioned that quickly typically.
- D: Storage Gateway is not a bulk one‑time transfer solution.


---

## AWS Systems Manager

### Question #517

A company wants to send all AWS Systems Manager Session Manager logs to an Amazon S3 bucket for archival purposes. Which solution will meet this requirement with the MOST operational eciency?

- A. Enable S3 logging in the Systems Manager console. Choose an S3 bucket to send the session data to.

- B. Install the Amazon CloudWatch agent. Push all logs to a CloudWatch log group. Export the logs to an S3 bucket from the group for archival purposes.

- C. Create a Systems Manager document to upload all server logs to a central S3 bucket. Use Amazon EventBridge to run the Systems Manager document against all servers that are in the account daily.

- D. Install an Amazon CloudWatch agent. Push all logs to a CloudWatch log group. Create a CloudWatch logs subscription that pushes any incoming log events to an Amazon Kinesis Data Firehose delivery stream. Set Amazon S3 as the destination.

**Correct:** A
**Why:** Session Manager supports direct delivery of session logs to S3 from the console with minimal setup.

**Incorrect:**
- B: Extra agents/pipelines add complexity.
- C: Extra agents/pipelines add complexity.
- D: Extra agents/pipelines add complexity.


---

---

### Question #519

A consulting company provides professional services to customers worldwide. The company provides solutions and tools for customers to expedite gathering and analyzing data on AWS. The company needs to centrally manage and deploy a common set of solutions and tools for customers to use for self-service purposes. Which solution will meet these requirements?

- A. Create AWS CloudFormation templates for the customers.

- B. Create AWS Service Catalog products for the customers.

- C. Create AWS Systems Manager templates for the customers.

- D. Create AWS Cong items for the customers.

**Correct:** B
**Why:** AWS Service Catalog lets you centrally define and govern self‑service portfolios of solutions and tools.

**Incorrect:**
- A: CloudFormation/Systems Manager/Config don’t provide end‑user self‑service catalogs.
- C: CloudFormation/Systems Manager/Config don’t provide end‑user self‑service catalogs.
- D: CloudFormation/Systems Manager/Config don’t provide end‑user self‑service catalogs.


---

---

### Question #548

A company has separate AWS accounts for its nance, data analytics, and development departments. Because of costs and security concerns, the company wants to control which services each AWS account can use. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use AWS Systems Manager templates to control which AWS services each department can use.

- B. Create organization units (OUs) for each department in AWS Organizations. Attach service control policies (SCPs) to the OUs.

- C. Use AWS CloudFormation to automatically provision only the AWS services that each department can use.

- D. Set up a list of products in AWS Service Catalog in the AWS accounts to manage and control the usage of specic AWS services.

**Correct:** B
**Why:** Use Organizations OUs with SCPs to centrally control which services accounts can use.

**Incorrect:**
- A: Systems Manager/CloudFormation/Service Catalog are not primary service blockers.
- C: Systems Manager/CloudFormation/Service Catalog are not primary service blockers.
- D: Systems Manager/CloudFormation/Service Catalog are not primary service blockers.


---

---

### Question #563

A company runs its applications on both Amazon Elastic Kubernetes Service (Amazon EKS) clusters and on-premises Kubernetes clusters. The company wants to view all clusters and workloads from a central location. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use Amazon CloudWatch Container Insights to collect and group the cluster information.

- B. Use Amazon EKS Connector to register and connect all Kubernetes clusters.

- C. Use AWS Systems Manager to collect and view the cluster information.

- D. Use Amazon EKS Anywhere as the primary cluster to view the other clusters with native Kubernetes commands.

**Correct:** B
**Why:** Amazon EKS Connector lets you register both EKS and on-premises Kubernetes clusters to view and manage them centrally in the EKS console with low operational overhead.

**Incorrect:**
- A: CloudWatch Container Insights collects metrics/logs per cluster; it doesn’t serve as a single pane to register non-EKS clusters.
- C: Systems Manager doesn’t centrally register and view Kubernetes clusters.
- D: EKS Anywhere is for on-prem provisioning/management, not a central view of arbitrary existing clusters.


---

---

### Question #613

A company uses Amazon Elastic Kubernetes Service (Amazon EKS) to run a container application. The EKS cluster stores sensitive information in the Kubernetes secrets object. The company wants to ensure that the information is encrypted. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use the container application to encrypt the information by using AWS Key Management Service (AWS KMS).

- B. Enable secrets encryption in the EKS cluster by using AWS Key Management Service (AWS KMS).

- C. Implement an AWS Lambda function to encrypt the information by using AWS Key Management Service (AWS KMS).

- D. Use AWS Systems Manager Parameter Store to encrypt the information by using AWS Key Management Service (AWS KMS).

**Correct:** B
**Why:** EKS secrets encryption with KMS provides at‑rest encryption for Kubernetes secrets with minimal ops.

**Incorrect:**
- A: App/Lambda encryption adds complexity and key handling.
- C: App/Lambda encryption adds complexity and key handling.
- D: Parameter Store is separate from native K8s secrets management.


---

---

### Question #669

A company runs its databases on Amazon RDS for PostgreSQL. The company wants a secure solution to manage the master user password by rotating the password every 30 days. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use Amazon EventBridge to schedule a custom AWS Lambda function to rotate the password every 30 days.

- B. Use the modify-db-instance command in the AWS CLI to change the password.

- C. Integrate AWS Secrets Manager with Amazon RDS for PostgreSQL to automate password rotation.

- D. Integrate AWS Systems Manager Parameter Store with Amazon RDS for PostgreSQL to automate password rotation.

**Correct:** C
**Why:** Secrets Manager integrates with RDS to automatically rotate the master password on a schedule with minimal ops.

**Incorrect:**
- A: Custom Lambda is more work.
- B: CLI changes are manual and error‑prone.
- D: Parameter Store lacks built‑in rotation for RDS master passwords.


---

---

### Question #682

A company needs a solution to enforce data encryption at rest on Amazon EC2 instances. The solution must automatically identify noncompliant resources and enforce compliance policies on ndings. Which solution will meet these requirements with the LEAST administrative overhead?

- A. Use an IAM policy that allows users to create only encrypted Amazon Elastic Block Store (Amazon EBS) volumes. Use AWS Cong and AWS Systems Manager to automate the detection and remediation of unencrypted EBS volumes.

- B. Use AWS Key Management Service (AWS KMS) to manage access to encrypted Amazon Elastic Block Store (Amazon EBS) volumes. Use AWS Lambda and Amazon EventBridge to automate the detection and remediation of unencrypted EBS volumes.

- C. Use Amazon Macie to detect unencrypted Amazon Elastic Block Store (Amazon EBS) volumes. Use AWS Systems Manager Automation rules to automatically encrypt existing and new EBS volumes.

- D. Use Amazon inspector to detect unencrypted Amazon Elastic Block Store (Amazon EBS) volumes. Use AWS Systems Manager Automation rules to automatically encrypt existing and new EBS volumes.

**Correct:** A
**Why:** Enforce encrypted EBS creation via IAM, and use AWS Config with Systems Manager Automation to detect and remediate unencrypted volumes automatically.

**Incorrect:**
- B: Lambda + EventBridge is more custom ops; KMS alone doesn’t enforce encryption.
- C: Macie/Inspector do not detect EBS encryption compliance.
- D: Macie/Inspector do not detect EBS encryption compliance.


---

## AWS WAF & Shield

### Question #608

A company has an application that serves clients that are deployed in more than 20.000 retail storefront locations around the world. The application consists of backend web services that are exposed over HTTPS on port 443. The application is hosted on Amazon EC2 instances behind an Application Load Balancer (ALB). The retail locations communicate with the web application over the public internet. The company allows each retail location to register the IP address that the retail location has been allocated by its local ISP. The company's security team recommends to increase the security of the application endpoint by restricting access to only the IP addresses registered by the retail locations. What should a solutions architect do to meet these requirements?

- A. Associate an AWS WAF web ACL with the ALB. Use IP rule sets on the ALB to filter trac. Update the IP addresses in the rule to include the registered IP addresses.

- B. Deploy AWS Firewall Manager to manage the ALCongure firewall rules to restrict trac to the ALModify the firewall rules to include the registered IP addresses.

- C. Store the IP addresses in an Amazon DynamoDB table. Configure an AWS Lambda authorization function on the ALB to validate that incoming requests are from the registered IP addresses.

- D. Configure the network ACL on the subnet that contains the public interface of the ALB. Update the ingress rules on the network ACL with entries for each of the registered IP addresses.

**Correct:** A
**Why:** Attach an AWS WAF web ACL to the ALB with IP set rules; update the IP set with registered site IPs to restrict access.

**Incorrect:**
- B: Firewall Manager helps manage WAF across accounts but still relies on WAF/IP sets.
- C: ALB does not support Lambda authorizers; and DynamoDB storage is unnecessary.
- D: Network ACLs are coarse and hard to manage at scale.


---

---

### Question #623

A company uses Amazon API Gateway to manage its REST APIs that third-party service providers access. The company must protect the REST APIs from SQL injection and cross-site scripting attacks. What is the MOST operationally ecient solution that meets these requirements?

- A. Configure AWS Shield.

- B. Configure AWS WAF.

- C. Set up API Gateway with an Amazon CloudFront distribution. Configure AWS Shield in CloudFront.

- D. Set up API Gateway with an Amazon CloudFront distribution. Configure AWS WAF in CloudFront.

**Correct:** B
**Why:** AWS WAF protects against SQLi and XSS and integrates with API Gateway via CloudFront or regional.

**Incorrect:**
- A: Shield is for DDoS mitigation, not app‑layer attacks.
- C: Shield is for DDoS mitigation, not app‑layer attacks.
- D: WAF can be attached via CloudFront, but adding CF is not required for REST APIs; direct WAF is simpler.


---

---

### Question #625

A company is hosting a website behind multiple Application Load Balancers. The company has different distribution rights for its content around the world. A solutions architect needs to ensure that users are served the correct content without violating distribution rights. Which configuration should the solutions architect choose to meet these requirements?

- A. Configure Amazon CloudFront with AWS WAF.

- B. Configure Application Load Balancers with AWS WAF

- C. Configure Amazon Route 53 with a geolocation policy

- D. Configure Amazon Route 53 with a geoproximity routing policy

**Correct:** C
**Why:** Route 53 geolocation routing serves content based on user location across multiple ALB endpoints to respect distribution rights.

**Incorrect:**
- A: WAF doesn’t handle routing to different content by geography.
- B: WAF doesn’t handle routing to different content by geography.
- D: Geoproximity adjusts by distance/bias, not strict country mapping.


---

---

### Question #655

A company runs a web application on Amazon EC2 instances in an Auto Scaling group that has a target group. The company designed the application to work with session anity (sticky sessions) for a better user experience. The application must be available publicly over the internet as an endpoint. A WAF must be applied to the endpoint for additional security. Session anity (sticky sessions) must be congured on the endpoint. Which combination of steps will meet these requirements? (Choose two.)

- A. Create a public Network Load Balancer. Specify the application target group.

- B. Create a Gateway Load Balancer. Specify the application target group.

- C. Create a public Application Load Balancer. Specify the application target group.

- D. Create a second target group. Add Elastic IP addresses to the EC2 instances.

E. Create a web ACL in AWS WAF. Associate the web ACL with the endpoint

**Correct:** C, E
**Why:** ALB supports sticky sessions and integrates with AWS WAF via a web ACL for security.

**Incorrect:**
- A: NLB/GWLB don’t provide sticky sessions for HTTP; Elastic IPs are not target group members.
- B: NLB/GWLB don’t provide sticky sessions for HTTP; Elastic IPs are not target group members.
- D: NLB/GWLB don’t provide sticky sessions for HTTP; Elastic IPs are not target group members.


---

## Amazon API Gateway

### Question #501

A company wants to ingest customer payment data into the company's data lake in Amazon S3. The company receives payment data every minute on average. The company wants to analyze the payment data in real time. Then the company wants to ingest the data into the data lake. Which solution will meet these requirements with the MOST operational eciency?

- A. Use Amazon Kinesis Data Streams to ingest data. Use AWS Lambda to analyze the data in real time.

- B. Use AWS Glue to ingest data. Use Amazon Kinesis Data Analytics to analyze the data in real time.

- C. Use Amazon Kinesis Data Firehose to ingest data. Use Amazon Kinesis Data Analytics to analyze the data in real time.

- D. Use Amazon API Gateway to ingest data. Use AWS Lambda to analyze the data in real time.

**Correct:** C
**Why:** Kinesis Data Firehose provides fully managed ingestion to S3; Kinesis Data Analytics analyzes the stream in real time with minimal ops.

**Incorrect:**
- A: Lambda analysis is more custom and operationally heavier than KDA for streaming analytics.
- B: Glue/API Gateway are not optimal for continuous real‑time ingestion/analysis.
- D: Glue/API Gateway are not optimal for continuous real‑time ingestion/analysis.


---

---

### Question #516

A company provides an API interface to customers so the customers can retrieve their nancial information. Е he company expects a larger number of requests during peak usage times of the year. The company requires the API to respond consistently with low latency to ensure customer satisfaction. The company needs to provide a compute host for the API. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use an Application Load Balancer and Amazon Elastic Container Service (Amazon ECS).

- B. Use Amazon API Gateway and AWS Lambda functions with provisioned concurrency.

- C. Use an Application Load Balancer and an Amazon Elastic Kubernetes Service (Amazon EKS) cluster.

- D. Use Amazon API Gateway and AWS Lambda functions with reserved concurrency.

**Correct:** B
**Why:** API Gateway + Lambda with provisioned concurrency delivers consistently low latency with minimal ops.

**Incorrect:**
- A: ALB+ECS/EKS add cluster ops.
- C: ALB+ECS/EKS add cluster ops.
- D: Reserved concurrency controls throughput but doesn’t remove cold starts.


---

---

### Question #522

A company runs container applications by using Amazon Elastic Kubernetes Service (Amazon EKS). The company's workload is not consistent throughout the day. The company wants Amazon EKS to scale in and out according to the workload. Which combination of steps will meet these requirements with the LEAST operational overhead? (Choose two.)

- A. Use an AWS Lambda function to resize the EKS cluster.

- B. Use the Kubernetes Metrics Server to activate horizontal pod autoscaling.

- C. Use the Kubernetes Cluster Autoscaler to manage the number of nodes in the cluster.

- D. Use Amazon API Gateway and connect it to Amazon EKS.

E. Use AWS App Mesh to observe network activity.

**Correct:** B, C
**Why:** Use the Metrics Server for HPA (pods) and the Cluster Autoscaler for node count—low operational overhead.

**Incorrect:**
- A: Lambda/API Gateway/App Mesh are not needed for autoscaling here.
- D: Lambda/API Gateway/App Mesh are not needed for autoscaling here.
- E: Lambda/API Gateway/App Mesh are not needed for autoscaling here.


---

---

### Question #523

A company runs a microservice-based serverless web application. The application must be able to retrieve data from multiple Amazon DynamoDB tables A solutions architect needs to give the application the ability to retrieve the data with no impact on the baseline performance of the application. Which solution will meet these requirements in the MOST operationally ecient way?

- A. AWS AppSync pipeline resolvers

- B. Amazon CloudFront with Lambda@Edge functions

- C. Edge-optimized Amazon API Gateway with AWS Lambda functions

- D. Amazon Athena Federated Query with a DynamoDB connector

**Correct:** A
**Why:** AppSync pipeline resolvers can aggregate data from multiple DynamoDB tables efficiently without impacting baseline performance.

**Incorrect:**
- B: Edge/REST proxy/Athena are less suitable for orchestrated multi‑table reads in a serverless app.
- C: Edge/REST proxy/Athena are less suitable for orchestrated multi‑table reads in a serverless app.
- D: Edge/REST proxy/Athena are less suitable for orchestrated multi‑table reads in a serverless app.


---

---

### Question #530

A company has an online gaming application that has TCP and UDP multiplayer gaming capabilities. The company uses Amazon Route 53 to point the application trac to multiple Network Load Balancers (NLBs) in different AWS Regions. The company needs to improve application performance and decrease latency for the online game in preparation for user growth. Which solution will meet these requirements?

- A. Add an Amazon CloudFront distribution in front of the NLBs. Increase the Cache-Control max-age parameter.

- B. Replace the NLBs with Application Load Balancers (ALBs). Configure Route 53 to use latency-based routing.

- C. Add AWS Global Accelerator in front of the NLBs. Configure a Global Accelerator endpoint to use the correct listener ports.

- D. Add an Amazon API Gateway endpoint behind the NLBs. Enable API caching. Override method caching for the different stages.

**Correct:** C
**Why:** Global Accelerator improves global TCP/UDP performance with anycast IPs in front of NLBs.

**Incorrect:**
- A: CloudFront/ALB/API Gateway are not suited for arbitrary TCP/UDP improvements.
- B: CloudFront/ALB/API Gateway are not suited for arbitrary TCP/UDP improvements.
- D: CloudFront/ALB/API Gateway are not suited for arbitrary TCP/UDP improvements.


---

---

### Question #532

A company has a workload in an AWS Region. Customers connect to and access the workload by using an Amazon API Gateway REST API. The company uses Amazon Route 53 as its DNS provider. The company wants to provide individual and secure URLs for all customers. Which combination of steps will meet these requirements with the MOST operational eciency? (Choose three.)

- A. Register the required domain in a registrar. Create a wildcard custom domain name in a Route 53 hosted zone and record in the zone that points to the API Gateway endpoint.

- B. Request a wildcard certicate that matches the domains in AWS Certicate Manager (ACM) in a different Region.

- C. Create hosted zones for each customer as required in Route 53. Create zone records that point to the API Gateway endpoint.

- D. Request a wildcard certicate that matches the custom domain name in AWS Certicate Manager (ACM) in the same Region.

E. Create multiple API endpoints for each customer in API Gateway.

F. Create a custom domain name in API Gateway for the REST API. Import the certicate from AWS Certicate Manager (ACM).

**Correct:** A, D, F
**Why:** Use a wildcard custom domain in Route 53, request a matching wildcard ACM cert in the same Region, and create a custom domain in API Gateway with that cert.

**Incorrect:**
- B: Wrong Region for ACM, per‑customer hosted zones, or multiple API endpoints add overhead.
- C: Wrong Region for ACM, per‑customer hosted zones, or multiple API endpoints add overhead.
- E: Wrong Region for ACM, per‑customer hosted zones, or multiple API endpoints add overhead.


---

---

### Question #541

A company wants to build a web application on AWS. Client access requests to the website are not predictable and can be idle for a long time. Only customers who have paid a subscription fee can have the ability to sign in and use the web application. Which combination of steps will meet these requirements MOST cost-effectively? (Choose three.)

- A. Create an AWS Lambda function to retrieve user information from Amazon DynamoDB. Create an Amazon API Gateway endpoint to accept RESTful APIs. Send the API calls to the Lambda function.

- B. Create an Amazon Elastic Container Service (Amazon ECS) service behind an Application Load Balancer to retrieve user information from Amazon RDS. Create an Amazon API Gateway endpoint to accept RESTful APIs. Send the API calls to the Lambda function.

- C. Create an Amazon Cognito user pool to authenticate users.

- D. Create an Amazon Cognito identity pool to authenticate users.

E. Use AWS Amplify to serve the frontend web content with HTML, CSS, and JS. Use an integrated Amazon CloudFront configuration.

F. Use Amazon S3 static web hosting with PHP, CSS, and JS. Use Amazon CloudFront to serve the frontend web content.

**Correct:** A, C, E
**Why:** Serverless API (API Gateway → Lambda) is cost‑effective for spiky/idle loads; Cognito user pool handles subscription auth; Amplify hosts frontend with integrated CloudFront.

**Incorrect:**
- B: ECS/EC2 PHP or identity pools are unnecessary here.
- D: ECS/EC2 PHP or identity pools are unnecessary here.
- F: ECS/EC2 PHP or identity pools are unnecessary here.


---

---

### Question #544

A retail company uses a regional Amazon API Gateway API for its public REST APIs. The API Gateway endpoint is a custom domain name that points to an Amazon Route 53 alias record. A solutions architect needs to create a solution that has minimal effects on customers and minimal data loss to release the new version of APIs. Which solution will meet these requirements?

- A. Create a canary release deployment stage for API Gateway. Deploy the latest API version. Point an appropriate percentage of trac to the canary stage. After API verication, promote the canary stage to the production stage.

- B. Create a new API Gateway endpoint with a new version of the API in OpenAPI YAML file format. Use the import-to-update operation in merge mode into the API in API Gateway. Deploy the new version of the API to the production stage.

- C. Create a new API Gateway endpoint with a new version of the API in OpenAPI JSON file format. Use the import-to-update operation in overwrite mode into the API in API Gateway. Deploy the new version of the API to the production stage.

- D. Create a new API Gateway endpoint with new versions of the API denitions. Create a custom domain name for the new API Gateway API. Point the Route 53 alias record to the new API Gateway API custom domain name.

**Correct:** A
**Why:** Canary release in API Gateway shifts a small percentage of traffic to the new version, minimizing impact and data loss before promotion.

**Incorrect:**
- B: Import‑to‑update risks broad changes without gradual rollout.
- C: Import‑to‑update risks broad changes without gradual rollout.
- D: New endpoint/domain switch has higher impact.


---

---

### Question #567

A solutions architect is designing a workload that will store hourly energy consumption by business tenants in a building. The sensors will feed a database through HTTP requests that will add up usage for each tenant. The solutions architect must use managed services when possible. The workload will receive more features in the future as the solutions architect adds independent components. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use Amazon API Gateway with AWS Lambda functions to receive the data from the sensors, process the data, and store the data in an Amazon DynamoDB table.

- B. Use an Elastic Load Balancer that is supported by an Auto Scaling group of Amazon EC2 instances to receive and process the data from the sensors. Use an Amazon S3 bucket to store the processed data.

- C. Use Amazon API Gateway with AWS Lambda functions to receive the data from the sensors, process the data, and store the data in a Microsoft SQL Server Express database on an Amazon EC2 instance.

- D. Use an Elastic Load Balancer that is supported by an Auto Scaling group of Amazon EC2 instances to receive and process the data from the sensors. Use an Amazon Elastic File System (Amazon EFS) shared file system to store the processed data.

**Correct:** A
**Why:** API Gateway + Lambda gives a fully managed, serverless, event-driven ingestion and processing path with low overhead and easy future extensibility; store results in DynamoDB.

**Incorrect:**
- B: ELB + EC2 adds operational burden and is not necessary for simple HTTP ingest.
- C: EC2-hosted SQL Server Express increases ops overhead and reduces elasticity.
- D: ELB + EC2 adds operational burden and is not necessary for simple HTTP ingest.


---

---

### Question #571

A company is creating a REST API. The company has strict requirements for the use of TLS. The company requires TLSv1.3 on the API endpoints. The company also requires a specic public third-party certicate authority (CA) to sign the TLS certicate. Which solution will meet these requirements?

- A. Use a local machine to create a certicate that is signed by the third-party CImport the certicate into AWS Certicate Manager (ACM). Create an HTTP API in Amazon API Gateway with a custom domain. Configure the custom domain to use the certicate.

- B. Create a certicate in AWS Certicate Manager (ACM) that is signed by the third-party CA. Create an HTTP API in Amazon API Gateway with a custom domain. Configure the custom domain to use the certicate.

- C. Use AWS Certicate Manager (ACM) to create a certicate that is signed by the third-party CA. Import the certicate into AWS Certicate Manager (ACM). Create an AWS Lambda function with a Lambda function URL. Configure the Lambda function URL to use the certicate.

- D. Create a certicate in AWS Certicate Manager (ACM) that is signed by the third-party CA. Create an AWS Lambda function with a Lambda function URL. Configure the Lambda function URL to use the certicate.

**Correct:** A
**Why:** Import a certificate signed by the required third-party CA into ACM and use it on an API Gateway custom domain. ACM cannot issue third‑party CA certs directly; importing meets the TLS policy needs.

**Incorrect:**
- B: ACM cannot create a certificate that is signed by an external third-party CA; you must import it.
- C: Lambda function URLs cannot use externally issued certs via ACM like this; also not an API endpoint replacement.
- D: Lambda URLs plus ACM do not fulfill the REST API requirement or TLS policy at the edge.


---

---

### Question #576

A company is building a RESTful serverless web application on AWS by using Amazon API Gateway and AWS Lambda. The users of this web application will be geographically distributed, and the company wants to reduce the latency of API requests to these users. Which type of endpoint should a solutions architect use to meet these requirements?

- A. Private endpoint

- B. Regional endpoint

- C. Interface VPC endpoint

- D. Edge-optimized endpoint

**Correct:** D
**Why:** Edge-optimized API Gateway endpoints use CloudFront to reduce latency for geographically distributed users.

**Incorrect:**
- A: Private endpoints are for VPC-only access.
- B: Regional endpoints don’t leverage global edge locations.
- C: Interface VPC endpoints are for private access within a VPC, not global latency reduction.


---

---

### Question #587

A company is designing a solution to capture customer activity in different web applications to process analytics and make predictions. Customer activity in the web applications is unpredictable and can increase suddenly. The company requires a solution that integrates with other web applications. The solution must include an authorization step for security purposes. Which solution will meet these requirements?

- A. Configure a Gateway Load Balancer (GWLB) in front of an Amazon Elastic Container Service (Amazon ECS) container instance that stores the information that the company receives in an Amazon Elastic File System (Amazon EFS) file system. Authorization is resolved at the GWLB.

- B. Configure an Amazon API Gateway endpoint in front of an Amazon Kinesis data stream that stores the information that the company receives in an Amazon S3 bucket. Use an AWS Lambda function to resolve authorization.

- C. Configure an Amazon API Gateway endpoint in front of an Amazon Kinesis Data Firehose that stores the information that the company receives in an Amazon S3 bucket. Use an API Gateway Lambda authorizer to resolve authorization.

- D. Configure a Gateway Load Balancer (GWLB) in front of an Amazon Elastic Container Service (Amazon ECS) container instance that stores the information that the company receives on an Amazon Elastic File System (Amazon EFS) file system. Use an AWS Lambda function to resolve authorization.

**Correct:** C
**Why:** API Gateway with a Lambda authorizer provides auth. Kinesis Data Firehose scales ingestion and delivers to S3 with minimal ops overhead.

**Incorrect:**
- A: GWLB + ECS introduces heavy ops complexity for simple event ingestion.
- B: API Gateway to Kinesis Data Streams is viable but requires more scaling/consumer management than Firehose for S3 delivery.
- D: GWLB + ECS introduces heavy ops complexity for simple event ingestion.


---

---

### Question #591

A company runs a container application by using Amazon Elastic Kubernetes Service (Amazon EKS). The application includes microservices that manage customers and place orders. The company needs to route incoming requests to the appropriate microservices. Which solution will meet this requirement MOST cost-effectively?

- A. Use the AWS Load Balancer Controller to provision a Network Load Balancer.

- B. Use the AWS Load Balancer Controller to provision an Application Load Balancer.

- C. Use an AWS Lambda function to connect the requests to Amazon EKS.

- D. Use Amazon API Gateway to connect the requests to Amazon EKS.

**Correct:** B
**Why:** The AWS Load Balancer Controller can provision an ALB for path/host routing to EKS microservices cost‑effectively.

**Incorrect:**
- A: NLB is L4 and not suited for HTTP routing across microservices.
- C: Lambda or API Gateway add unnecessary abstraction and cost.
- D: Lambda or API Gateway add unnecessary abstraction and cost.


---

---

### Question #597

A company hosts an internal serverless application on AWS by using Amazon API Gateway and AWS Lambda. The company’s employees report issues with high latency when they begin using the application each day. The company wants to reduce latency. Which solution will meet these requirements?

- A. Increase the API Gateway throttling limit.

- B. Set up a scheduled scaling to increase Lambda provisioned concurrency before employees begin to use the application each day.

- C. Create an Amazon CloudWatch alarm to initiate a Lambda function as a target for the alarm at the beginning of each day.

- D. Increase the Lambda function memory.

**Correct:** B
**Why:** Schedule provisioned concurrency before users start to eliminate cold starts and reduce latency.

**Incorrect:**
- A: API Gateway throttling limits won’t affect cold starts.
- C: Invoking a warm‑up Lambda is ad‑hoc vs. built‑in provisioned concurrency.
- D: More memory doesn’t eliminate cold starts.


---

---

### Question #600

A company is planning to migrate a TCP-based application into the company's VPC. The application is publicly accessible on a nonstandard TCP port through a hardware appliance in the company's data center. This public endpoint can process up to 3 million requests per second with low latency. The company requires the same level of performance for the new public endpoint in AWS. What should a solutions architect recommend to meet this requirement?

- A. Deploy a Network Load Balancer (NLB). Configure the NLB to be publicly accessible over the TCP port that the application requires.

- B. Deploy an Application Load Balancer (ALB). Configure the ALB to be publicly accessible over the TCP port that the application requires.

- C. Deploy an Amazon CloudFront distribution that listens on the TCP port that the application requires. Use an Application Load Balancer as the origin.

- D. Deploy an Amazon API Gateway API that is congured with the TCP port that the application requires. Configure AWS Lambda functions with provisioned concurrency to process the requests.

**Correct:** A
**Why:** NLB supports millions of requests per second with low latency on arbitrary TCP ports.

**Incorrect:**
- B: ALB is HTTP/HTTPS (L7) and not optimized for raw TCP performance at this scale.
- C: CloudFront/API Gateway do not meet the raw TCP nonstandard port requirement.
- D: CloudFront/API Gateway do not meet the raw TCP nonstandard port requirement.


---

---

### Question #611

A company has an application with a REST-based interface that allows data to be received in near-real time from a third-party vendor. Once received, the application processes and stores the data for further analysis. The application is running on Amazon EC2 instances. The third-party vendor has received many 503 Service Unavailable Errors when sending data to the application. When the data volume spikes, the compute capacity reaches its maximum limit and the application is unable to process all requests. Which design should a solutions architect recommend to provide a more scalable solution?

- A. Use Amazon Kinesis Data Streams to ingest the data. Process the data using AWS Lambda functions.

- B. Use Amazon API Gateway on top of the existing application. Create a usage plan with a quota limit for the third-party vendor.

- C. Use Amazon Simple Notification Service (Amazon SNS) to ingest the data. Put the EC2 instances in an Auto Scaling group behind an Application Load Balancer.

- D. Repackage the application as a container. Deploy the application using Amazon Elastic Container Service (Amazon ECS) using the EC2 launch type with an Auto Scaling group.

**Correct:** A
**Why:** Kinesis Data Streams buffers spikes and decouples producers from consumers; Lambda scales to process without 503s.

**Incorrect:**
- B: API Gateway with quotas throttles the vendor rather than scaling.
- C: SNS is pub/sub and not ideal for high‑throughput buffering + ordering.
- D: ECS on EC2 still faces sudden capacity limits without a buffer.


---

---

### Question #623

A company uses Amazon API Gateway to manage its REST APIs that third-party service providers access. The company must protect the REST APIs from SQL injection and cross-site scripting attacks. What is the MOST operationally ecient solution that meets these requirements?

- A. Configure AWS Shield.

- B. Configure AWS WAF.

- C. Set up API Gateway with an Amazon CloudFront distribution. Configure AWS Shield in CloudFront.

- D. Set up API Gateway with an Amazon CloudFront distribution. Configure AWS WAF in CloudFront.

**Correct:** B
**Why:** AWS WAF protects against SQLi and XSS and integrates with API Gateway via CloudFront or regional.

**Incorrect:**
- A: Shield is for DDoS mitigation, not app‑layer attacks.
- C: Shield is for DDoS mitigation, not app‑layer attacks.
- D: WAF can be attached via CloudFront, but adding CF is not required for REST APIs; direct WAF is simpler.


---

---

### Question #637

A solutions architect is designing a new service behind Amazon API Gateway. The request patterns for the service will be unpredictable and can change suddenly from 0 requests to over 500 per second. The total size of the data that needs to be persisted in a backend database is currently less than 1 GB with unpredictable future growth. Data can be queried using simple key-value requests. Which combination ofAWS services would meet these requirements? (Choose two.)

- A. AWS Fargate

- B. AWS Lambda

- C. Amazon DynamoDB

- D. Amazon EC2 Auto Scaling

E. MySQL-compatible Amazon Aurora

**Correct:** B, C
**Why:** Lambda scales to sudden bursts. DynamoDB provides key‑value storage with <1 GB easily and elastic throughput.

**Incorrect:**
- A: Fargate/ASG/Aurora add ops or are overkill for KB/MB‑scale key‑value.
- D: Fargate/ASG/Aurora add ops or are overkill for KB/MB‑scale key‑value.
- E: Fargate/ASG/Aurora add ops or are overkill for KB/MB‑scale key‑value.


---

---

### Question #654

A company recently migrated its web application to the AWS Cloud. The company uses an Amazon EC2 instance to run multiple processes to host the application. The processes include an Apache web server that serves static content. The Apache web server makes requests to a PHP application that uses a local Redis server for user sessions. The company wants to redesign the architecture to be highly available and to use AWS managed solutions. Which solution will meet these requirements?

- A. Use AWS Elastic Beanstalk to host the static content and the PHP application. Configure Elastic Beanstalk to deploy its EC2 instance into a public subnet. Assign a public IP address.

- B. Use AWS Lambda to host the static content and the PHP application. Use an Amazon API Gateway REST API to proxy requests to the Lambda function. Set the API Gateway CORS configuration to respond to the domain name. Configure Amazon ElastiCache for Redis to handle session information.

- C. Keep the backend code on the EC2 instance. Create an Amazon ElastiCache for Redis cluster that has Multi-AZ enabled. Configure the ElastiCache for Redis cluster in cluster mode. Copy the frontend resources to Amazon S3. Configure the backend code to reference the EC2 instance.

- D. Configure an Amazon CloudFront distribution with an Amazon S3 endpoint to an S3 bucket that is congured to host the static content. Configure an Application Load Balancer that targets an Amazon Elastic Container Service (Amazon ECS) service that runs AWS Fargate tasks for the PHP application. Configure the PHP application to use an Amazon ElastiCache for Redis cluster that runs in multiple Availability Zones.

**Correct:** D
**Why:** S3 + CloudFront for static assets; ECS Fargate behind ALB for PHP app; Redis (Multi‑AZ) for sessions meets HA with managed services.

**Incorrect:**
- A: Single EC2 in public subnet is not HA.
- B: Lambda for PHP monolith adds complexity and cold‑start concerns.
- C: Keeping backend on EC2 is not fully managed/HA.


---

## Amazon Athena

### Question #523

A company runs a microservice-based serverless web application. The application must be able to retrieve data from multiple Amazon DynamoDB tables A solutions architect needs to give the application the ability to retrieve the data with no impact on the baseline performance of the application. Which solution will meet these requirements in the MOST operationally ecient way?

- A. AWS AppSync pipeline resolvers

- B. Amazon CloudFront with Lambda@Edge functions

- C. Edge-optimized Amazon API Gateway with AWS Lambda functions

- D. Amazon Athena Federated Query with a DynamoDB connector

**Correct:** A
**Why:** AppSync pipeline resolvers can aggregate data from multiple DynamoDB tables efficiently without impacting baseline performance.

**Incorrect:**
- B: Edge/REST proxy/Athena are less suitable for orchestrated multi‑table reads in a serverless app.
- C: Edge/REST proxy/Athena are less suitable for orchestrated multi‑table reads in a serverless app.
- D: Edge/REST proxy/Athena are less suitable for orchestrated multi‑table reads in a serverless app.


---

---

### Question #524

A company wants to analyze and troubleshoot Access Denied errors and Unauthorized errors that are related to IAM permissions. The company has AWS CloudTrail turned on. Which solution will meet these requirements with the LEAST effort?

- A. Use AWS Glue and write custom scripts to query CloudTrail logs for the errors.

- B. Use AWS Batch and write custom scripts to query CloudTrail logs for the errors.

- C. Search CloudTrail logs with Amazon Athena queries to identify the errors.

- D. Search CloudTrail logs with Amazon QuickSight. Create a dashboard to identify the errors.

**Correct:** C
**Why:** Query CloudTrail logs directly with Athena to find AccessDenied/Unauthorized events—lowest effort.

**Incorrect:**
- A: Glue/Batch/QuickSight add unnecessary development overhead.
- B: Glue/Batch/QuickSight add unnecessary development overhead.
- D: Glue/Batch/QuickSight add unnecessary development overhead.


---

---

### Question #557

A solutions architect manages an analytics application. The application stores large amounts of semistructured data in an Amazon S3 bucket. The solutions architect wants to use parallel data processing to process the data more quickly. The solutions architect also wants to use information that is stored in an Amazon Redshift database to enrich the data. Which solution will meet these requirements?

- A. Use Amazon Athena to process the S3 data. Use AWS Glue with the Amazon Redshift data to enrich the S3 data.

- B. Use Amazon EMR to process the S3 data. Use Amazon EMR with the Amazon Redshift data to enrich the S3 data.

- C. Use Amazon EMR to process the S3 data. Use Amazon Kinesis Data Streams to move the S3 data into Amazon Redshift so that the data can be enriched.

- D. Use AWS Glue to process the S3 data. Use AWS Lake Formation with the Amazon Redshift data to enrich the S3 data.

**Correct:** B
**Why:** Amazon EMR supports large-scale parallel processing on S3 data and can integrate with Amazon Redshift to enrich S3 data with Redshift data (e.g., via Spark connectors/JDBC).

**Incorrect:**
- A: Athena + Glue can join, but enriching with Redshift data is more direct and scalable with EMR compute.
- C: Kinesis Data Streams is for streaming ingestion, not enriching S3 batch data with Redshift.
- D: Glue can process S3 data, but enrichment specifically with Redshift is better served by EMR’s flexible engines.


---

---

### Question #590

A company migrated a MySQL database from the company's on-premises data center to an Amazon RDS for MySQL DB instance. The company sized the RDS DB instance to meet the company's average daily workload. Once a month, the database performs slowly when the company runs queries for a report. The company wants to have the ability to run reports and maintain the performance of the daily workloads. Which solution will meet these requirements?

- A. Create a read replica of the database. Direct the queries to the read replica.

- B. Create a backup of the database. Restore the backup to another DB instance. Direct the queries to the new database.

- C. Export the data to Amazon S3. Use Amazon Athena to query the S3 bucket.

- D. Resize the DB instance to accommodate the additional workload.

**Correct:** A
**Why:** A read replica offloads reporting queries without impacting primary OLTP performance.

**Incorrect:**
- B: Restoring a backup is slower and manual.
- C: Athena on S3 requires exports and a different access pattern.
- D: Upsizing increases cost and still mixes workloads on one instance.


---

---

### Question #598

A research company uses on-premises devices to generate data for analysis. The company wants to use the AWS Cloud to analyze the data. The devices generate .csv files and support writing the data to an SMB file share. Company analysts must be able to use SQL commands to query the data. The analysts will run queries periodically throughout the day. Which combination of steps will meet these requirements MOST cost-effectively? (Choose three.)

- A. Deploy an AWS Storage Gateway on premises in Amazon S3 File Gateway mode.

- B. Deploy an AWS Storage Gateway on premises in Amazon FSx File Gateway made.

- C. Set up an AWS Glue crawler to create a table based on the data that is in Amazon S3.

- D. Set up an Amazon EMR cluster with EMR File System (EMRFS) to query the data that is in Amazon S3. Provide access to analysts.

E. Set up an Amazon Redshift cluster to query the data that is in Amazon S3. Provide access to analysts.

F. Setup Amazon Athena to query the data that is in Amazon S3. Provide access to analysts.

**Correct:** A, C, F
**Why:** Use S3 File Gateway to land CSVs in S3 over SMB, crawl with Glue to build schema, and query with Athena using SQL on demand.

**Incorrect:**
- B: FSx File Gateway presents FSx, not S3.
- D: EMR/Redshift add cost/ops for periodic ad‑hoc queries.
- E: EMR/Redshift add cost/ops for periodic ad‑hoc queries.


---

---

### Question #641

A company wants to monitor its AWS costs for nancial review. The cloud operations team is designing an architecture in the AWS Organizations management account to query AWS Cost and Usage Reports for all member accounts. The team must run this query once a month and provide a detailed analysis of the bill. Which solution is the MOST scalable and cost-effective way to meet these requirements?

- A. Enable Cost and Usage Reports in the management account. Deliver reports to Amazon Kinesis. Use Amazon EMR for analysis.

- B. Enable Cost and Usage Reports in the management account. Deliver the reports to Amazon S3 Use Amazon Athena for analysis.

- C. Enable Cost and Usage Reports for member accounts. Deliver the reports to Amazon S3 Use Amazon Redshift for analysis.

- D. Enable Cost and Usage Reports for member accounts. Deliver the reports to Amazon Kinesis. Use Amazon QuickSight tor analysis.

**Correct:** B
**Why:** CUR to S3 + Athena provides scalable, low‑cost monthly querying across member accounts from the management account.

**Incorrect:**
- A: Kinesis/QuickSight not needed; CUR+Athena is simpler/cheaper.
- C: Enabling CUR per member is unnecessary; centralize in management.
- D: Kinesis/QuickSight not needed; CUR+Athena is simpler/cheaper.


---

---

### Question #643

A company runs several websites on AWS for its different brands. Each website generates tens of gigabytes of web trac logs each day. A solutions architect needs to design a scalable solution to give the company's developers the ability to analyze trac patterns across all the company's websites. This analysis by the developers will occur on demand once a week over the course of several months. The solution must support queries with standard SQL. Which solution will meet these requirements MOST cost-effectively?

- A. Store the logs in Amazon S3. Use Amazon Athena tor analysis.

- B. Store the logs in Amazon RDS. Use a database client for analysis.

- C. Store the logs in Amazon OpenSearch Service. Use OpenSearch Service for analysis.

- D. Store the logs in an Amazon EMR cluster Use a supported open-source framework for SQL-based analysis.

**Correct:** A
**Why:** Store logs in S3 and query with Athena using SQL only when needed; minimal cost/ops.

**Incorrect:**
- B: RDS is expensive and not ideal for log analytics.
- C: OpenSearch is more costly for weekly ad‑hoc queries.
- D: EMR cluster management adds significant overhead.


---

---

### Question #672

A marketing company receives a large amount of new clickstream data in Amazon S3 from a marketing campaign. The company needs to analyze the clickstream data in Amazon S3 quickly. Then the company needs to determine whether to process the data further in the data pipeline. Which solution will meet these requirements with the LEAST operational overhead?

- A. Create external tables in a Spark catalog. Configure jobs in AWS Glue to query the data.

- B. Configure an AWS Glue crawler to crawl the data. Configure Amazon Athena to query the data.

- C. Create external tables in a Hive metastore. Configure Spark jobs in Amazon EMR to query the data.

- D. Configure an AWS Glue crawler to crawl the data. Configure Amazon Kinesis Data Analytics to use SQL to query the data.

**Correct:** B
**Why:** Run an AWS Glue crawler to catalog the S3 data, then use Amazon Athena to query immediately with SQL and minimal ops.

**Incorrect:**
- A: Spark catalog setup adds unnecessary overhead for a quick assessment.
- C: EMR + Hive metastore increases cost/ops for ad‑hoc queries.
- D: Kinesis Data Analytics is for streaming SQL, not batch S3 analysis.


---

## Amazon Aurora

### Question #502

A company runs a website that uses a content management system (CMS) on Amazon EC2. The CMS runs on a single EC2 instance and uses an Amazon Aurora MySQL Multi-AZ DB instance for the data tier. Website images are stored on an Amazon Elastic Block Store (Amazon EBS) volume that is mounted inside the EC2 instance. Which combination of actions should a solutions architect take to improve the performance and resilience of the website? (Choose two.)

- A. Move the website images into an Amazon S3 bucket that is mounted on every EC2 instance

- B. Share the website images by using an NFS share from the primary EC2 instance. Mount this share on the other EC2 instances.

- C. Move the website images onto an Amazon Elastic File System (Amazon EFS) file system that is mounted on every EC2 instance.

- D. Create an Amazon Machine Image (AMI) from the existing EC2 instance. Use the AMI to provision new instances behind an Application Load Balancer as part of an Auto Scaling group. Configure the Auto Scaling group to maintain a minimum of two instances. Configure an accelerator in AWS Global Accelerator for the website

E. Create an Amazon Machine Image (AMI) from the existing EC2 instance. Use the AMI to provision new instances behind an Application Load Balancer as part of an Auto Scaling group. Configure the Auto Scaling group to maintain a minimum of two instances. Configure an Amazon CloudFront distribution for the website.

**Correct:** C, E
**Why:** Move images to EFS for shared, scalable storage; use ALB+Auto Scaling behind a CloudFront distribution for performance and resilience.

**Incorrect:**
- A: S3 mounted or EC2 NFS via a primary instance are not ideal.
- B: S3 mounted or EC2 NFS via a primary instance are not ideal.
- D: Global Accelerator is unnecessary for origin performance here.


---

---

### Question #507

A company has a web application for travel ticketing. The application is based on a database that runs in a single data center in North America. The company wants to expand the application to serve a global user base. The company needs to deploy the application to multiple AWS Regions. Average latency must be less than 1 second on updates to the reservation database. The company wants to have separate deployments of its web platform across multiple Regions. However, the company must maintain a single primary reservation database that is globally consistent. Which solution should a solutions architect recommend to meet these requirements?

- A. Convert the application to use Amazon DynamoDB. Use a global table for the center reservation table. Use the correct Regional endpoint in each Regional deployment.

- B. Migrate the database to an Amazon Aurora MySQL database. Deploy Aurora Read Replicas in each Region. Use the correct Regional endpoint in each Regional deployment for access to the database.

- C. Migrate the database to an Amazon RDS for MySQL database. Deploy MySQL read replicas in each Region. Use the correct Regional endpoint in each Regional deployment for access to the database.

- D. Migrate the application to an Amazon Aurora Serverless database. Deploy instances of the database to each Region. Use the correct Regional endpoint in each Regional deployment to access the database. Use AWS Lambda functions to process event streams in each Region to synchronize the databases.

**Correct:** B
**Why:** Aurora MySQL with cross‑Region Aurora Replicas (Aurora Global Database) keeps a single primary and low‑latency replicas; web tiers use Regional endpoints.

**Incorrect:**
- A: DynamoDB changes the data model.
- C: RDS MySQL cross‑Region replication is slower and less managed.
- D: Serverless with custom sync adds complexity.


---

---

### Question #511

A company is developing software that uses a PostgreSQL database schema. The company needs to configure multiple development environments and databases for the company's developers. On average, each development environment is used for half of the 8-hour workday. Which solution will meet these requirements MOST cost-effectively?

- A. Configure each development environment with its own Amazon Aurora PostgreSQL database

- B. Configure each development environment with its own Amazon RDS for PostgreSQL Single-AZ DB instances

- C. Configure each development environment with its own Amazon Aurora On-Demand PostgreSQL-Compatible database

- D. Configure each development environment with its own Amazon S3 bucket by using Amazon S3 Object Select

**Correct:** C
**Why:** Aurora Serverless/On‑Demand PostgreSQL is cost‑effective for dev environments that are idle for long periods.

**Incorrect:**
- A: Always‑on instances cost more for idle time.
- B: Always‑on instances cost more for idle time.
- D: S3 is not a relational database.


---

---

### Question #526

A solutions architect is reviewing the resilience of an application. The solutions architect notices that a database administrator recently failed over the application's Amazon Aurora PostgreSQL database writer instance as part of a scaling exercise. The failover resulted in 3 minutes of downtime for the application. Which solution will reduce the downtime for scaling exercises with the LEAST operational overhead?

- A. Create more Aurora PostgreSQL read replicas in the cluster to handle the load during failover.

- B. Set up a secondary Aurora PostgreSQL cluster in the same AWS Region. During failover, update the application to use the secondary cluster's writer endpoint.

- C. Create an Amazon ElastiCache for Memcached cluster to handle the load during failover.

- D. Set up an Amazon RDS proxy for the database. Update the application to use the proxy endpoint.

**Correct:** D
**Why:** RDS Proxy maintains connections during failover/scaling, reducing downtime with minimal changes.

**Incorrect:**
- A: Read replicas/cache don’t address connection failover.
- B: Secondary cluster and app rewiring add ops and downtime.
- C: Read replicas/cache don’t address connection failover.


---

---

### Question #527

A company has a regional subscription-based streaming service that runs in a single AWS Region. The architecture consists of web servers and application servers on Amazon EC2 instances. The EC2 instances are in Auto Scaling groups behind Elastic Load Balancers. The architecture includes an Amazon Aurora global database cluster that extends across multiple Availability Zones. The company wants to expand globally and to ensure that its application has minimal downtime. Which solution will provide the MOST fault tolerance?

- A. Extend the Auto Scaling groups for the web tier and the application tier to deploy instances in Availability Zones in a second Region. Use an Aurora global database to deploy the database in the primary Region and the second Region. Use Amazon Route 53 health checks with a failover routing policy to the second Region.

- B. Deploy the web tier and the application tier to a second Region. Add an Aurora PostgreSQL cross-Region Aurora Replica in the second Region. Use Amazon Route 53 health checks with a failover routing policy to the second Region. Promote the secondary to primary as needed.

- C. Deploy the web tier and the application tier to a second Region. Create an Aurora PostgreSQL database in the second Region. Use AWS Database Migration Service (AWS DMS) to replicate the primary database to the second Region. Use Amazon Route 53 health checks with a failover routing policy to the second Region.

- D. Deploy the web tier and the application tier to a second Region. Use an Amazon Aurora global database to deploy the database in the primary Region and the second Region. Use Amazon Route 53 health checks with a failover routing policy to the second Region. Promote the secondary to primary as needed.

**Correct:** D
**Why:** Deploy app tiers in a second Region and use Aurora Global Database plus Route 53 failover for maximal fault tolerance.

**Incorrect:**
- A: Less integrated or slower replication and more manual promotion.
- B: Less integrated or slower replication and more manual promotion.
- C: Less integrated or slower replication and more manual promotion.


---

---

### Question #540

A company has an on-premises server that uses an Oracle database to process and store customer information. The company wants to use an AWS database service to achieve higher availability and to improve application performance. The company also wants to ooad reporting from its primary database system. Which solution will meet these requirements in the MOST operationally ecient way?

- A. Use AWS Database Migration Service (AWS DMS) to create an Amazon RDS DB instance in multiple AWS Regions. Point the reporting functions toward a separate DB instance from the primary DB instance.

- B. Use Amazon RDS in a Single-AZ deployment to create an Oracle database. Create a read replica in the same zone as the primary DB instance. Direct the reporting functions to the read replica.

- C. Use Amazon RDS deployed in a Multi-AZ cluster deployment to create an Oracle database. Direct the reporting functions to use the reader instance in the cluster deployment.

- D. Use Amazon RDS deployed in a Multi-AZ instance deployment to create an Amazon Aurora database. Direct the reporting functions to the reader instances.

**Correct:** C
**Why:** RDS Oracle Multi‑AZ cluster improves availability; use the reader for reporting offload with minimal ops.

**Incorrect:**
- A: Multi‑Region primaries/Single‑AZ/engine change add cost or complexity.
- B: Multi‑Region primaries/Single‑AZ/engine change add cost or complexity.
- D: Multi‑Region primaries/Single‑AZ/engine change add cost or complexity.


---

---

### Question #565

A company has an on-premises MySQL database that handles transactional data. The company is migrating the database to the AWS Cloud. The migrated database must maintain compatibility with the company's applications that use the database. The migrated database also must scale automatically during periods of increased demand. Which migration solution will meet these requirements?

- A. Use native MySQL tools to migrate the database to Amazon RDS for MySQL. Configure elastic storage scaling.

- B. Migrate the database to Amazon Redshift by using the mysqldump utility. Turn on Auto Scaling for the Amazon Redshift cluster.

- C. Use AWS Database Migration Service (AWS DMS) to migrate the database to Amazon Aurora. Turn on Aurora Auto Scaling.

- D. Use AWS Database Migration Service (AWS DMS) to migrate the database to Amazon DynamoDB. Configure an Auto Scaling policy.

**Correct:** C
**Why:** Migrate with AWS DMS to Amazon Aurora (MySQL-compatible). Aurora Auto Scaling (e.g., readers, and with Aurora Serverless v2 if adopted) provides automatic scaling to meet demand while maintaining compatibility.

**Incorrect:**
- A: RDS for MySQL with elastic storage scaling does not auto scale compute to handle demand spikes.
- B: Redshift is a data warehouse, not a transactional DB replacement.
- D: DynamoDB is NoSQL and not MySQL-compatible for existing apps.


---

---

### Question #572

A company runs an application on AWS. The application receives inconsistent amounts of usage. The application uses AWS Direct Connect to connect to an on-premises MySQL-compatible database. The on-premises database consistently uses a minimum of 2 GiB of memory. The company wants to migrate the on-premises database to a managed AWS service. The company wants to use auto scaling capabilities to manage unexpected workload increases. Which solution will meet these requirements with the LEAST administrative overhead?

- A. Provision an Amazon DynamoDB database with default read and write capacity settings.

- B. Provision an Amazon Aurora database with a minimum capacity of 1 Aurora capacity unit (ACU).

- C. Provision an Amazon Aurora Serverless v2 database with a minimum capacity of 1 Aurora capacity unit (ACU).

- D. Provision an Amazon RDS for MySQL database with 2 GiB of memory.

**Correct:** C
**Why:** Aurora Serverless v2 (MySQL-compatible) supports automatic, fine-grained scaling with minimal admin overhead; a 1 ACU minimum covers the 2 GiB baseline.

**Incorrect:**
- A: DynamoDB is not MySQL-compatible.
- B: Provisioned Aurora (non-serverless) requires capacity management.
- D: RDS for MySQL is managed but does not auto scale compute to absorb unexpected spikes.


---

---

### Question #574

A nancial services company launched a new application that uses an Amazon RDS for MySQL database. The company uses the application to track stock market trends. The company needs to operate the application for only 2 hours at the end of each week. The company needs to optimize the cost of running the database. Which solution will meet these requirements MOST cost-effectively?

- A. Migrate the existing RDS for MySQL database to an Aurora Serverless v2 MySQL database cluster.

- B. Migrate the existing RDS for MySQL database to an Aurora MySQL database cluster.

- C. Migrate the existing RDS for MySQL database to an Amazon EC2 instance that runs MySQL. Purchase an instance reservation for the EC2 instance.

- D. Migrate the existing RDS for MySQL database to an Amazon Elastic Container Service (Amazon ECS) cluster that uses MySQL container images to run tasks.

**Correct:** A
**Why:** Aurora Serverless v2 scales capacity to meet the brief weekly usage window and minimizes cost when idle, with low ops overhead.

**Incorrect:**
- B: Provisioned Aurora runs 24/7 and costs more for a 2‑hour/week workload.
- C: EC2 self-managed MySQL increases operational effort.
- D: ECS for MySQL adds container and storage management complexity.


---

---

### Question #596

An ecommerce application uses a PostgreSQL database that runs on an Amazon EC2 instance. During a monthly sales event, database usage increases and causes database connection issues for the application. The trac is unpredictable for subsequent monthly sales events, which impacts the sales forecast. The company needs to maintain performance when there is an unpredictable increase in trac. Which solution resolves this issue in the MOST cost-effective way?

- A. Migrate the PostgreSQL database to Amazon Aurora Serverless v2.

- B. Enable auto scaling for the PostgreSQL database on the EC2 instance to accommodate increased usage.

- C. Migrate the PostgreSQL database to Amazon RDS for PostgreSQL with a larger instance type.

- D. Migrate the PostgreSQL database to Amazon Redshift to accommodate increased usage.

**Correct:** A
**Why:** Aurora Serverless v2 for PostgreSQL auto scales capacity to handle unpredictable event spikes cost‑effectively.

**Incorrect:**
- B: EC2 DB auto scaling isn’t available and requires self‑management.
- C: Fixed RDS size lacks elasticity.
- D: Redshift is for analytics, not transactional workloads.


---

---

### Question #601

A company runs its critical database on an Amazon RDS for PostgreSQL DB instance. The company wants to migrate to Amazon Aurora PostgreSQL with minimal downtime and data loss. Which solution will meet these requirements with the LEAST operational overhead?

- A. Create a DB snapshot of the RDS for PostgreSQL DB instance to populate a new Aurora PostgreSQL DB cluster.

- B. Create an Aurora read replica of the RDS for PostgreSQL DB instance. Promote the Aurora read replicate to a new Aurora PostgreSQL DB cluster.

- C. Use data import from Amazon S3 to migrate the database to an Aurora PostgreSQL DB cluster.

- D. Use the pg_dump utility to back up the RDS for PostgreSQL database. Restore the backup to a new Aurora PostgreSQL DB cluster.

**Correct:** B
**Why:** Create an Aurora read replica of RDS for PostgreSQL, then promote. This minimizes downtime and operational effort.

**Incorrect:**
- A: Snapshot/restore incurs longer downtime.
- C: S3 import/pg_dump are manual and operationally heavy.
- D: S3 import/pg_dump are manual and operationally heavy.


---

---

### Question #622

A company is creating a new web application for its subscribers. The application will consist of a static single page and a persistent database layer. The application will have millions of users for 4 hours in the morning, but the application will have only a few thousand users during the rest of the day. The company's data architects have requested the ability to rapidly evolve their schema. Which solutions will meet these requirements and provide the MOST scalability? (Choose two.)

- A. Deploy Amazon DynamoDB as the database solution. Provision on-demand capacity.

- B. Deploy Amazon Aurora as the database solution. Choose the serverless DB engine mode.

- C. Deploy Amazon DynamoDB as the database solution. Ensure that DynamoDB auto scaling is enabled.

- D. Deploy the static content into an Amazon S3 bucket. Provision an Amazon CloudFront distribution with the S3 bucket as the origin.

E. Deploy the web servers for static content across a eet of Amazon EC2 instances in Auto Scaling groups. Configure the instances to periodically refresh the content from an Amazon Elastic File System (Amazon EFS) volume.

**Correct:** A, D
**Why:** DynamoDB (on‑demand) offers massive, bursty scalability with schema flexibility. S3 + CloudFront serves static content at scale.

**Incorrect:**
- B: Aurora Serverless is more ops overhead and cost for brief heavy peaks compared to DynamoDB.
- C: Auto scaling on provisioned may lag and require tuning vs. on‑demand.
- E: EC2 fleet for static content is unnecessary.


---

---

### Question #637

A solutions architect is designing a new service behind Amazon API Gateway. The request patterns for the service will be unpredictable and can change suddenly from 0 requests to over 500 per second. The total size of the data that needs to be persisted in a backend database is currently less than 1 GB with unpredictable future growth. Data can be queried using simple key-value requests. Which combination ofAWS services would meet these requirements? (Choose two.)

- A. AWS Fargate

- B. AWS Lambda

- C. Amazon DynamoDB

- D. Amazon EC2 Auto Scaling

E. MySQL-compatible Amazon Aurora

**Correct:** B, C
**Why:** Lambda scales to sudden bursts. DynamoDB provides key‑value storage with <1 GB easily and elastic throughput.

**Incorrect:**
- A: Fargate/ASG/Aurora add ops or are overkill for KB/MB‑scale key‑value.
- D: Fargate/ASG/Aurora add ops or are overkill for KB/MB‑scale key‑value.
- E: Fargate/ASG/Aurora add ops or are overkill for KB/MB‑scale key‑value.


---

---

### Question #650

A company wants to migrate its on-premises Microsoft SQL Server Enterprise edition database to AWS. The company's online application uses the database to process transactions. The data analysis team uses the same production database to run reports for analytical processing. The company wants to reduce operational overhead by moving to managed services wherever possible. Which solution will meet these requirements with the LEAST operational overhead?

- A. Migrate to Amazon RDS for Microsoft SOL Server. Use read replicas for reporting purposes

- B. Migrate to Microsoft SQL Server on Amazon EC2. Use Always On read replicas for reporting purposes

- C. Migrate to Amazon DynamoDB. Use DynamoDB on-demand replicas for reporting purposes

- D. Migrate to Amazon Aurora MySQL. Use Aurora read replicas for reporting purposes

**Correct:** A
**Why:** RDS for SQL Server Enterprise supports read replicas for reporting (Always On readable secondaries), reducing ops overhead compared to self‑managed EC2.

**Incorrect:**
- B: EC2 + Always On is higher ops.
- C: DynamoDB/Aurora MySQL require major app changes.
- D: DynamoDB/Aurora MySQL require major app changes.


---

## Amazon CloudFront

### Question #502

A company runs a website that uses a content management system (CMS) on Amazon EC2. The CMS runs on a single EC2 instance and uses an Amazon Aurora MySQL Multi-AZ DB instance for the data tier. Website images are stored on an Amazon Elastic Block Store (Amazon EBS) volume that is mounted inside the EC2 instance. Which combination of actions should a solutions architect take to improve the performance and resilience of the website? (Choose two.)

- A. Move the website images into an Amazon S3 bucket that is mounted on every EC2 instance

- B. Share the website images by using an NFS share from the primary EC2 instance. Mount this share on the other EC2 instances.

- C. Move the website images onto an Amazon Elastic File System (Amazon EFS) file system that is mounted on every EC2 instance.

- D. Create an Amazon Machine Image (AMI) from the existing EC2 instance. Use the AMI to provision new instances behind an Application Load Balancer as part of an Auto Scaling group. Configure the Auto Scaling group to maintain a minimum of two instances. Configure an accelerator in AWS Global Accelerator for the website

E. Create an Amazon Machine Image (AMI) from the existing EC2 instance. Use the AMI to provision new instances behind an Application Load Balancer as part of an Auto Scaling group. Configure the Auto Scaling group to maintain a minimum of two instances. Configure an Amazon CloudFront distribution for the website.

**Correct:** C, E
**Why:** Move images to EFS for shared, scalable storage; use ALB+Auto Scaling behind a CloudFront distribution for performance and resilience.

**Incorrect:**
- A: S3 mounted or EC2 NFS via a primary instance are not ideal.
- B: S3 mounted or EC2 NFS via a primary instance are not ideal.
- D: Global Accelerator is unnecessary for origin performance here.


---

---

### Question #513

A social media company wants to allow its users to upload images in an application that is hosted in the AWS Cloud. The company needs a solution that automatically resizes the images so that the images can be displayed on multiple device types. The application experiences unpredictable trac patterns throughout the day. The company is seeking a highly available solution that maximizes scalability. What should a solutions architect do to meet these requirements?

- A. Create a static website hosted in Amazon S3 that invokes AWS Lambda functions to resize the images and store the images in an Amazon S3 bucket.

- B. Create a static website hosted in Amazon CloudFront that invokes AWS Step Functions to resize the images and store the images in an Amazon RDS database.

- C. Create a dynamic website hosted on a web server that runs on an Amazon EC2 instance. Configure a process that runs on the EC2 instance to resize the images and store the images in an Amazon S3 bucket.

- D. Create a dynamic website hosted on an automatically scaling Amazon Elastic Container Service (Amazon ECS) cluster that creates a resize job in Amazon Simple Queue Service (Amazon SQS). Set up an image-resizing program that runs on an Amazon EC2 instance to process the resize jobs.

**Correct:** A
**Why:** Static site front end in S3 with Lambda resizing on upload provides high availability and scalability with minimal ops; store results in S3.

**Incorrect:**
- B: CloudFront+Step Functions/EC2/ECS add complexity and are less serverless.
- C: CloudFront+Step Functions/EC2/ECS add complexity and are less serverless.
- D: CloudFront+Step Functions/EC2/ECS add complexity and are less serverless.


---

---

### Question #523

A company runs a microservice-based serverless web application. The application must be able to retrieve data from multiple Amazon DynamoDB tables A solutions architect needs to give the application the ability to retrieve the data with no impact on the baseline performance of the application. Which solution will meet these requirements in the MOST operationally ecient way?

- A. AWS AppSync pipeline resolvers

- B. Amazon CloudFront with Lambda@Edge functions

- C. Edge-optimized Amazon API Gateway with AWS Lambda functions

- D. Amazon Athena Federated Query with a DynamoDB connector

**Correct:** A
**Why:** AppSync pipeline resolvers can aggregate data from multiple DynamoDB tables efficiently without impacting baseline performance.

**Incorrect:**
- B: Edge/REST proxy/Athena are less suitable for orchestrated multi‑table reads in a serverless app.
- C: Edge/REST proxy/Athena are less suitable for orchestrated multi‑table reads in a serverless app.
- D: Edge/REST proxy/Athena are less suitable for orchestrated multi‑table reads in a serverless app.


---

---

### Question #530

A company has an online gaming application that has TCP and UDP multiplayer gaming capabilities. The company uses Amazon Route 53 to point the application trac to multiple Network Load Balancers (NLBs) in different AWS Regions. The company needs to improve application performance and decrease latency for the online game in preparation for user growth. Which solution will meet these requirements?

- A. Add an Amazon CloudFront distribution in front of the NLBs. Increase the Cache-Control max-age parameter.

- B. Replace the NLBs with Application Load Balancers (ALBs). Configure Route 53 to use latency-based routing.

- C. Add AWS Global Accelerator in front of the NLBs. Configure a Global Accelerator endpoint to use the correct listener ports.

- D. Add an Amazon API Gateway endpoint behind the NLBs. Enable API caching. Override method caching for the different stages.

**Correct:** C
**Why:** Global Accelerator improves global TCP/UDP performance with anycast IPs in front of NLBs.

**Incorrect:**
- A: CloudFront/ALB/API Gateway are not suited for arbitrary TCP/UDP improvements.
- B: CloudFront/ALB/API Gateway are not suited for arbitrary TCP/UDP improvements.
- D: CloudFront/ALB/API Gateway are not suited for arbitrary TCP/UDP improvements.


---

---

### Question #538

A global video streaming company uses Amazon CloudFront as a content distribution network (CDN). The company wants to roll out content in a phased manner across multiple countries. The company needs to ensure that viewers who are outside the countries to which the company rolls out content are not able to view the content. Which solution will meet these requirements?

- A. Add geographic restrictions to the content in CloudFront by using an allow list. Set up a custom error message.

- B. Set up a new URL tor restricted content. Authorize access by using a signed URL and cookies. Set up a custom error message.

- C. Encrypt the data for the content that the company distributes. Set up a custom error message.

- D. Create a new URL for restricted content. Set up a time-restricted access policy for signed URLs.

**Correct:** A
**Why:** Use CloudFront geo‑restriction allow lists to limit content to rolled‑out countries, with custom error messages for others.

**Incorrect:**
- B: Signed URLs/time limits do not enforce geography.
- C: Encryption does not restrict access by country.
- D: Signed URLs/time limits do not enforce geography.


---

---

### Question #541

A company wants to build a web application on AWS. Client access requests to the website are not predictable and can be idle for a long time. Only customers who have paid a subscription fee can have the ability to sign in and use the web application. Which combination of steps will meet these requirements MOST cost-effectively? (Choose three.)

- A. Create an AWS Lambda function to retrieve user information from Amazon DynamoDB. Create an Amazon API Gateway endpoint to accept RESTful APIs. Send the API calls to the Lambda function.

- B. Create an Amazon Elastic Container Service (Amazon ECS) service behind an Application Load Balancer to retrieve user information from Amazon RDS. Create an Amazon API Gateway endpoint to accept RESTful APIs. Send the API calls to the Lambda function.

- C. Create an Amazon Cognito user pool to authenticate users.

- D. Create an Amazon Cognito identity pool to authenticate users.

E. Use AWS Amplify to serve the frontend web content with HTML, CSS, and JS. Use an integrated Amazon CloudFront configuration.

F. Use Amazon S3 static web hosting with PHP, CSS, and JS. Use Amazon CloudFront to serve the frontend web content.

**Correct:** A, C, E
**Why:** Serverless API (API Gateway → Lambda) is cost‑effective for spiky/idle loads; Cognito user pool handles subscription auth; Amplify hosts frontend with integrated CloudFront.

**Incorrect:**
- B: ECS/EC2 PHP or identity pools are unnecessary here.
- D: ECS/EC2 PHP or identity pools are unnecessary here.
- F: ECS/EC2 PHP or identity pools are unnecessary here.


---

---

### Question #542

A media company uses an Amazon CloudFront distribution to deliver content over the internet. The company wants only premium customers to have access to the media streams and file content. The company stores all content in an Amazon S3 bucket. The company also delivers content on demand to customers for a specic purpose, such as movie rentals or music downloads. Which solution will meet these requirements?

- A. Generate and provide S3 signed cookies to premium customers.

- B. Generate and provide CloudFront signed URLs to premium customers.

- C. Use origin access control (OAC) to limit the access of non-premium customers.

- D. Generate and activate eld-level encryption to block non-premium customers.

**Correct:** B
**Why:** CloudFront signed URLs restrict access to premium, time‑limited content from the S3 origin.

**Incorrect:**
- A: S3 signed cookies are not used with CloudFront for this scenario.
- C: OAC/encryption do not implement premium gating.
- D: OAC/encryption do not implement premium gating.


---

---

### Question #568

A solutions architect is designing the storage architecture for a new web application used for storing and viewing engineering drawings. All application components will be deployed on the AWS infrastructure. The application design must support caching to minimize the amount of time that users wait for the engineering drawings to load. The application must be able to store petabytes of data. Which combination of storage and caching should the solutions architect use?

- A. Amazon S3 with Amazon CloudFront

- B. Amazon S3 Glacier with Amazon ElastiCache

- C. Amazon Elastic Block Store (Amazon EBS) volumes with Amazon CloudFront

- D. AWS Storage Gateway with Amazon ElastiCache

**Correct:** A
**Why:** Amazon S3 scales to petabytes and serves as durable storage. CloudFront provides global edge caching to reduce latency loading large drawings.

**Incorrect:**
- B: Glacier is archival and not suited for frequent/interactive access.
- C: EBS is block storage tied to instances; not optimal for petabyte-scale/serving globally.
- D: Storage Gateway is for hybrid integrations; not needed when fully on AWS.


---

---

### Question #576

A company is building a RESTful serverless web application on AWS by using Amazon API Gateway and AWS Lambda. The users of this web application will be geographically distributed, and the company wants to reduce the latency of API requests to these users. Which type of endpoint should a solutions architect use to meet these requirements?

- A. Private endpoint

- B. Regional endpoint

- C. Interface VPC endpoint

- D. Edge-optimized endpoint

**Correct:** D
**Why:** Edge-optimized API Gateway endpoints use CloudFront to reduce latency for geographically distributed users.

**Incorrect:**
- A: Private endpoints are for VPC-only access.
- B: Regional endpoints don’t leverage global edge locations.
- C: Interface VPC endpoints are for private access within a VPC, not global latency reduction.


---

---

### Question #577

A company uses an Amazon CloudFront distribution to serve content pages for its website. The company needs to ensure that clients use a TLS certicate when accessing the company's website. The company wants to automate the creation and renewal of the TLS certicates. Which solution will meet these requirements with the MOST operational eciency?

- A. Use a CloudFront security policy to create a certicate.

- B. Use a CloudFront origin access control (OAC) to create a certicate.

- C. Use AWS Certicate Manager (ACM) to create a certicate. Use DNS validation for the domain.

- D. Use AWS Certicate Manager (ACM) to create a certicate. Use email validation for the domain.

**Correct:** C
**Why:** Use ACM with DNS validation for automatic renewal and simple management of certificates used by CloudFront.

**Incorrect:**
- A: CloudFront policies and OAC do not create TLS certificates.
- B: CloudFront policies and OAC do not create TLS certificates.
- D: Email validation works but is more operationally intensive than DNS validation.


---

---

### Question #592

A company uses AWS and sells access to copyrighted images. The company’s global customer base needs to be able to access these images quickly. The company must deny access to users from specic countries. The company wants to minimize costs as much as possible. Which solution will meet these requirements?

- A. Use Amazon S3 to store the images. Turn on multi-factor authentication (MFA) and public bucket access. Provide customers with a link to the S3 bucket.

- B. Use Amazon S3 to store the images. Create an IAM user for each customer. Add the users to a group that has permission to access the S3 bucket.

- C. Use Amazon EC2 instances that are behind Application Load Balancers (ALBs) to store the images. Deploy the instances only in the countries the company services. Provide customers with links to the ALBs for their specic country's instances.

- D. Use Amazon S3 to store the images. Use Amazon CloudFront to distribute the images with geographic restrictions. Provide a signed URL for each customer to access the data in CloudFront.

**Correct:** D
**Why:** S3 with CloudFront provides low‑latency global delivery. Geo restrictions and signed URLs enforce country blocks and per‑customer access.

**Incorrect:**
- A: Public buckets or per‑user IAM are insecure or operationally heavy.
- B: Public buckets or per‑user IAM are insecure or operationally heavy.
- C: EC2 + ALB for serving files is costly and complex.


---

---

### Question #600

A company is planning to migrate a TCP-based application into the company's VPC. The application is publicly accessible on a nonstandard TCP port through a hardware appliance in the company's data center. This public endpoint can process up to 3 million requests per second with low latency. The company requires the same level of performance for the new public endpoint in AWS. What should a solutions architect recommend to meet this requirement?

- A. Deploy a Network Load Balancer (NLB). Configure the NLB to be publicly accessible over the TCP port that the application requires.

- B. Deploy an Application Load Balancer (ALB). Configure the ALB to be publicly accessible over the TCP port that the application requires.

- C. Deploy an Amazon CloudFront distribution that listens on the TCP port that the application requires. Use an Application Load Balancer as the origin.

- D. Deploy an Amazon API Gateway API that is congured with the TCP port that the application requires. Configure AWS Lambda functions with provisioned concurrency to process the requests.

**Correct:** A
**Why:** NLB supports millions of requests per second with low latency on arbitrary TCP ports.

**Incorrect:**
- B: ALB is HTTP/HTTPS (L7) and not optimized for raw TCP performance at this scale.
- C: CloudFront/API Gateway do not meet the raw TCP nonstandard port requirement.
- D: CloudFront/API Gateway do not meet the raw TCP nonstandard port requirement.


---

---

### Question #622

A company is creating a new web application for its subscribers. The application will consist of a static single page and a persistent database layer. The application will have millions of users for 4 hours in the morning, but the application will have only a few thousand users during the rest of the day. The company's data architects have requested the ability to rapidly evolve their schema. Which solutions will meet these requirements and provide the MOST scalability? (Choose two.)

- A. Deploy Amazon DynamoDB as the database solution. Provision on-demand capacity.

- B. Deploy Amazon Aurora as the database solution. Choose the serverless DB engine mode.

- C. Deploy Amazon DynamoDB as the database solution. Ensure that DynamoDB auto scaling is enabled.

- D. Deploy the static content into an Amazon S3 bucket. Provision an Amazon CloudFront distribution with the S3 bucket as the origin.

E. Deploy the web servers for static content across a eet of Amazon EC2 instances in Auto Scaling groups. Configure the instances to periodically refresh the content from an Amazon Elastic File System (Amazon EFS) volume.

**Correct:** A, D
**Why:** DynamoDB (on‑demand) offers massive, bursty scalability with schema flexibility. S3 + CloudFront serves static content at scale.

**Incorrect:**
- B: Aurora Serverless is more ops overhead and cost for brief heavy peaks compared to DynamoDB.
- C: Auto scaling on provisioned may lag and require tuning vs. on‑demand.
- E: EC2 fleet for static content is unnecessary.


---

---

### Question #623

A company uses Amazon API Gateway to manage its REST APIs that third-party service providers access. The company must protect the REST APIs from SQL injection and cross-site scripting attacks. What is the MOST operationally ecient solution that meets these requirements?

- A. Configure AWS Shield.

- B. Configure AWS WAF.

- C. Set up API Gateway with an Amazon CloudFront distribution. Configure AWS Shield in CloudFront.

- D. Set up API Gateway with an Amazon CloudFront distribution. Configure AWS WAF in CloudFront.

**Correct:** B
**Why:** AWS WAF protects against SQLi and XSS and integrates with API Gateway via CloudFront or regional.

**Incorrect:**
- A: Shield is for DDoS mitigation, not app‑layer attacks.
- C: Shield is for DDoS mitigation, not app‑layer attacks.
- D: WAF can be attached via CloudFront, but adding CF is not required for REST APIs; direct WAF is simpler.


---

---

### Question #625

A company is hosting a website behind multiple Application Load Balancers. The company has different distribution rights for its content around the world. A solutions architect needs to ensure that users are served the correct content without violating distribution rights. Which configuration should the solutions architect choose to meet these requirements?

- A. Configure Amazon CloudFront with AWS WAF.

- B. Configure Application Load Balancers with AWS WAF

- C. Configure Amazon Route 53 with a geolocation policy

- D. Configure Amazon Route 53 with a geoproximity routing policy

**Correct:** C
**Why:** Route 53 geolocation routing serves content based on user location across multiple ALB endpoints to respect distribution rights.

**Incorrect:**
- A: WAF doesn’t handle routing to different content by geography.
- B: WAF doesn’t handle routing to different content by geography.
- D: Geoproximity adjusts by distance/bias, not strict country mapping.


---

---

### Question #647

A gaming company is building an application with Voice over IP capabilities. The application will serve trac to users across the world. The application needs to be highly available with an automated failover across AWS Regions. The company wants to minimize the latency of users without relying on IP address caching on user devices. What should a solutions architect do to meet these requirements?

- A. Use AWS Global Accelerator with health checks.

- B. Use Amazon Route 53 with a geolocation routing policy.

- C. Create an Amazon CloudFront distribution that includes multiple origins.

- D. Create an Application Load Balancer that uses path-based routing.

**Correct:** A
**Why:** Global Accelerator provides anycast IPs, health checks, and automatic multi‑Region failover without relying on DNS caching.

**Incorrect:**
- B: Route 53 relies on DNS caching/TTL.
- C: CloudFront is for HTTP(S), not generic VoIP/UDP or bi‑directional traffic patterns.
- D: ALB routes within a Region only.


---

---

### Question #654

A company recently migrated its web application to the AWS Cloud. The company uses an Amazon EC2 instance to run multiple processes to host the application. The processes include an Apache web server that serves static content. The Apache web server makes requests to a PHP application that uses a local Redis server for user sessions. The company wants to redesign the architecture to be highly available and to use AWS managed solutions. Which solution will meet these requirements?

- A. Use AWS Elastic Beanstalk to host the static content and the PHP application. Configure Elastic Beanstalk to deploy its EC2 instance into a public subnet. Assign a public IP address.

- B. Use AWS Lambda to host the static content and the PHP application. Use an Amazon API Gateway REST API to proxy requests to the Lambda function. Set the API Gateway CORS configuration to respond to the domain name. Configure Amazon ElastiCache for Redis to handle session information.

- C. Keep the backend code on the EC2 instance. Create an Amazon ElastiCache for Redis cluster that has Multi-AZ enabled. Configure the ElastiCache for Redis cluster in cluster mode. Copy the frontend resources to Amazon S3. Configure the backend code to reference the EC2 instance.

- D. Configure an Amazon CloudFront distribution with an Amazon S3 endpoint to an S3 bucket that is congured to host the static content. Configure an Application Load Balancer that targets an Amazon Elastic Container Service (Amazon ECS) service that runs AWS Fargate tasks for the PHP application. Configure the PHP application to use an Amazon ElastiCache for Redis cluster that runs in multiple Availability Zones.

**Correct:** D
**Why:** S3 + CloudFront for static assets; ECS Fargate behind ALB for PHP app; Redis (Multi‑AZ) for sessions meets HA with managed services.

**Incorrect:**
- A: Single EC2 in public subnet is not HA.
- B: Lambda for PHP monolith adds complexity and cold‑start concerns.
- C: Keeping backend on EC2 is not fully managed/HA.


---

---

### Question #684

A company wants to migrate its web applications from on premises to AWS. The company is located close to the eu-central-1 Region. Because of regulations, the company cannot launch some of its applications in eu-central-1. The company wants to achieve single-digit millisecond latency. Which solution will meet these requirements?

- A. Deploy the applications in eu-central-1. Extend the company’s VPC from eu-central-1 to an edge location in Amazon CloudFront.

- B. Deploy the applications in AWS Local Zones by extending the company's VPC from eu-central-1 to the chosen Local Zone.

- C. Deploy the applications in eu-central-1. Extend the company’s VPC from eu-central-1 to the regional edge caches in Amazon CloudFront.

- D. Deploy the applications in AWS Wavelength Zones by extending the company’s VPC from eu-central-1 to the chosen Wavelength Zone.

**Correct:** B
**Why:** Deploy to AWS Local Zones to achieve single‑digit ms latency near the users while associating with eu‑central‑1 control plane; CloudFront/Wavelength do not host the applications.

**Incorrect:**
- A: CloudFront cannot host applications; only caches content.
- C: CloudFront cannot host applications; only caches content.
- D: Wavelength Zones target 5G/mobile edge and are not general app hosting replacements.


---

## Amazon CloudWatch & EventBridge

### Question #503

A company runs an infrastructure monitoring service. The company is building a new feature that will enable the service to monitor data in customer AWS accounts. The new feature will call AWS APIs in customer accounts to describe Amazon EC2 instances and read Amazon CloudWatch metrics. What should the company do to obtain access to customer accounts in the MOST secure way?

- A. Ensure that the customers create an IAM role in their account with read-only EC2 and CloudWatch permissions and a trust policy to the company’s account.

- B. Create a serverless API that implements a token vending machine to provide temporary AWS credentials for a role with read-only EC2 and CloudWatch permissions.

- C. Ensure that the customers create an IAM user in their account with read-only EC2 and CloudWatch permissions. Encrypt and store customer access and secret keys in a secrets management system.

- D. Ensure that the customers create an Amazon Cognito user in their account to use an IAM role with read-only EC2 and CloudWatch permissions. Encrypt and store the Amazon Cognito user and password in a secrets management system.

**Correct:** A
**Why:** Customers create a read‑only role with a trust to the company’s account; the company assumes the role securely with STS.

**Incorrect:**
- B: Do not use long‑lived credentials; Cognito/users are not appropriate.
- C: Do not use long‑lived credentials; Cognito/users are not appropriate.
- D: Do not use long‑lived credentials; Cognito/users are not appropriate.


---

---

### Question #517

A company wants to send all AWS Systems Manager Session Manager logs to an Amazon S3 bucket for archival purposes. Which solution will meet this requirement with the MOST operational eciency?

- A. Enable S3 logging in the Systems Manager console. Choose an S3 bucket to send the session data to.

- B. Install the Amazon CloudWatch agent. Push all logs to a CloudWatch log group. Export the logs to an S3 bucket from the group for archival purposes.

- C. Create a Systems Manager document to upload all server logs to a central S3 bucket. Use Amazon EventBridge to run the Systems Manager document against all servers that are in the account daily.

- D. Install an Amazon CloudWatch agent. Push all logs to a CloudWatch log group. Create a CloudWatch logs subscription that pushes any incoming log events to an Amazon Kinesis Data Firehose delivery stream. Set Amazon S3 as the destination.

**Correct:** A
**Why:** Session Manager supports direct delivery of session logs to S3 from the console with minimal setup.

**Incorrect:**
- B: Extra agents/pipelines add complexity.
- C: Extra agents/pipelines add complexity.
- D: Extra agents/pipelines add complexity.


---

---

### Question #528

A data analytics company wants to migrate its batch processing system to AWS. The company receives thousands of small data files periodically during the day through FTP. An on-premises batch job processes the data files overnight. However, the batch job takes hours to nish running. The company wants the AWS solution to process incoming data files as soon as possible with minimal changes to the FTP clients that send the files. The solution must delete the incoming data files after the files have been processed successfully. Processing for each file needs to take 3-8 minutes. Which solution will meet these requirements in the MOST operationally ecient way?

- A. Use an Amazon EC2 instance that runs an FTP server to store incoming files as objects in Amazon S3 Glacier Flexible Retrieval. Configure a job queue in AWS Batch. Use Amazon EventBridge rules to invoke the job to process the objects nightly from S3 Glacier Flexible Retrieval. Delete the objects after the job has processed the objects.

- B. Use an Amazon EC2 instance that runs an FTP server to store incoming files on an Amazon Elastic Block Store (Amazon EBS) volume. Configure a job queue in AWS Batch. Use Amazon EventBridge rules to invoke the job to process the files nightly from the EBS volume. Delete the files after the job has processed the files.

- C. Use AWS Transfer Family to create an FTP server to store incoming files on an Amazon Elastic Block Store (Amazon EBS) volume. Configure a job queue in AWS Batch. Use an Amazon S3 event notification when each file arrives to invoke the job in AWS Batch. Delete the files after the job has processed the files.

- D. Use AWS Transfer Family to create an FTP server to store incoming files in Amazon S3 Standard. Create an AWS Lambda function to process the files and to delete the files after they are processed. Use an S3 event notification to invoke the Lambda function when the files arrive.

**Correct:** D
**Why:** Transfer Family (FTP) to S3 with S3 event → Lambda processes and deletes files as they arrive—near real time, minimal client changes.

**Incorrect:**
- A: Glacier/EBS nightly batches or Batch jobs add latency/ops.
- B: Glacier/EBS nightly batches or Batch jobs add latency/ops.
- C: Glacier/EBS nightly batches or Batch jobs add latency/ops.


---

---

### Question #529

A company is migrating its workloads to AWS. The company has transactional and sensitive data in its databases. The company wants to use AWS Cloud solutions to increase security and reduce operational overhead for the databases. Which solution will meet these requirements?

- A. Migrate the databases to Amazon EC2. Use an AWS Key Management Service (AWS KMS) AWS managed key for encryption.

- B. Migrate the databases to Amazon RDS Configure encryption at rest.

- C. Migrate the data to Amazon S3 Use Amazon Macie for data security and protection

- D. Migrate the database to Amazon RDS. Use Amazon CloudWatch Logs for data security and protection.

**Correct:** B
**Why:** RDS is managed, supports encryption at rest/in transit, and reduces operational overhead for transactional/sensitive data.

**Incorrect:**
- A: EC2/CloudWatch Logs/Macie alone do not meet the database requirements.
- C: EC2/CloudWatch Logs/Macie alone do not meet the database requirements.
- D: EC2/CloudWatch Logs/Macie alone do not meet the database requirements.


---

---

### Question #533

A company stores data in Amazon S3. According to regulations, the data must not contain personally identiable information (PII). The company recently discovered that S3 buckets have some objects that contain PII. The company needs to automatically detect PII in S3 buckets and to notify the company’s security team. Which solution will meet these requirements?

- A. Use Amazon Macie. Create an Amazon EventBridge rule to filter the SensitiveData event type from Macie ndings and to send an Amazon Simple Notification Service (Amazon SNS) notification to the security team.

- B. Use Amazon GuardDuty. Create an Amazon EventBridge rule to filter the CRITICAL event type from GuardDuty ndings and to send an Amazon Simple Notification Service (Amazon SNS) notification to the security team.

- C. Use Amazon Macie. Create an Amazon EventBridge rule to filter the SensitiveData:S3Object/Personal event type from Macie ndings and to send an Amazon Simple Queue Service (Amazon SQS) notification to the security team.

- D. Use Amazon GuardDuty. Create an Amazon EventBridge rule to filter the CRITICAL event type from GuardDuty ndings and to send an Amazon Simple Queue Service (Amazon SQS) notification to the security team.

**Correct:** A
**Why:** Macie detects PII in S3; route SensitiveData events to SNS via EventBridge to notify security.

**Incorrect:**
- B: GuardDuty is not for PII in S3.
- C: SQS is not ideal for notifications to humans.
- D: GuardDuty is not for PII in S3.


---

---

### Question #563

A company runs its applications on both Amazon Elastic Kubernetes Service (Amazon EKS) clusters and on-premises Kubernetes clusters. The company wants to view all clusters and workloads from a central location. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use Amazon CloudWatch Container Insights to collect and group the cluster information.

- B. Use Amazon EKS Connector to register and connect all Kubernetes clusters.

- C. Use AWS Systems Manager to collect and view the cluster information.

- D. Use Amazon EKS Anywhere as the primary cluster to view the other clusters with native Kubernetes commands.

**Correct:** B
**Why:** Amazon EKS Connector lets you register both EKS and on-premises Kubernetes clusters to view and manage them centrally in the EKS console with low operational overhead.

**Incorrect:**
- A: CloudWatch Container Insights collects metrics/logs per cluster; it doesn’t serve as a single pane to register non-EKS clusters.
- C: Systems Manager doesn’t centrally register and view Kubernetes clusters.
- D: EKS Anywhere is for on-prem provisioning/management, not a central view of arbitrary existing clusters.


---

---

### Question #569

An Amazon EventBridge rule targets a third-party API. The third-party API has not received any incoming trac. A solutions architect needs to determine whether the rule conditions are being met and if the rule's target is being invoked. Which solution will meet these requirements?

- A. Check for metrics in Amazon CloudWatch in the namespace for AWS/Events.

- B. Review events in the Amazon Simple Queue Service (Amazon SQS) dead-letter queue.

- C. Check for the events in Amazon CloudWatch Logs.

- D. Check the trails in AWS CloudTrail for the EventBridge events.

**Correct:** A
**Why:** CloudWatch provides AWS/Events metrics (e.g., Invocations, MatchedEvents, DeliveryToTargetFailures) to verify rule matching and target invocation.

**Incorrect:**
- B: DLQ is relevant if a target supports and you configured one; not inherent for third-party API targets.
- C: CloudWatch Logs may be used if target logs there, but the primary signal for EventBridge rule evaluation is CloudWatch metrics.
- D: CloudTrail logs API calls, not internal EventBridge rule evaluations and target invocations.


---

---

### Question #570

A company has a large workload that runs every Friday evening. The workload runs on Amazon EC2 instances that are in two Availability Zones in the us-east-1 Region. Normally, the company must run no more than two instances at all times. However, the company wants to scale up to six instances each Friday to handle a regularly repeating increased workload. Which solution will meet these requirements with the LEAST operational overhead?

- A. Create a reminder in Amazon EventBridge to scale the instances.

- B. Create an Auto Scaling group that has a scheduled action.

- C. Create an Auto Scaling group that uses manual scaling.

- D. Create an Auto Scaling group that uses automatic scaling.

**Correct:** B
**Why:** Use an Auto Scaling group with a scheduled action to scale out to six instances each Friday and scale back after, minimizing overhead.

**Incorrect:**
- A: EventBridge reminder alone doesn’t scale instances.
- C: Manual scaling is error-prone and operationally heavy.
- D: Target tracking or step scaling won’t pre-warm for a predictable weekly spike as effectively as scheduled actions.


---

---

### Question #597

A company hosts an internal serverless application on AWS by using Amazon API Gateway and AWS Lambda. The company’s employees report issues with high latency when they begin using the application each day. The company wants to reduce latency. Which solution will meet these requirements?

- A. Increase the API Gateway throttling limit.

- B. Set up a scheduled scaling to increase Lambda provisioned concurrency before employees begin to use the application each day.

- C. Create an Amazon CloudWatch alarm to initiate a Lambda function as a target for the alarm at the beginning of each day.

- D. Increase the Lambda function memory.

**Correct:** B
**Why:** Schedule provisioned concurrency before users start to eliminate cold starts and reduce latency.

**Incorrect:**
- A: API Gateway throttling limits won’t affect cold starts.
- C: Invoking a warm‑up Lambda is ad‑hoc vs. built‑in provisioned concurrency.
- D: More memory doesn’t eliminate cold starts.


---

---

### Question #615

A company runs a critical, customer-facing application on Amazon Elastic Kubernetes Service (Amazon EKS). The application has a microservices architecture. The company needs to implement a solution that collects, aggregates, and summarizes metrics and logs from the application in a centralized location. Which solution meets these requirements?

- A. Run the Amazon CloudWatch agent in the existing EKS cluster. View the metrics and logs in the CloudWatch console.

- B. Run AWS App Mesh in the existing EKS cluster. View the metrics and logs in the App Mesh console.

- C. Configure AWS CloudTrail to capture data events. Query CloudTrail by using Amazon OpenSearch Service.

- D. Configure Amazon CloudWatch Container Insights in the existing EKS cluster. View the metrics and logs in the CloudWatch console.

**Correct:** D
**Why:** CloudWatch Container Insights provides cluster‑wide metrics and logs aggregation for EKS with centralized dashboards.

**Incorrect:**
- A: Agent alone lacks curated EKS insights.
- B: App Mesh is a service mesh, not a logging/metrics aggregator.
- C: CloudTrail data events are not application metrics/logs.


---

---

### Question #616

A company has deployed its newest product on AWS. The product runs in an Auto Scaling group behind a Network Load Balancer. The company stores the product’s objects in an Amazon S3 bucket. The company recently experienced malicious attacks against its systems. The company needs a solution that continuously monitors for malicious activity in the AWS account, workloads, and access patterns to the S3 bucket. The solution must also report suspicious activity and display the information on a dashboard. Which solution will meet these requirements?

- A. Configure Amazon Macie to monitor and report ndings to AWS Cong.

- B. Configure Amazon Inspector to monitor and report ndings to AWS CloudTrail.

- C. Configure Amazon GuardDuty to monitor and report ndings to AWS Security Hub.

- D. Configure AWS Cong to monitor and report ndings to Amazon EventBridge.

**Correct:** C
**Why:** GuardDuty continuously monitors account, workload, and S3 access for threats; Security Hub aggregates and dashboards findings.

**Incorrect:**
- A: Macie focuses on sensitive data discovery, not threat detection.
- B: Inspector is for vulnerability assessment, not S3 access/threat patterns.
- D: Config tracks resource configuration, not threat activity.


---

---

### Question #627

A company wants to migrate two DNS servers to AWS. The servers host a total of approximately 200 zones and receive 1 million requests each day on average. The company wants to maximize availability while minimizing the operational overhead that is related to the management of the two servers. What should a solutions architect recommend to meet these requirements?

- A. Create 200 new hosted zones in the Amazon Route 53 console Import zone files.

- B. Launch a single large Amazon EC2 instance Import zone tiles. Configure Amazon CloudWatch alarms and notications to alert the company about any downtime.

- C. Migrate the servers to AWS by using AWS Server Migration Service (AWS SMS). Configure Amazon CloudWatch alarms and notications to alert the company about any downtime.

- D. Launch an Amazon EC2 instance in an Auto Scaling group across two Availability Zones. Import zone files. Set the desired capacity to 1 and the maximum capacity to 3 for the Auto Scaling group. Configure scaling alarms to scale based on CPU utilization.

**Correct:** A
**Why:** Route 53 hosted zones are fully managed and highly available. Import existing zone files for low operational overhead.

**Incorrect:**
- B: EC2‑based DNS introduces ops burden and single points or scaling work.
- C: EC2‑based DNS introduces ops burden and single points or scaling work.
- D: EC2‑based DNS introduces ops burden and single points or scaling work.


---

---

### Question #630

A solutions architect is creating a data processing job that runs once daily and can take up to 2 hours to complete. If the job is interrupted, it has to restart from the beginning. How should the solutions architect address this issue in the MOST cost-effective manner?

- A. Create a script that runs locally on an Amazon EC2 Reserved Instance that is triggered by a cron job.

- B. Create an AWS Lambda function triggered by an Amazon EventBridge scheduled event.

- C. Use an Amazon Elastic Container Service (Amazon ECS) Fargate task triggered by an Amazon EventBridge scheduled event.

- D. Use an Amazon Elastic Container Service (Amazon ECS) task running on Amazon EC2 triggered by an Amazon EventBridge scheduled event.

**Correct:** C
**Why:** ECS Fargate scheduled by EventBridge runs containers up to hours long without managing servers; resilient to interruptions.

**Incorrect:**
- A: A single RI instance is brittle and always on.
- B: Lambda max runtime is insufficient for a 2‑hour job.
- D: ECS on EC2 requires capacity management.


---

---

### Question #653

A company maintains an Amazon RDS database that maps users to cost centers. The company has accounts in an organization in AWS Organizations. The company needs a solution that will tag all resources that are created in a specic AWS account in the organization. The solution must tag each resource with the cost center ID of the user who created the resource. Which solution will meet these requirements?

- A. Move the specic AWS account to a new organizational unit (OU) in Organizations from the management account. Create a service control policy (SCP) that requires all existing resources to have the correct cost center tag before the resources are created. Apply the SCP to the new OU.

- B. Create an AWS Lambda function to tag the resources after the Lambda function looks up the appropriate cost center from the RDS database. Configure an Amazon EventBridge rule that reacts to AWS CloudTrail events to invoke the Lambda function.

- C. Create an AWS CloudFormation stack to deploy an AWS Lambda function. Configure the Lambda function to look up the appropriate cost center from the RDS database and to tag resources. Create an Amazon EventBridge scheduled rule to invoke the CloudFormation stack.

- D. Create an AWS Lambda function to tag the resources with a default value. Configure an Amazon EventBridge rule that reacts to AWS CloudTrail events to invoke the Lambda function when a resource is missing the cost center tag.

**Correct:** B
**Why:** Use EventBridge (CloudTrail events) to invoke Lambda that tags new resources after looking up the creator’s cost center in RDS.

**Incorrect:**
- A: SCPs cannot inject tags pre‑creation; they can only allow/deny.
- C: Re‑deploying a stack on a schedule won’t tag arbitrary resources created outside CloudFormation.
- D: Default tags without lookup won’t meet correctness.


---

---

### Question #662

A company uses AWS Cost Explorer to monitor its AWS costs. The company notices that Amazon Elastic Block Store (Amazon EBS) storage and snapshot costs increase every month. However, the company does not purchase additional EBS storage every month. The company wants to optimize monthly costs for its current storage usage. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use logs in Amazon CloudWatch Logs to monitor the storage utilization of Amazon EBS. Use Amazon EBS Elastic Volumes to reduce the size of the EBS volumes.

- B. Use a custom script to monitor space usage. Use Amazon EBS Elastic Volumes to reduce the size of the EBS volumes.

- C. Delete all expired and unused snapshots to reduce snapshot costs.

- D. Delete all nonessential snapshots. Use Amazon Data Lifecycle Manager to create and manage the snapshots according to the company's snapshot policy requirements.

**Correct:** D
**Why:** Clean up nonessential snapshots and automate lifecycle with Data Lifecycle Manager to control ongoing costs.

**Incorrect:**
- A: Monitoring alone doesn’t reduce costs; resizing EBS may not be feasible.
- B: Monitoring alone doesn’t reduce costs; resizing EBS may not be feasible.
- C: Only expired/unused snapshots should be deleted; policy is required for ongoing control.


---

---

### Question #669

A company runs its databases on Amazon RDS for PostgreSQL. The company wants a secure solution to manage the master user password by rotating the password every 30 days. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use Amazon EventBridge to schedule a custom AWS Lambda function to rotate the password every 30 days.

- B. Use the modify-db-instance command in the AWS CLI to change the password.

- C. Integrate AWS Secrets Manager with Amazon RDS for PostgreSQL to automate password rotation.

- D. Integrate AWS Systems Manager Parameter Store with Amazon RDS for PostgreSQL to automate password rotation.

**Correct:** C
**Why:** Secrets Manager integrates with RDS to automatically rotate the master password on a schedule with minimal ops.

**Incorrect:**
- A: Custom Lambda is more work.
- B: CLI changes are manual and error‑prone.
- D: Parameter Store lacks built‑in rotation for RDS master passwords.


---

---

### Question #671

A company runs its applications on Amazon EC2 instances. The company performs periodic nancial assessments of its AWS costs. The company recently identied unusual spending. The company needs a solution to prevent unusual spending. The solution must monitor costs and notify responsible stakeholders in the event of unusual spending. Which solution will meet these requirements?

- A. Use an AWS Budgets template to create a zero spend budget.

- B. Create an AWS Cost Anomaly Detection monitor in the AWS Billing and Cost Management console.

- C. Create AWS Pricing Calculator estimates for the current running workload pricing details.

- D. Use Amazon CloudWatch to monitor costs and to identify unusual spending.

**Correct:** B
**Why:** AWS Cost Anomaly Detection monitors spend with ML and sends alerts on unusual patterns, meeting prevention and notification needs.

**Incorrect:**
- A: A zero‑spend budget is not practical and does not detect anomalies appropriately.
- C: Pricing Calculator is for estimates, not monitoring actual spend.
- D: CloudWatch does not natively monitor detailed cost anomalies; use Cost Anomaly Detection.


---

---

### Question #676

A company's application uses Network Load Balancers, Auto Scaling groups, Amazon EC2 instances, and databases that are deployed in an Amazon VPC. The company wants to capture information about trac to and from the network interfaces in near real time in its Amazon VPC. The company wants to send the information to Amazon OpenSearch Service for analysis. Which solution will meet these requirements?

- A. Create a log group in Amazon CloudWatch Logs. Configure VPC Flow Logs to send the log data to the log group. Use Amazon Kinesis Data Streams to stream the logs from the log group to OpenSearch Service.

- B. Create a log group in Amazon CloudWatch Logs. Configure VPC Flow Logs to send the log data to the log group. Use Amazon Kinesis Data Firehose to stream the logs from the log group to OpenSearch Service.

- C. Create a trail in AWS CloudTrail. Configure VPC Flow Logs to send the log data to the trail. Use Amazon Kinesis Data Streams to stream the logs from the trail to OpenSearch Service.

- D. Create a trail in AWS CloudTrail. Configure VPC Flow Logs to send the log data to the trail. Use Amazon Kinesis Data Firehose to stream the logs from the trail to OpenSearch Service.

**Correct:** B
**Why:** Send VPC Flow Logs to CloudWatch Logs, then stream to OpenSearch Service with Kinesis Data Firehose for near real‑time analysis.

**Incorrect:**
- A: Data Streams adds custom consumer management; Firehose is simpler.
- C: CloudTrail is not used for VPC Flow Logs delivery.
- D: CloudTrail is not used for VPC Flow Logs delivery.


---

---

### Question #682

A company needs a solution to enforce data encryption at rest on Amazon EC2 instances. The solution must automatically identify noncompliant resources and enforce compliance policies on ndings. Which solution will meet these requirements with the LEAST administrative overhead?

- A. Use an IAM policy that allows users to create only encrypted Amazon Elastic Block Store (Amazon EBS) volumes. Use AWS Cong and AWS Systems Manager to automate the detection and remediation of unencrypted EBS volumes.

- B. Use AWS Key Management Service (AWS KMS) to manage access to encrypted Amazon Elastic Block Store (Amazon EBS) volumes. Use AWS Lambda and Amazon EventBridge to automate the detection and remediation of unencrypted EBS volumes.

- C. Use Amazon Macie to detect unencrypted Amazon Elastic Block Store (Amazon EBS) volumes. Use AWS Systems Manager Automation rules to automatically encrypt existing and new EBS volumes.

- D. Use Amazon inspector to detect unencrypted Amazon Elastic Block Store (Amazon EBS) volumes. Use AWS Systems Manager Automation rules to automatically encrypt existing and new EBS volumes.

**Correct:** A
**Why:** Enforce encrypted EBS creation via IAM, and use AWS Config with Systems Manager Automation to detect and remediate unencrypted volumes automatically.

**Incorrect:**
- B: Lambda + EventBridge is more custom ops; KMS alone doesn’t enforce encryption.
- C: Macie/Inspector do not detect EBS encryption compliance.
- D: Macie/Inspector do not detect EBS encryption compliance.


---

## Amazon DynamoDB

### Question #507

A company has a web application for travel ticketing. The application is based on a database that runs in a single data center in North America. The company wants to expand the application to serve a global user base. The company needs to deploy the application to multiple AWS Regions. Average latency must be less than 1 second on updates to the reservation database. The company wants to have separate deployments of its web platform across multiple Regions. However, the company must maintain a single primary reservation database that is globally consistent. Which solution should a solutions architect recommend to meet these requirements?

- A. Convert the application to use Amazon DynamoDB. Use a global table for the center reservation table. Use the correct Regional endpoint in each Regional deployment.

- B. Migrate the database to an Amazon Aurora MySQL database. Deploy Aurora Read Replicas in each Region. Use the correct Regional endpoint in each Regional deployment for access to the database.

- C. Migrate the database to an Amazon RDS for MySQL database. Deploy MySQL read replicas in each Region. Use the correct Regional endpoint in each Regional deployment for access to the database.

- D. Migrate the application to an Amazon Aurora Serverless database. Deploy instances of the database to each Region. Use the correct Regional endpoint in each Regional deployment to access the database. Use AWS Lambda functions to process event streams in each Region to synchronize the databases.

**Correct:** B
**Why:** Aurora MySQL with cross‑Region Aurora Replicas (Aurora Global Database) keeps a single primary and low‑latency replicas; web tiers use Regional endpoints.

**Incorrect:**
- A: DynamoDB changes the data model.
- C: RDS MySQL cross‑Region replication is slower and less managed.
- D: Serverless with custom sync adds complexity.


---

---

### Question #520

A company is designing a new web application that will run on Amazon EC2 Instances. The application will use Amazon DynamoDB for backend data storage. The application trac will be unpredictable. The company expects that the application read and write throughput to the database will be moderate to high. The company needs to scale in response to application trac. Which DynamoDB table configuration will meet these requirements MOST cost-effectively?

- A. Configure DynamoDB with provisioned read and write by using the DynamoDB Standard table class. Set DynamoDB auto scaling to a maximum dened capacity.

- B. Configure DynamoDB in on-demand mode by using the DynamoDB Standard table class.

- C. Configure DynamoDB with provisioned read and write by using the DynamoDB Standard Infrequent Access (DynamoDB Standard-IA) table class. Set DynamoDB auto scaling to a maximum dened capacity.

- D. Configure DynamoDB in on-demand mode by using the DynamoDB Standard Infrequent Access (DynamoDB Standard-IA) table class.

**Correct:** B
**Why:** DynamoDB on‑demand handles unpredictable traffic with automatic scaling and cost‑efficiency when throughput varies.

**Incorrect:**
- A: Provisioned or Standard‑IA table class is less cost‑effective for variable, moderate‑to‑high traffic.
- C: Provisioned or Standard‑IA table class is less cost‑effective for variable, moderate‑to‑high traffic.
- D: Provisioned or Standard‑IA table class is less cost‑effective for variable, moderate‑to‑high traffic.


---

---

### Question #521

A retail company has several businesses. The IT team for each business manages its own AWS account. Each team account is part of an organization in AWS Organizations. Each team monitors its product inventory levels in an Amazon DynamoDB table in the team's own AWS account. The company is deploying a central inventory reporting application into a shared AWS account. The application must be able to read items from all the teams' DynamoDB tables. Which authentication option will meet these requirements MOST securely?

- A. Integrate DynamoDB with AWS Secrets Manager in the inventory application account. Configure the application to use the correct secret from Secrets Manager to authenticate and read the DynamoDB table. Schedule secret rotation for every 30 days.

- B. In every business account, create an IAM user that has programmatic access. Configure the application to use the correct IAM user access key ID and secret access key to authenticate and read the DynamoDB table. Manually rotate IAM access keys every 30 days.

- C. In every business account, create an IAM role named BU_ROLE with a policy that gives the role access to the DynamoDB table and a trust policy to trust a specic role in the inventory application account. In the inventory account, create a role named APP_ROLE that allows access to the STS AssumeRole API operation. Configure the application to use APP_ROLE and assume the crossaccount role BU_ROLE to read the DynamoDB table.

- D. Integrate DynamoDB with AWS Certicate Manager (ACM). Generate identity certicates to authenticate DynamoDB. Configure the application to use the correct certicate to authenticate and read the DynamoDB table.

**Correct:** C
**Why:** Cross‑account role assumption (STS AssumeRole) is the most secure way to access each account’s DynamoDB table.

**Incorrect:**
- A: Long‑lived credentials or ACM are not appropriate.
- B: Long‑lived credentials or ACM are not appropriate.
- D: Long‑lived credentials or ACM are not appropriate.


---

---

### Question #523

A company runs a microservice-based serverless web application. The application must be able to retrieve data from multiple Amazon DynamoDB tables A solutions architect needs to give the application the ability to retrieve the data with no impact on the baseline performance of the application. Which solution will meet these requirements in the MOST operationally ecient way?

- A. AWS AppSync pipeline resolvers

- B. Amazon CloudFront with Lambda@Edge functions

- C. Edge-optimized Amazon API Gateway with AWS Lambda functions

- D. Amazon Athena Federated Query with a DynamoDB connector

**Correct:** A
**Why:** AppSync pipeline resolvers can aggregate data from multiple DynamoDB tables efficiently without impacting baseline performance.

**Incorrect:**
- B: Edge/REST proxy/Athena are less suitable for orchestrated multi‑table reads in a serverless app.
- C: Edge/REST proxy/Athena are less suitable for orchestrated multi‑table reads in a serverless app.
- D: Edge/REST proxy/Athena are less suitable for orchestrated multi‑table reads in a serverless app.


---

---

### Question #537

A company runs a three-tier web application in the AWS Cloud that operates across three Availability Zones. The application architecture has an Application Load Balancer, an Amazon EC2 web server that hosts user session states, and a MySQL database that runs on an EC2 instance. The company expects sudden increases in application trac. The company wants to be able to scale to meet future application capacity demands and to ensure high availability across all three Availability Zones. Which solution will meet these requirements?

- A. Migrate the MySQL database to Amazon RDS for MySQL with a Multi-AZ DB cluster deployment. Use Amazon ElastiCache for Redis with high availability to store session data and to cache reads. Migrate the web server to an Auto Scaling group that is in three Availability Zones.

- B. Migrate the MySQL database to Amazon RDS for MySQL with a Multi-AZ DB cluster deployment. Use Amazon ElastiCache for Memcached with high availability to store session data and to cache reads. Migrate the web server to an Auto Scaling group that is in three Availability Zones.

- C. Migrate the MySQL database to Amazon DynamoDB Use DynamoDB Accelerator (DAX) to cache reads. Store the session data in DynamoDB. Migrate the web server to an Auto Scaling group that is in three Availability Zones.

- D. Migrate the MySQL database to Amazon RDS for MySQL in a single Availability Zone. Use Amazon ElastiCache for Redis with high availability to store session data and to cache reads. Migrate the web server to an Auto Scaling group that is in three Availability Zones.

**Correct:** A
**Why:** RDS MySQL Multi‑AZ DB cluster for HA, ElastiCache Redis for sessions/cache, and an ASG across three AZs meets scale and HA goals.

**Incorrect:**
- B: Memcached lacks persistence/HA and is less preferred for sessions.
- C: Rewriting to DynamoDB is unnecessary.
- D: Single‑AZ DB is not highly available.


---

---

### Question #541

A company wants to build a web application on AWS. Client access requests to the website are not predictable and can be idle for a long time. Only customers who have paid a subscription fee can have the ability to sign in and use the web application. Which combination of steps will meet these requirements MOST cost-effectively? (Choose three.)

- A. Create an AWS Lambda function to retrieve user information from Amazon DynamoDB. Create an Amazon API Gateway endpoint to accept RESTful APIs. Send the API calls to the Lambda function.

- B. Create an Amazon Elastic Container Service (Amazon ECS) service behind an Application Load Balancer to retrieve user information from Amazon RDS. Create an Amazon API Gateway endpoint to accept RESTful APIs. Send the API calls to the Lambda function.

- C. Create an Amazon Cognito user pool to authenticate users.

- D. Create an Amazon Cognito identity pool to authenticate users.

E. Use AWS Amplify to serve the frontend web content with HTML, CSS, and JS. Use an integrated Amazon CloudFront configuration.

F. Use Amazon S3 static web hosting with PHP, CSS, and JS. Use Amazon CloudFront to serve the frontend web content.

**Correct:** A, C, E
**Why:** Serverless API (API Gateway → Lambda) is cost‑effective for spiky/idle loads; Cognito user pool handles subscription auth; Amplify hosts frontend with integrated CloudFront.

**Incorrect:**
- B: ECS/EC2 PHP or identity pools are unnecessary here.
- D: ECS/EC2 PHP or identity pools are unnecessary here.
- F: ECS/EC2 PHP or identity pools are unnecessary here.


---

---

### Question #556

A solutions architect is using an AWS CloudFormation template to deploy a three-tier web application. The web application consists of a web tier and an application tier that stores and retrieves user data in Amazon DynamoDB tables. The web and application tiers are hosted on Amazon EC2 instances, and the database tier is not publicly accessible. The application EC2 instances need to access the DynamoDB tables without exposing API credentials in the template. What should the solutions architect do to meet these requirements?

- A. Create an IAM role to read the DynamoDB tables. Associate the role with the application instances by referencing an instance profile.

- B. Create an IAM role that has the required permissions to read and write from the DynamoDB tables. Add the role to the EC2 instance profile, and associate the instance profile with the application instances.

- C. Use the parameter section in the AWS CloudFormation template to have the user input access and secret keys from an already-created IAM user that has the required permissions to read and write from the DynamoDB tables.

- D. Create an IAM user in the AWS CloudFormation template that has the required permissions to read and write from the DynamoDB tables. Use the GetAtt function to retrieve the access and secret keys, and pass them to the application instances through the user data.

**Correct:** B
**Why:** Create an IAM role with required DynamoDB permissions and attach via instance profile to the application EC2 instances so credentials aren’t exposed in templates.

**Incorrect:**
- A: Read-only role is insufficient (needs read/write per problem statement).
- C: User-supplied static access keys are insecure and operationally heavy.
- D: Creating IAM users and passing keys via user data exposes credentials.


---

---

### Question #561

A company's website handles millions of requests each day, and the number of requests continues to increase. A solutions architect needs to improve the response time of the web application. The solutions architect determines that the application needs to decrease latency when retrieving product details from the Amazon DynamoDB table. Which solution will meet these requirements with the LEAST amount of operational overhead?

- A. Set up a DynamoDB Accelerator (DAX) cluster. Route all read requests through DAX.

- B. Set up Amazon ElastiCache for Redis between the DynamoDB table and the web application. Route all read requests through Redis.

- C. Set up Amazon ElastiCache for Memcached between the DynamoDB table and the web application. Route all read requests through Memcached.

- D. Set up Amazon DynamoDB Streams on the table, and have AWS Lambda read from the table and populate Amazon ElastiCache. Route all read requests through ElastiCache.

**Correct:** A
**Why:** DynamoDB Accelerator (DAX) provides microsecond read latency with minimal changes and low operational overhead for read-heavy, latency-sensitive workloads.

**Incorrect:**
- B: ElastiCache layers require cache invalidation strategies and more app changes than DAX for DynamoDB.
- C: ElastiCache layers require cache invalidation strategies and more app changes than DAX for DynamoDB.
- D: Streams + Lambda + ElastiCache is complex and higher overhead.


---

---

### Question #562

A solutions architect needs to ensure that API calls to Amazon DynamoDB from Amazon EC2 instances in a VPC do not travel across the internet. Which combination of steps should the solutions architect take to meet this requirement? (Choose two.)

- A. Create a route table entry for the endpoint.

- B. Create a gateway endpoint for DynamoDB.

- C. Create an interface endpoint for Amazon EC2.

- D. Create an elastic network interface for the endpoint in each of the subnets of the VPC.

E. Create a security group entry in the endpoint's security group to provide access.

**Correct:** A, B
**Why:** Use a DynamoDB gateway VPC endpoint and update route tables to ensure DynamoDB API calls stay within the AWS network and not over the internet.

**Incorrect:**
- C: Interface endpoint for EC2 is unrelated.
- D: Gateway endpoints do not create ENIs; that’s for interface endpoints.
- E: Gateway endpoints don’t use security groups.


---

---

### Question #565

A company has an on-premises MySQL database that handles transactional data. The company is migrating the database to the AWS Cloud. The migrated database must maintain compatibility with the company's applications that use the database. The migrated database also must scale automatically during periods of increased demand. Which migration solution will meet these requirements?

- A. Use native MySQL tools to migrate the database to Amazon RDS for MySQL. Configure elastic storage scaling.

- B. Migrate the database to Amazon Redshift by using the mysqldump utility. Turn on Auto Scaling for the Amazon Redshift cluster.

- C. Use AWS Database Migration Service (AWS DMS) to migrate the database to Amazon Aurora. Turn on Aurora Auto Scaling.

- D. Use AWS Database Migration Service (AWS DMS) to migrate the database to Amazon DynamoDB. Configure an Auto Scaling policy.

**Correct:** C
**Why:** Migrate with AWS DMS to Amazon Aurora (MySQL-compatible). Aurora Auto Scaling (e.g., readers, and with Aurora Serverless v2 if adopted) provides automatic scaling to meet demand while maintaining compatibility.

**Incorrect:**
- A: RDS for MySQL with elastic storage scaling does not auto scale compute to handle demand spikes.
- B: Redshift is a data warehouse, not a transactional DB replacement.
- D: DynamoDB is NoSQL and not MySQL-compatible for existing apps.


---

---

### Question #567

A solutions architect is designing a workload that will store hourly energy consumption by business tenants in a building. The sensors will feed a database through HTTP requests that will add up usage for each tenant. The solutions architect must use managed services when possible. The workload will receive more features in the future as the solutions architect adds independent components. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use Amazon API Gateway with AWS Lambda functions to receive the data from the sensors, process the data, and store the data in an Amazon DynamoDB table.

- B. Use an Elastic Load Balancer that is supported by an Auto Scaling group of Amazon EC2 instances to receive and process the data from the sensors. Use an Amazon S3 bucket to store the processed data.

- C. Use Amazon API Gateway with AWS Lambda functions to receive the data from the sensors, process the data, and store the data in a Microsoft SQL Server Express database on an Amazon EC2 instance.

- D. Use an Elastic Load Balancer that is supported by an Auto Scaling group of Amazon EC2 instances to receive and process the data from the sensors. Use an Amazon Elastic File System (Amazon EFS) shared file system to store the processed data.

**Correct:** A
**Why:** API Gateway + Lambda gives a fully managed, serverless, event-driven ingestion and processing path with low overhead and easy future extensibility; store results in DynamoDB.

**Incorrect:**
- B: ELB + EC2 adds operational burden and is not necessary for simple HTTP ingest.
- C: EC2-hosted SQL Server Express increases ops overhead and reduces elasticity.
- D: ELB + EC2 adds operational burden and is not necessary for simple HTTP ingest.


---

---

### Question #572

A company runs an application on AWS. The application receives inconsistent amounts of usage. The application uses AWS Direct Connect to connect to an on-premises MySQL-compatible database. The on-premises database consistently uses a minimum of 2 GiB of memory. The company wants to migrate the on-premises database to a managed AWS service. The company wants to use auto scaling capabilities to manage unexpected workload increases. Which solution will meet these requirements with the LEAST administrative overhead?

- A. Provision an Amazon DynamoDB database with default read and write capacity settings.

- B. Provision an Amazon Aurora database with a minimum capacity of 1 Aurora capacity unit (ACU).

- C. Provision an Amazon Aurora Serverless v2 database with a minimum capacity of 1 Aurora capacity unit (ACU).

- D. Provision an Amazon RDS for MySQL database with 2 GiB of memory.

**Correct:** C
**Why:** Aurora Serverless v2 (MySQL-compatible) supports automatic, fine-grained scaling with minimal admin overhead; a 1 ACU minimum covers the 2 GiB baseline.

**Incorrect:**
- A: DynamoDB is not MySQL-compatible.
- B: Provisioned Aurora (non-serverless) requires capacity management.
- D: RDS for MySQL is managed but does not auto scale compute to absorb unexpected spikes.


---

---

### Question #575

A company deploys its applications on Amazon Elastic Kubernetes Service (Amazon EKS) behind an Application Load Balancer in an AWS Region. The application needs to store data in a PostgreSQL database engine. The company wants the data in the database to be highly available. The company also needs increased capacity for read workloads. Which solution will meet these requirements with the MOST operational eciency?

- A. Create an Amazon DynamoDB database table congured with global tables.

- B. Create an Amazon RDS database with Multi-AZ deployments.

- C. Create an Amazon RDS database with Multi-AZ DB cluster deployment.

- D. Create an Amazon RDS database congured with cross-Region read replicas.

**Correct:** C
**Why:** RDS Multi-AZ DB cluster deployment provides high availability and additional reader capacity through readable standbys for read scaling.

**Incorrect:**
- A: DynamoDB is not a PostgreSQL engine.
- B: Traditional Multi-AZ (single-standby) does not provide increased read capacity.
- D: Cross-Region read replicas add latency/complexity and are for DR, not primary read scaling.


---

---

### Question #578

A company deployed a serverless application that uses Amazon DynamoDB as a database layer. The application has experienced a large increase in users. The company wants to improve database response time from milliseconds to microseconds and to cache requests to the database. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use DynamoDB Accelerator (DAX).

- B. Migrate the database to Amazon Redshift.

- C. Migrate the database to Amazon RDS.

- D. Use Amazon ElastiCache for Redis.

**Correct:** A
**Why:** DynamoDB Accelerator (DAX) provides microsecond response times and caches DynamoDB queries with minimal operational overhead.

**Incorrect:**
- B: Redshift/RDS are different database engines, not a cache for DynamoDB.
- C: Redshift/RDS are different database engines, not a cache for DynamoDB.
- D: ElastiCache can cache but requires more app-side caching logic than DAX.


---

---

### Question #607

A company has migrated a two-tier application from its on-premises data center to the AWS Cloud. The data tier is a Multi-AZ deployment of Amazon RDS for Oracle with 12 TB of General Purpose SSD Amazon Elastic Block Store (Amazon EBS) storage. The application is designed to process and store documents in the database as binary large objects (blobs) with an average document size of 6 MB. The database size has grown over time, reducing the performance and increasing the cost of storage. The company must improve the database performance and needs a solution that is highly available and resilient. Which solution will meet these requirements MOST cost-effectively?

- A. Reduce the RDS DB instance size. Increase the storage capacity to 24 TiB. Change the storage type to Magnetic.

- B. Increase the RDS DB instance size. Increase the storage capacity to 24 TiChange the storage type to Provisioned IOPS.

- C. Create an Amazon S3 bucket. Update the application to store documents in the S3 bucket. Store the object metadata in the existing database.

- D. Create an Amazon DynamoDB table. Update the application to use DynamoDB. Use AWS Database Migration Service (AWS DMS) to migrate data from the Oracle database to DynamoDB.

**Correct:** C
**Why:** Offload large blobs to S3 and keep only metadata in RDS to reduce DB size/cost and improve performance.

**Incorrect:**
- A: Increasing size/IOPS increases cost and doesn’t address bloated storage from blobs.
- B: Increasing size/IOPS increases cost and doesn’t address bloated storage from blobs.
- D: DynamoDB migration is unnecessary and higher effort.


---

---

### Question #608

A company has an application that serves clients that are deployed in more than 20.000 retail storefront locations around the world. The application consists of backend web services that are exposed over HTTPS on port 443. The application is hosted on Amazon EC2 instances behind an Application Load Balancer (ALB). The retail locations communicate with the web application over the public internet. The company allows each retail location to register the IP address that the retail location has been allocated by its local ISP. The company's security team recommends to increase the security of the application endpoint by restricting access to only the IP addresses registered by the retail locations. What should a solutions architect do to meet these requirements?

- A. Associate an AWS WAF web ACL with the ALB. Use IP rule sets on the ALB to filter trac. Update the IP addresses in the rule to include the registered IP addresses.

- B. Deploy AWS Firewall Manager to manage the ALCongure firewall rules to restrict trac to the ALModify the firewall rules to include the registered IP addresses.

- C. Store the IP addresses in an Amazon DynamoDB table. Configure an AWS Lambda authorization function on the ALB to validate that incoming requests are from the registered IP addresses.

- D. Configure the network ACL on the subnet that contains the public interface of the ALB. Update the ingress rules on the network ACL with entries for each of the registered IP addresses.

**Correct:** A
**Why:** Attach an AWS WAF web ACL to the ALB with IP set rules; update the IP set with registered site IPs to restrict access.

**Incorrect:**
- B: Firewall Manager helps manage WAF across accounts but still relies on WAF/IP sets.
- C: ALB does not support Lambda authorizers; and DynamoDB storage is unnecessary.
- D: Network ACLs are coarse and hard to manage at scale.


---

---

### Question #622

A company is creating a new web application for its subscribers. The application will consist of a static single page and a persistent database layer. The application will have millions of users for 4 hours in the morning, but the application will have only a few thousand users during the rest of the day. The company's data architects have requested the ability to rapidly evolve their schema. Which solutions will meet these requirements and provide the MOST scalability? (Choose two.)

- A. Deploy Amazon DynamoDB as the database solution. Provision on-demand capacity.

- B. Deploy Amazon Aurora as the database solution. Choose the serverless DB engine mode.

- C. Deploy Amazon DynamoDB as the database solution. Ensure that DynamoDB auto scaling is enabled.

- D. Deploy the static content into an Amazon S3 bucket. Provision an Amazon CloudFront distribution with the S3 bucket as the origin.

E. Deploy the web servers for static content across a eet of Amazon EC2 instances in Auto Scaling groups. Configure the instances to periodically refresh the content from an Amazon Elastic File System (Amazon EFS) volume.

**Correct:** A, D
**Why:** DynamoDB (on‑demand) offers massive, bursty scalability with schema flexibility. S3 + CloudFront serves static content at scale.

**Incorrect:**
- B: Aurora Serverless is more ops overhead and cost for brief heavy peaks compared to DynamoDB.
- C: Auto scaling on provisioned may lag and require tuning vs. on‑demand.
- E: EC2 fleet for static content is unnecessary.


---

---

### Question #637

A solutions architect is designing a new service behind Amazon API Gateway. The request patterns for the service will be unpredictable and can change suddenly from 0 requests to over 500 per second. The total size of the data that needs to be persisted in a backend database is currently less than 1 GB with unpredictable future growth. Data can be queried using simple key-value requests. Which combination ofAWS services would meet these requirements? (Choose two.)

- A. AWS Fargate

- B. AWS Lambda

- C. Amazon DynamoDB

- D. Amazon EC2 Auto Scaling

E. MySQL-compatible Amazon Aurora

**Correct:** B, C
**Why:** Lambda scales to sudden bursts. DynamoDB provides key‑value storage with <1 GB easily and elastic throughput.

**Incorrect:**
- A: Fargate/ASG/Aurora add ops or are overkill for KB/MB‑scale key‑value.
- D: Fargate/ASG/Aurora add ops or are overkill for KB/MB‑scale key‑value.
- E: Fargate/ASG/Aurora add ops or are overkill for KB/MB‑scale key‑value.


---

---

### Question #650

A company wants to migrate its on-premises Microsoft SQL Server Enterprise edition database to AWS. The company's online application uses the database to process transactions. The data analysis team uses the same production database to run reports for analytical processing. The company wants to reduce operational overhead by moving to managed services wherever possible. Which solution will meet these requirements with the LEAST operational overhead?

- A. Migrate to Amazon RDS for Microsoft SOL Server. Use read replicas for reporting purposes

- B. Migrate to Microsoft SQL Server on Amazon EC2. Use Always On read replicas for reporting purposes

- C. Migrate to Amazon DynamoDB. Use DynamoDB on-demand replicas for reporting purposes

- D. Migrate to Amazon Aurora MySQL. Use Aurora read replicas for reporting purposes

**Correct:** A
**Why:** RDS for SQL Server Enterprise supports read replicas for reporting (Always On readable secondaries), reducing ops overhead compared to self‑managed EC2.

**Incorrect:**
- B: EC2 + Always On is higher ops.
- C: DynamoDB/Aurora MySQL require major app changes.
- D: DynamoDB/Aurora MySQL require major app changes.


---

---

### Question #661

A company runs applications on AWS that connect to the company's Amazon RDS database. The applications scale on weekends and at peak times of the year. The company wants to scale the database more effectively for its applications that connect to the database. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use Amazon DynamoDB with connection pooling with a target group configuration for the database. Change the applications to use the DynamoDB endpoint.

- B. Use Amazon RDS Proxy with a target group for the database. Change the applications to use the RDS Proxy endpoint.

- C. Use a custom proxy that runs on Amazon EC2 as an intermediary to the database. Change the applications to use the custom proxy endpoint.

- D. Use an AWS Lambda function to provide connection pooling with a target group configuration for the database. Change the applications to use the Lambda function.

**Correct:** B
**Why:** RDS Proxy pools and shares DB connections, improving scalability during surges with minimal app changes.

**Incorrect:**
- A: DynamoDB/Lambda are unrelated to SQL connection pooling.
- C: Custom proxy increases ops burden.
- D: DynamoDB/Lambda are unrelated to SQL connection pooling.


---

---

### Question #666

A startup company is hosting a website for its customers on an Amazon EC2 instance. The website consists of a stateless Python application and a MySQL database. The website serves only a small amount of trac. The company is concerned about the reliability of the instance and needs to migrate to a highly available architecture. The company cannot modify the application code. Which combination of actions should a solutions architect take to achieve high availability for the website? (Choose two.)

- A. Provision an internet gateway in each Availability Zone in use.

- B. Migrate the database to an Amazon RDS for MySQL Multi-AZ DB instance.

- C. Migrate the database to Amazon DynamoDB, and enable DynamoDB auto scaling.

- D. Use AWS DataSync to synchronize the database data across multiple EC2 instances.

E. Create an Application Load Balancer to distribute trac to an Auto Scaling group of EC2 instances that are distributed across two Availability Zones.

**Correct:** B, E
**Why:** RDS for MySQL Multi‑AZ provides HA for the DB. ALB + Auto Scaling across two AZs provides HA for the stateless app without code changes.

**Incorrect:**
- A: Internet gateways are per VPC, not per AZ.
- C: DynamoDB/DataSync are irrelevant here.
- D: DynamoDB/DataSync are irrelevant here.


---

---

### Question #670

A company performs tests on an application that uses an Amazon DynamoDB table. The tests run for 4 hours once a week. The company knows how many read and write operations the application performs to the table each second during the tests. The company does not currently use DynamoDB for any other use case. A solutions architect needs to optimize the costs for the table. Which solution will meet these requirements?

- A. Choose on-demand mode. Update the read and write capacity units appropriately.

- B. Choose provisioned mode. Update the read and write capacity units appropriately.

- C. Purchase DynamoDB reserved capacity for a 1-year term.

- D. Purchase DynamoDB reserved capacity for a 3-year term.

**Correct:** B
**Why:** Provisioned capacity is most cost‑effective when usage is known and periodic; adjust capacity (or schedule scaling) for the 4‑hour weekly tests.

**Incorrect:**
- A: On‑demand may cost more for predictable bursts.
- C: Reserved capacity is for steady usage, not weekly 4‑hour tests.
- D: Reserved capacity is for steady usage, not weekly 4‑hour tests.


---

---

### Question #683

A company is migrating its multi-tier on-premises application to AWS. The application consists of a single-node MySQL database and a multi-node web tier. The company must minimize changes to the application during the migration. The company wants to improve application resiliency after the migration. Which combination of steps will meet these requirements? (Choose two.)

- A. Migrate the web tier to Amazon EC2 instances in an Auto Scaling group behind an Application Load Balancer.

- B. Migrate the database to Amazon EC2 instances in an Auto Scaling group behind a Network Load Balancer.

- C. Migrate the database to an Amazon RDS Multi-AZ deployment.

- D. Migrate the web tier to an AWS Lambda function.

E. Migrate the database to an Amazon DynamoDB table.

**Correct:** A, C
**Why:** Move the web tier behind an ALB with Auto Scaling for resiliency, and migrate the DB to RDS Multi‑AZ for high availability with minimal app changes.

**Incorrect:**
- B: EC2 DB on NLB is self‑managed and higher ops.
- D: Lambda/DynamoDB require major app changes.
- E: Lambda/DynamoDB require major app changes.


---

## Amazon EBS

### Question #502

A company runs a website that uses a content management system (CMS) on Amazon EC2. The CMS runs on a single EC2 instance and uses an Amazon Aurora MySQL Multi-AZ DB instance for the data tier. Website images are stored on an Amazon Elastic Block Store (Amazon EBS) volume that is mounted inside the EC2 instance. Which combination of actions should a solutions architect take to improve the performance and resilience of the website? (Choose two.)

- A. Move the website images into an Amazon S3 bucket that is mounted on every EC2 instance

- B. Share the website images by using an NFS share from the primary EC2 instance. Mount this share on the other EC2 instances.

- C. Move the website images onto an Amazon Elastic File System (Amazon EFS) file system that is mounted on every EC2 instance.

- D. Create an Amazon Machine Image (AMI) from the existing EC2 instance. Use the AMI to provision new instances behind an Application Load Balancer as part of an Auto Scaling group. Configure the Auto Scaling group to maintain a minimum of two instances. Configure an accelerator in AWS Global Accelerator for the website

E. Create an Amazon Machine Image (AMI) from the existing EC2 instance. Use the AMI to provision new instances behind an Application Load Balancer as part of an Auto Scaling group. Configure the Auto Scaling group to maintain a minimum of two instances. Configure an Amazon CloudFront distribution for the website.

**Correct:** C, E
**Why:** Move images to EFS for shared, scalable storage; use ALB+Auto Scaling behind a CloudFront distribution for performance and resilience.

**Incorrect:**
- A: S3 mounted or EC2 NFS via a primary instance are not ideal.
- B: S3 mounted or EC2 NFS via a primary instance are not ideal.
- D: Global Accelerator is unnecessary for origin performance here.


---

---

### Question #528

A data analytics company wants to migrate its batch processing system to AWS. The company receives thousands of small data files periodically during the day through FTP. An on-premises batch job processes the data files overnight. However, the batch job takes hours to nish running. The company wants the AWS solution to process incoming data files as soon as possible with minimal changes to the FTP clients that send the files. The solution must delete the incoming data files after the files have been processed successfully. Processing for each file needs to take 3-8 minutes. Which solution will meet these requirements in the MOST operationally ecient way?

- A. Use an Amazon EC2 instance that runs an FTP server to store incoming files as objects in Amazon S3 Glacier Flexible Retrieval. Configure a job queue in AWS Batch. Use Amazon EventBridge rules to invoke the job to process the objects nightly from S3 Glacier Flexible Retrieval. Delete the objects after the job has processed the objects.

- B. Use an Amazon EC2 instance that runs an FTP server to store incoming files on an Amazon Elastic Block Store (Amazon EBS) volume. Configure a job queue in AWS Batch. Use Amazon EventBridge rules to invoke the job to process the files nightly from the EBS volume. Delete the files after the job has processed the files.

- C. Use AWS Transfer Family to create an FTP server to store incoming files on an Amazon Elastic Block Store (Amazon EBS) volume. Configure a job queue in AWS Batch. Use an Amazon S3 event notification when each file arrives to invoke the job in AWS Batch. Delete the files after the job has processed the files.

- D. Use AWS Transfer Family to create an FTP server to store incoming files in Amazon S3 Standard. Create an AWS Lambda function to process the files and to delete the files after they are processed. Use an S3 event notification to invoke the Lambda function when the files arrive.

**Correct:** D
**Why:** Transfer Family (FTP) to S3 with S3 event → Lambda processes and deletes files as they arrive—near real time, minimal client changes.

**Incorrect:**
- A: Glacier/EBS nightly batches or Batch jobs add latency/ops.
- B: Glacier/EBS nightly batches or Batch jobs add latency/ops.
- C: Glacier/EBS nightly batches or Batch jobs add latency/ops.


---

---

### Question #535

A company is building an Amazon Elastic Kubernetes Service (Amazon EKS) cluster for its workloads. All secrets that are stored in Amazon EKS must be encrypted in the Kubernetes etcd key-value store. Which solution will meet these requirements?

- A. Create a new AWS Key Management Service (AWS KMS) key. Use AWS Secrets Manager to manage, rotate, and store all secrets in Amazon EKS.

- B. Create a new AWS Key Management Service (AWS KMS) key. Enable Amazon EKS KMS secrets encryption on the Amazon EKS cluster.

- C. Create the Amazon EKS cluster with default options. Use the Amazon Elastic Block Store (Amazon EBS) Container Storage Interface (CSI) driver as an add-on.

- D. Create a new AWS Key Management Service (AWS KMS) key with the alias/aws/ebs alias. Enable default Amazon Elastic Block Store (Amazon EBS) volume encryption for the account.

**Correct:** B
**Why:** Enable EKS KMS secrets encryption with a customer KMS key to encrypt Kubernetes secrets in etcd.

**Incorrect:**
- A: Secrets Manager/EBS encryption don’t encrypt etcd secrets by default.
- C: Secrets Manager/EBS encryption don’t encrypt etcd secrets by default.
- D: Secrets Manager/EBS encryption don’t encrypt etcd secrets by default.


---

---

### Question #564

A company is building an ecommerce application and needs to store sensitive customer information. The company needs to give customers the ability to complete purchase transactions on the website. The company also needs to ensure that sensitive customer data is protected, even from database administrators. Which solution meets these requirements?

- A. Store sensitive data in an Amazon Elastic Block Store (Amazon EBS) volume. Use EBS encryption to encrypt the data. Use an IAM instance role to restrict access.

- B. Store sensitive data in Amazon RDS for MySQL. Use AWS Key Management Service (AWS KMS) client-side encryption to encrypt the data.

- C. Store sensitive data in Amazon S3. Use AWS Key Management Service (AWS KMS) server-side encryption to encrypt the data. Use S3 bucket policies to restrict access.

- D. Store sensitive data in Amazon FSx for Windows Server. Mount the file share on application servers. Use Windows file permissions to restrict access.

**Correct:** B
**Why:** To prevent even DBAs from accessing sensitive data, encrypt at the application/client layer before storage (client-side KMS encryption) and store ciphertext in the database.

**Incorrect:**
- A: EBS encryption protects at the volume level; DBAs can still read decrypted data via the DB engine.
- C: S3 is not the right backend for transactional ecommerce data; SSE-KMS also does not prevent privileged DB access.
- D: FSx + Windows permissions doesn’t address app-level transactional storage nor protect from DBAs.


---

---

### Question #566

A company runs multiple Amazon EC2 Linux instances in a VPC across two Availability Zones. The instances host applications that use a hierarchical directory structure. The applications need to read and write rapidly and concurrently to shared storage. What should a solutions architect do to meet these requirements?

- A. Create an Amazon S3 bucket. Allow access from all the EC2 instances in the VPC.

- B. Create an Amazon Elastic File System (Amazon EFS) file system. Mount the EFS file system from each EC2 instance.

- C. Create a file system on a Provisioned IOPS SSD (io2) Amazon Elastic Block Store (Amazon EBS) volume. Attach the EBS volume to all the EC2 instances.

- D. Create file systems on Amazon Elastic Block Store (Amazon EBS) volumes that are attached to each EC2 instance. Synchronize the EBS volumes across the different EC2 instances.

**Correct:** B
**Why:** Amazon EFS provides shared POSIX file system semantics, high concurrency, and multi-AZ access for EC2 instances; ideal for hierarchical directory structures and concurrent read/write.

**Incorrect:**
- A: S3 is object storage, not a shared POSIX file system.
- C: EBS volumes cannot be concurrently attached to multiple instances across AZs for shared writes.
- D: EBS volumes cannot be concurrently attached to multiple instances across AZs for shared writes.


---

---

### Question #568

A solutions architect is designing the storage architecture for a new web application used for storing and viewing engineering drawings. All application components will be deployed on the AWS infrastructure. The application design must support caching to minimize the amount of time that users wait for the engineering drawings to load. The application must be able to store petabytes of data. Which combination of storage and caching should the solutions architect use?

- A. Amazon S3 with Amazon CloudFront

- B. Amazon S3 Glacier with Amazon ElastiCache

- C. Amazon Elastic Block Store (Amazon EBS) volumes with Amazon CloudFront

- D. AWS Storage Gateway with Amazon ElastiCache

**Correct:** A
**Why:** Amazon S3 scales to petabytes and serves as durable storage. CloudFront provides global edge caching to reduce latency loading large drawings.

**Incorrect:**
- B: Glacier is archival and not suited for frequent/interactive access.
- C: EBS is block storage tied to instances; not optimal for petabyte-scale/serving globally.
- D: Storage Gateway is for hybrid integrations; not needed when fully on AWS.


---

---

### Question #580

A company uses locally attached storage to run a latency-sensitive application on premises. The company is using a lift and shift method to move the application to the AWS Cloud. The company does not want to change the application architecture. Which solution will meet these requirements MOST cost-effectively?

- A. Configure an Auto Scaling group with an Amazon EC2 instance. Use an Amazon FSx for Lustre file system to run the application.

- B. Host the application on an Amazon EC2 instance. Use an Amazon Elastic Block Store (Amazon EBS) GP2 volume to run the application.

- C. Configure an Auto Scaling group with an Amazon EC2 instance. Use an Amazon FSx for OpenZFS file system to run the application.

- D. Host the application on an Amazon EC2 instance. Use an Amazon Elastic Block Store (Amazon EBS) GP3 volume to run the application.

**Correct:** D
**Why:** EC2 with gp3 EBS provides low-latency block storage and is more cost-effective than gp2 for lift‑and‑shift without app changes.

**Incorrect:**
- A: FSx families are network file systems and require app changes.
- B: gp2 is older and less cost-efficient than gp3.
- C: FSx families are network file systems and require app changes.


---

---

### Question #602

A company's infrastructure consists of hundreds of Amazon EC2 instances that use Amazon Elastic Block Store (Amazon EBS) storage. A solutions architect must ensure that every EC2 instance can be recovered after a disaster. What should the solutions architect do to meet this requirement with the LEAST amount of effort?

- A. Take a snapshot of the EBS storage that is attached to each EC2 instance. Create an AWS CloudFormation template to launch new EC2 instances from the EBS storage.

- B. Take a snapshot of the EBS storage that is attached to each EC2 instance. Use AWS Elastic Beanstalk to set the environment based on the EC2 template and attach the EBS storage.

- C. Use AWS Backup to set up a backup plan for the entire group of EC2 instances. Use the AWS Backup API or the AWS CLI to speed up the restore process for multiple EC2 instances.

- D. Create an AWS Lambda function to take a snapshot of the EBS storage that is attached to each EC2 instance and copy the Amazon Machine Images (AMIs). Create another Lambda function to perform the restores with the copied AMIs and attach the EBS storage.

**Correct:** C
**Why:** AWS Backup can centrally back up and restore fleets of EC2/EBS with minimal effort.

**Incorrect:**
- A: Custom snapshots/scripts/Beanstalk add operational complexity.
- B: Custom snapshots/scripts/Beanstalk add operational complexity.
- D: Custom snapshots/scripts/Beanstalk add operational complexity.


---

---

### Question #605

A company has several on-premises Internet Small Computer Systems Interface (ISCSI) network storage servers. The company wants to reduce the number of these servers by moving to the AWS Cloud. A solutions architect must provide low-latency access to frequently used data and reduce the dependency on on-premises servers with a minimal number of infrastructure changes. Which solution will meet these requirements?

- A. Deploy an Amazon S3 File Gateway.

- B. Deploy Amazon Elastic Block Store (Amazon EBS) storage with backups to Amazon S3.

- C. Deploy an AWS Storage Gateway volume gateway that is congured with stored volumes.

- D. Deploy an AWS Storage Gateway volume gateway that is congured with cached volumes.

**Correct:** D
**Why:** Volume Gateway cached volumes present iSCSI locally while storing primary data in S3, reducing on‑prem dependency and providing low‑latency cache access.

**Incorrect:**
- A: S3 File Gateway is for SMB/NFS files, not iSCSI block.
- B: EBS is in‑cloud only and not iSCSI to on‑prem.
- C: Stored volumes keep primary data on‑prem.


---

---

### Question #607

A company has migrated a two-tier application from its on-premises data center to the AWS Cloud. The data tier is a Multi-AZ deployment of Amazon RDS for Oracle with 12 TB of General Purpose SSD Amazon Elastic Block Store (Amazon EBS) storage. The application is designed to process and store documents in the database as binary large objects (blobs) with an average document size of 6 MB. The database size has grown over time, reducing the performance and increasing the cost of storage. The company must improve the database performance and needs a solution that is highly available and resilient. Which solution will meet these requirements MOST cost-effectively?

- A. Reduce the RDS DB instance size. Increase the storage capacity to 24 TiB. Change the storage type to Magnetic.

- B. Increase the RDS DB instance size. Increase the storage capacity to 24 TiChange the storage type to Provisioned IOPS.

- C. Create an Amazon S3 bucket. Update the application to store documents in the S3 bucket. Store the object metadata in the existing database.

- D. Create an Amazon DynamoDB table. Update the application to use DynamoDB. Use AWS Database Migration Service (AWS DMS) to migrate data from the Oracle database to DynamoDB.

**Correct:** C
**Why:** Offload large blobs to S3 and keep only metadata in RDS to reduce DB size/cost and improve performance.

**Incorrect:**
- A: Increasing size/IOPS increases cost and doesn’t address bloated storage from blobs.
- B: Increasing size/IOPS increases cost and doesn’t address bloated storage from blobs.
- D: DynamoDB migration is unnecessary and higher effort.


---

---

### Question #620

A company is planning to deploy a business-critical application in the AWS Cloud. The application requires durable storage with consistent, low- latency performance. Which type of storage should a solutions architect recommend to meet these requirements?

- A. Instance store volume

- B. Amazon ElastiCache for Memcached cluster

- C. Provisioned IOPS SSD Amazon Elastic Block Store (Amazon EBS) volume

- D. Throughput Optimized HDD Amazon Elastic Block Store (Amazon EBS) volume

**Correct:** C
**Why:** Provisioned IOPS SSD (io2/io1) EBS provides consistent low‑latency and high durability for business‑critical apps.

**Incorrect:**
- A: Instance store is ephemeral.
- B: ElastiCache is memory cache, not durable storage.
- D: Throughput Optimized HDD is for big, sequential throughput, not low latency.


---

---

### Question #632

A company is creating a new application that will store a large amount of data. The data will be analyzed hourly and will be modied by several Amazon EC2 Linux instances that are deployed across multiple Availability Zones. The needed amount of storage space will continue to grow for the next 6 months. Which storage solution should a solutions architect recommend to meet these requirements?

- A. Store the data in Amazon S3 Glacier. Update the S3 Glacier vault policy to allow access to the application instances.

- B. Store the data in an Amazon Elastic Block Store (Amazon EBS) volume. Mount the EBS volume on the application instances.

- C. Store the data in an Amazon Elastic File System (Amazon EFS) file system. Mount the file system on the application instances.

- D. Store the data in an Amazon Elastic Block Store (Amazon EBS) Provisioned IOPS volume shared between the application instances.

**Correct:** C
**Why:** Amazon EFS provides a shared, scalable file system across AZs, ideal for concurrent modification and hourly analytics.

**Incorrect:**
- A: Glacier is archival and slow.
- B: EBS can’t be shared across instances/AZs concurrently.
- D: EBS can’t be shared across instances/AZs concurrently.


---

---

### Question #649

An ecommerce company runs a PostgreSQL database on premises. The database stores data by using high IOPS Amazon Elastic Block Store (Amazon EBS) block storage. The daily peak I/O transactions per second do not exceed 15,000 IOPS. The company wants to migrate the database to Amazon RDS for PostgreSQL and provision disk IOPS performance independent of disk storage capacity. Which solution will meet these requirements MOST cost-effectively?

- A. Configure the General Purpose SSD (gp2) EBS volume storage type and provision 15,000 IOPS.

- B. Configure the Provisioned IOPS SSD (io1) EBS volume storage type and provision 15,000 IOPS.

- C. Configure the General Purpose SSD (gp3) EBS volume storage type and provision 15,000 IOPS.

- D. Configure the EBS magnetic volume type to achieve maximum IOPS.

**Correct:** C
**Why:** gp3 lets you provision IOPS independently of storage size at lower cost than io1/io2 for 15k IOPS.

**Incorrect:**
- A: gp2 IOPS scale only with size.
- B: io1 is costlier for this need.
- D: Magnetic cannot meet IOPS needs.


---

---

### Question #656

A company runs a website that stores images of historical events. Website users need the ability to search and view images based on the year that the event in the image occurred. On average, users request each image only once or twice a year. The company wants a highly available solution to store and deliver the images to users. Which solution will meet these requirements MOST cost-effectively?

- A. Store images in Amazon Elastic Block Store (Amazon EBS). Use a web server that runs on Amazon EC2.

- B. Store images in Amazon Elastic File System (Amazon EFS). Use a web server that runs on Amazon EC2.

- C. Store images in Amazon S3 Standard. Use S3 Standard to directly deliver images by using a static website.

- D. Store images in Amazon S3 Standard-Infrequent Access (S3 Standard-IA). Use S3 Standard-IA to directly deliver images by using a static website.

**Correct:** D
**Why:** S3 Standard‑IA stores infrequently accessed images cost‑effectively and can serve via static website hosting when requested.

**Incorrect:**
- A: EBS/EFS require EC2 and add ops.
- B: EBS/EFS require EC2 and add ops.
- C: S3 Standard costs more for rarely accessed objects.


---

---

### Question #662

A company uses AWS Cost Explorer to monitor its AWS costs. The company notices that Amazon Elastic Block Store (Amazon EBS) storage and snapshot costs increase every month. However, the company does not purchase additional EBS storage every month. The company wants to optimize monthly costs for its current storage usage. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use logs in Amazon CloudWatch Logs to monitor the storage utilization of Amazon EBS. Use Amazon EBS Elastic Volumes to reduce the size of the EBS volumes.

- B. Use a custom script to monitor space usage. Use Amazon EBS Elastic Volumes to reduce the size of the EBS volumes.

- C. Delete all expired and unused snapshots to reduce snapshot costs.

- D. Delete all nonessential snapshots. Use Amazon Data Lifecycle Manager to create and manage the snapshots according to the company's snapshot policy requirements.

**Correct:** D
**Why:** Clean up nonessential snapshots and automate lifecycle with Data Lifecycle Manager to control ongoing costs.

**Incorrect:**
- A: Monitoring alone doesn’t reduce costs; resizing EBS may not be feasible.
- B: Monitoring alone doesn’t reduce costs; resizing EBS may not be feasible.
- C: Only expired/unused snapshots should be deleted; policy is required for ongoing control.


---

---

### Question #675

A company uses Amazon EC2 instances and Amazon Elastic Block Store (Amazon EBS) volumes to run an application. The company creates one snapshot of each EBS volume every day to meet compliance requirements. The company wants to implement an architecture that prevents the accidental deletion of EBS volume snapshots. The solution must not change the administrative rights of the storage administrator user. Which solution will meet these requirements with the LEAST administrative effort?

- A. Create an IAM role that has permission to delete snapshots. Attach the role to a new EC2 instance. Use the AWS CLI from the new EC2 instance to delete snapshots.

- B. Create an IAM policy that denies snapshot deletion. Attach the policy to the storage administrator user.

- C. Add tags to the snapshots. Create retention rules in Recycle Bin for EBS snapshots that have the tags.

- D. Lock the EBS snapshots to prevent deletion.

**Correct:** C
**Why:** Use Recycle Bin with tags and retention rules so accidentally deleted snapshots can be recovered without changing admin rights.

**Incorrect:**
- A: Adding a role and deleting from a separate instance is not a safeguard.
- B: Denying deletion changes administrator rights, violating the requirement.
- D: There is no snapshot "lock" feature; use Recycle Bin.


---

---

### Question #681

A company uses Amazon EC2 instances and stores data on Amazon Elastic Block Store (Amazon EBS) volumes. The company must ensure that all data is encrypted at rest by using AWS Key Management Service (AWS KMS). The company must be able to control rotation of the encryption keys. Which solution will meet these requirements with the LEAST operational overhead?

- A. Create a customer managed key. Use the key to encrypt the EBS volumes.

- B. Use an AWS managed key to encrypt the EBS volumes. Use the key to configure automatic key rotation.

- C. Create an external KMS key with imported key material. Use the key to encrypt the EBS volumes.

- D. Use an AWS owned key to encrypt the EBS volumes.

**Correct:** A
**Why:** A customer managed KMS key encrypts EBS volumes with customer‑controlled rotation, meeting requirements with low ops.

**Incorrect:**
- B: AWS managed keys do not give customer control over rotation/disable.
- C: External key material increases complexity without additional benefit here.
- D: AWS owned keys provide no control or visibility.


---

---

### Question #682

A company needs a solution to enforce data encryption at rest on Amazon EC2 instances. The solution must automatically identify noncompliant resources and enforce compliance policies on ndings. Which solution will meet these requirements with the LEAST administrative overhead?

- A. Use an IAM policy that allows users to create only encrypted Amazon Elastic Block Store (Amazon EBS) volumes. Use AWS Cong and AWS Systems Manager to automate the detection and remediation of unencrypted EBS volumes.

- B. Use AWS Key Management Service (AWS KMS) to manage access to encrypted Amazon Elastic Block Store (Amazon EBS) volumes. Use AWS Lambda and Amazon EventBridge to automate the detection and remediation of unencrypted EBS volumes.

- C. Use Amazon Macie to detect unencrypted Amazon Elastic Block Store (Amazon EBS) volumes. Use AWS Systems Manager Automation rules to automatically encrypt existing and new EBS volumes.

- D. Use Amazon inspector to detect unencrypted Amazon Elastic Block Store (Amazon EBS) volumes. Use AWS Systems Manager Automation rules to automatically encrypt existing and new EBS volumes.

**Correct:** A
**Why:** Enforce encrypted EBS creation via IAM, and use AWS Config with Systems Manager Automation to detect and remediate unencrypted volumes automatically.

**Incorrect:**
- B: Lambda + EventBridge is more custom ops; KMS alone doesn’t enforce encryption.
- C: Macie/Inspector do not detect EBS encryption compliance.
- D: Macie/Inspector do not detect EBS encryption compliance.


---

## Amazon EC2 / Auto Scaling

### Question #502

A company runs a website that uses a content management system (CMS) on Amazon EC2. The CMS runs on a single EC2 instance and uses an Amazon Aurora MySQL Multi-AZ DB instance for the data tier. Website images are stored on an Amazon Elastic Block Store (Amazon EBS) volume that is mounted inside the EC2 instance. Which combination of actions should a solutions architect take to improve the performance and resilience of the website? (Choose two.)

- A. Move the website images into an Amazon S3 bucket that is mounted on every EC2 instance

- B. Share the website images by using an NFS share from the primary EC2 instance. Mount this share on the other EC2 instances.

- C. Move the website images onto an Amazon Elastic File System (Amazon EFS) file system that is mounted on every EC2 instance.

- D. Create an Amazon Machine Image (AMI) from the existing EC2 instance. Use the AMI to provision new instances behind an Application Load Balancer as part of an Auto Scaling group. Configure the Auto Scaling group to maintain a minimum of two instances. Configure an accelerator in AWS Global Accelerator for the website

E. Create an Amazon Machine Image (AMI) from the existing EC2 instance. Use the AMI to provision new instances behind an Application Load Balancer as part of an Auto Scaling group. Configure the Auto Scaling group to maintain a minimum of two instances. Configure an Amazon CloudFront distribution for the website.

**Correct:** C, E
**Why:** Move images to EFS for shared, scalable storage; use ALB+Auto Scaling behind a CloudFront distribution for performance and resilience.

**Incorrect:**
- A: S3 mounted or EC2 NFS via a primary instance are not ideal.
- B: S3 mounted or EC2 NFS via a primary instance are not ideal.
- D: Global Accelerator is unnecessary for origin performance here.


---

---

### Question #503

A company runs an infrastructure monitoring service. The company is building a new feature that will enable the service to monitor data in customer AWS accounts. The new feature will call AWS APIs in customer accounts to describe Amazon EC2 instances and read Amazon CloudWatch metrics. What should the company do to obtain access to customer accounts in the MOST secure way?

- A. Ensure that the customers create an IAM role in their account with read-only EC2 and CloudWatch permissions and a trust policy to the company’s account.

- B. Create a serverless API that implements a token vending machine to provide temporary AWS credentials for a role with read-only EC2 and CloudWatch permissions.

- C. Ensure that the customers create an IAM user in their account with read-only EC2 and CloudWatch permissions. Encrypt and store customer access and secret keys in a secrets management system.

- D. Ensure that the customers create an Amazon Cognito user in their account to use an IAM role with read-only EC2 and CloudWatch permissions. Encrypt and store the Amazon Cognito user and password in a secrets management system.

**Correct:** A
**Why:** Customers create a read‑only role with a trust to the company’s account; the company assumes the role securely with STS.

**Incorrect:**
- B: Do not use long‑lived credentials; Cognito/users are not appropriate.
- C: Do not use long‑lived credentials; Cognito/users are not appropriate.
- D: Do not use long‑lived credentials; Cognito/users are not appropriate.


---

---

### Question #505

A company has Amazon EC2 instances that run nightly batch jobs to process data. The EC2 instances run in an Auto Scaling group that uses On- Demand billing. If a job fails on one instance, another instance will reprocess the job. The batch jobs run between 12:00 AM and 06:00 AM local time every day. Which solution will provide EC2 instances to meet these requirements MOST cost-effectively?

- A. Purchase a 1-year Savings Plan for Amazon EC2 that covers the instance family of the Auto Scaling group that the batch job uses.

- B. Purchase a 1-year Reserved Instance for the specic instance type and operating system of the instances in the Auto Scaling group that the batch job uses.

- C. Create a new launch template for the Auto Scaling group. Set the instances to Spot Instances. Set a policy to scale out based on CPU usage.

- D. Create a new launch template for the Auto Scaling group. Increase the instance size. Set a policy to scale out based on CPU usage.

**Correct:** C
**Why:** Spot Instances in the Auto Scaling group minimize cost for nightly batch with fault‑tolerant reprocessing.

**Incorrect:**
- A: Savings Plans/RIs or upsizing increase cost for short windows.
- B: Savings Plans/RIs or upsizing increase cost for short windows.
- D: Savings Plans/RIs or upsizing increase cost for short windows.


---

---

### Question #508

A company has migrated multiple Microsoft Windows Server workloads to Amazon EC2 instances that run in the us-west-1 Region. The company manually backs up the workloads to create an image as needed. In the event of a natural disaster in the us-west-1 Region, the company wants to recover workloads quickly in the us-west-2 Region. The company wants no more than 24 hours of data loss on the EC2 instances. The company also wants to automate any backups of the EC2 instances. Which solutions will meet these requirements with the LEAST administrative effort? (Choose two.)

- A. Create an Amazon EC2-backed Amazon Machine Image (AMI) lifecycle policy to create a backup based on tags. Schedule the backup to run twice daily. Copy the image on demand.

- B. Create an Amazon EC2-backed Amazon Machine Image (AMI) lifecycle policy to create a backup based on tags. Schedule the backup to run twice daily. Configure the copy to the us-west-2 Region.

- C. Create backup vaults in us-west-1 and in us-west-2 by using AWS Backup. Create a backup plan for the EC2 instances based on tag values. Create an AWS Lambda function to run as a scheduled job to copy the backup data to us-west-2.

- D. Create a backup vault by using AWS Backup. Use AWS Backup to create a backup plan for the EC2 instances based on tag values. Dene the destination for the copy as us-west-2. Specify the backup schedule to run twice daily.

E. Create a backup vault by using AWS Backup. Use AWS Backup to create a backup plan for the EC2 instances based on tag values. Specify the backup schedule to run twice daily. Copy on demand to us-west-2.

**Correct:** B, D
**Why:** AMI lifecycle with cross‑Region copy and AWS Backup cross‑Region backups both automate twice‑daily backups within the 24‑hour RPO.

**Incorrect:**
- A: On‑demand copies add manual steps.
- C: Lambda copy adds unnecessary custom code.
- E: On‑demand copies add manual steps.


---

---

### Question #509

A company operates a two-tier application for image processing. The application uses two Availability Zones, each with one public subnet and one private subnet. An Application Load Balancer (ALB) for the web tier uses the public subnets. Amazon EC2 instances for the application tier use the private subnets. Users report that the application is running more slowly than expected. A security audit of the web server log files shows that the application is receiving millions of illegitimate requests from a small number of IP addresses. A solutions architect needs to resolve the immediate performance problem while the company investigates a more permanent solution. What should the solutions architect recommend to meet this requirement?

- A. Modify the inbound security group for the web tier. Add a deny rule for the IP addresses that are consuming resources.

- B. Modify the network ACL for the web tier subnets. Add an inbound deny rule for the IP addresses that are consuming resources.

- C. Modify the inbound security group for the application tier. Add a deny rule for the IP addresses that are consuming resources.

- D. Modify the network ACL for the application tier subnets. Add an inbound deny rule for the IP addresses that are consuming resources.

**Correct:** B
**Why:** NACLs support explicit deny rules by IP to immediately block abusive sources on the web subnets.

**Incorrect:**
- A: Security groups are allow‑only—no deny rules.
- C: Security groups are allow‑only—no deny rules.
- D: Block at the web tier first, not the app subnets.


---

---

### Question #513

A social media company wants to allow its users to upload images in an application that is hosted in the AWS Cloud. The company needs a solution that automatically resizes the images so that the images can be displayed on multiple device types. The application experiences unpredictable trac patterns throughout the day. The company is seeking a highly available solution that maximizes scalability. What should a solutions architect do to meet these requirements?

- A. Create a static website hosted in Amazon S3 that invokes AWS Lambda functions to resize the images and store the images in an Amazon S3 bucket.

- B. Create a static website hosted in Amazon CloudFront that invokes AWS Step Functions to resize the images and store the images in an Amazon RDS database.

- C. Create a dynamic website hosted on a web server that runs on an Amazon EC2 instance. Configure a process that runs on the EC2 instance to resize the images and store the images in an Amazon S3 bucket.

- D. Create a dynamic website hosted on an automatically scaling Amazon Elastic Container Service (Amazon ECS) cluster that creates a resize job in Amazon Simple Queue Service (Amazon SQS). Set up an image-resizing program that runs on an Amazon EC2 instance to process the resize jobs.

**Correct:** A
**Why:** Static site front end in S3 with Lambda resizing on upload provides high availability and scalability with minimal ops; store results in S3.

**Incorrect:**
- B: CloudFront+Step Functions/EC2/ECS add complexity and are less serverless.
- C: CloudFront+Step Functions/EC2/ECS add complexity and are less serverless.
- D: CloudFront+Step Functions/EC2/ECS add complexity and are less serverless.


---

---

### Question #514

A company is running a microservices application on Amazon EC2 instances. The company wants to migrate the application to an Amazon Elastic Kubernetes Service (Amazon EKS) cluster for scalability. The company must configure the Amazon EKS control plane with endpoint private access set to true and endpoint public access set to false to maintain security compliance. The company must also put the data plane in private subnets. However, the company has received error notications because the node cannot join the cluster. Which solution will allow the node to join the cluster?

- A. Grant the required permission in AWS Identity and Access Management (IAM) to the AmazonEKSNodeRole IAM role.

- B. Create interface VPC endpoints to allow nodes to access the control plane.

- C. Recreate nodes in the public subnet. Restrict security groups for EC2 nodes.

- D. Allow outbound trac in the security group of the nodes.

**Correct:** B
**Why:** With private EKS endpoint and private node subnets, create interface VPC endpoints so nodes can reach the control plane APIs.

**Incorrect:**
- A: IAM/placing nodes public/SG egress alone won’t fix private endpoint reachability.
- C: IAM/placing nodes public/SG egress alone won’t fix private endpoint reachability.
- D: IAM/placing nodes public/SG egress alone won’t fix private endpoint reachability.


---

---

### Question #520

A company is designing a new web application that will run on Amazon EC2 Instances. The application will use Amazon DynamoDB for backend data storage. The application trac will be unpredictable. The company expects that the application read and write throughput to the database will be moderate to high. The company needs to scale in response to application trac. Which DynamoDB table configuration will meet these requirements MOST cost-effectively?

- A. Configure DynamoDB with provisioned read and write by using the DynamoDB Standard table class. Set DynamoDB auto scaling to a maximum dened capacity.

- B. Configure DynamoDB in on-demand mode by using the DynamoDB Standard table class.

- C. Configure DynamoDB with provisioned read and write by using the DynamoDB Standard Infrequent Access (DynamoDB Standard-IA) table class. Set DynamoDB auto scaling to a maximum dened capacity.

- D. Configure DynamoDB in on-demand mode by using the DynamoDB Standard Infrequent Access (DynamoDB Standard-IA) table class.

**Correct:** B
**Why:** DynamoDB on‑demand handles unpredictable traffic with automatic scaling and cost‑efficiency when throughput varies.

**Incorrect:**
- A: Provisioned or Standard‑IA table class is less cost‑effective for variable, moderate‑to‑high traffic.
- C: Provisioned or Standard‑IA table class is less cost‑effective for variable, moderate‑to‑high traffic.
- D: Provisioned or Standard‑IA table class is less cost‑effective for variable, moderate‑to‑high traffic.


---

---

### Question #527

A company has a regional subscription-based streaming service that runs in a single AWS Region. The architecture consists of web servers and application servers on Amazon EC2 instances. The EC2 instances are in Auto Scaling groups behind Elastic Load Balancers. The architecture includes an Amazon Aurora global database cluster that extends across multiple Availability Zones. The company wants to expand globally and to ensure that its application has minimal downtime. Which solution will provide the MOST fault tolerance?

- A. Extend the Auto Scaling groups for the web tier and the application tier to deploy instances in Availability Zones in a second Region. Use an Aurora global database to deploy the database in the primary Region and the second Region. Use Amazon Route 53 health checks with a failover routing policy to the second Region.

- B. Deploy the web tier and the application tier to a second Region. Add an Aurora PostgreSQL cross-Region Aurora Replica in the second Region. Use Amazon Route 53 health checks with a failover routing policy to the second Region. Promote the secondary to primary as needed.

- C. Deploy the web tier and the application tier to a second Region. Create an Aurora PostgreSQL database in the second Region. Use AWS Database Migration Service (AWS DMS) to replicate the primary database to the second Region. Use Amazon Route 53 health checks with a failover routing policy to the second Region.

- D. Deploy the web tier and the application tier to a second Region. Use an Amazon Aurora global database to deploy the database in the primary Region and the second Region. Use Amazon Route 53 health checks with a failover routing policy to the second Region. Promote the secondary to primary as needed.

**Correct:** D
**Why:** Deploy app tiers in a second Region and use Aurora Global Database plus Route 53 failover for maximal fault tolerance.

**Incorrect:**
- A: Less integrated or slower replication and more manual promotion.
- B: Less integrated or slower replication and more manual promotion.
- C: Less integrated or slower replication and more manual promotion.


---

---

### Question #528

A data analytics company wants to migrate its batch processing system to AWS. The company receives thousands of small data files periodically during the day through FTP. An on-premises batch job processes the data files overnight. However, the batch job takes hours to nish running. The company wants the AWS solution to process incoming data files as soon as possible with minimal changes to the FTP clients that send the files. The solution must delete the incoming data files after the files have been processed successfully. Processing for each file needs to take 3-8 minutes. Which solution will meet these requirements in the MOST operationally ecient way?

- A. Use an Amazon EC2 instance that runs an FTP server to store incoming files as objects in Amazon S3 Glacier Flexible Retrieval. Configure a job queue in AWS Batch. Use Amazon EventBridge rules to invoke the job to process the objects nightly from S3 Glacier Flexible Retrieval. Delete the objects after the job has processed the objects.

- B. Use an Amazon EC2 instance that runs an FTP server to store incoming files on an Amazon Elastic Block Store (Amazon EBS) volume. Configure a job queue in AWS Batch. Use Amazon EventBridge rules to invoke the job to process the files nightly from the EBS volume. Delete the files after the job has processed the files.

- C. Use AWS Transfer Family to create an FTP server to store incoming files on an Amazon Elastic Block Store (Amazon EBS) volume. Configure a job queue in AWS Batch. Use an Amazon S3 event notification when each file arrives to invoke the job in AWS Batch. Delete the files after the job has processed the files.

- D. Use AWS Transfer Family to create an FTP server to store incoming files in Amazon S3 Standard. Create an AWS Lambda function to process the files and to delete the files after they are processed. Use an S3 event notification to invoke the Lambda function when the files arrive.

**Correct:** D
**Why:** Transfer Family (FTP) to S3 with S3 event → Lambda processes and deletes files as they arrive—near real time, minimal client changes.

**Incorrect:**
- A: Glacier/EBS nightly batches or Batch jobs add latency/ops.
- B: Glacier/EBS nightly batches or Batch jobs add latency/ops.
- C: Glacier/EBS nightly batches or Batch jobs add latency/ops.


---

---

### Question #529

A company is migrating its workloads to AWS. The company has transactional and sensitive data in its databases. The company wants to use AWS Cloud solutions to increase security and reduce operational overhead for the databases. Which solution will meet these requirements?

- A. Migrate the databases to Amazon EC2. Use an AWS Key Management Service (AWS KMS) AWS managed key for encryption.

- B. Migrate the databases to Amazon RDS Configure encryption at rest.

- C. Migrate the data to Amazon S3 Use Amazon Macie for data security and protection

- D. Migrate the database to Amazon RDS. Use Amazon CloudWatch Logs for data security and protection.

**Correct:** B
**Why:** RDS is managed, supports encryption at rest/in transit, and reduces operational overhead for transactional/sensitive data.

**Incorrect:**
- A: EC2/CloudWatch Logs/Macie alone do not meet the database requirements.
- C: EC2/CloudWatch Logs/Macie alone do not meet the database requirements.
- D: EC2/CloudWatch Logs/Macie alone do not meet the database requirements.


---

---

### Question #537

A company runs a three-tier web application in the AWS Cloud that operates across three Availability Zones. The application architecture has an Application Load Balancer, an Amazon EC2 web server that hosts user session states, and a MySQL database that runs on an EC2 instance. The company expects sudden increases in application trac. The company wants to be able to scale to meet future application capacity demands and to ensure high availability across all three Availability Zones. Which solution will meet these requirements?

- A. Migrate the MySQL database to Amazon RDS for MySQL with a Multi-AZ DB cluster deployment. Use Amazon ElastiCache for Redis with high availability to store session data and to cache reads. Migrate the web server to an Auto Scaling group that is in three Availability Zones.

- B. Migrate the MySQL database to Amazon RDS for MySQL with a Multi-AZ DB cluster deployment. Use Amazon ElastiCache for Memcached with high availability to store session data and to cache reads. Migrate the web server to an Auto Scaling group that is in three Availability Zones.

- C. Migrate the MySQL database to Amazon DynamoDB Use DynamoDB Accelerator (DAX) to cache reads. Store the session data in DynamoDB. Migrate the web server to an Auto Scaling group that is in three Availability Zones.

- D. Migrate the MySQL database to Amazon RDS for MySQL in a single Availability Zone. Use Amazon ElastiCache for Redis with high availability to store session data and to cache reads. Migrate the web server to an Auto Scaling group that is in three Availability Zones.

**Correct:** A
**Why:** RDS MySQL Multi‑AZ DB cluster for HA, ElastiCache Redis for sessions/cache, and an ASG across three AZs meets scale and HA goals.

**Incorrect:**
- B: Memcached lacks persistence/HA and is less preferred for sessions.
- C: Rewriting to DynamoDB is unnecessary.
- D: Single‑AZ DB is not highly available.


---

---

### Question #543

A company runs Amazon EC2 instances in multiple AWS accounts that are individually bled. The company recently purchased a Savings Pian. Because of changes in the company’s business requirements, the company has decommissioned a large number of EC2 instances. The company wants to use its Savings Plan discounts on its other AWS accounts. Which combination of steps will meet these requirements? (Choose two.)

- A. From the AWS Account Management Console of the management account, turn on discount sharing from the billing preferences section.

- B. From the AWS Account Management Console of the account that purchased the existing Savings Plan, turn on discount sharing from the billing preferences section. Include all accounts.

- C. From the AWS Organizations management account, use AWS Resource Access Manager (AWS RAM) to share the Savings Plan with other accounts.

- D. Create an organization in AWS Organizations in a new payer account. Invite the other AWS accounts to join the organization from the management account.

E. Create an organization in AWS Organizations in the existing AWS account with the existing EC2 instances and Savings Plan. Invite the other AWS accounts to join the organization from the management account.

**Correct:** A, E
**Why:** Turn on discount sharing in the management account and place accounts under one Organization so Savings Plan discounts can float.

**Incorrect:**
- B: Enabling in a member account, RAM sharing, or moving to a new payer account is not required.
- C: Enabling in a member account, RAM sharing, or moving to a new payer account is not required.
- D: Enabling in a member account, RAM sharing, or moving to a new payer account is not required.


---

---

### Question #545

A company wants to direct its users to a backup static error page if the company's primary website is unavailable. The primary website's DNS records are hosted in Amazon Route 53. The domain is pointing to an Application Load Balancer (ALB). The company needs a solution that minimizes changes and infrastructure overhead. Which solution will meet these requirements?

- A. Update the Route 53 records to use a latency routing policy. Add a static error page that is hosted in an Amazon S3 bucket to the records so that the trac is sent to the most responsive endpoints.

- B. Set up a Route 53 active-passive failover configuration. Direct trac to a static error page that is hosted in an Amazon S3 bucket when Route 53 health checks determine that the ALB endpoint is unhealthy.

- C. Set up a Route 53 active-active configuration with the ALB and an Amazon EC2 instance that hosts a static error page as endpoints. Configure Route 53 to send requests to the instance only if the health checks fail for the ALB.

- D. Update the Route 53 records to use a multivalue answer routing policy. Create a health check. Direct trac to the website if the health check passes. Direct trac to a static error page that is hosted in Amazon S3 if the health check does not pass.

**Correct:** B
**Why:** Route 53 active‑passive failover to an S3 static error page when ALB health checks fail—minimal infra/changes.

**Incorrect:**
- A: Latency/multivalue policies don’t provide ALB health‑based failover to S3.
- C: Maintaining EC2 for a static page adds ops.
- D: Latency/multivalue policies don’t provide ALB health‑based failover to S3.


---

---

### Question #549

A company has created a multi-tier application for its ecommerce website. The website uses an Application Load Balancer that resides in the public subnets, a web tier in the public subnets, and a MySQL cluster hosted on Amazon EC2 instances in the private subnets. The MySQL database needs to retrieve product catalog and pricing information that is hosted on the internet by a third-party provider. A solutions architect must devise a strategy that maximizes security without increasing operational overhead. What should the solutions architect do to meet these requirements?

- A. Deploy a NAT instance in the VPC. Route all the internet-based trac through the NAT instance.

- B. Deploy a NAT gateway in the public subnets. Modify the private subnet route table to direct all internet-bound trac to the NAT gateway.

- C. Configure an internet gateway and attach it to the VPModify the private subnet route table to direct internet-bound trac to the internet gateway.

- D. Configure a virtual private gateway and attach it to the VPC. Modify the private subnet route table to direct internet-bound trac to the virtual private gateway.

**Correct:** B
**Why:** A NAT gateway in a public subnet provides secure outbound internet from private subnets without exposing instances.

**Incorrect:**
- A: NAT instance adds ops.
- C: IGW/VGW are not for private outbound egress.
- D: IGW/VGW are not for private outbound egress.


---

---

### Question #552

A company needs to optimize the cost of its Amazon EC2 instances. The company also needs to change the type and family of its EC2 instances every 2-3 months. What should the company do to meet these requirements?

- A. Purchase Partial Upfront Reserved Instances for a 3-year term.

- B. Purchase a No Upfront Compute Savings Plan for a 1-year term.

- C. Purchase All Upfront Reserved Instances for a 1-year term.

- D. Purchase an All Upfront EC2 Instance Savings Plan for a 1-year term.

**Correct:** B
**Why:** A No Upfront Compute Savings Plan (1-year) applies across instance families, sizes, Regions, and operating systems, allowing frequent changes in instance type/family while optimizing cost.

**Incorrect:**
- A: RIs are less flexible; partial upfront 3-year also overcommits given changes every 2–3 months.
- C: All Upfront RIs lock instance family/attributes; not suitable for frequent changes.
- D: EC2 Instance Savings Plans are tied to specific families, reducing flexibility; Compute Savings Plan is better.


---

---

### Question #555

A company runs an application in a VPC with public and private subnets. The VPC extends across multiple Availability Zones. The application runs on Amazon EC2 instances in private subnets. The application uses an Amazon Simple Queue Service (Amazon SQS) queue. A solutions architect needs to design a secure solution to establish a connection between the EC2 instances and the SQS queue. Which solution will meet these requirements?

- A. Implement an interface VPC endpoint for Amazon SQS. Configure the endpoint to use the private subnets. Add to the endpoint a security group that has an inbound access rule that allows trac from the EC2 instances that are in the private subnets.

- B. Implement an interface VPC endpoint for Amazon SQS. Configure the endpoint to use the public subnets. Attach to the interface endpoint a VPC endpoint policy that allows access from the EC2 instances that are in the private subnets.

- C. Implement an interface VPC endpoint for Amazon SQS. Configure the endpoint to use the public subnets. Attach an Amazon SQS access policy to the interface VPC endpoint that allows requests from only a specied VPC endpoint.

- D. Implement a gateway endpoint for Amazon SQS. Add a NAT gateway to the private subnets. Attach an IAM role to the EC2 instances that allows access to the SQS queue.

**Correct:** A
**Why:** Use an interface VPC endpoint (AWS PrivateLink) for SQS in private subnets. Attach a security group allowing traffic from EC2 instances in those subnets for a private, secure path.

**Incorrect:**
- B: Public subnets are unnecessary; security groups apply to the endpoint, but placing it in public subnets doesn’t meet "secure private" requirement.
- C: SQS access policies attach to queues, not to interface endpoints. Also endpoint should be in private subnets.
- D: SQS does not support gateway endpoints. A NAT gateway would traverse the internet path, which is not desired.


---

---

### Question #556

A solutions architect is using an AWS CloudFormation template to deploy a three-tier web application. The web application consists of a web tier and an application tier that stores and retrieves user data in Amazon DynamoDB tables. The web and application tiers are hosted on Amazon EC2 instances, and the database tier is not publicly accessible. The application EC2 instances need to access the DynamoDB tables without exposing API credentials in the template. What should the solutions architect do to meet these requirements?

- A. Create an IAM role to read the DynamoDB tables. Associate the role with the application instances by referencing an instance profile.

- B. Create an IAM role that has the required permissions to read and write from the DynamoDB tables. Add the role to the EC2 instance profile, and associate the instance profile with the application instances.

- C. Use the parameter section in the AWS CloudFormation template to have the user input access and secret keys from an already-created IAM user that has the required permissions to read and write from the DynamoDB tables.

- D. Create an IAM user in the AWS CloudFormation template that has the required permissions to read and write from the DynamoDB tables. Use the GetAtt function to retrieve the access and secret keys, and pass them to the application instances through the user data.

**Correct:** B
**Why:** Create an IAM role with required DynamoDB permissions and attach via instance profile to the application EC2 instances so credentials aren’t exposed in templates.

**Incorrect:**
- A: Read-only role is insufficient (needs read/write per problem statement).
- C: User-supplied static access keys are insecure and operationally heavy.
- D: Creating IAM users and passing keys via user data exposes credentials.


---

---

### Question #559

A company hosts multiple applications on AWS for different product lines. The applications use different compute resources, including Amazon EC2 instances and Application Load Balancers. The applications run in different AWS accounts under the same organization in AWS Organizations across multiple AWS Regions. Teams for each product line have tagged each compute resource in the individual accounts. The company wants more details about the cost for each product line from the consolidated billing feature in Organizations. Which combination of steps will meet these requirements? (Choose two.)

- A. Select a specic AWS generated tag in the AWS Billing console.

- B. Select a specic user-dened tag in the AWS Billing console.

- C. Select a specic user-dened tag in the AWS Resource Groups console.

- D. Activate the selected tag from each AWS account.

E. Activate the selected tag from the Organizations management account.

**Correct:** B, E
**Why:** Use a specific user-defined cost allocation tag and activate it in the AWS Billing console of the Organizations management (payer) account to surface costs by tag across linked accounts.

**Incorrect:**
- A: AWS-generated tags are limited in usefulness and not aligned to product lines.
- C: Resource Groups is not where cost allocation tags are activated for billing.
- D: Tag activation for consolidated billing is performed in the management account, not individually in each member account.


---

---

### Question #562

A solutions architect needs to ensure that API calls to Amazon DynamoDB from Amazon EC2 instances in a VPC do not travel across the internet. Which combination of steps should the solutions architect take to meet this requirement? (Choose two.)

- A. Create a route table entry for the endpoint.

- B. Create a gateway endpoint for DynamoDB.

- C. Create an interface endpoint for Amazon EC2.

- D. Create an elastic network interface for the endpoint in each of the subnets of the VPC.

E. Create a security group entry in the endpoint's security group to provide access.

**Correct:** A, B
**Why:** Use a DynamoDB gateway VPC endpoint and update route tables to ensure DynamoDB API calls stay within the AWS network and not over the internet.

**Incorrect:**
- C: Interface endpoint for EC2 is unrelated.
- D: Gateway endpoints do not create ENIs; that’s for interface endpoints.
- E: Gateway endpoints don’t use security groups.


---

---

### Question #565

A company has an on-premises MySQL database that handles transactional data. The company is migrating the database to the AWS Cloud. The migrated database must maintain compatibility with the company's applications that use the database. The migrated database also must scale automatically during periods of increased demand. Which migration solution will meet these requirements?

- A. Use native MySQL tools to migrate the database to Amazon RDS for MySQL. Configure elastic storage scaling.

- B. Migrate the database to Amazon Redshift by using the mysqldump utility. Turn on Auto Scaling for the Amazon Redshift cluster.

- C. Use AWS Database Migration Service (AWS DMS) to migrate the database to Amazon Aurora. Turn on Aurora Auto Scaling.

- D. Use AWS Database Migration Service (AWS DMS) to migrate the database to Amazon DynamoDB. Configure an Auto Scaling policy.

**Correct:** C
**Why:** Migrate with AWS DMS to Amazon Aurora (MySQL-compatible). Aurora Auto Scaling (e.g., readers, and with Aurora Serverless v2 if adopted) provides automatic scaling to meet demand while maintaining compatibility.

**Incorrect:**
- A: RDS for MySQL with elastic storage scaling does not auto scale compute to handle demand spikes.
- B: Redshift is a data warehouse, not a transactional DB replacement.
- D: DynamoDB is NoSQL and not MySQL-compatible for existing apps.


---

---

### Question #566

A company runs multiple Amazon EC2 Linux instances in a VPC across two Availability Zones. The instances host applications that use a hierarchical directory structure. The applications need to read and write rapidly and concurrently to shared storage. What should a solutions architect do to meet these requirements?

- A. Create an Amazon S3 bucket. Allow access from all the EC2 instances in the VPC.

- B. Create an Amazon Elastic File System (Amazon EFS) file system. Mount the EFS file system from each EC2 instance.

- C. Create a file system on a Provisioned IOPS SSD (io2) Amazon Elastic Block Store (Amazon EBS) volume. Attach the EBS volume to all the EC2 instances.

- D. Create file systems on Amazon Elastic Block Store (Amazon EBS) volumes that are attached to each EC2 instance. Synchronize the EBS volumes across the different EC2 instances.

**Correct:** B
**Why:** Amazon EFS provides shared POSIX file system semantics, high concurrency, and multi-AZ access for EC2 instances; ideal for hierarchical directory structures and concurrent read/write.

**Incorrect:**
- A: S3 is object storage, not a shared POSIX file system.
- C: EBS volumes cannot be concurrently attached to multiple instances across AZs for shared writes.
- D: EBS volumes cannot be concurrently attached to multiple instances across AZs for shared writes.


---

---

### Question #567

A solutions architect is designing a workload that will store hourly energy consumption by business tenants in a building. The sensors will feed a database through HTTP requests that will add up usage for each tenant. The solutions architect must use managed services when possible. The workload will receive more features in the future as the solutions architect adds independent components. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use Amazon API Gateway with AWS Lambda functions to receive the data from the sensors, process the data, and store the data in an Amazon DynamoDB table.

- B. Use an Elastic Load Balancer that is supported by an Auto Scaling group of Amazon EC2 instances to receive and process the data from the sensors. Use an Amazon S3 bucket to store the processed data.

- C. Use Amazon API Gateway with AWS Lambda functions to receive the data from the sensors, process the data, and store the data in a Microsoft SQL Server Express database on an Amazon EC2 instance.

- D. Use an Elastic Load Balancer that is supported by an Auto Scaling group of Amazon EC2 instances to receive and process the data from the sensors. Use an Amazon Elastic File System (Amazon EFS) shared file system to store the processed data.

**Correct:** A
**Why:** API Gateway + Lambda gives a fully managed, serverless, event-driven ingestion and processing path with low overhead and easy future extensibility; store results in DynamoDB.

**Incorrect:**
- B: ELB + EC2 adds operational burden and is not necessary for simple HTTP ingest.
- C: EC2-hosted SQL Server Express increases ops overhead and reduces elasticity.
- D: ELB + EC2 adds operational burden and is not necessary for simple HTTP ingest.


---

---

### Question #570

A company has a large workload that runs every Friday evening. The workload runs on Amazon EC2 instances that are in two Availability Zones in the us-east-1 Region. Normally, the company must run no more than two instances at all times. However, the company wants to scale up to six instances each Friday to handle a regularly repeating increased workload. Which solution will meet these requirements with the LEAST operational overhead?

- A. Create a reminder in Amazon EventBridge to scale the instances.

- B. Create an Auto Scaling group that has a scheduled action.

- C. Create an Auto Scaling group that uses manual scaling.

- D. Create an Auto Scaling group that uses automatic scaling.

**Correct:** B
**Why:** Use an Auto Scaling group with a scheduled action to scale out to six instances each Friday and scale back after, minimizing overhead.

**Incorrect:**
- A: EventBridge reminder alone doesn’t scale instances.
- C: Manual scaling is error-prone and operationally heavy.
- D: Target tracking or step scaling won’t pre-warm for a predictable weekly spike as effectively as scheduled actions.


---

---

### Question #572

A company runs an application on AWS. The application receives inconsistent amounts of usage. The application uses AWS Direct Connect to connect to an on-premises MySQL-compatible database. The on-premises database consistently uses a minimum of 2 GiB of memory. The company wants to migrate the on-premises database to a managed AWS service. The company wants to use auto scaling capabilities to manage unexpected workload increases. Which solution will meet these requirements with the LEAST administrative overhead?

- A. Provision an Amazon DynamoDB database with default read and write capacity settings.

- B. Provision an Amazon Aurora database with a minimum capacity of 1 Aurora capacity unit (ACU).

- C. Provision an Amazon Aurora Serverless v2 database with a minimum capacity of 1 Aurora capacity unit (ACU).

- D. Provision an Amazon RDS for MySQL database with 2 GiB of memory.

**Correct:** C
**Why:** Aurora Serverless v2 (MySQL-compatible) supports automatic, fine-grained scaling with minimal admin overhead; a 1 ACU minimum covers the 2 GiB baseline.

**Incorrect:**
- A: DynamoDB is not MySQL-compatible.
- B: Provisioned Aurora (non-serverless) requires capacity management.
- D: RDS for MySQL is managed but does not auto scale compute to absorb unexpected spikes.


---

---

### Question #574

A nancial services company launched a new application that uses an Amazon RDS for MySQL database. The company uses the application to track stock market trends. The company needs to operate the application for only 2 hours at the end of each week. The company needs to optimize the cost of running the database. Which solution will meet these requirements MOST cost-effectively?

- A. Migrate the existing RDS for MySQL database to an Aurora Serverless v2 MySQL database cluster.

- B. Migrate the existing RDS for MySQL database to an Aurora MySQL database cluster.

- C. Migrate the existing RDS for MySQL database to an Amazon EC2 instance that runs MySQL. Purchase an instance reservation for the EC2 instance.

- D. Migrate the existing RDS for MySQL database to an Amazon Elastic Container Service (Amazon ECS) cluster that uses MySQL container images to run tasks.

**Correct:** A
**Why:** Aurora Serverless v2 scales capacity to meet the brief weekly usage window and minimizes cost when idle, with low ops overhead.

**Incorrect:**
- B: Provisioned Aurora runs 24/7 and costs more for a 2‑hour/week workload.
- C: EC2 self-managed MySQL increases operational effort.
- D: ECS for MySQL adds container and storage management complexity.


---

---

### Question #580

A company uses locally attached storage to run a latency-sensitive application on premises. The company is using a lift and shift method to move the application to the AWS Cloud. The company does not want to change the application architecture. Which solution will meet these requirements MOST cost-effectively?

- A. Configure an Auto Scaling group with an Amazon EC2 instance. Use an Amazon FSx for Lustre file system to run the application.

- B. Host the application on an Amazon EC2 instance. Use an Amazon Elastic Block Store (Amazon EBS) GP2 volume to run the application.

- C. Configure an Auto Scaling group with an Amazon EC2 instance. Use an Amazon FSx for OpenZFS file system to run the application.

- D. Host the application on an Amazon EC2 instance. Use an Amazon Elastic Block Store (Amazon EBS) GP3 volume to run the application.

**Correct:** D
**Why:** EC2 with gp3 EBS provides low-latency block storage and is more cost-effective than gp2 for lift‑and‑shift without app changes.

**Incorrect:**
- A: FSx families are network file systems and require app changes.
- B: gp2 is older and less cost-efficient than gp3.
- C: FSx families are network file systems and require app changes.


---

---

### Question #581

A company runs a stateful production application on Amazon EC2 instances. The application requires at least two EC2 instances to always be running. A solutions architect needs to design a highly available and fault-tolerant architecture for the application. The solutions architect creates an Auto Scaling group of EC2 instances. Which set of additional steps should the solutions architect take to meet these requirements?

- A. Set the Auto Scaling group's minimum capacity to two. Deploy one On-Demand Instance in one Availability Zone and one On-Demand Instance in a second Availability Zone.

- B. Set the Auto Scaling group's minimum capacity to four. Deploy two On-Demand Instances in one Availability Zone and two On-Demand Instances in a second Availability Zone.

- C. Set the Auto Scaling group's minimum capacity to two. Deploy four Spot Instances in one Availability Zone.

- D. Set the Auto Scaling group's minimum capacity to four. Deploy two On-Demand Instances in one Availability Zone and two Spot Instances in a second Availability Zone.

**Correct:** A
**Why:** Minimum capacity of two across two AZs with On-Demand instances ensures high availability and meets the requirement that two instances are always running.

**Incorrect:**
- B: Overprovisioned and unnecessary.
- C: Single AZ and Spot do not meet HA or availability needs.
- D: Mixing Spot for required baseline risks capacity loss; also single-AZ for half the capacity.


---

---

### Question #584

A company is deploying an application that processes large quantities of data in parallel. The company plans to use Amazon EC2 instances for the workload. The network architecture must be congurable to prevent groups of nodes from sharing the same underlying hardware. Which networking solution meets these requirements?

- A. Run the EC2 instances in a spread placement group.

- B. Group the EC2 instances in separate accounts.

- C. Configure the EC2 instances with dedicated tenancy.

- D. Configure the EC2 instances with shared tenancy.

**Correct:** A
**Why:** Spread placement groups place instances across distinct underlying hardware, reducing correlated failure and sharing of hardware.

**Incorrect:**
- B: Separate accounts don’t control underlying host placement.
- C: Tenancy controls host sharing with other customers, not distribution across distinct hardware.
- D: Tenancy controls host sharing with other customers, not distribution across distinct hardware.


---

---

### Question #585

A solutions architect is designing a disaster recovery (DR) strategy to provide Amazon EC2 capacity in a failover AWS Region. Business requirements state that the DR strategy must meet capacity in the failover Region. Which solution will meet these requirements?

- A. Purchase On-Demand Instances in the failover Region.

- B. Purchase an EC2 Savings Plan in the failover Region.

- C. Purchase regional Reserved Instances in the failover Region.

- D. Purchase a Capacity Reservation in the failover Region.

**Correct:** D
**Why:** Capacity Reservations ensure compute capacity availability in the failover Region when needed for DR.

**Incorrect:**
- A: These do not reserve capacity; they only affect billing/discounts.
- B: These do not reserve capacity; they only affect billing/discounts.
- C: These do not reserve capacity; they only affect billing/discounts.


---

---

### Question #589

A company runs a web application on Amazon EC2 instances in an Auto Scaling group behind an Application Load Balancer that has sticky sessions enabled. The web server currently hosts the user session state. The company wants to ensure high availability and avoid user session state loss in the event of a web server outage. Which solution will meet these requirements?

- A. Use an Amazon ElastiCache for Memcached instance to store the session data. Update the application to use ElastiCache for Memcached to store the session state.

- B. Use Amazon ElastiCache for Redis to store the session state. Update the application to use ElastiCache for Redis to store the session state.

- C. Use an AWS Storage Gateway cached volume to store session data. Update the application to use AWS Storage Gateway cached volume to store the session state.

- D. Use Amazon RDS to store the session state. Update the application to use Amazon RDS to store the session state.

**Correct:** B
**Why:** ElastiCache for Redis supports durable, highly available session storage and eliminates dependency on individual web servers.

**Incorrect:**
- A: Memcached lacks persistence and robust HA.
- C: Storage Gateway is not for session storage.
- D: RDS adds latency/overhead vs. an in‑memory cache for sessions.


---

---

### Question #592

A company uses AWS and sells access to copyrighted images. The company’s global customer base needs to be able to access these images quickly. The company must deny access to users from specic countries. The company wants to minimize costs as much as possible. Which solution will meet these requirements?

- A. Use Amazon S3 to store the images. Turn on multi-factor authentication (MFA) and public bucket access. Provide customers with a link to the S3 bucket.

- B. Use Amazon S3 to store the images. Create an IAM user for each customer. Add the users to a group that has permission to access the S3 bucket.

- C. Use Amazon EC2 instances that are behind Application Load Balancers (ALBs) to store the images. Deploy the instances only in the countries the company services. Provide customers with links to the ALBs for their specic country's instances.

- D. Use Amazon S3 to store the images. Use Amazon CloudFront to distribute the images with geographic restrictions. Provide a signed URL for each customer to access the data in CloudFront.

**Correct:** D
**Why:** S3 with CloudFront provides low‑latency global delivery. Geo restrictions and signed URLs enforce country blocks and per‑customer access.

**Incorrect:**
- A: Public buckets or per‑user IAM are insecure or operationally heavy.
- B: Public buckets or per‑user IAM are insecure or operationally heavy.
- C: EC2 + ALB for serving files is costly and complex.


---

---

### Question #593

A solutions architect is designing a highly available Amazon ElastiCache for Redis based solution. The solutions architect needs to ensure that failures do not result in performance degradation or loss of data locally and within an AWS Region. The solution needs to provide high availability at the node level and at the Region level. Which solution will meet these requirements?

- A. Use Multi-AZ Redis replication groups with shards that contain multiple nodes.

- B. Use Redis shards that contain multiple nodes with Redis append only files (AOF) turned on.

- C. Use a Multi-AZ Redis cluster with more than one read replica in the replication group.

- D. Use Redis shards that contain multiple nodes with Auto Scaling turned on.

**Correct:** A
**Why:** Multi‑AZ Redis replication groups with shards of multiple nodes provide node‑level HA and AZ‑level resilience without performance degradation.

**Incorrect:**
- B: AOF persistence doesn’t by itself ensure HA or regional resilience.
- C: Single read replica per shard is less robust than multi‑node shards and doesn’t address shard‑level failures.
- D: Auto Scaling isn’t applicable for Redis nodes in this context.


---

---

### Question #594

A company plans to migrate to AWS and use Amazon EC2 On-Demand Instances for its application. During the migration testing phase, a technical team observes that the application takes a long time to launch and load memory to become fully productive. Which solution will reduce the launch time of the application during the next testing phase?

- A. Launch two or more EC2 On-Demand Instances. Turn on auto scaling features and make the EC2 On-Demand Instances available during the next testing phase.

- B. Launch EC2 Spot Instances to support the application and to scale the application so it is available during the next testing phase.

- C. Launch the EC2 On-Demand Instances with hibernation turned on. Configure EC2 Auto Scaling warm pools during the next testing phase.

- D. Launch EC2 On-Demand Instances with Capacity Reservations. Start additional EC2 instances during the next testing phase.

**Correct:** C
**Why:** EC2 hibernation plus Auto Scaling warm pools pre-warm memory/state, reducing launch time significantly for subsequent tests.

**Incorrect:**
- A: Do not address slow warm‑up of memory/state; may add cost or not solve the problem.
- B: Do not address slow warm‑up of memory/state; may add cost or not solve the problem.
- D: Do not address slow warm‑up of memory/state; may add cost or not solve the problem.


---

---

### Question #595

A company's applications run on Amazon EC2 instances in Auto Scaling groups. The company notices that its applications experience sudden trac increases on random days of the week. The company wants to maintain application performance during sudden trac increases. Which solution will meet these requirements MOST cost-effectively?

- A. Use manual scaling to change the size of the Auto Scaling group.

- B. Use predictive scaling to change the size of the Auto Scaling group.

- C. Use dynamic scaling to change the size of the Auto Scaling group.

- D. Use schedule scaling to change the size of the Auto Scaling group.

**Correct:** C
**Why:** Dynamic scaling (target tracking/step scaling) responds to sudden, unpredictable spikes cost‑effectively.

**Incorrect:**
- A: Manual scaling is slow and labor‑intensive.
- B: Predictive scaling relies on patterns; spikes are random.
- D: Scheduled scaling doesn’t address random spikes.


---

---

### Question #596

An ecommerce application uses a PostgreSQL database that runs on an Amazon EC2 instance. During a monthly sales event, database usage increases and causes database connection issues for the application. The trac is unpredictable for subsequent monthly sales events, which impacts the sales forecast. The company needs to maintain performance when there is an unpredictable increase in trac. Which solution resolves this issue in the MOST cost-effective way?

- A. Migrate the PostgreSQL database to Amazon Aurora Serverless v2.

- B. Enable auto scaling for the PostgreSQL database on the EC2 instance to accommodate increased usage.

- C. Migrate the PostgreSQL database to Amazon RDS for PostgreSQL with a larger instance type.

- D. Migrate the PostgreSQL database to Amazon Redshift to accommodate increased usage.

**Correct:** A
**Why:** Aurora Serverless v2 for PostgreSQL auto scales capacity to handle unpredictable event spikes cost‑effectively.

**Incorrect:**
- B: EC2 DB auto scaling isn’t available and requires self‑management.
- C: Fixed RDS size lacks elasticity.
- D: Redshift is for analytics, not transactional workloads.


---

---

### Question #602

A company's infrastructure consists of hundreds of Amazon EC2 instances that use Amazon Elastic Block Store (Amazon EBS) storage. A solutions architect must ensure that every EC2 instance can be recovered after a disaster. What should the solutions architect do to meet this requirement with the LEAST amount of effort?

- A. Take a snapshot of the EBS storage that is attached to each EC2 instance. Create an AWS CloudFormation template to launch new EC2 instances from the EBS storage.

- B. Take a snapshot of the EBS storage that is attached to each EC2 instance. Use AWS Elastic Beanstalk to set the environment based on the EC2 template and attach the EBS storage.

- C. Use AWS Backup to set up a backup plan for the entire group of EC2 instances. Use the AWS Backup API or the AWS CLI to speed up the restore process for multiple EC2 instances.

- D. Create an AWS Lambda function to take a snapshot of the EBS storage that is attached to each EC2 instance and copy the Amazon Machine Images (AMIs). Create another Lambda function to perform the restores with the copied AMIs and attach the EBS storage.

**Correct:** C
**Why:** AWS Backup can centrally back up and restore fleets of EC2/EBS with minimal effort.

**Incorrect:**
- A: Custom snapshots/scripts/Beanstalk add operational complexity.
- B: Custom snapshots/scripts/Beanstalk add operational complexity.
- D: Custom snapshots/scripts/Beanstalk add operational complexity.


---

---

### Question #608

A company has an application that serves clients that are deployed in more than 20.000 retail storefront locations around the world. The application consists of backend web services that are exposed over HTTPS on port 443. The application is hosted on Amazon EC2 instances behind an Application Load Balancer (ALB). The retail locations communicate with the web application over the public internet. The company allows each retail location to register the IP address that the retail location has been allocated by its local ISP. The company's security team recommends to increase the security of the application endpoint by restricting access to only the IP addresses registered by the retail locations. What should a solutions architect do to meet these requirements?

- A. Associate an AWS WAF web ACL with the ALB. Use IP rule sets on the ALB to filter trac. Update the IP addresses in the rule to include the registered IP addresses.

- B. Deploy AWS Firewall Manager to manage the ALCongure firewall rules to restrict trac to the ALModify the firewall rules to include the registered IP addresses.

- C. Store the IP addresses in an Amazon DynamoDB table. Configure an AWS Lambda authorization function on the ALB to validate that incoming requests are from the registered IP addresses.

- D. Configure the network ACL on the subnet that contains the public interface of the ALB. Update the ingress rules on the network ACL with entries for each of the registered IP addresses.

**Correct:** A
**Why:** Attach an AWS WAF web ACL to the ALB with IP set rules; update the IP set with registered site IPs to restrict access.

**Incorrect:**
- B: Firewall Manager helps manage WAF across accounts but still relies on WAF/IP sets.
- C: ALB does not support Lambda authorizers; and DynamoDB storage is unnecessary.
- D: Network ACLs are coarse and hard to manage at scale.


---

---

### Question #610

A company deploys Amazon EC2 instances that run in a VPC. The EC2 instances load source data into Amazon S3 buckets so that the data can be processed in the future. According to compliance laws, the data must not be transmitted over the public internet. Servers in the company's on- premises data center will consume the output from an application that runs on the EC2 instances. Which solution will meet these requirements?

- A. Deploy an interface VPC endpoint for Amazon EC2. Create an AWS Site-to-Site VPN connection between the company and the VPC.

- B. Deploy a gateway VPC endpoint for Amazon S3. Set up an AWS Direct Connect connection between the on-premises network and the VPC.

- C. Set up an AWS Transit Gateway connection from the VPC to the S3 buckets. Create an AWS Site-to-Site VPN connection between the company and the VPC.

- D. Set up proxy EC2 instances that have routes to NAT gateways. Configure the proxy EC2 instances to fetch S3 data and feed the application instances.

**Correct:** B
**Why:** Use an S3 gateway endpoint for private access from EC2 to S3 and Direct Connect for private on‑prem access to VPC‑hosted outputs.

**Incorrect:**
- A: Do not provide private S3 access end‑to‑end without traversing the internet.
- C: Do not provide private S3 access end‑to‑end without traversing the internet.
- D: Do not provide private S3 access end‑to‑end without traversing the internet.


---

---

### Question #611

A company has an application with a REST-based interface that allows data to be received in near-real time from a third-party vendor. Once received, the application processes and stores the data for further analysis. The application is running on Amazon EC2 instances. The third-party vendor has received many 503 Service Unavailable Errors when sending data to the application. When the data volume spikes, the compute capacity reaches its maximum limit and the application is unable to process all requests. Which design should a solutions architect recommend to provide a more scalable solution?

- A. Use Amazon Kinesis Data Streams to ingest the data. Process the data using AWS Lambda functions.

- B. Use Amazon API Gateway on top of the existing application. Create a usage plan with a quota limit for the third-party vendor.

- C. Use Amazon Simple Notification Service (Amazon SNS) to ingest the data. Put the EC2 instances in an Auto Scaling group behind an Application Load Balancer.

- D. Repackage the application as a container. Deploy the application using Amazon Elastic Container Service (Amazon ECS) using the EC2 launch type with an Auto Scaling group.

**Correct:** A
**Why:** Kinesis Data Streams buffers spikes and decouples producers from consumers; Lambda scales to process without 503s.

**Incorrect:**
- B: API Gateway with quotas throttles the vendor rather than scaling.
- C: SNS is pub/sub and not ideal for high‑throughput buffering + ordering.
- D: ECS on EC2 still faces sudden capacity limits without a buffer.


---

---

### Question #612

A company has an application that runs on Amazon EC2 instances in a private subnet. The application needs to process sensitive information from an Amazon S3 bucket. The application must not use the internet to connect to the S3 bucket. Which solution will meet these requirements?

- A. Configure an internet gateway. Update the S3 bucket policy to allow access from the internet gateway. Update the application to use the new internet gateway.

- B. Configure a VPN connection. Update the S3 bucket policy to allow access from the VPN connection. Update the application to use the new VPN connection.

- C. Configure a NAT gateway. Update the S3 bucket policy to allow access from the NAT gateway. Update the application to use the new NAT gateway.

- D. Configure a VPC endpoint. Update the S3 bucket policy to allow access from the VPC endpoint. Update the application to use the new VPC endpoint.

**Correct:** D
**Why:** Use an S3 VPC endpoint and bucket policy to allow access only via the endpoint. No internet path is used.

**Incorrect:**
- A: These traverse the internet or are unnecessary.
- B: These traverse the internet or are unnecessary.
- C: These traverse the internet or are unnecessary.


---

---

### Question #614

A company is designing a new multi-tier web application that consists of the following components: • Web and application servers that run on Amazon EC2 instances as part of Auto Scaling groups • An Amazon RDS DB instance for data storage A solutions architect needs to limit access to the application servers so that only the web servers can access them. Which solution will meet these requirements?

- A. Deploy AWS PrivateLink in front of the application servers. Configure the network ACL to allow only the web servers to access the application servers.

- B. Deploy a VPC endpoint in front of the application servers. Configure the security group to allow only the web servers to access the application servers.

- C. Deploy a Network Load Balancer with a target group that contains the application servers' Auto Scaling group. Configure the network ACL to allow only the web servers to access the application servers.

- D. Deploy an Application Load Balancer with a target group that contains the application servers' Auto Scaling group. Configure the security group to allow only the web servers to access the application servers.

**Correct:** D
**Why:** ALB for the app tier with security groups allowing only the web tier enforces tiered access cleanly.

**Incorrect:**
- A: PrivateLink/VPC endpoints don’t fit this intra‑VPC tiering model.
- B: PrivateLink/VPC endpoints don’t fit this intra‑VPC tiering model.
- C: NLB lacks L7 features; NACLs are coarse and stateless.


---

---

### Question #616

A company has deployed its newest product on AWS. The product runs in an Auto Scaling group behind a Network Load Balancer. The company stores the product’s objects in an Amazon S3 bucket. The company recently experienced malicious attacks against its systems. The company needs a solution that continuously monitors for malicious activity in the AWS account, workloads, and access patterns to the S3 bucket. The solution must also report suspicious activity and display the information on a dashboard. Which solution will meet these requirements?

- A. Configure Amazon Macie to monitor and report ndings to AWS Cong.

- B. Configure Amazon Inspector to monitor and report ndings to AWS CloudTrail.

- C. Configure Amazon GuardDuty to monitor and report ndings to AWS Security Hub.

- D. Configure AWS Cong to monitor and report ndings to Amazon EventBridge.

**Correct:** C
**Why:** GuardDuty continuously monitors account, workload, and S3 access for threats; Security Hub aggregates and dashboards findings.

**Incorrect:**
- A: Macie focuses on sensitive data discovery, not threat detection.
- B: Inspector is for vulnerability assessment, not S3 access/threat patterns.
- D: Config tracks resource configuration, not threat activity.


---

---

### Question #618

A company wants to use Amazon FSx for Windows File Server for its Amazon EC2 instances that have an SMB file share mounted as a volume in the us-east-1 Region. The company has a recovery point objective (RPO) of 5 minutes for planned system maintenance or unplanned service disruptions. The company needs to replicate the file system to the us-west-2 Region. The replicated data must not be deleted by any user for 5 years. Which solution will meet these requirements?

- A. Create an FSx for Windows File Server file system in us-east-1 that has a Single-AZ 2 deployment type. Use AWS Backup to create a daily backup plan that includes a backup rule that copies the backup to us-west-2. Configure AWS Backup Vault Lock in compliance mode for a target vault in us-west-2. Configure a minimum duration of 5 years.

- B. Create an FSx for Windows File Server file system in us-east-1 that has a Multi-AZ deployment type. Use AWS Backup to create a daily backup plan that includes a backup rule that copies the backup to us-west-2. Configure AWS Backup Vault Lock in governance mode for a target vault in us-west-2. Configure a minimum duration of 5 years.

- C. Create an FSx for Windows File Server file system in us-east-1 that has a Multi-AZ deployment type. Use AWS Backup to create a daily backup plan that includes a backup rule that copies the backup to us-west-2. Configure AWS Backup Vault Lock in compliance mode for a target vault in us-west-2. Configure a minimum duration of 5 years.

- D. Create an FSx for Windows File Server file system in us-east-1 that has a Single-AZ 2 deployment type. Use AWS Backup to create a daily backup plan that includes a backup rule that copies the backup to us-west-2. Configure AWS Backup Vault Lock in governance mode for a target vault in us-west-2. Configure a minimum duration of 5 years.

**Correct:** C
**Why:** Multi‑AZ FSx for Windows for primary; copy backups to us‑west‑2 with AWS Backup and enable Vault Lock compliance mode for 5‑year immutability.

**Incorrect:**
- A: Single‑AZ reduces availability.
- B: Governance mode can be bypassed by privileged users; compliance mode is required for WORM.
- D: Single‑AZ reduces availability.


---

---

### Question #622

A company is creating a new web application for its subscribers. The application will consist of a static single page and a persistent database layer. The application will have millions of users for 4 hours in the morning, but the application will have only a few thousand users during the rest of the day. The company's data architects have requested the ability to rapidly evolve their schema. Which solutions will meet these requirements and provide the MOST scalability? (Choose two.)

- A. Deploy Amazon DynamoDB as the database solution. Provision on-demand capacity.

- B. Deploy Amazon Aurora as the database solution. Choose the serverless DB engine mode.

- C. Deploy Amazon DynamoDB as the database solution. Ensure that DynamoDB auto scaling is enabled.

- D. Deploy the static content into an Amazon S3 bucket. Provision an Amazon CloudFront distribution with the S3 bucket as the origin.

E. Deploy the web servers for static content across a eet of Amazon EC2 instances in Auto Scaling groups. Configure the instances to periodically refresh the content from an Amazon Elastic File System (Amazon EFS) volume.

**Correct:** A, D
**Why:** DynamoDB (on‑demand) offers massive, bursty scalability with schema flexibility. S3 + CloudFront serves static content at scale.

**Incorrect:**
- B: Aurora Serverless is more ops overhead and cost for brief heavy peaks compared to DynamoDB.
- C: Auto scaling on provisioned may lag and require tuning vs. on‑demand.
- E: EC2 fleet for static content is unnecessary.


---

---

### Question #627

A company wants to migrate two DNS servers to AWS. The servers host a total of approximately 200 zones and receive 1 million requests each day on average. The company wants to maximize availability while minimizing the operational overhead that is related to the management of the two servers. What should a solutions architect recommend to meet these requirements?

- A. Create 200 new hosted zones in the Amazon Route 53 console Import zone files.

- B. Launch a single large Amazon EC2 instance Import zone tiles. Configure Amazon CloudWatch alarms and notications to alert the company about any downtime.

- C. Migrate the servers to AWS by using AWS Server Migration Service (AWS SMS). Configure Amazon CloudWatch alarms and notications to alert the company about any downtime.

- D. Launch an Amazon EC2 instance in an Auto Scaling group across two Availability Zones. Import zone files. Set the desired capacity to 1 and the maximum capacity to 3 for the Auto Scaling group. Configure scaling alarms to scale based on CPU utilization.

**Correct:** A
**Why:** Route 53 hosted zones are fully managed and highly available. Import existing zone files for low operational overhead.

**Incorrect:**
- B: EC2‑based DNS introduces ops burden and single points or scaling work.
- C: EC2‑based DNS introduces ops burden and single points or scaling work.
- D: EC2‑based DNS introduces ops burden and single points or scaling work.


---

---

### Question #630

A solutions architect is creating a data processing job that runs once daily and can take up to 2 hours to complete. If the job is interrupted, it has to restart from the beginning. How should the solutions architect address this issue in the MOST cost-effective manner?

- A. Create a script that runs locally on an Amazon EC2 Reserved Instance that is triggered by a cron job.

- B. Create an AWS Lambda function triggered by an Amazon EventBridge scheduled event.

- C. Use an Amazon Elastic Container Service (Amazon ECS) Fargate task triggered by an Amazon EventBridge scheduled event.

- D. Use an Amazon Elastic Container Service (Amazon ECS) task running on Amazon EC2 triggered by an Amazon EventBridge scheduled event.

**Correct:** C
**Why:** ECS Fargate scheduled by EventBridge runs containers up to hours long without managing servers; resilient to interruptions.

**Incorrect:**
- A: A single RI instance is brittle and always on.
- B: Lambda max runtime is insufficient for a 2‑hour job.
- D: ECS on EC2 requires capacity management.


---

---

### Question #632

A company is creating a new application that will store a large amount of data. The data will be analyzed hourly and will be modied by several Amazon EC2 Linux instances that are deployed across multiple Availability Zones. The needed amount of storage space will continue to grow for the next 6 months. Which storage solution should a solutions architect recommend to meet these requirements?

- A. Store the data in Amazon S3 Glacier. Update the S3 Glacier vault policy to allow access to the application instances.

- B. Store the data in an Amazon Elastic Block Store (Amazon EBS) volume. Mount the EBS volume on the application instances.

- C. Store the data in an Amazon Elastic File System (Amazon EFS) file system. Mount the file system on the application instances.

- D. Store the data in an Amazon Elastic Block Store (Amazon EBS) Provisioned IOPS volume shared between the application instances.

**Correct:** C
**Why:** Amazon EFS provides a shared, scalable file system across AZs, ideal for concurrent modification and hourly analytics.

**Incorrect:**
- A: Glacier is archival and slow.
- B: EBS can’t be shared across instances/AZs concurrently.
- D: EBS can’t be shared across instances/AZs concurrently.


---

---

### Question #635

A company uses Amazon FSx for NetApp ONTAP in its primary AWS Region for CIFS and NFS file shares. Applications that run on Amazon EC2 instances access the file shares. The company needs a storage disaster recovery (DR) solution in a secondary Region. The data that is replicated in the secondary Region needs to be accessed by using the same protocols as the primary Region. Which solution will meet these requirements with the LEAST operational overhead?

- A. Create an AWS Lambda function to copy the data to an Amazon S3 bucket. Replicate the S3 bucket to the secondary Region.

- B. Create a backup of the FSx for ONTAP volumes by using AWS Backup. Copy the volumes to the secondary Region. Create a new FSx for ONTAP instance from the backup.

- C. Create an FSx for ONTAP instance in the secondary Region. Use NetApp SnapMirror to replicate data from the primary Region to the secondary Region.

- D. Create an Amazon Elastic File System (Amazon EFS) volume. Migrate the current data to the volume. Replicate the volume to the secondary Region.

**Correct:** C
**Why:** FSx for NetApp ONTAP supports SMB/NFS; use SnapMirror for cross‑Region replication with the same protocols on failover.

**Incorrect:**
- A: Lambda + S3 is not a file service and loses protocol semantics.
- B: Backup/restore increases RTO and ops.
- D: EFS is NFS only, not SMB.


---

---

### Question #637

A solutions architect is designing a new service behind Amazon API Gateway. The request patterns for the service will be unpredictable and can change suddenly from 0 requests to over 500 per second. The total size of the data that needs to be persisted in a backend database is currently less than 1 GB with unpredictable future growth. Data can be queried using simple key-value requests. Which combination ofAWS services would meet these requirements? (Choose two.)

- A. AWS Fargate

- B. AWS Lambda

- C. Amazon DynamoDB

- D. Amazon EC2 Auto Scaling

E. MySQL-compatible Amazon Aurora

**Correct:** B, C
**Why:** Lambda scales to sudden bursts. DynamoDB provides key‑value storage with <1 GB easily and elastic throughput.

**Incorrect:**
- A: Fargate/ASG/Aurora add ops or are overkill for KB/MB‑scale key‑value.
- D: Fargate/ASG/Aurora add ops or are overkill for KB/MB‑scale key‑value.
- E: Fargate/ASG/Aurora add ops or are overkill for KB/MB‑scale key‑value.


---

---

### Question #639

A company is building a new furniture inventory application. The company has deployed the application on a eet ofAmazon EC2 instances across multiple Availability Zones. The EC2 instances run behind an Application Load Balancer (ALB) in their VPC. A solutions architect has observed that incoming trac seems to favor one EC2 instance, resulting in latency for some requests. What should the solutions architect do to resolve this issue?

- A. Disable session anity (sticky sessions) on the ALB

- B. Replace the ALB with a Network Load Balancer

- C. Increase the number of EC2 instances in each Availability Zone

- D. Adjust the frequency of the health checks on the ALB's target group

**Correct:** A
**Why:** Sticky sessions (session affinity) can concentrate traffic; disabling distributes requests evenly among instances.

**Incorrect:**
- B: NLB doesn’t solve HTTP session stickiness issues.
- C: More instances treats symptoms but not root cause.
- D: Health check frequency isn’t the cause of imbalance.


---

---

### Question #642

A company wants to run a gaming application on Amazon EC2 instances that are part of an Auto Scaling group in the AWS Cloud. The application will transmit data by using UDP packets. The company wants to ensure that the application can scale out and in as trac increases and decreases. What should a solutions architect do to meet these requirements?

- A. Attach a Network Load Balancer to the Auto Scaling group.

- B. Attach an Application Load Balancer to the Auto Scaling group.

- C. Deploy an Amazon Route 53 record set with a weighted policy to route trac appropriately.

- D. Deploy a NAT instance that is congured with port forwarding to the EC2 instances in the Auto Scaling group.

**Correct:** A
**Why:** NLB supports UDP and scales out/in with the Auto Scaling group behind it.

**Incorrect:**
- B: ALB does not support UDP.
- C: Route 53/NAT instance do not provide scalable UDP load balancing.
- D: Route 53/NAT instance do not provide scalable UDP load balancing.


---

---

### Question #646

A solutions architect needs to host a high performance computing (HPC) workload in the AWS Cloud. The workload will run on hundreds of Amazon EC2 instances and will require parallel access to a shared file system to enable distributed processing of large datasets. Datasets will be accessed across multiple instances simultaneously. The workload requires access latency within 1 ms. After processing has completed, engineers will need access to the dataset for manual postprocessing. Which solution will meet these requirements?

- A. Use Amazon Elastic File System (Amazon EFS) as a shared file system. Access the dataset from Amazon EFS.

- B. Mount an Amazon S3 bucket to serve as the shared file system. Perform postprocessing directly from the S3 bucket.

- C. Use Amazon FSx for Lustre as a shared file system. Link the file system to an Amazon S3 bucket for postprocessing.

- D. Configure AWS Resource Access Manager to share an Amazon S3 bucket so that it can be mounted to all instances for processing and postprocessing.

**Correct:** B
**Why:** FSx for Lustre persistent file systems provide sub‑millisecond latency, high throughput, and HA for HPC, with optional S3 integration for data lifecycle.

**Incorrect:**
- A: Scratch has no HA.
- C: Not explicit about persistence/HA; persistent FSx is preferred for availability.
- D: S3 is not a POSIX FS and cannot be "mounted" natively with required latency.


---

---

### Question #650

A company wants to migrate its on-premises Microsoft SQL Server Enterprise edition database to AWS. The company's online application uses the database to process transactions. The data analysis team uses the same production database to run reports for analytical processing. The company wants to reduce operational overhead by moving to managed services wherever possible. Which solution will meet these requirements with the LEAST operational overhead?

- A. Migrate to Amazon RDS for Microsoft SOL Server. Use read replicas for reporting purposes

- B. Migrate to Microsoft SQL Server on Amazon EC2. Use Always On read replicas for reporting purposes

- C. Migrate to Amazon DynamoDB. Use DynamoDB on-demand replicas for reporting purposes

- D. Migrate to Amazon Aurora MySQL. Use Aurora read replicas for reporting purposes

**Correct:** A
**Why:** RDS for SQL Server Enterprise supports read replicas for reporting (Always On readable secondaries), reducing ops overhead compared to self‑managed EC2.

**Incorrect:**
- B: EC2 + Always On is higher ops.
- C: DynamoDB/Aurora MySQL require major app changes.
- D: DynamoDB/Aurora MySQL require major app changes.


---

---

### Question #654

A company recently migrated its web application to the AWS Cloud. The company uses an Amazon EC2 instance to run multiple processes to host the application. The processes include an Apache web server that serves static content. The Apache web server makes requests to a PHP application that uses a local Redis server for user sessions. The company wants to redesign the architecture to be highly available and to use AWS managed solutions. Which solution will meet these requirements?

- A. Use AWS Elastic Beanstalk to host the static content and the PHP application. Configure Elastic Beanstalk to deploy its EC2 instance into a public subnet. Assign a public IP address.

- B. Use AWS Lambda to host the static content and the PHP application. Use an Amazon API Gateway REST API to proxy requests to the Lambda function. Set the API Gateway CORS configuration to respond to the domain name. Configure Amazon ElastiCache for Redis to handle session information.

- C. Keep the backend code on the EC2 instance. Create an Amazon ElastiCache for Redis cluster that has Multi-AZ enabled. Configure the ElastiCache for Redis cluster in cluster mode. Copy the frontend resources to Amazon S3. Configure the backend code to reference the EC2 instance.

- D. Configure an Amazon CloudFront distribution with an Amazon S3 endpoint to an S3 bucket that is congured to host the static content. Configure an Application Load Balancer that targets an Amazon Elastic Container Service (Amazon ECS) service that runs AWS Fargate tasks for the PHP application. Configure the PHP application to use an Amazon ElastiCache for Redis cluster that runs in multiple Availability Zones.

**Correct:** D
**Why:** S3 + CloudFront for static assets; ECS Fargate behind ALB for PHP app; Redis (Multi‑AZ) for sessions meets HA with managed services.

**Incorrect:**
- A: Single EC2 in public subnet is not HA.
- B: Lambda for PHP monolith adds complexity and cold‑start concerns.
- C: Keeping backend on EC2 is not fully managed/HA.


---

---

### Question #655

A company runs a web application on Amazon EC2 instances in an Auto Scaling group that has a target group. The company designed the application to work with session anity (sticky sessions) for a better user experience. The application must be available publicly over the internet as an endpoint. A WAF must be applied to the endpoint for additional security. Session anity (sticky sessions) must be congured on the endpoint. Which combination of steps will meet these requirements? (Choose two.)

- A. Create a public Network Load Balancer. Specify the application target group.

- B. Create a Gateway Load Balancer. Specify the application target group.

- C. Create a public Application Load Balancer. Specify the application target group.

- D. Create a second target group. Add Elastic IP addresses to the EC2 instances.

E. Create a web ACL in AWS WAF. Associate the web ACL with the endpoint

**Correct:** C, E
**Why:** ALB supports sticky sessions and integrates with AWS WAF via a web ACL for security.

**Incorrect:**
- A: NLB/GWLB don’t provide sticky sessions for HTTP; Elastic IPs are not target group members.
- B: NLB/GWLB don’t provide sticky sessions for HTTP; Elastic IPs are not target group members.
- D: NLB/GWLB don’t provide sticky sessions for HTTP; Elastic IPs are not target group members.


---

---

### Question #656

A company runs a website that stores images of historical events. Website users need the ability to search and view images based on the year that the event in the image occurred. On average, users request each image only once or twice a year. The company wants a highly available solution to store and deliver the images to users. Which solution will meet these requirements MOST cost-effectively?

- A. Store images in Amazon Elastic Block Store (Amazon EBS). Use a web server that runs on Amazon EC2.

- B. Store images in Amazon Elastic File System (Amazon EFS). Use a web server that runs on Amazon EC2.

- C. Store images in Amazon S3 Standard. Use S3 Standard to directly deliver images by using a static website.

- D. Store images in Amazon S3 Standard-Infrequent Access (S3 Standard-IA). Use S3 Standard-IA to directly deliver images by using a static website.

**Correct:** D
**Why:** S3 Standard‑IA stores infrequently accessed images cost‑effectively and can serve via static website hosting when requested.

**Incorrect:**
- A: EBS/EFS require EC2 and add ops.
- B: EBS/EFS require EC2 and add ops.
- C: S3 Standard costs more for rarely accessed objects.


---

---

### Question #660

A company hosts an application on Amazon EC2 On-Demand Instances in an Auto Scaling group. Application peak hours occur at the same time each day. Application users report slow application performance at the start of peak hours. The application performs normally 2-3 hours after peak hours begin. The company wants to ensure that the application works properly at the start of peak hours. Which solution will meet these requirements?

- A. Configure an Application Load Balancer to distribute trac properly to the instances.

- B. Configure a dynamic scaling policy for the Auto Scaling group to launch new instances based on memory utilization.

- C. Configure a dynamic scaling policy for the Auto Scaling group to launch new instances based on CPU utilization.

- D. Configure a scheduled scaling policy for the Auto Scaling group to launch new instances before peak hours.

**Correct:** D
**Why:** Scheduled scaling pre‑warms capacity before predictable peak hours to avoid slow start.

**Incorrect:**
- A: Load balancer alone won’t add capacity.
- B: Reactive scaling lags at the start of peaks.
- C: Reactive scaling lags at the start of peaks.


---

---

### Question #661

A company runs applications on AWS that connect to the company's Amazon RDS database. The applications scale on weekends and at peak times of the year. The company wants to scale the database more effectively for its applications that connect to the database. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use Amazon DynamoDB with connection pooling with a target group configuration for the database. Change the applications to use the DynamoDB endpoint.

- B. Use Amazon RDS Proxy with a target group for the database. Change the applications to use the RDS Proxy endpoint.

- C. Use a custom proxy that runs on Amazon EC2 as an intermediary to the database. Change the applications to use the custom proxy endpoint.

- D. Use an AWS Lambda function to provide connection pooling with a target group configuration for the database. Change the applications to use the Lambda function.

**Correct:** B
**Why:** RDS Proxy pools and shares DB connections, improving scalability during surges with minimal app changes.

**Incorrect:**
- A: DynamoDB/Lambda are unrelated to SQL connection pooling.
- C: Custom proxy increases ops burden.
- D: DynamoDB/Lambda are unrelated to SQL connection pooling.


---

---

### Question #666

A startup company is hosting a website for its customers on an Amazon EC2 instance. The website consists of a stateless Python application and a MySQL database. The website serves only a small amount of trac. The company is concerned about the reliability of the instance and needs to migrate to a highly available architecture. The company cannot modify the application code. Which combination of actions should a solutions architect take to achieve high availability for the website? (Choose two.)

- A. Provision an internet gateway in each Availability Zone in use.

- B. Migrate the database to an Amazon RDS for MySQL Multi-AZ DB instance.

- C. Migrate the database to Amazon DynamoDB, and enable DynamoDB auto scaling.

- D. Use AWS DataSync to synchronize the database data across multiple EC2 instances.

E. Create an Application Load Balancer to distribute trac to an Auto Scaling group of EC2 instances that are distributed across two Availability Zones.

**Correct:** B, E
**Why:** RDS for MySQL Multi‑AZ provides HA for the DB. ALB + Auto Scaling across two AZs provides HA for the stateless app without code changes.

**Incorrect:**
- A: Internet gateways are per VPC, not per AZ.
- C: DynamoDB/DataSync are irrelevant here.
- D: DynamoDB/DataSync are irrelevant here.


---

---

### Question #671

A company runs its applications on Amazon EC2 instances. The company performs periodic nancial assessments of its AWS costs. The company recently identied unusual spending. The company needs a solution to prevent unusual spending. The solution must monitor costs and notify responsible stakeholders in the event of unusual spending. Which solution will meet these requirements?

- A. Use an AWS Budgets template to create a zero spend budget.

- B. Create an AWS Cost Anomaly Detection monitor in the AWS Billing and Cost Management console.

- C. Create AWS Pricing Calculator estimates for the current running workload pricing details.

- D. Use Amazon CloudWatch to monitor costs and to identify unusual spending.

**Correct:** B
**Why:** AWS Cost Anomaly Detection monitors spend with ML and sends alerts on unusual patterns, meeting prevention and notification needs.

**Incorrect:**
- A: A zero‑spend budget is not practical and does not detect anomalies appropriately.
- C: Pricing Calculator is for estimates, not monitoring actual spend.
- D: CloudWatch does not natively monitor detailed cost anomalies; use Cost Anomaly Detection.


---

---

### Question #674

A company runs a web application on Amazon EC2 instances in an Auto Scaling group. The application uses a database that runs on an Amazon RDS for PostgreSQL DB instance. The application performs slowly when trac increases. The database experiences a heavy read load during periods of high trac. Which actions should a solutions architect take to resolve these performance issues? (Choose two.)

- A. Turn on auto scaling for the DB instance.

- B. Create a read replica for the DB instance. Configure the application to send read trac to the read replica.

- C. Convert the DB instance to a Multi-AZ DB instance deployment. Configure the application to send read trac to the standby DB instance.

- D. Create an Amazon ElastiCache cluster. Configure the application to cache query results in the ElastiCache cluster.

E. Configure the Auto Scaling group subnets to ensure that the EC2 instances are provisioned in the same Availability Zone as the DB instance.

**Correct:** B, D
**Why:** Offload read traffic to an RDS read replica and/or cache frequent queries in ElastiCache to reduce DB load and improve response times.

**Incorrect:**
- A: RDS compute does not auto scale; this doesn’t solve read pressure.
- C: Multi‑AZ standby is not readable.


---

---

### Question #675

A company uses Amazon EC2 instances and Amazon Elastic Block Store (Amazon EBS) volumes to run an application. The company creates one snapshot of each EBS volume every day to meet compliance requirements. The company wants to implement an architecture that prevents the accidental deletion of EBS volume snapshots. The solution must not change the administrative rights of the storage administrator user. Which solution will meet these requirements with the LEAST administrative effort?

- A. Create an IAM role that has permission to delete snapshots. Attach the role to a new EC2 instance. Use the AWS CLI from the new EC2 instance to delete snapshots.

- B. Create an IAM policy that denies snapshot deletion. Attach the policy to the storage administrator user.

- C. Add tags to the snapshots. Create retention rules in Recycle Bin for EBS snapshots that have the tags.

- D. Lock the EBS snapshots to prevent deletion.

**Correct:** C
**Why:** Use Recycle Bin with tags and retention rules so accidentally deleted snapshots can be recovered without changing admin rights.

**Incorrect:**
- A: Adding a role and deleting from a separate instance is not a safeguard.
- B: Denying deletion changes administrator rights, violating the requirement.
- D: There is no snapshot "lock" feature; use Recycle Bin.


---

---

### Question #676

A company's application uses Network Load Balancers, Auto Scaling groups, Amazon EC2 instances, and databases that are deployed in an Amazon VPC. The company wants to capture information about trac to and from the network interfaces in near real time in its Amazon VPC. The company wants to send the information to Amazon OpenSearch Service for analysis. Which solution will meet these requirements?

- A. Create a log group in Amazon CloudWatch Logs. Configure VPC Flow Logs to send the log data to the log group. Use Amazon Kinesis Data Streams to stream the logs from the log group to OpenSearch Service.

- B. Create a log group in Amazon CloudWatch Logs. Configure VPC Flow Logs to send the log data to the log group. Use Amazon Kinesis Data Firehose to stream the logs from the log group to OpenSearch Service.

- C. Create a trail in AWS CloudTrail. Configure VPC Flow Logs to send the log data to the trail. Use Amazon Kinesis Data Streams to stream the logs from the trail to OpenSearch Service.

- D. Create a trail in AWS CloudTrail. Configure VPC Flow Logs to send the log data to the trail. Use Amazon Kinesis Data Firehose to stream the logs from the trail to OpenSearch Service.

**Correct:** B
**Why:** Send VPC Flow Logs to CloudWatch Logs, then stream to OpenSearch Service with Kinesis Data Firehose for near real‑time analysis.

**Incorrect:**
- A: Data Streams adds custom consumer management; Firehose is simpler.
- C: CloudTrail is not used for VPC Flow Logs delivery.
- D: CloudTrail is not used for VPC Flow Logs delivery.


---

---

### Question #677

A company is developing an application that will run on a production Amazon Elastic Kubernetes Service (Amazon EKS) cluster. The EKS cluster has managed node groups that are provisioned with On-Demand Instances. The company needs a dedicated EKS cluster for development work. The company will use the development cluster infrequently to test the resiliency of the application. The EKS cluster must manage all the nodes. Which solution will meet these requirements MOST cost-effectively?

- A. Create a managed node group that contains only Spot Instances.

- B. Create two managed node groups. Provision one node group with On-Demand Instances. Provision the second node group with Spot Instances.

- C. Create an Auto Scaling group that has a launch configuration that uses Spot Instances. Configure the user data to add the nodes to the EKS cluster.

- D. Create a managed node group that contains only On-Demand Instances.

**Correct:** A
**Why:** A managed node group with Spot Instances is cost‑effective for an infrequently used development cluster while remaining fully managed.

**Incorrect:**
- B: On‑Demand costs more for infrequent use.
- C: ASG + custom bootstrap adds ops overhead and is not a managed node group.
- D: On‑Demand only is highest cost.


---

---

### Question #678

A company stores sensitive data in Amazon S3. A solutions architect needs to create an encryption solution. The company needs to fully control the ability of users to create, rotate, and disable encryption keys with minimal effort for any data that must be encrypted. Which solution will meet these requirements?

- A. Use default server-side encryption with Amazon S3 managed encryption keys (SSE-S3) to store the sensitive data.

- B. Create a customer managed key by using AWS Key Management Service (AWS KMS). Use the new key to encrypt the S3 objects by using server-side encryption with AWS KMS keys (SSE-KMS).

- C. Create an AWS managed key by using AWS Key Management Service (AWS KMS). Use the new key to encrypt the S3 objects by using server-side encryption with AWS KMS keys (SSE-KMS).

- D. Download S3 objects to an Amazon EC2 instance. Encrypt the objects by using customer managed keys. Upload the encrypted objects back into Amazon S3.

**Correct:** B
**Why:** Use a customer managed KMS key with SSE‑KMS for S3 to fully control key creation, rotation, and disabling.

**Incorrect:**
- A: SSE‑S3 uses AWS‑owned keys with no customer control.
- C: AWS managed keys limit control of rotation/disable.
- D: Client‑side EC2 encryption adds operational complexity.


---

---

### Question #680

A solutions architect needs to copy files from an Amazon S3 bucket to an Amazon Elastic File System (Amazon EFS) file system and another S3 bucket. The files must be copied continuously. New files are added to the original S3 bucket consistently. The copied files should be overwritten only if the source file changes. Which solution will meet these requirements with the LEAST operational overhead?

- A. Create an AWS DataSync location for both the destination S3 bucket and the EFS file system. Create a task for the destination S3 bucket and the EFS file system. Set the transfer mode to transfer only data that has changed.

- B. Create an AWS Lambda function. Mount the file system to the function. Set up an S3 event notification to invoke the function when files are created and changed in Amazon S3. Configure the function to copy files to the file system and the destination S3 bucket.

- C. Create an AWS DataSync location for both the destination S3 bucket and the EFS file system. Create a task for the destination S3 bucket and the EFS file system. Set the transfer mode to transfer all data.

- D. Launch an Amazon EC2 instance in the same VPC as the file system. Mount the file system. Create a script to routinely synchronize all objects that changed in the origin S3 bucket to the destination S3 bucket and the mounted file system.

**Correct:** A
**Why:** AWS DataSync supports continuous copies S3→S3 and S3→EFS with change‑only transfers, minimizing overhead and avoiding unnecessary overwrites.

**Incorrect:**
- B: Lambda + mount is complex and not ideal for continuous, scalable sync.
- C: Transfer all data is inefficient and increases costs.
- D: EC2 + scripts adds ops and reliability risks.


---

---

### Question #681

A company uses Amazon EC2 instances and stores data on Amazon Elastic Block Store (Amazon EBS) volumes. The company must ensure that all data is encrypted at rest by using AWS Key Management Service (AWS KMS). The company must be able to control rotation of the encryption keys. Which solution will meet these requirements with the LEAST operational overhead?

- A. Create a customer managed key. Use the key to encrypt the EBS volumes.

- B. Use an AWS managed key to encrypt the EBS volumes. Use the key to configure automatic key rotation.

- C. Create an external KMS key with imported key material. Use the key to encrypt the EBS volumes.

- D. Use an AWS owned key to encrypt the EBS volumes.

**Correct:** A
**Why:** A customer managed KMS key encrypts EBS volumes with customer‑controlled rotation, meeting requirements with low ops.

**Incorrect:**
- B: AWS managed keys do not give customer control over rotation/disable.
- C: External key material increases complexity without additional benefit here.
- D: AWS owned keys provide no control or visibility.


---

---

### Question #682

A company needs a solution to enforce data encryption at rest on Amazon EC2 instances. The solution must automatically identify noncompliant resources and enforce compliance policies on ndings. Which solution will meet these requirements with the LEAST administrative overhead?

- A. Use an IAM policy that allows users to create only encrypted Amazon Elastic Block Store (Amazon EBS) volumes. Use AWS Cong and AWS Systems Manager to automate the detection and remediation of unencrypted EBS volumes.

- B. Use AWS Key Management Service (AWS KMS) to manage access to encrypted Amazon Elastic Block Store (Amazon EBS) volumes. Use AWS Lambda and Amazon EventBridge to automate the detection and remediation of unencrypted EBS volumes.

- C. Use Amazon Macie to detect unencrypted Amazon Elastic Block Store (Amazon EBS) volumes. Use AWS Systems Manager Automation rules to automatically encrypt existing and new EBS volumes.

- D. Use Amazon inspector to detect unencrypted Amazon Elastic Block Store (Amazon EBS) volumes. Use AWS Systems Manager Automation rules to automatically encrypt existing and new EBS volumes.

**Correct:** A
**Why:** Enforce encrypted EBS creation via IAM, and use AWS Config with Systems Manager Automation to detect and remediate unencrypted volumes automatically.

**Incorrect:**
- B: Lambda + EventBridge is more custom ops; KMS alone doesn’t enforce encryption.
- C: Macie/Inspector do not detect EBS encryption compliance.
- D: Macie/Inspector do not detect EBS encryption compliance.


---

---

### Question #683

A company is migrating its multi-tier on-premises application to AWS. The application consists of a single-node MySQL database and a multi-node web tier. The company must minimize changes to the application during the migration. The company wants to improve application resiliency after the migration. Which combination of steps will meet these requirements? (Choose two.)

- A. Migrate the web tier to Amazon EC2 instances in an Auto Scaling group behind an Application Load Balancer.

- B. Migrate the database to Amazon EC2 instances in an Auto Scaling group behind a Network Load Balancer.

- C. Migrate the database to an Amazon RDS Multi-AZ deployment.

- D. Migrate the web tier to an AWS Lambda function.

E. Migrate the database to an Amazon DynamoDB table.

**Correct:** A, C
**Why:** Move the web tier behind an ALB with Auto Scaling for resiliency, and migrate the DB to RDS Multi‑AZ for high availability with minimal app changes.

**Incorrect:**
- B: EC2 DB on NLB is self‑managed and higher ops.
- D: Lambda/DynamoDB require major app changes.
- E: Lambda/DynamoDB require major app changes.


---

## Amazon EFS

### Question #502

A company runs a website that uses a content management system (CMS) on Amazon EC2. The CMS runs on a single EC2 instance and uses an Amazon Aurora MySQL Multi-AZ DB instance for the data tier. Website images are stored on an Amazon Elastic Block Store (Amazon EBS) volume that is mounted inside the EC2 instance. Which combination of actions should a solutions architect take to improve the performance and resilience of the website? (Choose two.)

- A. Move the website images into an Amazon S3 bucket that is mounted on every EC2 instance

- B. Share the website images by using an NFS share from the primary EC2 instance. Mount this share on the other EC2 instances.

- C. Move the website images onto an Amazon Elastic File System (Amazon EFS) file system that is mounted on every EC2 instance.

- D. Create an Amazon Machine Image (AMI) from the existing EC2 instance. Use the AMI to provision new instances behind an Application Load Balancer as part of an Auto Scaling group. Configure the Auto Scaling group to maintain a minimum of two instances. Configure an accelerator in AWS Global Accelerator for the website

E. Create an Amazon Machine Image (AMI) from the existing EC2 instance. Use the AMI to provision new instances behind an Application Load Balancer as part of an Auto Scaling group. Configure the Auto Scaling group to maintain a minimum of two instances. Configure an Amazon CloudFront distribution for the website.

**Correct:** C, E
**Why:** Move images to EFS for shared, scalable storage; use ALB+Auto Scaling behind a CloudFront distribution for performance and resilience.

**Incorrect:**
- A: S3 mounted or EC2 NFS via a primary instance are not ideal.
- B: S3 mounted or EC2 NFS via a primary instance are not ideal.
- D: Global Accelerator is unnecessary for origin performance here.


---

---

### Question #506

A social media company is building a feature for its website. The feature will give users the ability to upload photos. The company expects signicant increases in demand during large events and must ensure that the website can handle the upload trac from users. Which solution meets these requirements with the MOST scalability?

- A. Upload files from the user's browser to the application servers. Transfer the files to an Amazon S3 bucket.

- B. Provision an AWS Storage Gateway file gateway. Upload files directly from the user's browser to the file gateway.

- C. Generate Amazon S3 presigned URLs in the application. Upload files directly from the user's browser into an S3 bucket.

- D. Provision an Amazon Elastic File System (Amazon EFS) file system. Upload files directly from the user's browser to the file system.

**Correct:** C
**Why:** Use S3 presigned URLs so browsers upload directly to S3, maximizing scalability and offloading servers.

**Incorrect:**
- A: Uploading through app servers/gateways/EFS reduces scalability.
- B: Uploading through app servers/gateways/EFS reduces scalability.
- D: Uploading through app servers/gateways/EFS reduces scalability.


---

---

### Question #546

A recent analysis of a company's IT expenses highlights the need to reduce backup costs. The company's chief information ocer wants to simplify the on-premises backup infrastructure and reduce costs by eliminating the use of physical backup tapes. The company must preserve the existing investment in the on-premises backup applications and workows. What should a solutions architect recommend?

- A. Set up AWS Storage Gateway to connect with the backup applications using the NFS interface.

- B. Set up an Amazon EFS file system that connects with the backup applications using the NFS interface.

- C. Set up an Amazon EFS file system that connects with the backup applications using the iSCSI interface.

- D. Set up AWS Storage Gateway to connect with the backup applications using the iSCSI-virtual tape library (VTL) interface.

**Correct:** D
**Why:** Storage Gateway VTL (iSCSI) integrates with existing backup apps and removes physical tapes.

**Incorrect:**
- A: NFS/iSCSI to EFS do not match tape workflows.
- B: NFS/iSCSI to EFS do not match tape workflows.
- C: NFS/iSCSI to EFS do not match tape workflows.


---

---

### Question #566

A company runs multiple Amazon EC2 Linux instances in a VPC across two Availability Zones. The instances host applications that use a hierarchical directory structure. The applications need to read and write rapidly and concurrently to shared storage. What should a solutions architect do to meet these requirements?

- A. Create an Amazon S3 bucket. Allow access from all the EC2 instances in the VPC.

- B. Create an Amazon Elastic File System (Amazon EFS) file system. Mount the EFS file system from each EC2 instance.

- C. Create a file system on a Provisioned IOPS SSD (io2) Amazon Elastic Block Store (Amazon EBS) volume. Attach the EBS volume to all the EC2 instances.

- D. Create file systems on Amazon Elastic Block Store (Amazon EBS) volumes that are attached to each EC2 instance. Synchronize the EBS volumes across the different EC2 instances.

**Correct:** B
**Why:** Amazon EFS provides shared POSIX file system semantics, high concurrency, and multi-AZ access for EC2 instances; ideal for hierarchical directory structures and concurrent read/write.

**Incorrect:**
- A: S3 is object storage, not a shared POSIX file system.
- C: EBS volumes cannot be concurrently attached to multiple instances across AZs for shared writes.
- D: EBS volumes cannot be concurrently attached to multiple instances across AZs for shared writes.


---

---

### Question #567

A solutions architect is designing a workload that will store hourly energy consumption by business tenants in a building. The sensors will feed a database through HTTP requests that will add up usage for each tenant. The solutions architect must use managed services when possible. The workload will receive more features in the future as the solutions architect adds independent components. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use Amazon API Gateway with AWS Lambda functions to receive the data from the sensors, process the data, and store the data in an Amazon DynamoDB table.

- B. Use an Elastic Load Balancer that is supported by an Auto Scaling group of Amazon EC2 instances to receive and process the data from the sensors. Use an Amazon S3 bucket to store the processed data.

- C. Use Amazon API Gateway with AWS Lambda functions to receive the data from the sensors, process the data, and store the data in a Microsoft SQL Server Express database on an Amazon EC2 instance.

- D. Use an Elastic Load Balancer that is supported by an Auto Scaling group of Amazon EC2 instances to receive and process the data from the sensors. Use an Amazon Elastic File System (Amazon EFS) shared file system to store the processed data.

**Correct:** A
**Why:** API Gateway + Lambda gives a fully managed, serverless, event-driven ingestion and processing path with low overhead and easy future extensibility; store results in DynamoDB.

**Incorrect:**
- B: ELB + EC2 adds operational burden and is not necessary for simple HTTP ingest.
- C: EC2-hosted SQL Server Express increases ops overhead and reduces elasticity.
- D: ELB + EC2 adds operational burden and is not necessary for simple HTTP ingest.


---

---

### Question #587

A company is designing a solution to capture customer activity in different web applications to process analytics and make predictions. Customer activity in the web applications is unpredictable and can increase suddenly. The company requires a solution that integrates with other web applications. The solution must include an authorization step for security purposes. Which solution will meet these requirements?

- A. Configure a Gateway Load Balancer (GWLB) in front of an Amazon Elastic Container Service (Amazon ECS) container instance that stores the information that the company receives in an Amazon Elastic File System (Amazon EFS) file system. Authorization is resolved at the GWLB.

- B. Configure an Amazon API Gateway endpoint in front of an Amazon Kinesis data stream that stores the information that the company receives in an Amazon S3 bucket. Use an AWS Lambda function to resolve authorization.

- C. Configure an Amazon API Gateway endpoint in front of an Amazon Kinesis Data Firehose that stores the information that the company receives in an Amazon S3 bucket. Use an API Gateway Lambda authorizer to resolve authorization.

- D. Configure a Gateway Load Balancer (GWLB) in front of an Amazon Elastic Container Service (Amazon ECS) container instance that stores the information that the company receives on an Amazon Elastic File System (Amazon EFS) file system. Use an AWS Lambda function to resolve authorization.

**Correct:** C
**Why:** API Gateway with a Lambda authorizer provides auth. Kinesis Data Firehose scales ingestion and delivers to S3 with minimal ops overhead.

**Incorrect:**
- A: GWLB + ECS introduces heavy ops complexity for simple event ingestion.
- B: API Gateway to Kinesis Data Streams is viable but requires more scaling/consumer management than Firehose for S3 delivery.
- D: GWLB + ECS introduces heavy ops complexity for simple event ingestion.


---

---

### Question #617

A company wants to migrate an on-premises data center to AWS. The data center hosts a storage server that stores data in an NFS-based file system. The storage server holds 200 GB of data. The company needs to migrate the data without interruption to existing services. Multiple resources in AWS must be able to access the data by using the NFS protocol. Which combination of steps will meet these requirements MOST cost-effectively? (Choose two.)

- A. Create an Amazon FSx for Lustre file system.

- B. Create an Amazon Elastic File System (Amazon EFS) file system.

- C. Create an Amazon S3 bucket to receive the data.

- D. Manually use an operating system copy command to push the data into the AWS destination.

E. Install an AWS DataSync agent in the on-premises data center. Use a DataSync task between the on-premises location and AWS.

**Correct:** B, E
**Why:** Create an EFS file system for NFS access and use DataSync to copy data from on‑prem to EFS without downtime.

**Incorrect:**
- A: Lustre/S3/Manual copy do not meet NFS access and minimal‑ops goals together.
- C: Lustre/S3/Manual copy do not meet NFS access and minimal‑ops goals together.
- D: Lustre/S3/Manual copy do not meet NFS access and minimal‑ops goals together.


---

---

### Question #622

A company is creating a new web application for its subscribers. The application will consist of a static single page and a persistent database layer. The application will have millions of users for 4 hours in the morning, but the application will have only a few thousand users during the rest of the day. The company's data architects have requested the ability to rapidly evolve their schema. Which solutions will meet these requirements and provide the MOST scalability? (Choose two.)

- A. Deploy Amazon DynamoDB as the database solution. Provision on-demand capacity.

- B. Deploy Amazon Aurora as the database solution. Choose the serverless DB engine mode.

- C. Deploy Amazon DynamoDB as the database solution. Ensure that DynamoDB auto scaling is enabled.

- D. Deploy the static content into an Amazon S3 bucket. Provision an Amazon CloudFront distribution with the S3 bucket as the origin.

E. Deploy the web servers for static content across a eet of Amazon EC2 instances in Auto Scaling groups. Configure the instances to periodically refresh the content from an Amazon Elastic File System (Amazon EFS) volume.

**Correct:** A, D
**Why:** DynamoDB (on‑demand) offers massive, bursty scalability with schema flexibility. S3 + CloudFront serves static content at scale.

**Incorrect:**
- B: Aurora Serverless is more ops overhead and cost for brief heavy peaks compared to DynamoDB.
- C: Auto scaling on provisioned may lag and require tuning vs. on‑demand.
- E: EC2 fleet for static content is unnecessary.


---

---

### Question #632

A company is creating a new application that will store a large amount of data. The data will be analyzed hourly and will be modied by several Amazon EC2 Linux instances that are deployed across multiple Availability Zones. The needed amount of storage space will continue to grow for the next 6 months. Which storage solution should a solutions architect recommend to meet these requirements?

- A. Store the data in Amazon S3 Glacier. Update the S3 Glacier vault policy to allow access to the application instances.

- B. Store the data in an Amazon Elastic Block Store (Amazon EBS) volume. Mount the EBS volume on the application instances.

- C. Store the data in an Amazon Elastic File System (Amazon EFS) file system. Mount the file system on the application instances.

- D. Store the data in an Amazon Elastic Block Store (Amazon EBS) Provisioned IOPS volume shared between the application instances.

**Correct:** C
**Why:** Amazon EFS provides a shared, scalable file system across AZs, ideal for concurrent modification and hourly analytics.

**Incorrect:**
- A: Glacier is archival and slow.
- B: EBS can’t be shared across instances/AZs concurrently.
- D: EBS can’t be shared across instances/AZs concurrently.


---

---

### Question #635

A company uses Amazon FSx for NetApp ONTAP in its primary AWS Region for CIFS and NFS file shares. Applications that run on Amazon EC2 instances access the file shares. The company needs a storage disaster recovery (DR) solution in a secondary Region. The data that is replicated in the secondary Region needs to be accessed by using the same protocols as the primary Region. Which solution will meet these requirements with the LEAST operational overhead?

- A. Create an AWS Lambda function to copy the data to an Amazon S3 bucket. Replicate the S3 bucket to the secondary Region.

- B. Create a backup of the FSx for ONTAP volumes by using AWS Backup. Copy the volumes to the secondary Region. Create a new FSx for ONTAP instance from the backup.

- C. Create an FSx for ONTAP instance in the secondary Region. Use NetApp SnapMirror to replicate data from the primary Region to the secondary Region.

- D. Create an Amazon Elastic File System (Amazon EFS) volume. Migrate the current data to the volume. Replicate the volume to the secondary Region.

**Correct:** C
**Why:** FSx for NetApp ONTAP supports SMB/NFS; use SnapMirror for cross‑Region replication with the same protocols on failover.

**Incorrect:**
- A: Lambda + S3 is not a file service and loses protocol semantics.
- B: Backup/restore increases RTO and ops.
- D: EFS is NFS only, not SMB.


---

---

### Question #646

A solutions architect needs to host a high performance computing (HPC) workload in the AWS Cloud. The workload will run on hundreds of Amazon EC2 instances and will require parallel access to a shared file system to enable distributed processing of large datasets. Datasets will be accessed across multiple instances simultaneously. The workload requires access latency within 1 ms. After processing has completed, engineers will need access to the dataset for manual postprocessing. Which solution will meet these requirements?

- A. Use Amazon Elastic File System (Amazon EFS) as a shared file system. Access the dataset from Amazon EFS.

- B. Mount an Amazon S3 bucket to serve as the shared file system. Perform postprocessing directly from the S3 bucket.

- C. Use Amazon FSx for Lustre as a shared file system. Link the file system to an Amazon S3 bucket for postprocessing.

- D. Configure AWS Resource Access Manager to share an Amazon S3 bucket so that it can be mounted to all instances for processing and postprocessing.

**Correct:** B
**Why:** FSx for Lustre persistent file systems provide sub‑millisecond latency, high throughput, and HA for HPC, with optional S3 integration for data lifecycle.

**Incorrect:**
- A: Scratch has no HA.
- C: Not explicit about persistence/HA; persistent FSx is preferred for availability.
- D: S3 is not a POSIX FS and cannot be "mounted" natively with required latency.


---

---

### Question #648

A weather forecasting company needs to process hundreds of gigabytes of data with sub-millisecond latency. The company has a high performance computing (HPC) environment in its data center and wants to expand its forecasting capabilities. A solutions architect must identify a highly available cloud storage solution that can handle large amounts of sustained throughput. Files that are stored in the solution should be accessible to thousands of compute instances that will simultaneously access and process the entire dataset. What should the solutions architect do to meet these requirements?

- A. Use Amazon FSx for Lustre scratch file systems.

- B. Use Amazon FSx for Lustre persistent file systems.

- C. Use Amazon Elastic File System (Amazon EFS) with Bursting Throughput mode.

- D. Use Amazon Elastic File System (Amazon EFS) with Provisioned Throughput mode.

**Correct:** B
**Why:** FSx for Lustre persistent provides high throughput, low latency, and availability for thousands of concurrent clients.

**Incorrect:**
- A: Scratch lacks durability/HA.
- C: EFS throughput modes are not optimal for this HPC latency/throughput profile.
- D: EFS throughput modes are not optimal for this HPC latency/throughput profile.


---

---

### Question #656

A company runs a website that stores images of historical events. Website users need the ability to search and view images based on the year that the event in the image occurred. On average, users request each image only once or twice a year. The company wants a highly available solution to store and deliver the images to users. Which solution will meet these requirements MOST cost-effectively?

- A. Store images in Amazon Elastic Block Store (Amazon EBS). Use a web server that runs on Amazon EC2.

- B. Store images in Amazon Elastic File System (Amazon EFS). Use a web server that runs on Amazon EC2.

- C. Store images in Amazon S3 Standard. Use S3 Standard to directly deliver images by using a static website.

- D. Store images in Amazon S3 Standard-Infrequent Access (S3 Standard-IA). Use S3 Standard-IA to directly deliver images by using a static website.

**Correct:** D
**Why:** S3 Standard‑IA stores infrequently accessed images cost‑effectively and can serve via static website hosting when requested.

**Incorrect:**
- A: EBS/EFS require EC2 and add ops.
- B: EBS/EFS require EC2 and add ops.
- C: S3 Standard costs more for rarely accessed objects.


---

---

### Question #680

A solutions architect needs to copy files from an Amazon S3 bucket to an Amazon Elastic File System (Amazon EFS) file system and another S3 bucket. The files must be copied continuously. New files are added to the original S3 bucket consistently. The copied files should be overwritten only if the source file changes. Which solution will meet these requirements with the LEAST operational overhead?

- A. Create an AWS DataSync location for both the destination S3 bucket and the EFS file system. Create a task for the destination S3 bucket and the EFS file system. Set the transfer mode to transfer only data that has changed.

- B. Create an AWS Lambda function. Mount the file system to the function. Set up an S3 event notification to invoke the function when files are created and changed in Amazon S3. Configure the function to copy files to the file system and the destination S3 bucket.

- C. Create an AWS DataSync location for both the destination S3 bucket and the EFS file system. Create a task for the destination S3 bucket and the EFS file system. Set the transfer mode to transfer all data.

- D. Launch an Amazon EC2 instance in the same VPC as the file system. Mount the file system. Create a script to routinely synchronize all objects that changed in the origin S3 bucket to the destination S3 bucket and the mounted file system.

**Correct:** A
**Why:** AWS DataSync supports continuous copies S3→S3 and S3→EFS with change‑only transfers, minimizing overhead and avoiding unnecessary overwrites.

**Incorrect:**
- B: Lambda + mount is complex and not ideal for continuous, scalable sync.
- C: Transfer all data is inefficient and increases costs.
- D: EC2 + scripts adds ops and reliability risks.


---

## Amazon FSx

### Question #564

A company is building an ecommerce application and needs to store sensitive customer information. The company needs to give customers the ability to complete purchase transactions on the website. The company also needs to ensure that sensitive customer data is protected, even from database administrators. Which solution meets these requirements?

- A. Store sensitive data in an Amazon Elastic Block Store (Amazon EBS) volume. Use EBS encryption to encrypt the data. Use an IAM instance role to restrict access.

- B. Store sensitive data in Amazon RDS for MySQL. Use AWS Key Management Service (AWS KMS) client-side encryption to encrypt the data.

- C. Store sensitive data in Amazon S3. Use AWS Key Management Service (AWS KMS) server-side encryption to encrypt the data. Use S3 bucket policies to restrict access.

- D. Store sensitive data in Amazon FSx for Windows Server. Mount the file share on application servers. Use Windows file permissions to restrict access.

**Correct:** B
**Why:** To prevent even DBAs from accessing sensitive data, encrypt at the application/client layer before storage (client-side KMS encryption) and store ciphertext in the database.

**Incorrect:**
- A: EBS encryption protects at the volume level; DBAs can still read decrypted data via the DB engine.
- C: S3 is not the right backend for transactional ecommerce data; SSE-KMS also does not prevent privileged DB access.
- D: FSx + Windows permissions doesn’t address app-level transactional storage nor protect from DBAs.


---

---

### Question #580

A company uses locally attached storage to run a latency-sensitive application on premises. The company is using a lift and shift method to move the application to the AWS Cloud. The company does not want to change the application architecture. Which solution will meet these requirements MOST cost-effectively?

- A. Configure an Auto Scaling group with an Amazon EC2 instance. Use an Amazon FSx for Lustre file system to run the application.

- B. Host the application on an Amazon EC2 instance. Use an Amazon Elastic Block Store (Amazon EBS) GP2 volume to run the application.

- C. Configure an Auto Scaling group with an Amazon EC2 instance. Use an Amazon FSx for OpenZFS file system to run the application.

- D. Host the application on an Amazon EC2 instance. Use an Amazon Elastic Block Store (Amazon EBS) GP3 volume to run the application.

**Correct:** D
**Why:** EC2 with gp3 EBS provides low-latency block storage and is more cost-effective than gp2 for lift‑and‑shift without app changes.

**Incorrect:**
- A: FSx families are network file systems and require app changes.
- B: gp2 is older and less cost-efficient than gp3.
- C: FSx families are network file systems and require app changes.


---

---

### Question #598

A research company uses on-premises devices to generate data for analysis. The company wants to use the AWS Cloud to analyze the data. The devices generate .csv files and support writing the data to an SMB file share. Company analysts must be able to use SQL commands to query the data. The analysts will run queries periodically throughout the day. Which combination of steps will meet these requirements MOST cost-effectively? (Choose three.)

- A. Deploy an AWS Storage Gateway on premises in Amazon S3 File Gateway mode.

- B. Deploy an AWS Storage Gateway on premises in Amazon FSx File Gateway made.

- C. Set up an AWS Glue crawler to create a table based on the data that is in Amazon S3.

- D. Set up an Amazon EMR cluster with EMR File System (EMRFS) to query the data that is in Amazon S3. Provide access to analysts.

E. Set up an Amazon Redshift cluster to query the data that is in Amazon S3. Provide access to analysts.

F. Setup Amazon Athena to query the data that is in Amazon S3. Provide access to analysts.

**Correct:** A, C, F
**Why:** Use S3 File Gateway to land CSVs in S3 over SMB, crawl with Glue to build schema, and query with Athena using SQL on demand.

**Incorrect:**
- B: FSx File Gateway presents FSx, not S3.
- D: EMR/Redshift add cost/ops for periodic ad‑hoc queries.
- E: EMR/Redshift add cost/ops for periodic ad‑hoc queries.


---

---

### Question #617

A company wants to migrate an on-premises data center to AWS. The data center hosts a storage server that stores data in an NFS-based file system. The storage server holds 200 GB of data. The company needs to migrate the data without interruption to existing services. Multiple resources in AWS must be able to access the data by using the NFS protocol. Which combination of steps will meet these requirements MOST cost-effectively? (Choose two.)

- A. Create an Amazon FSx for Lustre file system.

- B. Create an Amazon Elastic File System (Amazon EFS) file system.

- C. Create an Amazon S3 bucket to receive the data.

- D. Manually use an operating system copy command to push the data into the AWS destination.

E. Install an AWS DataSync agent in the on-premises data center. Use a DataSync task between the on-premises location and AWS.

**Correct:** B, E
**Why:** Create an EFS file system for NFS access and use DataSync to copy data from on‑prem to EFS without downtime.

**Incorrect:**
- A: Lustre/S3/Manual copy do not meet NFS access and minimal‑ops goals together.
- C: Lustre/S3/Manual copy do not meet NFS access and minimal‑ops goals together.
- D: Lustre/S3/Manual copy do not meet NFS access and minimal‑ops goals together.


---

---

### Question #618

A company wants to use Amazon FSx for Windows File Server for its Amazon EC2 instances that have an SMB file share mounted as a volume in the us-east-1 Region. The company has a recovery point objective (RPO) of 5 minutes for planned system maintenance or unplanned service disruptions. The company needs to replicate the file system to the us-west-2 Region. The replicated data must not be deleted by any user for 5 years. Which solution will meet these requirements?

- A. Create an FSx for Windows File Server file system in us-east-1 that has a Single-AZ 2 deployment type. Use AWS Backup to create a daily backup plan that includes a backup rule that copies the backup to us-west-2. Configure AWS Backup Vault Lock in compliance mode for a target vault in us-west-2. Configure a minimum duration of 5 years.

- B. Create an FSx for Windows File Server file system in us-east-1 that has a Multi-AZ deployment type. Use AWS Backup to create a daily backup plan that includes a backup rule that copies the backup to us-west-2. Configure AWS Backup Vault Lock in governance mode for a target vault in us-west-2. Configure a minimum duration of 5 years.

- C. Create an FSx for Windows File Server file system in us-east-1 that has a Multi-AZ deployment type. Use AWS Backup to create a daily backup plan that includes a backup rule that copies the backup to us-west-2. Configure AWS Backup Vault Lock in compliance mode for a target vault in us-west-2. Configure a minimum duration of 5 years.

- D. Create an FSx for Windows File Server file system in us-east-1 that has a Single-AZ 2 deployment type. Use AWS Backup to create a daily backup plan that includes a backup rule that copies the backup to us-west-2. Configure AWS Backup Vault Lock in governance mode for a target vault in us-west-2. Configure a minimum duration of 5 years.

**Correct:** C
**Why:** Multi‑AZ FSx for Windows for primary; copy backups to us‑west‑2 with AWS Backup and enable Vault Lock compliance mode for 5‑year immutability.

**Incorrect:**
- A: Single‑AZ reduces availability.
- B: Governance mode can be bypassed by privileged users; compliance mode is required for WORM.
- D: Single‑AZ reduces availability.


---

---

### Question #635

A company uses Amazon FSx for NetApp ONTAP in its primary AWS Region for CIFS and NFS file shares. Applications that run on Amazon EC2 instances access the file shares. The company needs a storage disaster recovery (DR) solution in a secondary Region. The data that is replicated in the secondary Region needs to be accessed by using the same protocols as the primary Region. Which solution will meet these requirements with the LEAST operational overhead?

- A. Create an AWS Lambda function to copy the data to an Amazon S3 bucket. Replicate the S3 bucket to the secondary Region.

- B. Create a backup of the FSx for ONTAP volumes by using AWS Backup. Copy the volumes to the secondary Region. Create a new FSx for ONTAP instance from the backup.

- C. Create an FSx for ONTAP instance in the secondary Region. Use NetApp SnapMirror to replicate data from the primary Region to the secondary Region.

- D. Create an Amazon Elastic File System (Amazon EFS) volume. Migrate the current data to the volume. Replicate the volume to the secondary Region.

**Correct:** C
**Why:** FSx for NetApp ONTAP supports SMB/NFS; use SnapMirror for cross‑Region replication with the same protocols on failover.

**Incorrect:**
- A: Lambda + S3 is not a file service and loses protocol semantics.
- B: Backup/restore increases RTO and ops.
- D: EFS is NFS only, not SMB.


---

---

### Question #646

A solutions architect needs to host a high performance computing (HPC) workload in the AWS Cloud. The workload will run on hundreds of Amazon EC2 instances and will require parallel access to a shared file system to enable distributed processing of large datasets. Datasets will be accessed across multiple instances simultaneously. The workload requires access latency within 1 ms. After processing has completed, engineers will need access to the dataset for manual postprocessing. Which solution will meet these requirements?

- A. Use Amazon Elastic File System (Amazon EFS) as a shared file system. Access the dataset from Amazon EFS.

- B. Mount an Amazon S3 bucket to serve as the shared file system. Perform postprocessing directly from the S3 bucket.

- C. Use Amazon FSx for Lustre as a shared file system. Link the file system to an Amazon S3 bucket for postprocessing.

- D. Configure AWS Resource Access Manager to share an Amazon S3 bucket so that it can be mounted to all instances for processing and postprocessing.

**Correct:** B
**Why:** FSx for Lustre persistent file systems provide sub‑millisecond latency, high throughput, and HA for HPC, with optional S3 integration for data lifecycle.

**Incorrect:**
- A: Scratch has no HA.
- C: Not explicit about persistence/HA; persistent FSx is preferred for availability.
- D: S3 is not a POSIX FS and cannot be "mounted" natively with required latency.


---

---

### Question #648

A weather forecasting company needs to process hundreds of gigabytes of data with sub-millisecond latency. The company has a high performance computing (HPC) environment in its data center and wants to expand its forecasting capabilities. A solutions architect must identify a highly available cloud storage solution that can handle large amounts of sustained throughput. Files that are stored in the solution should be accessible to thousands of compute instances that will simultaneously access and process the entire dataset. What should the solutions architect do to meet these requirements?

- A. Use Amazon FSx for Lustre scratch file systems.

- B. Use Amazon FSx for Lustre persistent file systems.

- C. Use Amazon Elastic File System (Amazon EFS) with Bursting Throughput mode.

- D. Use Amazon Elastic File System (Amazon EFS) with Provisioned Throughput mode.

**Correct:** B
**Why:** FSx for Lustre persistent provides high throughput, low latency, and availability for thousands of concurrent clients.

**Incorrect:**
- A: Scratch lacks durability/HA.
- C: EFS throughput modes are not optimal for this HPC latency/throughput profile.
- D: EFS throughput modes are not optimal for this HPC latency/throughput profile.


---

---

### Question #658

A company uses an on-premises network-attached storage (NAS) system to provide file shares to its high performance computing (HPC) workloads. The company wants to migrate its latency-sensitive HPC workloads and its storage to the AWS Cloud. The company must be able to provide NFS and SMB multi-protocol access from the file system. Which solution will meet these requirements with the LEAST latency? (Choose two.)

- A. Deploy compute optimized EC2 instances into a cluster placement group.

- B. Deploy compute optimized EC2 instances into a partition placement group.

- C. Attach the EC2 instances to an Amazon FSx for Lustre file system.

- D. Attach the EC2 instances to an Amazon FSx for OpenZFS file system.

E. Attach the EC2 instances to an Amazon FSx for NetApp ONTAP file system.

**Correct:** A, E
**Why:** Cluster placement groups reduce intra‑cluster latency; FSx for NetApp ONTAP provides both NFS and SMB multi‑protocol access.

**Incorrect:**
- B: Partition groups are for failure domains, not lowest latency.
- C: Lustre/OpenZFS lack SMB multi‑protocol.
- D: Lustre/OpenZFS lack SMB multi‑protocol.


---

---

### Question #673

A company runs an SMB file server in its data center. The file server stores large files that the company frequently accesses for up to 7 days after the file creation date. After 7 days, the company needs to be able to access the files with a maximum retrieval time of 24 hours. Which solution will meet these requirements?

- A. Use AWS DataSync to copy data that is older than 7 days from the SMB file server to AWS.

- B. Create an Amazon S3 File Gateway to increase the company's storage space. Create an S3 Lifecycle policy to transition the data to S3 Glacier Deep Archive after 7 days.

- C. Create an Amazon FSx File Gateway to increase the company's storage space. Create an Amazon S3 Lifecycle policy to transition the data after 7 days.

- D. Configure access to Amazon S3 for each user. Create an S3 Lifecycle policy to transition the data to S3 Glacier Flexible Retrieval after 7 days.

**Correct:** B
**Why:** S3 File Gateway provides SMB access with local cache; lifecycle to S3 Glacier Deep Archive after 7 days keeps costs low and meets 24‑hour retrieval SLA.

**Incorrect:**
- A: DataSync alone does not provide SMB access or caching and is not continuous storage.
- C: FSx File Gateway targets FSx for Windows, not S3; S3 lifecycle rules don’t apply to FSx.
- D: Direct S3 access removes SMB access and user workflow compatibility.


---

## Amazon Kinesis

### Question #501

A company wants to ingest customer payment data into the company's data lake in Amazon S3. The company receives payment data every minute on average. The company wants to analyze the payment data in real time. Then the company wants to ingest the data into the data lake. Which solution will meet these requirements with the MOST operational eciency?

- A. Use Amazon Kinesis Data Streams to ingest data. Use AWS Lambda to analyze the data in real time.

- B. Use AWS Glue to ingest data. Use Amazon Kinesis Data Analytics to analyze the data in real time.

- C. Use Amazon Kinesis Data Firehose to ingest data. Use Amazon Kinesis Data Analytics to analyze the data in real time.

- D. Use Amazon API Gateway to ingest data. Use AWS Lambda to analyze the data in real time.

**Correct:** C
**Why:** Kinesis Data Firehose provides fully managed ingestion to S3; Kinesis Data Analytics analyzes the stream in real time with minimal ops.

**Incorrect:**
- A: Lambda analysis is more custom and operationally heavier than KDA for streaming analytics.
- B: Glue/API Gateway are not optimal for continuous real‑time ingestion/analysis.
- D: Glue/API Gateway are not optimal for continuous real‑time ingestion/analysis.


---

---

### Question #517

A company wants to send all AWS Systems Manager Session Manager logs to an Amazon S3 bucket for archival purposes. Which solution will meet this requirement with the MOST operational eciency?

- A. Enable S3 logging in the Systems Manager console. Choose an S3 bucket to send the session data to.

- B. Install the Amazon CloudWatch agent. Push all logs to a CloudWatch log group. Export the logs to an S3 bucket from the group for archival purposes.

- C. Create a Systems Manager document to upload all server logs to a central S3 bucket. Use Amazon EventBridge to run the Systems Manager document against all servers that are in the account daily.

- D. Install an Amazon CloudWatch agent. Push all logs to a CloudWatch log group. Create a CloudWatch logs subscription that pushes any incoming log events to an Amazon Kinesis Data Firehose delivery stream. Set Amazon S3 as the destination.

**Correct:** A
**Why:** Session Manager supports direct delivery of session logs to S3 from the console with minimal setup.

**Incorrect:**
- B: Extra agents/pipelines add complexity.
- C: Extra agents/pipelines add complexity.
- D: Extra agents/pipelines add complexity.


---

---

### Question #547

A company has data collection sensors at different locations. The data collection sensors stream a high volume of data to the company. The company wants to design a platform on AWS to ingest and process high-volume streaming data. The solution must be scalable and support data collection in near real time. The company must store the data in Amazon S3 for future reporting. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use Amazon Kinesis Data Firehose to deliver streaming data to Amazon S3.

- B. Use AWS Glue to deliver streaming data to Amazon S3.

- C. Use AWS Lambda to deliver streaming data and store the data to Amazon S3.

- D. Use AWS Database Migration Service (AWS DMS) to deliver streaming data to Amazon S3.

**Correct:** A
**Why:** Kinesis Data Firehose ingests high‑volume streams and delivers to S3 with near real‑time buffering and minimal ops.

**Incorrect:**
- B: Glue/Lambda/DMS are not the best fit for streaming ingestion at scale.
- C: Glue/Lambda/DMS are not the best fit for streaming ingestion at scale.
- D: Glue/Lambda/DMS are not the best fit for streaming ingestion at scale.


---

---

### Question #557

A solutions architect manages an analytics application. The application stores large amounts of semistructured data in an Amazon S3 bucket. The solutions architect wants to use parallel data processing to process the data more quickly. The solutions architect also wants to use information that is stored in an Amazon Redshift database to enrich the data. Which solution will meet these requirements?

- A. Use Amazon Athena to process the S3 data. Use AWS Glue with the Amazon Redshift data to enrich the S3 data.

- B. Use Amazon EMR to process the S3 data. Use Amazon EMR with the Amazon Redshift data to enrich the S3 data.

- C. Use Amazon EMR to process the S3 data. Use Amazon Kinesis Data Streams to move the S3 data into Amazon Redshift so that the data can be enriched.

- D. Use AWS Glue to process the S3 data. Use AWS Lake Formation with the Amazon Redshift data to enrich the S3 data.

**Correct:** B
**Why:** Amazon EMR supports large-scale parallel processing on S3 data and can integrate with Amazon Redshift to enrich S3 data with Redshift data (e.g., via Spark connectors/JDBC).

**Incorrect:**
- A: Athena + Glue can join, but enriching with Redshift data is more direct and scalable with EMR compute.
- C: Kinesis Data Streams is for streaming ingestion, not enriching S3 batch data with Redshift.
- D: Glue can process S3 data, but enrichment specifically with Redshift is better served by EMR’s flexible engines.


---

---

### Question #587

A company is designing a solution to capture customer activity in different web applications to process analytics and make predictions. Customer activity in the web applications is unpredictable and can increase suddenly. The company requires a solution that integrates with other web applications. The solution must include an authorization step for security purposes. Which solution will meet these requirements?

- A. Configure a Gateway Load Balancer (GWLB) in front of an Amazon Elastic Container Service (Amazon ECS) container instance that stores the information that the company receives in an Amazon Elastic File System (Amazon EFS) file system. Authorization is resolved at the GWLB.

- B. Configure an Amazon API Gateway endpoint in front of an Amazon Kinesis data stream that stores the information that the company receives in an Amazon S3 bucket. Use an AWS Lambda function to resolve authorization.

- C. Configure an Amazon API Gateway endpoint in front of an Amazon Kinesis Data Firehose that stores the information that the company receives in an Amazon S3 bucket. Use an API Gateway Lambda authorizer to resolve authorization.

- D. Configure a Gateway Load Balancer (GWLB) in front of an Amazon Elastic Container Service (Amazon ECS) container instance that stores the information that the company receives on an Amazon Elastic File System (Amazon EFS) file system. Use an AWS Lambda function to resolve authorization.

**Correct:** C
**Why:** API Gateway with a Lambda authorizer provides auth. Kinesis Data Firehose scales ingestion and delivers to S3 with minimal ops overhead.

**Incorrect:**
- A: GWLB + ECS introduces heavy ops complexity for simple event ingestion.
- B: API Gateway to Kinesis Data Streams is viable but requires more scaling/consumer management than Firehose for S3 delivery.
- D: GWLB + ECS introduces heavy ops complexity for simple event ingestion.


---

---

### Question #611

A company has an application with a REST-based interface that allows data to be received in near-real time from a third-party vendor. Once received, the application processes and stores the data for further analysis. The application is running on Amazon EC2 instances. The third-party vendor has received many 503 Service Unavailable Errors when sending data to the application. When the data volume spikes, the compute capacity reaches its maximum limit and the application is unable to process all requests. Which design should a solutions architect recommend to provide a more scalable solution?

- A. Use Amazon Kinesis Data Streams to ingest the data. Process the data using AWS Lambda functions.

- B. Use Amazon API Gateway on top of the existing application. Create a usage plan with a quota limit for the third-party vendor.

- C. Use Amazon Simple Notification Service (Amazon SNS) to ingest the data. Put the EC2 instances in an Auto Scaling group behind an Application Load Balancer.

- D. Repackage the application as a container. Deploy the application using Amazon Elastic Container Service (Amazon ECS) using the EC2 launch type with an Auto Scaling group.

**Correct:** A
**Why:** Kinesis Data Streams buffers spikes and decouples producers from consumers; Lambda scales to process without 503s.

**Incorrect:**
- B: API Gateway with quotas throttles the vendor rather than scaling.
- C: SNS is pub/sub and not ideal for high‑throughput buffering + ordering.
- D: ECS on EC2 still faces sudden capacity limits without a buffer.


---

---

### Question #631

A social media company wants to store its database of user proles, relationships, and interactions in the AWS Cloud. The company needs an application to monitor any changes in the database. The application needs to analyze the relationships between the data entities and to provide recommendations to users. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use Amazon Neptune to store the information. Use Amazon Kinesis Data Streams to process changes in the database.

- B. Use Amazon Neptune to store the information. Use Neptune Streams to process changes in the database.

- C. Use Amazon Quantum Ledger Database (Amazon QLDB) to store the information. Use Amazon Kinesis Data Streams to process changes in the database.

- D. Use Amazon Quantum Ledger Database (Amazon QLDB) to store the information. Use Neptune Streams to process changes in the database.

**Correct:** B
**Why:** Amazon Neptune stores graph data, and Neptune Streams provides change streams for downstream processing.

**Incorrect:**
- A: Kinesis can move data, but Neptune Streams is purpose‑built for Neptune changes.
- C: QLDB is a ledger DB, not a graph DB.
- D: QLDB is a ledger DB, not a graph DB.


---

---

### Question #633

A company manages an application that stores data on an Amazon RDS for PostgreSQL Multi-AZ DB instance. Increases in trac are causing performance problems. The company determines that database queries are the primary reason for the slow performance. What should a solutions architect do to improve the application's performance?

- A. Serve read trac from the Multi-AZ standby replica.

- B. Configure the DB instance to use Transfer Acceleration.

- C. Create a read replica from the source DB instance. Serve read trac from the read replica.

- D. Use Amazon Kinesis Data Firehose between the application and Amazon RDS to increase the concurrency of database requests.

**Correct:** C
**Why:** A read replica offloads read traffic from the primary RDS instance to improve performance.

**Incorrect:**
- A: Multi-AZ standby is not for reads.
- B: Transfer Acceleration is for S3, not RDS.
- D: Kinesis Data Firehose is irrelevant here.


---

---

### Question #641

A company wants to monitor its AWS costs for nancial review. The cloud operations team is designing an architecture in the AWS Organizations management account to query AWS Cost and Usage Reports for all member accounts. The team must run this query once a month and provide a detailed analysis of the bill. Which solution is the MOST scalable and cost-effective way to meet these requirements?

- A. Enable Cost and Usage Reports in the management account. Deliver reports to Amazon Kinesis. Use Amazon EMR for analysis.

- B. Enable Cost and Usage Reports in the management account. Deliver the reports to Amazon S3 Use Amazon Athena for analysis.

- C. Enable Cost and Usage Reports for member accounts. Deliver the reports to Amazon S3 Use Amazon Redshift for analysis.

- D. Enable Cost and Usage Reports for member accounts. Deliver the reports to Amazon Kinesis. Use Amazon QuickSight tor analysis.

**Correct:** B
**Why:** CUR to S3 + Athena provides scalable, low‑cost monthly querying across member accounts from the management account.

**Incorrect:**
- A: Kinesis/QuickSight not needed; CUR+Athena is simpler/cheaper.
- C: Enabling CUR per member is unnecessary; centralize in management.
- D: Kinesis/QuickSight not needed; CUR+Athena is simpler/cheaper.


---

---

### Question #672

A marketing company receives a large amount of new clickstream data in Amazon S3 from a marketing campaign. The company needs to analyze the clickstream data in Amazon S3 quickly. Then the company needs to determine whether to process the data further in the data pipeline. Which solution will meet these requirements with the LEAST operational overhead?

- A. Create external tables in a Spark catalog. Configure jobs in AWS Glue to query the data.

- B. Configure an AWS Glue crawler to crawl the data. Configure Amazon Athena to query the data.

- C. Create external tables in a Hive metastore. Configure Spark jobs in Amazon EMR to query the data.

- D. Configure an AWS Glue crawler to crawl the data. Configure Amazon Kinesis Data Analytics to use SQL to query the data.

**Correct:** B
**Why:** Run an AWS Glue crawler to catalog the S3 data, then use Amazon Athena to query immediately with SQL and minimal ops.

**Incorrect:**
- A: Spark catalog setup adds unnecessary overhead for a quick assessment.
- C: EMR + Hive metastore increases cost/ops for ad‑hoc queries.
- D: Kinesis Data Analytics is for streaming SQL, not batch S3 analysis.


---

---

### Question #676

A company's application uses Network Load Balancers, Auto Scaling groups, Amazon EC2 instances, and databases that are deployed in an Amazon VPC. The company wants to capture information about trac to and from the network interfaces in near real time in its Amazon VPC. The company wants to send the information to Amazon OpenSearch Service for analysis. Which solution will meet these requirements?

- A. Create a log group in Amazon CloudWatch Logs. Configure VPC Flow Logs to send the log data to the log group. Use Amazon Kinesis Data Streams to stream the logs from the log group to OpenSearch Service.

- B. Create a log group in Amazon CloudWatch Logs. Configure VPC Flow Logs to send the log data to the log group. Use Amazon Kinesis Data Firehose to stream the logs from the log group to OpenSearch Service.

- C. Create a trail in AWS CloudTrail. Configure VPC Flow Logs to send the log data to the trail. Use Amazon Kinesis Data Streams to stream the logs from the trail to OpenSearch Service.

- D. Create a trail in AWS CloudTrail. Configure VPC Flow Logs to send the log data to the trail. Use Amazon Kinesis Data Firehose to stream the logs from the trail to OpenSearch Service.

**Correct:** B
**Why:** Send VPC Flow Logs to CloudWatch Logs, then stream to OpenSearch Service with Kinesis Data Firehose for near real‑time analysis.

**Incorrect:**
- A: Data Streams adds custom consumer management; Firehose is simpler.
- C: CloudTrail is not used for VPC Flow Logs delivery.
- D: CloudTrail is not used for VPC Flow Logs delivery.


---

## Amazon Macie / Rekognition / Comprehend

### Question #529

A company is migrating its workloads to AWS. The company has transactional and sensitive data in its databases. The company wants to use AWS Cloud solutions to increase security and reduce operational overhead for the databases. Which solution will meet these requirements?

- A. Migrate the databases to Amazon EC2. Use an AWS Key Management Service (AWS KMS) AWS managed key for encryption.

- B. Migrate the databases to Amazon RDS Configure encryption at rest.

- C. Migrate the data to Amazon S3 Use Amazon Macie for data security and protection

- D. Migrate the database to Amazon RDS. Use Amazon CloudWatch Logs for data security and protection.

**Correct:** B
**Why:** RDS is managed, supports encryption at rest/in transit, and reduces operational overhead for transactional/sensitive data.

**Incorrect:**
- A: EC2/CloudWatch Logs/Macie alone do not meet the database requirements.
- C: EC2/CloudWatch Logs/Macie alone do not meet the database requirements.
- D: EC2/CloudWatch Logs/Macie alone do not meet the database requirements.


---

---

### Question #533

A company stores data in Amazon S3. According to regulations, the data must not contain personally identiable information (PII). The company recently discovered that S3 buckets have some objects that contain PII. The company needs to automatically detect PII in S3 buckets and to notify the company’s security team. Which solution will meet these requirements?

- A. Use Amazon Macie. Create an Amazon EventBridge rule to filter the SensitiveData event type from Macie ndings and to send an Amazon Simple Notification Service (Amazon SNS) notification to the security team.

- B. Use Amazon GuardDuty. Create an Amazon EventBridge rule to filter the CRITICAL event type from GuardDuty ndings and to send an Amazon Simple Notification Service (Amazon SNS) notification to the security team.

- C. Use Amazon Macie. Create an Amazon EventBridge rule to filter the SensitiveData:S3Object/Personal event type from Macie ndings and to send an Amazon Simple Queue Service (Amazon SQS) notification to the security team.

- D. Use Amazon GuardDuty. Create an Amazon EventBridge rule to filter the CRITICAL event type from GuardDuty ndings and to send an Amazon Simple Queue Service (Amazon SQS) notification to the security team.

**Correct:** A
**Why:** Macie detects PII in S3; route SensitiveData events to SNS via EventBridge to notify security.

**Incorrect:**
- B: GuardDuty is not for PII in S3.
- C: SQS is not ideal for notifications to humans.
- D: GuardDuty is not for PII in S3.


---

---

### Question #553

A solutions architect needs to review a company's Amazon S3 buckets to discover personally identiable information (PII). The company stores the PII data in the us-east-1 Region and us-west-2 Region. Which solution will meet these requirements with the LEAST operational overhead?

- A. Configure Amazon Macie in each Region. Create a job to analyze the data that is in Amazon S3.

- B. Configure AWS Security Hub for all Regions. Create an AWS Cong rule to analyze the data that is in Amazon S3.

- C. Configure Amazon Inspector to analyze the data that is in Amazon S3.

- D. Configure Amazon GuardDuty to analyze the data that is in Amazon S3.

**Correct:** A
**Why:** Amazon Macie natively discovers and classifies PII in S3, per Region, with minimal operational overhead.

**Incorrect:**
- B: Security Hub aggregates findings; it does not scan S3 data for PII.
- C: Amazon Inspector assesses EC2/ECR; not for S3 PII discovery.
- D: GuardDuty detects threats; it does not inspect S3 object contents for PII.


---

---

### Question #616

A company has deployed its newest product on AWS. The product runs in an Auto Scaling group behind a Network Load Balancer. The company stores the product’s objects in an Amazon S3 bucket. The company recently experienced malicious attacks against its systems. The company needs a solution that continuously monitors for malicious activity in the AWS account, workloads, and access patterns to the S3 bucket. The solution must also report suspicious activity and display the information on a dashboard. Which solution will meet these requirements?

- A. Configure Amazon Macie to monitor and report ndings to AWS Cong.

- B. Configure Amazon Inspector to monitor and report ndings to AWS CloudTrail.

- C. Configure Amazon GuardDuty to monitor and report ndings to AWS Security Hub.

- D. Configure AWS Cong to monitor and report ndings to Amazon EventBridge.

**Correct:** C
**Why:** GuardDuty continuously monitors account, workload, and S3 access for threats; Security Hub aggregates and dashboards findings.

**Incorrect:**
- A: Macie focuses on sensitive data discovery, not threat detection.
- B: Inspector is for vulnerability assessment, not S3 access/threat patterns.
- D: Config tracks resource configuration, not threat activity.


---

---

### Question #682

A company needs a solution to enforce data encryption at rest on Amazon EC2 instances. The solution must automatically identify noncompliant resources and enforce compliance policies on ndings. Which solution will meet these requirements with the LEAST administrative overhead?

- A. Use an IAM policy that allows users to create only encrypted Amazon Elastic Block Store (Amazon EBS) volumes. Use AWS Cong and AWS Systems Manager to automate the detection and remediation of unencrypted EBS volumes.

- B. Use AWS Key Management Service (AWS KMS) to manage access to encrypted Amazon Elastic Block Store (Amazon EBS) volumes. Use AWS Lambda and Amazon EventBridge to automate the detection and remediation of unencrypted EBS volumes.

- C. Use Amazon Macie to detect unencrypted Amazon Elastic Block Store (Amazon EBS) volumes. Use AWS Systems Manager Automation rules to automatically encrypt existing and new EBS volumes.

- D. Use Amazon inspector to detect unencrypted Amazon Elastic Block Store (Amazon EBS) volumes. Use AWS Systems Manager Automation rules to automatically encrypt existing and new EBS volumes.

**Correct:** A
**Why:** Enforce encrypted EBS creation via IAM, and use AWS Config with Systems Manager Automation to detect and remediate unencrypted volumes automatically.

**Incorrect:**
- B: Lambda + EventBridge is more custom ops; KMS alone doesn’t enforce encryption.
- C: Macie/Inspector do not detect EBS encryption compliance.
- D: Macie/Inspector do not detect EBS encryption compliance.


---

## Amazon OpenSearch Service

### Question #615

A company runs a critical, customer-facing application on Amazon Elastic Kubernetes Service (Amazon EKS). The application has a microservices architecture. The company needs to implement a solution that collects, aggregates, and summarizes metrics and logs from the application in a centralized location. Which solution meets these requirements?

- A. Run the Amazon CloudWatch agent in the existing EKS cluster. View the metrics and logs in the CloudWatch console.

- B. Run AWS App Mesh in the existing EKS cluster. View the metrics and logs in the App Mesh console.

- C. Configure AWS CloudTrail to capture data events. Query CloudTrail by using Amazon OpenSearch Service.

- D. Configure Amazon CloudWatch Container Insights in the existing EKS cluster. View the metrics and logs in the CloudWatch console.

**Correct:** D
**Why:** CloudWatch Container Insights provides cluster‑wide metrics and logs aggregation for EKS with centralized dashboards.

**Incorrect:**
- A: Agent alone lacks curated EKS insights.
- B: App Mesh is a service mesh, not a logging/metrics aggregator.
- C: CloudTrail data events are not application metrics/logs.


---

---

### Question #643

A company runs several websites on AWS for its different brands. Each website generates tens of gigabytes of web trac logs each day. A solutions architect needs to design a scalable solution to give the company's developers the ability to analyze trac patterns across all the company's websites. This analysis by the developers will occur on demand once a week over the course of several months. The solution must support queries with standard SQL. Which solution will meet these requirements MOST cost-effectively?

- A. Store the logs in Amazon S3. Use Amazon Athena tor analysis.

- B. Store the logs in Amazon RDS. Use a database client for analysis.

- C. Store the logs in Amazon OpenSearch Service. Use OpenSearch Service for analysis.

- D. Store the logs in an Amazon EMR cluster Use a supported open-source framework for SQL-based analysis.

**Correct:** A
**Why:** Store logs in S3 and query with Athena using SQL only when needed; minimal cost/ops.

**Incorrect:**
- B: RDS is expensive and not ideal for log analytics.
- C: OpenSearch is more costly for weekly ad‑hoc queries.
- D: EMR cluster management adds significant overhead.


---

---

### Question #676

A company's application uses Network Load Balancers, Auto Scaling groups, Amazon EC2 instances, and databases that are deployed in an Amazon VPC. The company wants to capture information about trac to and from the network interfaces in near real time in its Amazon VPC. The company wants to send the information to Amazon OpenSearch Service for analysis. Which solution will meet these requirements?

- A. Create a log group in Amazon CloudWatch Logs. Configure VPC Flow Logs to send the log data to the log group. Use Amazon Kinesis Data Streams to stream the logs from the log group to OpenSearch Service.

- B. Create a log group in Amazon CloudWatch Logs. Configure VPC Flow Logs to send the log data to the log group. Use Amazon Kinesis Data Firehose to stream the logs from the log group to OpenSearch Service.

- C. Create a trail in AWS CloudTrail. Configure VPC Flow Logs to send the log data to the trail. Use Amazon Kinesis Data Streams to stream the logs from the trail to OpenSearch Service.

- D. Create a trail in AWS CloudTrail. Configure VPC Flow Logs to send the log data to the trail. Use Amazon Kinesis Data Firehose to stream the logs from the trail to OpenSearch Service.

**Correct:** B
**Why:** Send VPC Flow Logs to CloudWatch Logs, then stream to OpenSearch Service with Kinesis Data Firehose for near real‑time analysis.

**Incorrect:**
- A: Data Streams adds custom consumer management; Firehose is simpler.
- C: CloudTrail is not used for VPC Flow Logs delivery.
- D: CloudTrail is not used for VPC Flow Logs delivery.


---

## Amazon QuickSight

### Question #524

A company wants to analyze and troubleshoot Access Denied errors and Unauthorized errors that are related to IAM permissions. The company has AWS CloudTrail turned on. Which solution will meet these requirements with the LEAST effort?

- A. Use AWS Glue and write custom scripts to query CloudTrail logs for the errors.

- B. Use AWS Batch and write custom scripts to query CloudTrail logs for the errors.

- C. Search CloudTrail logs with Amazon Athena queries to identify the errors.

- D. Search CloudTrail logs with Amazon QuickSight. Create a dashboard to identify the errors.

**Correct:** C
**Why:** Query CloudTrail logs directly with Athena to find AccessDenied/Unauthorized events—lowest effort.

**Incorrect:**
- A: Glue/Batch/QuickSight add unnecessary development overhead.
- B: Glue/Batch/QuickSight add unnecessary development overhead.
- D: Glue/Batch/QuickSight add unnecessary development overhead.


---

---

### Question #641

A company wants to monitor its AWS costs for nancial review. The cloud operations team is designing an architecture in the AWS Organizations management account to query AWS Cost and Usage Reports for all member accounts. The team must run this query once a month and provide a detailed analysis of the bill. Which solution is the MOST scalable and cost-effective way to meet these requirements?

- A. Enable Cost and Usage Reports in the management account. Deliver reports to Amazon Kinesis. Use Amazon EMR for analysis.

- B. Enable Cost and Usage Reports in the management account. Deliver the reports to Amazon S3 Use Amazon Athena for analysis.

- C. Enable Cost and Usage Reports for member accounts. Deliver the reports to Amazon S3 Use Amazon Redshift for analysis.

- D. Enable Cost and Usage Reports for member accounts. Deliver the reports to Amazon Kinesis. Use Amazon QuickSight tor analysis.

**Correct:** B
**Why:** CUR to S3 + Athena provides scalable, low‑cost monthly querying across member accounts from the management account.

**Incorrect:**
- A: Kinesis/QuickSight not needed; CUR+Athena is simpler/cheaper.
- C: Enabling CUR per member is unnecessary; centralize in management.
- D: Kinesis/QuickSight not needed; CUR+Athena is simpler/cheaper.


---

## Amazon RDS

### Question #507

A company has a web application for travel ticketing. The application is based on a database that runs in a single data center in North America. The company wants to expand the application to serve a global user base. The company needs to deploy the application to multiple AWS Regions. Average latency must be less than 1 second on updates to the reservation database. The company wants to have separate deployments of its web platform across multiple Regions. However, the company must maintain a single primary reservation database that is globally consistent. Which solution should a solutions architect recommend to meet these requirements?

- A. Convert the application to use Amazon DynamoDB. Use a global table for the center reservation table. Use the correct Regional endpoint in each Regional deployment.

- B. Migrate the database to an Amazon Aurora MySQL database. Deploy Aurora Read Replicas in each Region. Use the correct Regional endpoint in each Regional deployment for access to the database.

- C. Migrate the database to an Amazon RDS for MySQL database. Deploy MySQL read replicas in each Region. Use the correct Regional endpoint in each Regional deployment for access to the database.

- D. Migrate the application to an Amazon Aurora Serverless database. Deploy instances of the database to each Region. Use the correct Regional endpoint in each Regional deployment to access the database. Use AWS Lambda functions to process event streams in each Region to synchronize the databases.

**Correct:** B
**Why:** Aurora MySQL with cross‑Region Aurora Replicas (Aurora Global Database) keeps a single primary and low‑latency replicas; web tiers use Regional endpoints.

**Incorrect:**
- A: DynamoDB changes the data model.
- C: RDS MySQL cross‑Region replication is slower and less managed.
- D: Serverless with custom sync adds complexity.


---

---

### Question #511

A company is developing software that uses a PostgreSQL database schema. The company needs to configure multiple development environments and databases for the company's developers. On average, each development environment is used for half of the 8-hour workday. Which solution will meet these requirements MOST cost-effectively?

- A. Configure each development environment with its own Amazon Aurora PostgreSQL database

- B. Configure each development environment with its own Amazon RDS for PostgreSQL Single-AZ DB instances

- C. Configure each development environment with its own Amazon Aurora On-Demand PostgreSQL-Compatible database

- D. Configure each development environment with its own Amazon S3 bucket by using Amazon S3 Object Select

**Correct:** C
**Why:** Aurora Serverless/On‑Demand PostgreSQL is cost‑effective for dev environments that are idle for long periods.

**Incorrect:**
- A: Always‑on instances cost more for idle time.
- B: Always‑on instances cost more for idle time.
- D: S3 is not a relational database.


---

---

### Question #513

A social media company wants to allow its users to upload images in an application that is hosted in the AWS Cloud. The company needs a solution that automatically resizes the images so that the images can be displayed on multiple device types. The application experiences unpredictable trac patterns throughout the day. The company is seeking a highly available solution that maximizes scalability. What should a solutions architect do to meet these requirements?

- A. Create a static website hosted in Amazon S3 that invokes AWS Lambda functions to resize the images and store the images in an Amazon S3 bucket.

- B. Create a static website hosted in Amazon CloudFront that invokes AWS Step Functions to resize the images and store the images in an Amazon RDS database.

- C. Create a dynamic website hosted on a web server that runs on an Amazon EC2 instance. Configure a process that runs on the EC2 instance to resize the images and store the images in an Amazon S3 bucket.

- D. Create a dynamic website hosted on an automatically scaling Amazon Elastic Container Service (Amazon ECS) cluster that creates a resize job in Amazon Simple Queue Service (Amazon SQS). Set up an image-resizing program that runs on an Amazon EC2 instance to process the resize jobs.

**Correct:** A
**Why:** Static site front end in S3 with Lambda resizing on upload provides high availability and scalability with minimal ops; store results in S3.

**Incorrect:**
- B: CloudFront+Step Functions/EC2/ECS add complexity and are less serverless.
- C: CloudFront+Step Functions/EC2/ECS add complexity and are less serverless.
- D: CloudFront+Step Functions/EC2/ECS add complexity and are less serverless.


---

---

### Question #518

An application uses an Amazon RDS MySQL DB instance. The RDS database is becoming low on disk space. A solutions architect wants to increase the disk space without downtime. Which solution meets these requirements with the LEAST amount of effort?

- A. Enable storage autoscaling in RDS

- B. Increase the RDS database instance size

- C. Change the RDS database instance storage type to Provisioned IOPS

- D. Back up the RDS database, increase the storage capacity, restore the database, and stop the previous instance

**Correct:** A
**Why:** Turn on storage autoscaling to grow RDS storage without downtime and with minimal effort.

**Incorrect:**
- B: Instance resize/type changes or backup/restore add downtime/effort.
- C: Instance resize/type changes or backup/restore add downtime/effort.
- D: Instance resize/type changes or backup/restore add downtime/effort.


---

---

### Question #526

A solutions architect is reviewing the resilience of an application. The solutions architect notices that a database administrator recently failed over the application's Amazon Aurora PostgreSQL database writer instance as part of a scaling exercise. The failover resulted in 3 minutes of downtime for the application. Which solution will reduce the downtime for scaling exercises with the LEAST operational overhead?

- A. Create more Aurora PostgreSQL read replicas in the cluster to handle the load during failover.

- B. Set up a secondary Aurora PostgreSQL cluster in the same AWS Region. During failover, update the application to use the secondary cluster's writer endpoint.

- C. Create an Amazon ElastiCache for Memcached cluster to handle the load during failover.

- D. Set up an Amazon RDS proxy for the database. Update the application to use the proxy endpoint.

**Correct:** D
**Why:** RDS Proxy maintains connections during failover/scaling, reducing downtime with minimal changes.

**Incorrect:**
- A: Read replicas/cache don’t address connection failover.
- B: Secondary cluster and app rewiring add ops and downtime.
- C: Read replicas/cache don’t address connection failover.


---

---

### Question #529

A company is migrating its workloads to AWS. The company has transactional and sensitive data in its databases. The company wants to use AWS Cloud solutions to increase security and reduce operational overhead for the databases. Which solution will meet these requirements?

- A. Migrate the databases to Amazon EC2. Use an AWS Key Management Service (AWS KMS) AWS managed key for encryption.

- B. Migrate the databases to Amazon RDS Configure encryption at rest.

- C. Migrate the data to Amazon S3 Use Amazon Macie for data security and protection

- D. Migrate the database to Amazon RDS. Use Amazon CloudWatch Logs for data security and protection.

**Correct:** B
**Why:** RDS is managed, supports encryption at rest/in transit, and reduces operational overhead for transactional/sensitive data.

**Incorrect:**
- A: EC2/CloudWatch Logs/Macie alone do not meet the database requirements.
- C: EC2/CloudWatch Logs/Macie alone do not meet the database requirements.
- D: EC2/CloudWatch Logs/Macie alone do not meet the database requirements.


---

---

### Question #532

A company has a workload in an AWS Region. Customers connect to and access the workload by using an Amazon API Gateway REST API. The company uses Amazon Route 53 as its DNS provider. The company wants to provide individual and secure URLs for all customers. Which combination of steps will meet these requirements with the MOST operational eciency? (Choose three.)

- A. Register the required domain in a registrar. Create a wildcard custom domain name in a Route 53 hosted zone and record in the zone that points to the API Gateway endpoint.

- B. Request a wildcard certicate that matches the domains in AWS Certicate Manager (ACM) in a different Region.

- C. Create hosted zones for each customer as required in Route 53. Create zone records that point to the API Gateway endpoint.

- D. Request a wildcard certicate that matches the custom domain name in AWS Certicate Manager (ACM) in the same Region.

E. Create multiple API endpoints for each customer in API Gateway.

F. Create a custom domain name in API Gateway for the REST API. Import the certicate from AWS Certicate Manager (ACM).

**Correct:** A, D, F
**Why:** Use a wildcard custom domain in Route 53, request a matching wildcard ACM cert in the same Region, and create a custom domain in API Gateway with that cert.

**Incorrect:**
- B: Wrong Region for ACM, per‑customer hosted zones, or multiple API endpoints add overhead.
- C: Wrong Region for ACM, per‑customer hosted zones, or multiple API endpoints add overhead.
- E: Wrong Region for ACM, per‑customer hosted zones, or multiple API endpoints add overhead.


---

---

### Question #536

A company wants to provide data scientists with near real-time read-only access to the company's production Amazon RDS for PostgreSQL database. The database is currently congured as a Single-AZ database. The data scientists use complex queries that will not affect the production database. The company needs a solution that is highly available. Which solution will meet these requirements MOST cost-effectively?

- A. Scale the existing production database in a maintenance window to provide enough power for the data scientists.

- B. Change the setup from a Single-AZ to a Multi-AZ instance deployment with a larger secondary standby instance. Provide the data scientists access to the secondary instance.

- C. Change the setup from a Single-AZ to a Multi-AZ instance deployment. Provide two additional read replicas for the data scientists.

- D. Change the setup from a Single-AZ to a Multi-AZ cluster deployment with two readable standby instances. Provide read endpoints to the data scientists.

**Correct:** D
**Why:** An RDS Multi‑AZ cluster provides highly available reader instances for near real‑time read‑only access.

**Incorrect:**
- A: Scaling primary for reads impacts production.
- B: Multi‑AZ instance standby is not readable.
- C: Multi‑AZ instance + two replicas is costlier and more complex than a cluster with readable standbys.


---

---

### Question #537

A company runs a three-tier web application in the AWS Cloud that operates across three Availability Zones. The application architecture has an Application Load Balancer, an Amazon EC2 web server that hosts user session states, and a MySQL database that runs on an EC2 instance. The company expects sudden increases in application trac. The company wants to be able to scale to meet future application capacity demands and to ensure high availability across all three Availability Zones. Which solution will meet these requirements?

- A. Migrate the MySQL database to Amazon RDS for MySQL with a Multi-AZ DB cluster deployment. Use Amazon ElastiCache for Redis with high availability to store session data and to cache reads. Migrate the web server to an Auto Scaling group that is in three Availability Zones.

- B. Migrate the MySQL database to Amazon RDS for MySQL with a Multi-AZ DB cluster deployment. Use Amazon ElastiCache for Memcached with high availability to store session data and to cache reads. Migrate the web server to an Auto Scaling group that is in three Availability Zones.

- C. Migrate the MySQL database to Amazon DynamoDB Use DynamoDB Accelerator (DAX) to cache reads. Store the session data in DynamoDB. Migrate the web server to an Auto Scaling group that is in three Availability Zones.

- D. Migrate the MySQL database to Amazon RDS for MySQL in a single Availability Zone. Use Amazon ElastiCache for Redis with high availability to store session data and to cache reads. Migrate the web server to an Auto Scaling group that is in three Availability Zones.

**Correct:** A
**Why:** RDS MySQL Multi‑AZ DB cluster for HA, ElastiCache Redis for sessions/cache, and an ASG across three AZs meets scale and HA goals.

**Incorrect:**
- B: Memcached lacks persistence/HA and is less preferred for sessions.
- C: Rewriting to DynamoDB is unnecessary.
- D: Single‑AZ DB is not highly available.


---

---

### Question #539

A company wants to use the AWS Cloud to improve its on-premises disaster recovery (DR) configuration. The company's core production business application uses Microsoft SQL Server Standard, which runs on a virtual machine (VM). The application has a recovery point objective (RPO) of 30 seconds or fewer and a recovery time objective (RTO) of 60 minutes. The DR solution needs to minimize costs wherever possible. Which solution will meet these requirements?

- A. Configure a multi-site active/active setup between the on-premises server and AWS by using Microsoft SQL Server Enterprise with Always On availability groups.

- B. Configure a warm standby Amazon RDS for SQL Server database on AWS. Configure AWS Database Migration Service (AWS DMS) to use change data capture (CDC).

- C. Use AWS Elastic Disaster Recovery congured to replicate disk changes to AWS as a pilot light.

- D. Use third-party backup software to capture backups every night. Store a secondary set of backups in Amazon S3.

**Correct:** C
**Why:** AWS Elastic Disaster Recovery provides near‑continuous replication (low RPO) and quick spin‑up (RTO ≤ 60 min) at low standby cost.

**Incorrect:**
- A: SQL Server Enterprise AOAG is costly.
- B: Warm standby RDS incurs ongoing cost and may not meet RPO.
- D: Nightly backups miss the 30‑second RPO.


---

---

### Question #540

A company has an on-premises server that uses an Oracle database to process and store customer information. The company wants to use an AWS database service to achieve higher availability and to improve application performance. The company also wants to ooad reporting from its primary database system. Which solution will meet these requirements in the MOST operationally ecient way?

- A. Use AWS Database Migration Service (AWS DMS) to create an Amazon RDS DB instance in multiple AWS Regions. Point the reporting functions toward a separate DB instance from the primary DB instance.

- B. Use Amazon RDS in a Single-AZ deployment to create an Oracle database. Create a read replica in the same zone as the primary DB instance. Direct the reporting functions to the read replica.

- C. Use Amazon RDS deployed in a Multi-AZ cluster deployment to create an Oracle database. Direct the reporting functions to use the reader instance in the cluster deployment.

- D. Use Amazon RDS deployed in a Multi-AZ instance deployment to create an Amazon Aurora database. Direct the reporting functions to the reader instances.

**Correct:** C
**Why:** RDS Oracle Multi‑AZ cluster improves availability; use the reader for reporting offload with minimal ops.

**Incorrect:**
- A: Multi‑Region primaries/Single‑AZ/engine change add cost or complexity.
- B: Multi‑Region primaries/Single‑AZ/engine change add cost or complexity.
- D: Multi‑Region primaries/Single‑AZ/engine change add cost or complexity.


---

---

### Question #541

A company wants to build a web application on AWS. Client access requests to the website are not predictable and can be idle for a long time. Only customers who have paid a subscription fee can have the ability to sign in and use the web application. Which combination of steps will meet these requirements MOST cost-effectively? (Choose three.)

- A. Create an AWS Lambda function to retrieve user information from Amazon DynamoDB. Create an Amazon API Gateway endpoint to accept RESTful APIs. Send the API calls to the Lambda function.

- B. Create an Amazon Elastic Container Service (Amazon ECS) service behind an Application Load Balancer to retrieve user information from Amazon RDS. Create an Amazon API Gateway endpoint to accept RESTful APIs. Send the API calls to the Lambda function.

- C. Create an Amazon Cognito user pool to authenticate users.

- D. Create an Amazon Cognito identity pool to authenticate users.

E. Use AWS Amplify to serve the frontend web content with HTML, CSS, and JS. Use an integrated Amazon CloudFront configuration.

F. Use Amazon S3 static web hosting with PHP, CSS, and JS. Use Amazon CloudFront to serve the frontend web content.

**Correct:** A, C, E
**Why:** Serverless API (API Gateway → Lambda) is cost‑effective for spiky/idle loads; Cognito user pool handles subscription auth; Amplify hosts frontend with integrated CloudFront.

**Incorrect:**
- B: ECS/EC2 PHP or identity pools are unnecessary here.
- D: ECS/EC2 PHP or identity pools are unnecessary here.
- F: ECS/EC2 PHP or identity pools are unnecessary here.


---

---

### Question #545

A company wants to direct its users to a backup static error page if the company's primary website is unavailable. The primary website's DNS records are hosted in Amazon Route 53. The domain is pointing to an Application Load Balancer (ALB). The company needs a solution that minimizes changes and infrastructure overhead. Which solution will meet these requirements?

- A. Update the Route 53 records to use a latency routing policy. Add a static error page that is hosted in an Amazon S3 bucket to the records so that the trac is sent to the most responsive endpoints.

- B. Set up a Route 53 active-passive failover configuration. Direct trac to a static error page that is hosted in an Amazon S3 bucket when Route 53 health checks determine that the ALB endpoint is unhealthy.

- C. Set up a Route 53 active-active configuration with the ALB and an Amazon EC2 instance that hosts a static error page as endpoints. Configure Route 53 to send requests to the instance only if the health checks fail for the ALB.

- D. Update the Route 53 records to use a multivalue answer routing policy. Create a health check. Direct trac to the website if the health check passes. Direct trac to a static error page that is hosted in Amazon S3 if the health check does not pass.

**Correct:** B
**Why:** Route 53 active‑passive failover to an S3 static error page when ALB health checks fail—minimal infra/changes.

**Incorrect:**
- A: Latency/multivalue policies don’t provide ALB health‑based failover to S3.
- C: Maintaining EC2 for a static page adds ops.
- D: Latency/multivalue policies don’t provide ALB health‑based failover to S3.


---

---

### Question #560

A company's solutions architect is designing an AWS multi-account solution that uses AWS Organizations. The solutions architect has organized the company's accounts into organizational units (OUs). The solutions architect needs a solution that will identify any changes to the OU hierarchy. The solution also needs to notify the company's operations team of any changes. Which solution will meet these requirements with the LEAST operational overhead?

- A. Provision the AWS accounts by using AWS Control Tower. Use account drift notications to identify the changes to the OU hierarchy.

- B. Provision the AWS accounts by using AWS Control Tower. Use AWS Cong aggregated rules to identify the changes to the OU hierarchy.

- C. Use AWS Service Catalog to create accounts in Organizations. Use an AWS CloudTrail organization trail to identify the changes to the OU hierarchy.

- D. Use AWS CloudFormation templates to create accounts in Organizations. Use the drift detection operation on a stack to identify the changes to the OU hierarchy.

**Correct:** C
**Why:** An organization trail in AWS CloudTrail records changes to AWS Organizations (including OU hierarchy). Pairing account creation via Service Catalog is incidental; the key is CloudTrail org trail plus notifications for changes.

**Incorrect:**
- A: Control Tower drift notifications relate to account/VPC baselines, not specifically OU hierarchy changes.
- B: AWS Config rules don’t natively report OU hierarchy changes; CloudTrail does.
- D: CloudFormation drift detection applies to stacks, not Organizations OU structure.


---

---

### Question #564

A company is building an ecommerce application and needs to store sensitive customer information. The company needs to give customers the ability to complete purchase transactions on the website. The company also needs to ensure that sensitive customer data is protected, even from database administrators. Which solution meets these requirements?

- A. Store sensitive data in an Amazon Elastic Block Store (Amazon EBS) volume. Use EBS encryption to encrypt the data. Use an IAM instance role to restrict access.

- B. Store sensitive data in Amazon RDS for MySQL. Use AWS Key Management Service (AWS KMS) client-side encryption to encrypt the data.

- C. Store sensitive data in Amazon S3. Use AWS Key Management Service (AWS KMS) server-side encryption to encrypt the data. Use S3 bucket policies to restrict access.

- D. Store sensitive data in Amazon FSx for Windows Server. Mount the file share on application servers. Use Windows file permissions to restrict access.

**Correct:** B
**Why:** To prevent even DBAs from accessing sensitive data, encrypt at the application/client layer before storage (client-side KMS encryption) and store ciphertext in the database.

**Incorrect:**
- A: EBS encryption protects at the volume level; DBAs can still read decrypted data via the DB engine.
- C: S3 is not the right backend for transactional ecommerce data; SSE-KMS also does not prevent privileged DB access.
- D: FSx + Windows permissions doesn’t address app-level transactional storage nor protect from DBAs.


---

---

### Question #565

A company has an on-premises MySQL database that handles transactional data. The company is migrating the database to the AWS Cloud. The migrated database must maintain compatibility with the company's applications that use the database. The migrated database also must scale automatically during periods of increased demand. Which migration solution will meet these requirements?

- A. Use native MySQL tools to migrate the database to Amazon RDS for MySQL. Configure elastic storage scaling.

- B. Migrate the database to Amazon Redshift by using the mysqldump utility. Turn on Auto Scaling for the Amazon Redshift cluster.

- C. Use AWS Database Migration Service (AWS DMS) to migrate the database to Amazon Aurora. Turn on Aurora Auto Scaling.

- D. Use AWS Database Migration Service (AWS DMS) to migrate the database to Amazon DynamoDB. Configure an Auto Scaling policy.

**Correct:** C
**Why:** Migrate with AWS DMS to Amazon Aurora (MySQL-compatible). Aurora Auto Scaling (e.g., readers, and with Aurora Serverless v2 if adopted) provides automatic scaling to meet demand while maintaining compatibility.

**Incorrect:**
- A: RDS for MySQL with elastic storage scaling does not auto scale compute to handle demand spikes.
- B: Redshift is a data warehouse, not a transactional DB replacement.
- D: DynamoDB is NoSQL and not MySQL-compatible for existing apps.


---

---

### Question #572

A company runs an application on AWS. The application receives inconsistent amounts of usage. The application uses AWS Direct Connect to connect to an on-premises MySQL-compatible database. The on-premises database consistently uses a minimum of 2 GiB of memory. The company wants to migrate the on-premises database to a managed AWS service. The company wants to use auto scaling capabilities to manage unexpected workload increases. Which solution will meet these requirements with the LEAST administrative overhead?

- A. Provision an Amazon DynamoDB database with default read and write capacity settings.

- B. Provision an Amazon Aurora database with a minimum capacity of 1 Aurora capacity unit (ACU).

- C. Provision an Amazon Aurora Serverless v2 database with a minimum capacity of 1 Aurora capacity unit (ACU).

- D. Provision an Amazon RDS for MySQL database with 2 GiB of memory.

**Correct:** C
**Why:** Aurora Serverless v2 (MySQL-compatible) supports automatic, fine-grained scaling with minimal admin overhead; a 1 ACU minimum covers the 2 GiB baseline.

**Incorrect:**
- A: DynamoDB is not MySQL-compatible.
- B: Provisioned Aurora (non-serverless) requires capacity management.
- D: RDS for MySQL is managed but does not auto scale compute to absorb unexpected spikes.


---

---

### Question #574

A nancial services company launched a new application that uses an Amazon RDS for MySQL database. The company uses the application to track stock market trends. The company needs to operate the application for only 2 hours at the end of each week. The company needs to optimize the cost of running the database. Which solution will meet these requirements MOST cost-effectively?

- A. Migrate the existing RDS for MySQL database to an Aurora Serverless v2 MySQL database cluster.

- B. Migrate the existing RDS for MySQL database to an Aurora MySQL database cluster.

- C. Migrate the existing RDS for MySQL database to an Amazon EC2 instance that runs MySQL. Purchase an instance reservation for the EC2 instance.

- D. Migrate the existing RDS for MySQL database to an Amazon Elastic Container Service (Amazon ECS) cluster that uses MySQL container images to run tasks.

**Correct:** A
**Why:** Aurora Serverless v2 scales capacity to meet the brief weekly usage window and minimizes cost when idle, with low ops overhead.

**Incorrect:**
- B: Provisioned Aurora runs 24/7 and costs more for a 2‑hour/week workload.
- C: EC2 self-managed MySQL increases operational effort.
- D: ECS for MySQL adds container and storage management complexity.


---

---

### Question #575

A company deploys its applications on Amazon Elastic Kubernetes Service (Amazon EKS) behind an Application Load Balancer in an AWS Region. The application needs to store data in a PostgreSQL database engine. The company wants the data in the database to be highly available. The company also needs increased capacity for read workloads. Which solution will meet these requirements with the MOST operational eciency?

- A. Create an Amazon DynamoDB database table congured with global tables.

- B. Create an Amazon RDS database with Multi-AZ deployments.

- C. Create an Amazon RDS database with Multi-AZ DB cluster deployment.

- D. Create an Amazon RDS database congured with cross-Region read replicas.

**Correct:** C
**Why:** RDS Multi-AZ DB cluster deployment provides high availability and additional reader capacity through readable standbys for read scaling.

**Incorrect:**
- A: DynamoDB is not a PostgreSQL engine.
- B: Traditional Multi-AZ (single-standby) does not provide increased read capacity.
- D: Cross-Region read replicas add latency/complexity and are for DR, not primary read scaling.


---

---

### Question #578

A company deployed a serverless application that uses Amazon DynamoDB as a database layer. The application has experienced a large increase in users. The company wants to improve database response time from milliseconds to microseconds and to cache requests to the database. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use DynamoDB Accelerator (DAX).

- B. Migrate the database to Amazon Redshift.

- C. Migrate the database to Amazon RDS.

- D. Use Amazon ElastiCache for Redis.

**Correct:** A
**Why:** DynamoDB Accelerator (DAX) provides microsecond response times and caches DynamoDB queries with minimal operational overhead.

**Incorrect:**
- B: Redshift/RDS are different database engines, not a cache for DynamoDB.
- C: Redshift/RDS are different database engines, not a cache for DynamoDB.
- D: ElastiCache can cache but requires more app-side caching logic than DAX.


---

---

### Question #579

A company runs an application that uses Amazon RDS for PostgreSQL. The application receives trac only on weekdays during business hours. The company wants to optimize costs and reduce operational overhead based on this usage. Which solution will meet these requirements?

- A. Use the Instance Scheduler on AWS to configure start and stop schedules.

- B. Turn off automatic backups. Create weekly manual snapshots of the database.

- C. Create a custom AWS Lambda function to start and stop the database based on minimum CPU utilization.

- D. Purchase All Upfront reserved DB instances.

**Correct:** A
**Why:** The Instance Scheduler on AWS can start/stop RDS instances on a schedule to reduce cost when idle.

**Incorrect:**
- B: Turning off backups risks data loss and doesn’t optimize running costs.
- C: Custom Lambda adds overhead and brittleness.
- D: Reserved instances charge continuously despite low utilization.


---

---

### Question #588

An ecommerce company wants a disaster recovery solution for its Amazon RDS DB instances that run Microsoft SQL Server Enterprise Edition. The company's current recovery point objective (RPO) and recovery time objective (RTO) are 24 hours. Which solution will meet these requirements MOST cost-effectively?

- A. Create a cross-Region read replica and promote the read replica to the primary instance.

- B. Use AWS Database Migration Service (AWS DMS) to create RDS cross-Region replication.

- C. Use cross-Region replication every 24 hours to copy native backups to an Amazon S3 bucket.

- D. Copy automatic snapshots to another Region every 24 hours.

**Correct:** D
**Why:** Copy automatic snapshots cross‑Region every 24 hours to meet 24‑hour RPO/RTO at the lowest cost.

**Incorrect:**
- A: Cross‑Region read replica costs more and is overkill for 24‑hour objectives.
- B: DMS is for migration/replication at higher cost/complexity.
- C: Native backups to S3 and custom replication add ops overhead.


---

---

### Question #589

A company runs a web application on Amazon EC2 instances in an Auto Scaling group behind an Application Load Balancer that has sticky sessions enabled. The web server currently hosts the user session state. The company wants to ensure high availability and avoid user session state loss in the event of a web server outage. Which solution will meet these requirements?

- A. Use an Amazon ElastiCache for Memcached instance to store the session data. Update the application to use ElastiCache for Memcached to store the session state.

- B. Use Amazon ElastiCache for Redis to store the session state. Update the application to use ElastiCache for Redis to store the session state.

- C. Use an AWS Storage Gateway cached volume to store session data. Update the application to use AWS Storage Gateway cached volume to store the session state.

- D. Use Amazon RDS to store the session state. Update the application to use Amazon RDS to store the session state.

**Correct:** B
**Why:** ElastiCache for Redis supports durable, highly available session storage and eliminates dependency on individual web servers.

**Incorrect:**
- A: Memcached lacks persistence and robust HA.
- C: Storage Gateway is not for session storage.
- D: RDS adds latency/overhead vs. an in‑memory cache for sessions.


---

---

### Question #590

A company migrated a MySQL database from the company's on-premises data center to an Amazon RDS for MySQL DB instance. The company sized the RDS DB instance to meet the company's average daily workload. Once a month, the database performs slowly when the company runs queries for a report. The company wants to have the ability to run reports and maintain the performance of the daily workloads. Which solution will meet these requirements?

- A. Create a read replica of the database. Direct the queries to the read replica.

- B. Create a backup of the database. Restore the backup to another DB instance. Direct the queries to the new database.

- C. Export the data to Amazon S3. Use Amazon Athena to query the S3 bucket.

- D. Resize the DB instance to accommodate the additional workload.

**Correct:** A
**Why:** A read replica offloads reporting queries without impacting primary OLTP performance.

**Incorrect:**
- B: Restoring a backup is slower and manual.
- C: Athena on S3 requires exports and a different access pattern.
- D: Upsizing increases cost and still mixes workloads on one instance.


---

---

### Question #593

A solutions architect is designing a highly available Amazon ElastiCache for Redis based solution. The solutions architect needs to ensure that failures do not result in performance degradation or loss of data locally and within an AWS Region. The solution needs to provide high availability at the node level and at the Region level. Which solution will meet these requirements?

- A. Use Multi-AZ Redis replication groups with shards that contain multiple nodes.

- B. Use Redis shards that contain multiple nodes with Redis append only files (AOF) turned on.

- C. Use a Multi-AZ Redis cluster with more than one read replica in the replication group.

- D. Use Redis shards that contain multiple nodes with Auto Scaling turned on.

**Correct:** A
**Why:** Multi‑AZ Redis replication groups with shards of multiple nodes provide node‑level HA and AZ‑level resilience without performance degradation.

**Incorrect:**
- B: AOF persistence doesn’t by itself ensure HA or regional resilience.
- C: Single read replica per shard is less robust than multi‑node shards and doesn’t address shard‑level failures.
- D: Auto Scaling isn’t applicable for Redis nodes in this context.


---

---

### Question #596

An ecommerce application uses a PostgreSQL database that runs on an Amazon EC2 instance. During a monthly sales event, database usage increases and causes database connection issues for the application. The trac is unpredictable for subsequent monthly sales events, which impacts the sales forecast. The company needs to maintain performance when there is an unpredictable increase in trac. Which solution resolves this issue in the MOST cost-effective way?

- A. Migrate the PostgreSQL database to Amazon Aurora Serverless v2.

- B. Enable auto scaling for the PostgreSQL database on the EC2 instance to accommodate increased usage.

- C. Migrate the PostgreSQL database to Amazon RDS for PostgreSQL with a larger instance type.

- D. Migrate the PostgreSQL database to Amazon Redshift to accommodate increased usage.

**Correct:** A
**Why:** Aurora Serverless v2 for PostgreSQL auto scales capacity to handle unpredictable event spikes cost‑effectively.

**Incorrect:**
- B: EC2 DB auto scaling isn’t available and requires self‑management.
- C: Fixed RDS size lacks elasticity.
- D: Redshift is for analytics, not transactional workloads.


---

---

### Question #599

A company wants to use Amazon Elastic Container Service (Amazon ECS) clusters and Amazon RDS DB instances to build and run a payment processing application. The company will run the application in its on-premises data center for compliance purposes. A solutions architect wants to use AWS Outposts as part of the solution. The solutions architect is working with the company's operational team to build the application. Which activities are the responsibility of the company's operational team? (Choose three.)

- A. Providing resilient power and network connectivity to the Outposts racks

- B. Managing the virtualization hypervisor, storage systems, and the AWS services that run on Outposts

- C. Physical security and access controls of the data center environment

- D. Availability of the Outposts infrastructure including the power supplies, servers, and networking equipment within the Outposts racks

E. Physical maintenance of Outposts components

F. Providing extrafficapacity for Amazon ECS clusters to mitigate server failures and maintenance events

**Correct:** A, C, F
**Why:** Customers provide resilient power/network and physical security, and plan for extra capacity. AWS maintains Outposts hardware and services.

**Incorrect:**
- B: AWS is responsible for hypervisor/services, rack availability, and physical maintenance of Outposts.
- D: AWS is responsible for hypervisor/services, rack availability, and physical maintenance of Outposts.
- E: AWS is responsible for hypervisor/services, rack availability, and physical maintenance of Outposts.


---

---

### Question #601

A company runs its critical database on an Amazon RDS for PostgreSQL DB instance. The company wants to migrate to Amazon Aurora PostgreSQL with minimal downtime and data loss. Which solution will meet these requirements with the LEAST operational overhead?

- A. Create a DB snapshot of the RDS for PostgreSQL DB instance to populate a new Aurora PostgreSQL DB cluster.

- B. Create an Aurora read replica of the RDS for PostgreSQL DB instance. Promote the Aurora read replicate to a new Aurora PostgreSQL DB cluster.

- C. Use data import from Amazon S3 to migrate the database to an Aurora PostgreSQL DB cluster.

- D. Use the pg_dump utility to back up the RDS for PostgreSQL database. Restore the backup to a new Aurora PostgreSQL DB cluster.

**Correct:** B
**Why:** Create an Aurora read replica of RDS for PostgreSQL, then promote. This minimizes downtime and operational effort.

**Incorrect:**
- A: Snapshot/restore incurs longer downtime.
- C: S3 import/pg_dump are manual and operationally heavy.
- D: S3 import/pg_dump are manual and operationally heavy.


---

---

### Question #607

A company has migrated a two-tier application from its on-premises data center to the AWS Cloud. The data tier is a Multi-AZ deployment of Amazon RDS for Oracle with 12 TB of General Purpose SSD Amazon Elastic Block Store (Amazon EBS) storage. The application is designed to process and store documents in the database as binary large objects (blobs) with an average document size of 6 MB. The database size has grown over time, reducing the performance and increasing the cost of storage. The company must improve the database performance and needs a solution that is highly available and resilient. Which solution will meet these requirements MOST cost-effectively?

- A. Reduce the RDS DB instance size. Increase the storage capacity to 24 TiB. Change the storage type to Magnetic.

- B. Increase the RDS DB instance size. Increase the storage capacity to 24 TiChange the storage type to Provisioned IOPS.

- C. Create an Amazon S3 bucket. Update the application to store documents in the S3 bucket. Store the object metadata in the existing database.

- D. Create an Amazon DynamoDB table. Update the application to use DynamoDB. Use AWS Database Migration Service (AWS DMS) to migrate data from the Oracle database to DynamoDB.

**Correct:** C
**Why:** Offload large blobs to S3 and keep only metadata in RDS to reduce DB size/cost and improve performance.

**Incorrect:**
- A: Increasing size/IOPS increases cost and doesn’t address bloated storage from blobs.
- B: Increasing size/IOPS increases cost and doesn’t address bloated storage from blobs.
- D: DynamoDB migration is unnecessary and higher effort.


---

---

### Question #609

A company is building a data analysis platform on AWS by using AWS Lake Formation. The platform will ingest data from different sources such as Amazon S3 and Amazon RDS. The company needs a secure solution to prevent access to portions of the data that contain sensitive information. Which solution will meet these requirements with the LEAST operational overhead?

- A. Create an IAM role that includes permissions to access Lake Formation tables.

- B. Create data lters to implement row-level security and cell-level security.

- C. Create an AWS Lambda function that removes sensitive information before Lake Formation ingests the data.

- D. Create an AWS Lambda function that periodically queries and removes sensitive information from Lake Formation tables.

**Correct:** B
**Why:** Lake Formation row‑level and cell‑level filters natively enforce fine‑grained access to sensitive data with minimal ops.

**Incorrect:**
- A: IAM role alone cannot implement row/cell security at the table data level.
- C: Lambda preprocessing/postprocessing adds complexity and is brittle.
- D: Lambda preprocessing/postprocessing adds complexity and is brittle.


---

---

### Question #614

A company is designing a new multi-tier web application that consists of the following components: • Web and application servers that run on Amazon EC2 instances as part of Auto Scaling groups • An Amazon RDS DB instance for data storage A solutions architect needs to limit access to the application servers so that only the web servers can access them. Which solution will meet these requirements?

- A. Deploy AWS PrivateLink in front of the application servers. Configure the network ACL to allow only the web servers to access the application servers.

- B. Deploy a VPC endpoint in front of the application servers. Configure the security group to allow only the web servers to access the application servers.

- C. Deploy a Network Load Balancer with a target group that contains the application servers' Auto Scaling group. Configure the network ACL to allow only the web servers to access the application servers.

- D. Deploy an Application Load Balancer with a target group that contains the application servers' Auto Scaling group. Configure the security group to allow only the web servers to access the application servers.

**Correct:** D
**Why:** ALB for the app tier with security groups allowing only the web tier enforces tiered access cleanly.

**Incorrect:**
- A: PrivateLink/VPC endpoints don’t fit this intra‑VPC tiering model.
- B: PrivateLink/VPC endpoints don’t fit this intra‑VPC tiering model.
- C: NLB lacks L7 features; NACLs are coarse and stateless.


---

---

### Question #615

A company runs a critical, customer-facing application on Amazon Elastic Kubernetes Service (Amazon EKS). The application has a microservices architecture. The company needs to implement a solution that collects, aggregates, and summarizes metrics and logs from the application in a centralized location. Which solution meets these requirements?

- A. Run the Amazon CloudWatch agent in the existing EKS cluster. View the metrics and logs in the CloudWatch console.

- B. Run AWS App Mesh in the existing EKS cluster. View the metrics and logs in the App Mesh console.

- C. Configure AWS CloudTrail to capture data events. Query CloudTrail by using Amazon OpenSearch Service.

- D. Configure Amazon CloudWatch Container Insights in the existing EKS cluster. View the metrics and logs in the CloudWatch console.

**Correct:** D
**Why:** CloudWatch Container Insights provides cluster‑wide metrics and logs aggregation for EKS with centralized dashboards.

**Incorrect:**
- A: Agent alone lacks curated EKS insights.
- B: App Mesh is a service mesh, not a logging/metrics aggregator.
- C: CloudTrail data events are not application metrics/logs.


---

---

### Question #616

A company has deployed its newest product on AWS. The product runs in an Auto Scaling group behind a Network Load Balancer. The company stores the product’s objects in an Amazon S3 bucket. The company recently experienced malicious attacks against its systems. The company needs a solution that continuously monitors for malicious activity in the AWS account, workloads, and access patterns to the S3 bucket. The solution must also report suspicious activity and display the information on a dashboard. Which solution will meet these requirements?

- A. Configure Amazon Macie to monitor and report ndings to AWS Cong.

- B. Configure Amazon Inspector to monitor and report ndings to AWS CloudTrail.

- C. Configure Amazon GuardDuty to monitor and report ndings to AWS Security Hub.

- D. Configure AWS Cong to monitor and report ndings to Amazon EventBridge.

**Correct:** C
**Why:** GuardDuty continuously monitors account, workload, and S3 access for threats; Security Hub aggregates and dashboards findings.

**Incorrect:**
- A: Macie focuses on sensitive data discovery, not threat detection.
- B: Inspector is for vulnerability assessment, not S3 access/threat patterns.
- D: Config tracks resource configuration, not threat activity.


---

---

### Question #629

A company runs a production database on Amazon RDS for MySQL. The company wants to upgrade the database version for security compliance reasons. Because the database contains critical data, the company wants a quick solution to upgrade and test functionality without losing any data. Which solution will meet these requirements with the LEAST operational overhead?

- A. Create an RDS manual snapshot. Upgrade to the new version of Amazon RDS for MySQL.

- B. Use native backup and restore. Restore the data to the upgraded new version of Amazon RDS for MySQL.

- C. Use AWS Database Migration Service (AWS DMS) to replicate the data to the upgraded new version of Amazon RDS for MySQL.

- D. Use Amazon RDS Blue/Green Deployments to deploy and test production changes.

**Correct:** D
**Why:** RDS Blue/Green Deployments enable quick, low‑risk upgrades and testing without data loss and with minimal downtime.

**Incorrect:**
- A: Snapshot/restore, native backup/restore, or DMS add downtime/ops overhead.
- B: Snapshot/restore, native backup/restore, or DMS add downtime/ops overhead.
- C: Snapshot/restore, native backup/restore, or DMS add downtime/ops overhead.


---

---

### Question #633

A company manages an application that stores data on an Amazon RDS for PostgreSQL Multi-AZ DB instance. Increases in trac are causing performance problems. The company determines that database queries are the primary reason for the slow performance. What should a solutions architect do to improve the application's performance?

- A. Serve read trac from the Multi-AZ standby replica.

- B. Configure the DB instance to use Transfer Acceleration.

- C. Create a read replica from the source DB instance. Serve read trac from the read replica.

- D. Use Amazon Kinesis Data Firehose between the application and Amazon RDS to increase the concurrency of database requests.

**Correct:** C
**Why:** A read replica offloads read traffic from the primary RDS instance to improve performance.

**Incorrect:**
- A: Multi-AZ standby is not for reads.
- B: Transfer Acceleration is for S3, not RDS.
- D: Kinesis Data Firehose is irrelevant here.


---

---

### Question #643

A company runs several websites on AWS for its different brands. Each website generates tens of gigabytes of web trac logs each day. A solutions architect needs to design a scalable solution to give the company's developers the ability to analyze trac patterns across all the company's websites. This analysis by the developers will occur on demand once a week over the course of several months. The solution must support queries with standard SQL. Which solution will meet these requirements MOST cost-effectively?

- A. Store the logs in Amazon S3. Use Amazon Athena tor analysis.

- B. Store the logs in Amazon RDS. Use a database client for analysis.

- C. Store the logs in Amazon OpenSearch Service. Use OpenSearch Service for analysis.

- D. Store the logs in an Amazon EMR cluster Use a supported open-source framework for SQL-based analysis.

**Correct:** A
**Why:** Store logs in S3 and query with Athena using SQL only when needed; minimal cost/ops.

**Incorrect:**
- B: RDS is expensive and not ideal for log analytics.
- C: OpenSearch is more costly for weekly ad‑hoc queries.
- D: EMR cluster management adds significant overhead.


---

---

### Question #644

An international company has a subdomain for each country that the company operates in. The subdomains are formatted as example.com, country1.example.com, and country2.example.com. The company's workloads are behind an Application Load Balancer. The company wants to encrypt the website data that is in transit. Which combination of steps will meet these requirements? (Choose two.)

- A. Use the AWS Certicate Manager (ACM) console to request a public certicate for the apex top domain example com and a wildcard certicate for *.example.com.

- B. Use the AWS Certicate Manager (ACM) console to request a private certicate for the apex top domain example.com and a wildcard certicate for *.example.com.

- C. Use the AWS Certicate Manager (ACM) console to request a public and private certicate for the apex top domain example.com.

- D. Validate domain ownership by email address. Switch to DNS validation by adding the required DNS records to the DNS provider.

E. Validate domain ownership for the domain by adding the required DNS records to the DNS provider.

**Correct:** A, E
**Why:** Request a public cert for example.com and a wildcard for *.example.com in ACM; validate via DNS records.

**Incorrect:**
- B: Private certs or mixed public/private are not needed for public websites.
- C: Private certs or mixed public/private are not needed for public websites.
- D: Email validation is more manual vs. DNS validation.


---

---

### Question #649

An ecommerce company runs a PostgreSQL database on premises. The database stores data by using high IOPS Amazon Elastic Block Store (Amazon EBS) block storage. The daily peak I/O transactions per second do not exceed 15,000 IOPS. The company wants to migrate the database to Amazon RDS for PostgreSQL and provision disk IOPS performance independent of disk storage capacity. Which solution will meet these requirements MOST cost-effectively?

- A. Configure the General Purpose SSD (gp2) EBS volume storage type and provision 15,000 IOPS.

- B. Configure the Provisioned IOPS SSD (io1) EBS volume storage type and provision 15,000 IOPS.

- C. Configure the General Purpose SSD (gp3) EBS volume storage type and provision 15,000 IOPS.

- D. Configure the EBS magnetic volume type to achieve maximum IOPS.

**Correct:** C
**Why:** gp3 lets you provision IOPS independently of storage size at lower cost than io1/io2 for 15k IOPS.

**Incorrect:**
- A: gp2 IOPS scale only with size.
- B: io1 is costlier for this need.
- D: Magnetic cannot meet IOPS needs.


---

---

### Question #650

A company wants to migrate its on-premises Microsoft SQL Server Enterprise edition database to AWS. The company's online application uses the database to process transactions. The data analysis team uses the same production database to run reports for analytical processing. The company wants to reduce operational overhead by moving to managed services wherever possible. Which solution will meet these requirements with the LEAST operational overhead?

- A. Migrate to Amazon RDS for Microsoft SOL Server. Use read replicas for reporting purposes

- B. Migrate to Microsoft SQL Server on Amazon EC2. Use Always On read replicas for reporting purposes

- C. Migrate to Amazon DynamoDB. Use DynamoDB on-demand replicas for reporting purposes

- D. Migrate to Amazon Aurora MySQL. Use Aurora read replicas for reporting purposes

**Correct:** A
**Why:** RDS for SQL Server Enterprise supports read replicas for reporting (Always On readable secondaries), reducing ops overhead compared to self‑managed EC2.

**Incorrect:**
- B: EC2 + Always On is higher ops.
- C: DynamoDB/Aurora MySQL require major app changes.
- D: DynamoDB/Aurora MySQL require major app changes.


---

---

### Question #653

A company maintains an Amazon RDS database that maps users to cost centers. The company has accounts in an organization in AWS Organizations. The company needs a solution that will tag all resources that are created in a specic AWS account in the organization. The solution must tag each resource with the cost center ID of the user who created the resource. Which solution will meet these requirements?

- A. Move the specic AWS account to a new organizational unit (OU) in Organizations from the management account. Create a service control policy (SCP) that requires all existing resources to have the correct cost center tag before the resources are created. Apply the SCP to the new OU.

- B. Create an AWS Lambda function to tag the resources after the Lambda function looks up the appropriate cost center from the RDS database. Configure an Amazon EventBridge rule that reacts to AWS CloudTrail events to invoke the Lambda function.

- C. Create an AWS CloudFormation stack to deploy an AWS Lambda function. Configure the Lambda function to look up the appropriate cost center from the RDS database and to tag resources. Create an Amazon EventBridge scheduled rule to invoke the CloudFormation stack.

- D. Create an AWS Lambda function to tag the resources with a default value. Configure an Amazon EventBridge rule that reacts to AWS CloudTrail events to invoke the Lambda function when a resource is missing the cost center tag.

**Correct:** B
**Why:** Use EventBridge (CloudTrail events) to invoke Lambda that tags new resources after looking up the creator’s cost center in RDS.

**Incorrect:**
- A: SCPs cannot inject tags pre‑creation; they can only allow/deny.
- C: Re‑deploying a stack on a schedule won’t tag arbitrary resources created outside CloudFormation.
- D: Default tags without lookup won’t meet correctness.


---

---

### Question #661

A company runs applications on AWS that connect to the company's Amazon RDS database. The applications scale on weekends and at peak times of the year. The company wants to scale the database more effectively for its applications that connect to the database. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use Amazon DynamoDB with connection pooling with a target group configuration for the database. Change the applications to use the DynamoDB endpoint.

- B. Use Amazon RDS Proxy with a target group for the database. Change the applications to use the RDS Proxy endpoint.

- C. Use a custom proxy that runs on Amazon EC2 as an intermediary to the database. Change the applications to use the custom proxy endpoint.

- D. Use an AWS Lambda function to provide connection pooling with a target group configuration for the database. Change the applications to use the Lambda function.

**Correct:** B
**Why:** RDS Proxy pools and shares DB connections, improving scalability during surges with minimal app changes.

**Incorrect:**
- A: DynamoDB/Lambda are unrelated to SQL connection pooling.
- C: Custom proxy increases ops burden.
- D: DynamoDB/Lambda are unrelated to SQL connection pooling.


---

---

### Question #663

A company is developing a new application on AWS. The application consists of an Amazon Elastic Container Service (Amazon ECS) cluster, an Amazon S3 bucket that contains assets for the application, and an Amazon RDS for MySQL database that contains the dataset for the application. The dataset contains sensitive information. The company wants to ensure that only the ECS cluster can access the data in the RDS for MySQL database and the data in the S3 bucket. Which solution will meet these requirements?

- A. Create a new AWS Key Management Service (AWS KMS) customer managed key to encrypt both the S3 bucket and the RDS for MySQL database. Ensure that the KMS key policy includes encrypt and decrypt permissions for the ECS task execution role.

- B. Create an AWS Key Management Service (AWS KMS) AWS managed key to encrypt both the S3 bucket and the RDS for MySQL database. Ensure that the S3 bucket policy species the ECS task execution role as a user.

- C. Create an S3 bucket policy that restricts bucket access to the ECS task execution role. Create a VPC endpoint for Amazon RDS for MySQL. Update the RDS for MySQL security group to allow access from only the subnets that the ECS cluster will generate tasks in.

- D. Create a VPC endpoint for Amazon RDS for MySQL. Update the RDS for MySQL security group to allow access from only the subnets that the ECS cluster will generate tasks in. Create a VPC endpoint for Amazon S3. Update the S3 bucket policy to allow access from only the S3 VPC endpoint.

**Correct:** C
**Why:** Restrict S3 bucket access to the ECS task execution role, and tighten RDS access via security groups to only the ECS task subnets; combined, only the ECS tasks can reach data.

**Incorrect:**
- A: KMS encryption alone doesn’t restrict principal network/data access.
- B: KMS encryption alone doesn’t restrict principal network/data access.
- D: There is no VPC endpoint for RDS database connections; S3 endpoint restriction is good, but RDS SG is the right control.


---

---

### Question #666

A startup company is hosting a website for its customers on an Amazon EC2 instance. The website consists of a stateless Python application and a MySQL database. The website serves only a small amount of trac. The company is concerned about the reliability of the instance and needs to migrate to a highly available architecture. The company cannot modify the application code. Which combination of actions should a solutions architect take to achieve high availability for the website? (Choose two.)

- A. Provision an internet gateway in each Availability Zone in use.

- B. Migrate the database to an Amazon RDS for MySQL Multi-AZ DB instance.

- C. Migrate the database to Amazon DynamoDB, and enable DynamoDB auto scaling.

- D. Use AWS DataSync to synchronize the database data across multiple EC2 instances.

E. Create an Application Load Balancer to distribute trac to an Auto Scaling group of EC2 instances that are distributed across two Availability Zones.

**Correct:** B, E
**Why:** RDS for MySQL Multi‑AZ provides HA for the DB. ALB + Auto Scaling across two AZs provides HA for the stateless app without code changes.

**Incorrect:**
- A: Internet gateways are per VPC, not per AZ.
- C: DynamoDB/DataSync are irrelevant here.
- D: DynamoDB/DataSync are irrelevant here.


---

---

### Question #669

A company runs its databases on Amazon RDS for PostgreSQL. The company wants a secure solution to manage the master user password by rotating the password every 30 days. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use Amazon EventBridge to schedule a custom AWS Lambda function to rotate the password every 30 days.

- B. Use the modify-db-instance command in the AWS CLI to change the password.

- C. Integrate AWS Secrets Manager with Amazon RDS for PostgreSQL to automate password rotation.

- D. Integrate AWS Systems Manager Parameter Store with Amazon RDS for PostgreSQL to automate password rotation.

**Correct:** C
**Why:** Secrets Manager integrates with RDS to automatically rotate the master password on a schedule with minimal ops.

**Incorrect:**
- A: Custom Lambda is more work.
- B: CLI changes are manual and error‑prone.
- D: Parameter Store lacks built‑in rotation for RDS master passwords.


---

---

### Question #674

A company runs a web application on Amazon EC2 instances in an Auto Scaling group. The application uses a database that runs on an Amazon RDS for PostgreSQL DB instance. The application performs slowly when trac increases. The database experiences a heavy read load during periods of high trac. Which actions should a solutions architect take to resolve these performance issues? (Choose two.)

- A. Turn on auto scaling for the DB instance.

- B. Create a read replica for the DB instance. Configure the application to send read trac to the read replica.

- C. Convert the DB instance to a Multi-AZ DB instance deployment. Configure the application to send read trac to the standby DB instance.

- D. Create an Amazon ElastiCache cluster. Configure the application to cache query results in the ElastiCache cluster.

E. Configure the Auto Scaling group subnets to ensure that the EC2 instances are provisioned in the same Availability Zone as the DB instance.

**Correct:** B, D
**Why:** Offload read traffic to an RDS read replica and/or cache frequent queries in ElastiCache to reduce DB load and improve response times.

**Incorrect:**
- A: RDS compute does not auto scale; this doesn’t solve read pressure.
- C: Multi‑AZ standby is not readable.


---

---

### Question #683

A company is migrating its multi-tier on-premises application to AWS. The application consists of a single-node MySQL database and a multi-node web tier. The company must minimize changes to the application during the migration. The company wants to improve application resiliency after the migration. Which combination of steps will meet these requirements? (Choose two.)

- A. Migrate the web tier to Amazon EC2 instances in an Auto Scaling group behind an Application Load Balancer.

- B. Migrate the database to Amazon EC2 instances in an Auto Scaling group behind a Network Load Balancer.

- C. Migrate the database to an Amazon RDS Multi-AZ deployment.

- D. Migrate the web tier to an AWS Lambda function.

E. Migrate the database to an Amazon DynamoDB table.

**Correct:** A, C
**Why:** Move the web tier behind an ALB with Auto Scaling for resiliency, and migrate the DB to RDS Multi‑AZ for high availability with minimal app changes.

**Incorrect:**
- B: EC2 DB on NLB is self‑managed and higher ops.
- D: Lambda/DynamoDB require major app changes.
- E: Lambda/DynamoDB require major app changes.


---

## Amazon Redshift

### Question #515

A company is migrating an on-premises application to AWS. The company wants to use Amazon Redshift as a solution. Which use cases are suitable for Amazon Redshift in this scenario? (Choose three.)

- A. Supporting data APIs to access data with traditional, containerized, and event-driven applications

- B. Supporting client-side and server-side encryption

- C. Building analytics workloads during specied hours and when the application is not active

- D. Caching data to reduce the pressure on the backend database

E. Scaling globally to support petabytes of data and tens of millions of requests per minute

F. Creating a secondary replica of the cluster by using the AWS Management Console

**Correct:** A, B, C
**Why:** Redshift supports the Data API (A), encryption (B), and building analytics workloads during scheduled windows or serverless usage (C).

**Incorrect:**
- D: Caching, extreme per‑request scaling, or “secondary replica via console” are not core Redshift use cases/capabilities.
- E: Caching, extreme per‑request scaling, or “secondary replica via console” are not core Redshift use cases/capabilities.
- F: Caching, extreme per‑request scaling, or “secondary replica via console” are not core Redshift use cases/capabilities.


---

---

### Question #557

A solutions architect manages an analytics application. The application stores large amounts of semistructured data in an Amazon S3 bucket. The solutions architect wants to use parallel data processing to process the data more quickly. The solutions architect also wants to use information that is stored in an Amazon Redshift database to enrich the data. Which solution will meet these requirements?

- A. Use Amazon Athena to process the S3 data. Use AWS Glue with the Amazon Redshift data to enrich the S3 data.

- B. Use Amazon EMR to process the S3 data. Use Amazon EMR with the Amazon Redshift data to enrich the S3 data.

- C. Use Amazon EMR to process the S3 data. Use Amazon Kinesis Data Streams to move the S3 data into Amazon Redshift so that the data can be enriched.

- D. Use AWS Glue to process the S3 data. Use AWS Lake Formation with the Amazon Redshift data to enrich the S3 data.

**Correct:** B
**Why:** Amazon EMR supports large-scale parallel processing on S3 data and can integrate with Amazon Redshift to enrich S3 data with Redshift data (e.g., via Spark connectors/JDBC).

**Incorrect:**
- A: Athena + Glue can join, but enriching with Redshift data is more direct and scalable with EMR compute.
- C: Kinesis Data Streams is for streaming ingestion, not enriching S3 batch data with Redshift.
- D: Glue can process S3 data, but enrichment specifically with Redshift is better served by EMR’s flexible engines.


---

---

### Question #565

A company has an on-premises MySQL database that handles transactional data. The company is migrating the database to the AWS Cloud. The migrated database must maintain compatibility with the company's applications that use the database. The migrated database also must scale automatically during periods of increased demand. Which migration solution will meet these requirements?

- A. Use native MySQL tools to migrate the database to Amazon RDS for MySQL. Configure elastic storage scaling.

- B. Migrate the database to Amazon Redshift by using the mysqldump utility. Turn on Auto Scaling for the Amazon Redshift cluster.

- C. Use AWS Database Migration Service (AWS DMS) to migrate the database to Amazon Aurora. Turn on Aurora Auto Scaling.

- D. Use AWS Database Migration Service (AWS DMS) to migrate the database to Amazon DynamoDB. Configure an Auto Scaling policy.

**Correct:** C
**Why:** Migrate with AWS DMS to Amazon Aurora (MySQL-compatible). Aurora Auto Scaling (e.g., readers, and with Aurora Serverless v2 if adopted) provides automatic scaling to meet demand while maintaining compatibility.

**Incorrect:**
- A: RDS for MySQL with elastic storage scaling does not auto scale compute to handle demand spikes.
- B: Redshift is a data warehouse, not a transactional DB replacement.
- D: DynamoDB is NoSQL and not MySQL-compatible for existing apps.


---

---

### Question #578

A company deployed a serverless application that uses Amazon DynamoDB as a database layer. The application has experienced a large increase in users. The company wants to improve database response time from milliseconds to microseconds and to cache requests to the database. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use DynamoDB Accelerator (DAX).

- B. Migrate the database to Amazon Redshift.

- C. Migrate the database to Amazon RDS.

- D. Use Amazon ElastiCache for Redis.

**Correct:** A
**Why:** DynamoDB Accelerator (DAX) provides microsecond response times and caches DynamoDB queries with minimal operational overhead.

**Incorrect:**
- B: Redshift/RDS are different database engines, not a cache for DynamoDB.
- C: Redshift/RDS are different database engines, not a cache for DynamoDB.
- D: ElastiCache can cache but requires more app-side caching logic than DAX.


---

---

### Question #596

An ecommerce application uses a PostgreSQL database that runs on an Amazon EC2 instance. During a monthly sales event, database usage increases and causes database connection issues for the application. The trac is unpredictable for subsequent monthly sales events, which impacts the sales forecast. The company needs to maintain performance when there is an unpredictable increase in trac. Which solution resolves this issue in the MOST cost-effective way?

- A. Migrate the PostgreSQL database to Amazon Aurora Serverless v2.

- B. Enable auto scaling for the PostgreSQL database on the EC2 instance to accommodate increased usage.

- C. Migrate the PostgreSQL database to Amazon RDS for PostgreSQL with a larger instance type.

- D. Migrate the PostgreSQL database to Amazon Redshift to accommodate increased usage.

**Correct:** A
**Why:** Aurora Serverless v2 for PostgreSQL auto scales capacity to handle unpredictable event spikes cost‑effectively.

**Incorrect:**
- B: EC2 DB auto scaling isn’t available and requires self‑management.
- C: Fixed RDS size lacks elasticity.
- D: Redshift is for analytics, not transactional workloads.


---

---

### Question #598

A research company uses on-premises devices to generate data for analysis. The company wants to use the AWS Cloud to analyze the data. The devices generate .csv files and support writing the data to an SMB file share. Company analysts must be able to use SQL commands to query the data. The analysts will run queries periodically throughout the day. Which combination of steps will meet these requirements MOST cost-effectively? (Choose three.)

- A. Deploy an AWS Storage Gateway on premises in Amazon S3 File Gateway mode.

- B. Deploy an AWS Storage Gateway on premises in Amazon FSx File Gateway made.

- C. Set up an AWS Glue crawler to create a table based on the data that is in Amazon S3.

- D. Set up an Amazon EMR cluster with EMR File System (EMRFS) to query the data that is in Amazon S3. Provide access to analysts.

E. Set up an Amazon Redshift cluster to query the data that is in Amazon S3. Provide access to analysts.

F. Setup Amazon Athena to query the data that is in Amazon S3. Provide access to analysts.

**Correct:** A, C, F
**Why:** Use S3 File Gateway to land CSVs in S3 over SMB, crawl with Glue to build schema, and query with Athena using SQL on demand.

**Incorrect:**
- B: FSx File Gateway presents FSx, not S3.
- D: EMR/Redshift add cost/ops for periodic ad‑hoc queries.
- E: EMR/Redshift add cost/ops for periodic ad‑hoc queries.


---

---

### Question #641

A company wants to monitor its AWS costs for nancial review. The cloud operations team is designing an architecture in the AWS Organizations management account to query AWS Cost and Usage Reports for all member accounts. The team must run this query once a month and provide a detailed analysis of the bill. Which solution is the MOST scalable and cost-effective way to meet these requirements?

- A. Enable Cost and Usage Reports in the management account. Deliver reports to Amazon Kinesis. Use Amazon EMR for analysis.

- B. Enable Cost and Usage Reports in the management account. Deliver the reports to Amazon S3 Use Amazon Athena for analysis.

- C. Enable Cost and Usage Reports for member accounts. Deliver the reports to Amazon S3 Use Amazon Redshift for analysis.

- D. Enable Cost and Usage Reports for member accounts. Deliver the reports to Amazon Kinesis. Use Amazon QuickSight tor analysis.

**Correct:** B
**Why:** CUR to S3 + Athena provides scalable, low‑cost monthly querying across member accounts from the management account.

**Incorrect:**
- A: Kinesis/QuickSight not needed; CUR+Athena is simpler/cheaper.
- C: Enabling CUR per member is unnecessary; centralize in management.
- D: Kinesis/QuickSight not needed; CUR+Athena is simpler/cheaper.


---

## Amazon Route 53

### Question #527

A company has a regional subscription-based streaming service that runs in a single AWS Region. The architecture consists of web servers and application servers on Amazon EC2 instances. The EC2 instances are in Auto Scaling groups behind Elastic Load Balancers. The architecture includes an Amazon Aurora global database cluster that extends across multiple Availability Zones. The company wants to expand globally and to ensure that its application has minimal downtime. Which solution will provide the MOST fault tolerance?

- A. Extend the Auto Scaling groups for the web tier and the application tier to deploy instances in Availability Zones in a second Region. Use an Aurora global database to deploy the database in the primary Region and the second Region. Use Amazon Route 53 health checks with a failover routing policy to the second Region.

- B. Deploy the web tier and the application tier to a second Region. Add an Aurora PostgreSQL cross-Region Aurora Replica in the second Region. Use Amazon Route 53 health checks with a failover routing policy to the second Region. Promote the secondary to primary as needed.

- C. Deploy the web tier and the application tier to a second Region. Create an Aurora PostgreSQL database in the second Region. Use AWS Database Migration Service (AWS DMS) to replicate the primary database to the second Region. Use Amazon Route 53 health checks with a failover routing policy to the second Region.

- D. Deploy the web tier and the application tier to a second Region. Use an Amazon Aurora global database to deploy the database in the primary Region and the second Region. Use Amazon Route 53 health checks with a failover routing policy to the second Region. Promote the secondary to primary as needed.

**Correct:** D
**Why:** Deploy app tiers in a second Region and use Aurora Global Database plus Route 53 failover for maximal fault tolerance.

**Incorrect:**
- A: Less integrated or slower replication and more manual promotion.
- B: Less integrated or slower replication and more manual promotion.
- C: Less integrated or slower replication and more manual promotion.


---

---

### Question #530

A company has an online gaming application that has TCP and UDP multiplayer gaming capabilities. The company uses Amazon Route 53 to point the application trac to multiple Network Load Balancers (NLBs) in different AWS Regions. The company needs to improve application performance and decrease latency for the online game in preparation for user growth. Which solution will meet these requirements?

- A. Add an Amazon CloudFront distribution in front of the NLBs. Increase the Cache-Control max-age parameter.

- B. Replace the NLBs with Application Load Balancers (ALBs). Configure Route 53 to use latency-based routing.

- C. Add AWS Global Accelerator in front of the NLBs. Configure a Global Accelerator endpoint to use the correct listener ports.

- D. Add an Amazon API Gateway endpoint behind the NLBs. Enable API caching. Override method caching for the different stages.

**Correct:** C
**Why:** Global Accelerator improves global TCP/UDP performance with anycast IPs in front of NLBs.

**Incorrect:**
- A: CloudFront/ALB/API Gateway are not suited for arbitrary TCP/UDP improvements.
- B: CloudFront/ALB/API Gateway are not suited for arbitrary TCP/UDP improvements.
- D: CloudFront/ALB/API Gateway are not suited for arbitrary TCP/UDP improvements.


---

---

### Question #532

A company has a workload in an AWS Region. Customers connect to and access the workload by using an Amazon API Gateway REST API. The company uses Amazon Route 53 as its DNS provider. The company wants to provide individual and secure URLs for all customers. Which combination of steps will meet these requirements with the MOST operational eciency? (Choose three.)

- A. Register the required domain in a registrar. Create a wildcard custom domain name in a Route 53 hosted zone and record in the zone that points to the API Gateway endpoint.

- B. Request a wildcard certicate that matches the domains in AWS Certicate Manager (ACM) in a different Region.

- C. Create hosted zones for each customer as required in Route 53. Create zone records that point to the API Gateway endpoint.

- D. Request a wildcard certicate that matches the custom domain name in AWS Certicate Manager (ACM) in the same Region.

E. Create multiple API endpoints for each customer in API Gateway.

F. Create a custom domain name in API Gateway for the REST API. Import the certicate from AWS Certicate Manager (ACM).

**Correct:** A, D, F
**Why:** Use a wildcard custom domain in Route 53, request a matching wildcard ACM cert in the same Region, and create a custom domain in API Gateway with that cert.

**Incorrect:**
- B: Wrong Region for ACM, per‑customer hosted zones, or multiple API endpoints add overhead.
- C: Wrong Region for ACM, per‑customer hosted zones, or multiple API endpoints add overhead.
- E: Wrong Region for ACM, per‑customer hosted zones, or multiple API endpoints add overhead.


---

---

### Question #544

A retail company uses a regional Amazon API Gateway API for its public REST APIs. The API Gateway endpoint is a custom domain name that points to an Amazon Route 53 alias record. A solutions architect needs to create a solution that has minimal effects on customers and minimal data loss to release the new version of APIs. Which solution will meet these requirements?

- A. Create a canary release deployment stage for API Gateway. Deploy the latest API version. Point an appropriate percentage of trac to the canary stage. After API verication, promote the canary stage to the production stage.

- B. Create a new API Gateway endpoint with a new version of the API in OpenAPI YAML file format. Use the import-to-update operation in merge mode into the API in API Gateway. Deploy the new version of the API to the production stage.

- C. Create a new API Gateway endpoint with a new version of the API in OpenAPI JSON file format. Use the import-to-update operation in overwrite mode into the API in API Gateway. Deploy the new version of the API to the production stage.

- D. Create a new API Gateway endpoint with new versions of the API denitions. Create a custom domain name for the new API Gateway API. Point the Route 53 alias record to the new API Gateway API custom domain name.

**Correct:** A
**Why:** Canary release in API Gateway shifts a small percentage of traffic to the new version, minimizing impact and data loss before promotion.

**Incorrect:**
- B: Import‑to‑update risks broad changes without gradual rollout.
- C: Import‑to‑update risks broad changes without gradual rollout.
- D: New endpoint/domain switch has higher impact.


---

---

### Question #545

A company wants to direct its users to a backup static error page if the company's primary website is unavailable. The primary website's DNS records are hosted in Amazon Route 53. The domain is pointing to an Application Load Balancer (ALB). The company needs a solution that minimizes changes and infrastructure overhead. Which solution will meet these requirements?

- A. Update the Route 53 records to use a latency routing policy. Add a static error page that is hosted in an Amazon S3 bucket to the records so that the trac is sent to the most responsive endpoints.

- B. Set up a Route 53 active-passive failover configuration. Direct trac to a static error page that is hosted in an Amazon S3 bucket when Route 53 health checks determine that the ALB endpoint is unhealthy.

- C. Set up a Route 53 active-active configuration with the ALB and an Amazon EC2 instance that hosts a static error page as endpoints. Configure Route 53 to send requests to the instance only if the health checks fail for the ALB.

- D. Update the Route 53 records to use a multivalue answer routing policy. Create a health check. Direct trac to the website if the health check passes. Direct trac to a static error page that is hosted in Amazon S3 if the health check does not pass.

**Correct:** B
**Why:** Route 53 active‑passive failover to an S3 static error page when ALB health checks fail—minimal infra/changes.

**Incorrect:**
- A: Latency/multivalue policies don’t provide ALB health‑based failover to S3.
- C: Maintaining EC2 for a static page adds ops.
- D: Latency/multivalue policies don’t provide ALB health‑based failover to S3.


---

---

### Question #582

An ecommerce company uses Amazon Route 53 as its DNS provider. The company hosts its website on premises and in the AWS Cloud. The company's on-premises data center is near the us-west-1 Region. The company uses the eu-central-1 Region to host the website. The company wants to minimize load time for the website as much as possible. Which solution will meet these requirements?

- A. Set up a geolocation routing policy. Send the trac that is near us-west-1 to the on-premises data center. Send the trac that is near eu- central-1 to eu-central-1.

- B. Set up a simple routing policy that routes all trac that is near eu-central-1 to eu-central-1 and routes all trac that is near the on-premises datacenter to the on-premises data center.

- C. Set up a latency routing policy. Associate the policy with us-west-1.

- D. Set up a weighted routing policy. Split the trac evenly between eu-central-1 and the on-premises data center.

**Correct:** A
**Why:** Geolocation routing sends users to the nearest appropriate endpoint (on‑prem near us-west-1 or eu‑central‑1) to minimize load time.

**Incorrect:**
- B: Simple routing cannot split by geography.
- C: Latency routing is AWS‑measured between Regions and cannot directly consider on‑prem.
- D: Weighted routing ignores geography and may degrade performance.


---

---

### Question #625

A company is hosting a website behind multiple Application Load Balancers. The company has different distribution rights for its content around the world. A solutions architect needs to ensure that users are served the correct content without violating distribution rights. Which configuration should the solutions architect choose to meet these requirements?

- A. Configure Amazon CloudFront with AWS WAF.

- B. Configure Application Load Balancers with AWS WAF

- C. Configure Amazon Route 53 with a geolocation policy

- D. Configure Amazon Route 53 with a geoproximity routing policy

**Correct:** C
**Why:** Route 53 geolocation routing serves content based on user location across multiple ALB endpoints to respect distribution rights.

**Incorrect:**
- A: WAF doesn’t handle routing to different content by geography.
- B: WAF doesn’t handle routing to different content by geography.
- D: Geoproximity adjusts by distance/bias, not strict country mapping.


---

---

### Question #627

A company wants to migrate two DNS servers to AWS. The servers host a total of approximately 200 zones and receive 1 million requests each day on average. The company wants to maximize availability while minimizing the operational overhead that is related to the management of the two servers. What should a solutions architect recommend to meet these requirements?

- A. Create 200 new hosted zones in the Amazon Route 53 console Import zone files.

- B. Launch a single large Amazon EC2 instance Import zone tiles. Configure Amazon CloudWatch alarms and notications to alert the company about any downtime.

- C. Migrate the servers to AWS by using AWS Server Migration Service (AWS SMS). Configure Amazon CloudWatch alarms and notications to alert the company about any downtime.

- D. Launch an Amazon EC2 instance in an Auto Scaling group across two Availability Zones. Import zone files. Set the desired capacity to 1 and the maximum capacity to 3 for the Auto Scaling group. Configure scaling alarms to scale based on CPU utilization.

**Correct:** A
**Why:** Route 53 hosted zones are fully managed and highly available. Import existing zone files for low operational overhead.

**Incorrect:**
- B: EC2‑based DNS introduces ops burden and single points or scaling work.
- C: EC2‑based DNS introduces ops burden and single points or scaling work.
- D: EC2‑based DNS introduces ops burden and single points or scaling work.


---

---

### Question #642

A company wants to run a gaming application on Amazon EC2 instances that are part of an Auto Scaling group in the AWS Cloud. The application will transmit data by using UDP packets. The company wants to ensure that the application can scale out and in as trac increases and decreases. What should a solutions architect do to meet these requirements?

- A. Attach a Network Load Balancer to the Auto Scaling group.

- B. Attach an Application Load Balancer to the Auto Scaling group.

- C. Deploy an Amazon Route 53 record set with a weighted policy to route trac appropriately.

- D. Deploy a NAT instance that is congured with port forwarding to the EC2 instances in the Auto Scaling group.

**Correct:** A
**Why:** NLB supports UDP and scales out/in with the Auto Scaling group behind it.

**Incorrect:**
- B: ALB does not support UDP.
- C: Route 53/NAT instance do not provide scalable UDP load balancing.
- D: Route 53/NAT instance do not provide scalable UDP load balancing.


---

---

### Question #647

A gaming company is building an application with Voice over IP capabilities. The application will serve trac to users across the world. The application needs to be highly available with an automated failover across AWS Regions. The company wants to minimize the latency of users without relying on IP address caching on user devices. What should a solutions architect do to meet these requirements?

- A. Use AWS Global Accelerator with health checks.

- B. Use Amazon Route 53 with a geolocation routing policy.

- C. Create an Amazon CloudFront distribution that includes multiple origins.

- D. Create an Application Load Balancer that uses path-based routing.

**Correct:** A
**Why:** Global Accelerator provides anycast IPs, health checks, and automatic multi‑Region failover without relying on DNS caching.

**Incorrect:**
- B: Route 53 relies on DNS caching/TTL.
- C: CloudFront is for HTTP(S), not generic VoIP/UDP or bi‑directional traffic patterns.
- D: ALB routes within a Region only.


---

## Amazon S3

### Question #501

A company wants to ingest customer payment data into the company's data lake in Amazon S3. The company receives payment data every minute on average. The company wants to analyze the payment data in real time. Then the company wants to ingest the data into the data lake. Which solution will meet these requirements with the MOST operational eciency?

- A. Use Amazon Kinesis Data Streams to ingest data. Use AWS Lambda to analyze the data in real time.

- B. Use AWS Glue to ingest data. Use Amazon Kinesis Data Analytics to analyze the data in real time.

- C. Use Amazon Kinesis Data Firehose to ingest data. Use Amazon Kinesis Data Analytics to analyze the data in real time.

- D. Use Amazon API Gateway to ingest data. Use AWS Lambda to analyze the data in real time.

**Correct:** C
**Why:** Kinesis Data Firehose provides fully managed ingestion to S3; Kinesis Data Analytics analyzes the stream in real time with minimal ops.

**Incorrect:**
- A: Lambda analysis is more custom and operationally heavier than KDA for streaming analytics.
- B: Glue/API Gateway are not optimal for continuous real‑time ingestion/analysis.
- D: Glue/API Gateway are not optimal for continuous real‑time ingestion/analysis.


---

---

### Question #502

A company runs a website that uses a content management system (CMS) on Amazon EC2. The CMS runs on a single EC2 instance and uses an Amazon Aurora MySQL Multi-AZ DB instance for the data tier. Website images are stored on an Amazon Elastic Block Store (Amazon EBS) volume that is mounted inside the EC2 instance. Which combination of actions should a solutions architect take to improve the performance and resilience of the website? (Choose two.)

- A. Move the website images into an Amazon S3 bucket that is mounted on every EC2 instance

- B. Share the website images by using an NFS share from the primary EC2 instance. Mount this share on the other EC2 instances.

- C. Move the website images onto an Amazon Elastic File System (Amazon EFS) file system that is mounted on every EC2 instance.

- D. Create an Amazon Machine Image (AMI) from the existing EC2 instance. Use the AMI to provision new instances behind an Application Load Balancer as part of an Auto Scaling group. Configure the Auto Scaling group to maintain a minimum of two instances. Configure an accelerator in AWS Global Accelerator for the website

E. Create an Amazon Machine Image (AMI) from the existing EC2 instance. Use the AMI to provision new instances behind an Application Load Balancer as part of an Auto Scaling group. Configure the Auto Scaling group to maintain a minimum of two instances. Configure an Amazon CloudFront distribution for the website.

**Correct:** C, E
**Why:** Move images to EFS for shared, scalable storage; use ALB+Auto Scaling behind a CloudFront distribution for performance and resilience.

**Incorrect:**
- A: S3 mounted or EC2 NFS via a primary instance are not ideal.
- B: S3 mounted or EC2 NFS via a primary instance are not ideal.
- D: Global Accelerator is unnecessary for origin performance here.


---

---

### Question #506

A social media company is building a feature for its website. The feature will give users the ability to upload photos. The company expects signicant increases in demand during large events and must ensure that the website can handle the upload trac from users. Which solution meets these requirements with the MOST scalability?

- A. Upload files from the user's browser to the application servers. Transfer the files to an Amazon S3 bucket.

- B. Provision an AWS Storage Gateway file gateway. Upload files directly from the user's browser to the file gateway.

- C. Generate Amazon S3 presigned URLs in the application. Upload files directly from the user's browser into an S3 bucket.

- D. Provision an Amazon Elastic File System (Amazon EFS) file system. Upload files directly from the user's browser to the file system.

**Correct:** C
**Why:** Use S3 presigned URLs so browsers upload directly to S3, maximizing scalability and offloading servers.

**Incorrect:**
- A: Uploading through app servers/gateways/EFS reduces scalability.
- B: Uploading through app servers/gateways/EFS reduces scalability.
- D: Uploading through app servers/gateways/EFS reduces scalability.


---

---

### Question #511

A company is developing software that uses a PostgreSQL database schema. The company needs to configure multiple development environments and databases for the company's developers. On average, each development environment is used for half of the 8-hour workday. Which solution will meet these requirements MOST cost-effectively?

- A. Configure each development environment with its own Amazon Aurora PostgreSQL database

- B. Configure each development environment with its own Amazon RDS for PostgreSQL Single-AZ DB instances

- C. Configure each development environment with its own Amazon Aurora On-Demand PostgreSQL-Compatible database

- D. Configure each development environment with its own Amazon S3 bucket by using Amazon S3 Object Select

**Correct:** C
**Why:** Aurora Serverless/On‑Demand PostgreSQL is cost‑effective for dev environments that are idle for long periods.

**Incorrect:**
- A: Always‑on instances cost more for idle time.
- B: Always‑on instances cost more for idle time.
- D: S3 is not a relational database.


---

---

### Question #513

A social media company wants to allow its users to upload images in an application that is hosted in the AWS Cloud. The company needs a solution that automatically resizes the images so that the images can be displayed on multiple device types. The application experiences unpredictable trac patterns throughout the day. The company is seeking a highly available solution that maximizes scalability. What should a solutions architect do to meet these requirements?

- A. Create a static website hosted in Amazon S3 that invokes AWS Lambda functions to resize the images and store the images in an Amazon S3 bucket.

- B. Create a static website hosted in Amazon CloudFront that invokes AWS Step Functions to resize the images and store the images in an Amazon RDS database.

- C. Create a dynamic website hosted on a web server that runs on an Amazon EC2 instance. Configure a process that runs on the EC2 instance to resize the images and store the images in an Amazon S3 bucket.

- D. Create a dynamic website hosted on an automatically scaling Amazon Elastic Container Service (Amazon ECS) cluster that creates a resize job in Amazon Simple Queue Service (Amazon SQS). Set up an image-resizing program that runs on an Amazon EC2 instance to process the resize jobs.

**Correct:** A
**Why:** Static site front end in S3 with Lambda resizing on upload provides high availability and scalability with minimal ops; store results in S3.

**Incorrect:**
- B: CloudFront+Step Functions/EC2/ECS add complexity and are less serverless.
- C: CloudFront+Step Functions/EC2/ECS add complexity and are less serverless.
- D: CloudFront+Step Functions/EC2/ECS add complexity and are less serverless.


---

---

### Question #517

A company wants to send all AWS Systems Manager Session Manager logs to an Amazon S3 bucket for archival purposes. Which solution will meet this requirement with the MOST operational eciency?

- A. Enable S3 logging in the Systems Manager console. Choose an S3 bucket to send the session data to.

- B. Install the Amazon CloudWatch agent. Push all logs to a CloudWatch log group. Export the logs to an S3 bucket from the group for archival purposes.

- C. Create a Systems Manager document to upload all server logs to a central S3 bucket. Use Amazon EventBridge to run the Systems Manager document against all servers that are in the account daily.

- D. Install an Amazon CloudWatch agent. Push all logs to a CloudWatch log group. Create a CloudWatch logs subscription that pushes any incoming log events to an Amazon Kinesis Data Firehose delivery stream. Set Amazon S3 as the destination.

**Correct:** A
**Why:** Session Manager supports direct delivery of session logs to S3 from the console with minimal setup.

**Incorrect:**
- B: Extra agents/pipelines add complexity.
- C: Extra agents/pipelines add complexity.
- D: Extra agents/pipelines add complexity.


---

---

### Question #528

A data analytics company wants to migrate its batch processing system to AWS. The company receives thousands of small data files periodically during the day through FTP. An on-premises batch job processes the data files overnight. However, the batch job takes hours to nish running. The company wants the AWS solution to process incoming data files as soon as possible with minimal changes to the FTP clients that send the files. The solution must delete the incoming data files after the files have been processed successfully. Processing for each file needs to take 3-8 minutes. Which solution will meet these requirements in the MOST operationally ecient way?

- A. Use an Amazon EC2 instance that runs an FTP server to store incoming files as objects in Amazon S3 Glacier Flexible Retrieval. Configure a job queue in AWS Batch. Use Amazon EventBridge rules to invoke the job to process the objects nightly from S3 Glacier Flexible Retrieval. Delete the objects after the job has processed the objects.

- B. Use an Amazon EC2 instance that runs an FTP server to store incoming files on an Amazon Elastic Block Store (Amazon EBS) volume. Configure a job queue in AWS Batch. Use Amazon EventBridge rules to invoke the job to process the files nightly from the EBS volume. Delete the files after the job has processed the files.

- C. Use AWS Transfer Family to create an FTP server to store incoming files on an Amazon Elastic Block Store (Amazon EBS) volume. Configure a job queue in AWS Batch. Use an Amazon S3 event notification when each file arrives to invoke the job in AWS Batch. Delete the files after the job has processed the files.

- D. Use AWS Transfer Family to create an FTP server to store incoming files in Amazon S3 Standard. Create an AWS Lambda function to process the files and to delete the files after they are processed. Use an S3 event notification to invoke the Lambda function when the files arrive.

**Correct:** D
**Why:** Transfer Family (FTP) to S3 with S3 event → Lambda processes and deletes files as they arrive—near real time, minimal client changes.

**Incorrect:**
- A: Glacier/EBS nightly batches or Batch jobs add latency/ops.
- B: Glacier/EBS nightly batches or Batch jobs add latency/ops.
- C: Glacier/EBS nightly batches or Batch jobs add latency/ops.


---

---

### Question #529

A company is migrating its workloads to AWS. The company has transactional and sensitive data in its databases. The company wants to use AWS Cloud solutions to increase security and reduce operational overhead for the databases. Which solution will meet these requirements?

- A. Migrate the databases to Amazon EC2. Use an AWS Key Management Service (AWS KMS) AWS managed key for encryption.

- B. Migrate the databases to Amazon RDS Configure encryption at rest.

- C. Migrate the data to Amazon S3 Use Amazon Macie for data security and protection

- D. Migrate the database to Amazon RDS. Use Amazon CloudWatch Logs for data security and protection.

**Correct:** B
**Why:** RDS is managed, supports encryption at rest/in transit, and reduces operational overhead for transactional/sensitive data.

**Incorrect:**
- A: EC2/CloudWatch Logs/Macie alone do not meet the database requirements.
- C: EC2/CloudWatch Logs/Macie alone do not meet the database requirements.
- D: EC2/CloudWatch Logs/Macie alone do not meet the database requirements.


---

---

### Question #533

A company stores data in Amazon S3. According to regulations, the data must not contain personally identiable information (PII). The company recently discovered that S3 buckets have some objects that contain PII. The company needs to automatically detect PII in S3 buckets and to notify the company’s security team. Which solution will meet these requirements?

- A. Use Amazon Macie. Create an Amazon EventBridge rule to filter the SensitiveData event type from Macie ndings and to send an Amazon Simple Notification Service (Amazon SNS) notification to the security team.

- B. Use Amazon GuardDuty. Create an Amazon EventBridge rule to filter the CRITICAL event type from GuardDuty ndings and to send an Amazon Simple Notification Service (Amazon SNS) notification to the security team.

- C. Use Amazon Macie. Create an Amazon EventBridge rule to filter the SensitiveData:S3Object/Personal event type from Macie ndings and to send an Amazon Simple Queue Service (Amazon SQS) notification to the security team.

- D. Use Amazon GuardDuty. Create an Amazon EventBridge rule to filter the CRITICAL event type from GuardDuty ndings and to send an Amazon Simple Queue Service (Amazon SQS) notification to the security team.

**Correct:** A
**Why:** Macie detects PII in S3; route SensitiveData events to SNS via EventBridge to notify security.

**Incorrect:**
- B: GuardDuty is not for PII in S3.
- C: SQS is not ideal for notifications to humans.
- D: GuardDuty is not for PII in S3.


---

---

### Question #534

A company wants to build a logging solution for its multiple AWS accounts. The company currently stores the logs from all accounts in a centralized account. The company has created an Amazon S3 bucket in the centralized account to store the VPC flow logs and AWS CloudTrail logs. All logs must be highly available for 30 days for frequent analysis, retained for an additional 60 days for backup purposes, and deleted 90 days after creation. Which solution will meet these requirements MOST cost-effectively?

- A. Transition objects to the S3 Standard storage class 30 days after creation. Write an expiration action that directs Amazon S3 to delete objects after 90 days.

- B. Transition objects to the S3 Standard-Infrequent Access (S3 Standard-IA) storage class 30 days after creation. Move all objects to the S3 Glacier Flexible Retrieval storage class after 90 days. Write an expiration action that directs Amazon S3 to delete objects after 90 days.

- C. Transition objects to the S3 Glacier Flexible Retrieval storage class 30 days after creation. Write an expiration action that directs Amazon S3 to delete objects after 90 days.

- D. Transition objects to the S3 One Zone-Infrequent Access (S3 One Zone-IA) storage class 30 days after creation. Move all objects to the S3 Glacier Flexible Retrieval storage class after 90 days. Write an expiration action that directs Amazon S3 to delete objects after 90 days.

**Correct:** C
**Why:** Keep logs in Standard for 30 days, then transition to Glacier Flexible Retrieval until day 90, then expire—lowest cost for retention/restore needs.

**Incorrect:**
- A: Other tiering mixes are less cost‑effective or contradict the 90‑day deletion.
- B: Other tiering mixes are less cost‑effective or contradict the 90‑day deletion.
- D: Other tiering mixes are less cost‑effective or contradict the 90‑day deletion.


---

---

### Question #539

A company wants to use the AWS Cloud to improve its on-premises disaster recovery (DR) configuration. The company's core production business application uses Microsoft SQL Server Standard, which runs on a virtual machine (VM). The application has a recovery point objective (RPO) of 30 seconds or fewer and a recovery time objective (RTO) of 60 minutes. The DR solution needs to minimize costs wherever possible. Which solution will meet these requirements?

- A. Configure a multi-site active/active setup between the on-premises server and AWS by using Microsoft SQL Server Enterprise with Always On availability groups.

- B. Configure a warm standby Amazon RDS for SQL Server database on AWS. Configure AWS Database Migration Service (AWS DMS) to use change data capture (CDC).

- C. Use AWS Elastic Disaster Recovery congured to replicate disk changes to AWS as a pilot light.

- D. Use third-party backup software to capture backups every night. Store a secondary set of backups in Amazon S3.

**Correct:** C
**Why:** AWS Elastic Disaster Recovery provides near‑continuous replication (low RPO) and quick spin‑up (RTO ≤ 60 min) at low standby cost.

**Incorrect:**
- A: SQL Server Enterprise AOAG is costly.
- B: Warm standby RDS incurs ongoing cost and may not meet RPO.
- D: Nightly backups miss the 30‑second RPO.


---

---

### Question #541

A company wants to build a web application on AWS. Client access requests to the website are not predictable and can be idle for a long time. Only customers who have paid a subscription fee can have the ability to sign in and use the web application. Which combination of steps will meet these requirements MOST cost-effectively? (Choose three.)

- A. Create an AWS Lambda function to retrieve user information from Amazon DynamoDB. Create an Amazon API Gateway endpoint to accept RESTful APIs. Send the API calls to the Lambda function.

- B. Create an Amazon Elastic Container Service (Amazon ECS) service behind an Application Load Balancer to retrieve user information from Amazon RDS. Create an Amazon API Gateway endpoint to accept RESTful APIs. Send the API calls to the Lambda function.

- C. Create an Amazon Cognito user pool to authenticate users.

- D. Create an Amazon Cognito identity pool to authenticate users.

E. Use AWS Amplify to serve the frontend web content with HTML, CSS, and JS. Use an integrated Amazon CloudFront configuration.

F. Use Amazon S3 static web hosting with PHP, CSS, and JS. Use Amazon CloudFront to serve the frontend web content.

**Correct:** A, C, E
**Why:** Serverless API (API Gateway → Lambda) is cost‑effective for spiky/idle loads; Cognito user pool handles subscription auth; Amplify hosts frontend with integrated CloudFront.

**Incorrect:**
- B: ECS/EC2 PHP or identity pools are unnecessary here.
- D: ECS/EC2 PHP or identity pools are unnecessary here.
- F: ECS/EC2 PHP or identity pools are unnecessary here.


---

---

### Question #542

A media company uses an Amazon CloudFront distribution to deliver content over the internet. The company wants only premium customers to have access to the media streams and file content. The company stores all content in an Amazon S3 bucket. The company also delivers content on demand to customers for a specic purpose, such as movie rentals or music downloads. Which solution will meet these requirements?

- A. Generate and provide S3 signed cookies to premium customers.

- B. Generate and provide CloudFront signed URLs to premium customers.

- C. Use origin access control (OAC) to limit the access of non-premium customers.

- D. Generate and activate eld-level encryption to block non-premium customers.

**Correct:** B
**Why:** CloudFront signed URLs restrict access to premium, time‑limited content from the S3 origin.

**Incorrect:**
- A: S3 signed cookies are not used with CloudFront for this scenario.
- C: OAC/encryption do not implement premium gating.
- D: OAC/encryption do not implement premium gating.


---

---

### Question #545

A company wants to direct its users to a backup static error page if the company's primary website is unavailable. The primary website's DNS records are hosted in Amazon Route 53. The domain is pointing to an Application Load Balancer (ALB). The company needs a solution that minimizes changes and infrastructure overhead. Which solution will meet these requirements?

- A. Update the Route 53 records to use a latency routing policy. Add a static error page that is hosted in an Amazon S3 bucket to the records so that the trac is sent to the most responsive endpoints.

- B. Set up a Route 53 active-passive failover configuration. Direct trac to a static error page that is hosted in an Amazon S3 bucket when Route 53 health checks determine that the ALB endpoint is unhealthy.

- C. Set up a Route 53 active-active configuration with the ALB and an Amazon EC2 instance that hosts a static error page as endpoints. Configure Route 53 to send requests to the instance only if the health checks fail for the ALB.

- D. Update the Route 53 records to use a multivalue answer routing policy. Create a health check. Direct trac to the website if the health check passes. Direct trac to a static error page that is hosted in Amazon S3 if the health check does not pass.

**Correct:** B
**Why:** Route 53 active‑passive failover to an S3 static error page when ALB health checks fail—minimal infra/changes.

**Incorrect:**
- A: Latency/multivalue policies don’t provide ALB health‑based failover to S3.
- C: Maintaining EC2 for a static page adds ops.
- D: Latency/multivalue policies don’t provide ALB health‑based failover to S3.


---

---

### Question #547

A company has data collection sensors at different locations. The data collection sensors stream a high volume of data to the company. The company wants to design a platform on AWS to ingest and process high-volume streaming data. The solution must be scalable and support data collection in near real time. The company must store the data in Amazon S3 for future reporting. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use Amazon Kinesis Data Firehose to deliver streaming data to Amazon S3.

- B. Use AWS Glue to deliver streaming data to Amazon S3.

- C. Use AWS Lambda to deliver streaming data and store the data to Amazon S3.

- D. Use AWS Database Migration Service (AWS DMS) to deliver streaming data to Amazon S3.

**Correct:** A
**Why:** Kinesis Data Firehose ingests high‑volume streams and delivers to S3 with near real‑time buffering and minimal ops.

**Incorrect:**
- B: Glue/Lambda/DMS are not the best fit for streaming ingestion at scale.
- C: Glue/Lambda/DMS are not the best fit for streaming ingestion at scale.
- D: Glue/Lambda/DMS are not the best fit for streaming ingestion at scale.


---

---

### Question #551

A company has a nancial application that produces reports. The reports average 50 KB in size and are stored in Amazon S3. The reports are frequently accessed during the first week after production and must be stored for several years. The reports must be retrievable within 6 hours. Which solution meets these requirements MOST cost-effectively?

- A. Use S3 Standard. Use an S3 Lifecycle rule to transition the reports to S3 Glacier after 7 days.

- B. Use S3 Standard. Use an S3 Lifecycle rule to transition the reports to S3 Standard-Infrequent Access (S3 Standard-IA) after 7 days.

- C. Use S3 Intelligent-Tiering. Configure S3 Intelligent-Tiering to transition the reports to S3 Standard-Infrequent Access (S3 Standard-IA) and S3 Glacier.

- D. Use S3 Standard. Use an S3 Lifecycle rule to transition the reports to S3 Glacier Deep Archive after 7 days.

**Correct:** A
**Why:** S3 Standard for the first week meets frequent access, then transition to S3 Glacier Flexible Retrieval (formerly Glacier) after 7 days keeps costs low and still meets the 6-hour retrieval SLA.

**Incorrect:**
- B: S3 Standard-IA after 7 days is more expensive long-term than Glacier for multi-year retention when 6-hour retrieval is acceptable.
- C: Intelligent-Tiering adds per-object monitoring overhead and is unnecessary with known access pattern (hot for a week, then cold for years).
- D: Glacier Deep Archive retrieval is typically 12 hours+, which violates the 6-hour retrieval requirement.


---

---

### Question #553

A solutions architect needs to review a company's Amazon S3 buckets to discover personally identiable information (PII). The company stores the PII data in the us-east-1 Region and us-west-2 Region. Which solution will meet these requirements with the LEAST operational overhead?

- A. Configure Amazon Macie in each Region. Create a job to analyze the data that is in Amazon S3.

- B. Configure AWS Security Hub for all Regions. Create an AWS Cong rule to analyze the data that is in Amazon S3.

- C. Configure Amazon Inspector to analyze the data that is in Amazon S3.

- D. Configure Amazon GuardDuty to analyze the data that is in Amazon S3.

**Correct:** A
**Why:** Amazon Macie natively discovers and classifies PII in S3, per Region, with minimal operational overhead.

**Incorrect:**
- B: Security Hub aggregates findings; it does not scan S3 data for PII.
- C: Amazon Inspector assesses EC2/ECR; not for S3 PII discovery.
- D: GuardDuty detects threats; it does not inspect S3 object contents for PII.


---

---

### Question #557

A solutions architect manages an analytics application. The application stores large amounts of semistructured data in an Amazon S3 bucket. The solutions architect wants to use parallel data processing to process the data more quickly. The solutions architect also wants to use information that is stored in an Amazon Redshift database to enrich the data. Which solution will meet these requirements?

- A. Use Amazon Athena to process the S3 data. Use AWS Glue with the Amazon Redshift data to enrich the S3 data.

- B. Use Amazon EMR to process the S3 data. Use Amazon EMR with the Amazon Redshift data to enrich the S3 data.

- C. Use Amazon EMR to process the S3 data. Use Amazon Kinesis Data Streams to move the S3 data into Amazon Redshift so that the data can be enriched.

- D. Use AWS Glue to process the S3 data. Use AWS Lake Formation with the Amazon Redshift data to enrich the S3 data.

**Correct:** B
**Why:** Amazon EMR supports large-scale parallel processing on S3 data and can integrate with Amazon Redshift to enrich S3 data with Redshift data (e.g., via Spark connectors/JDBC).

**Incorrect:**
- A: Athena + Glue can join, but enriching with Redshift data is more direct and scalable with EMR compute.
- C: Kinesis Data Streams is for streaming ingestion, not enriching S3 batch data with Redshift.
- D: Glue can process S3 data, but enrichment specifically with Redshift is better served by EMR’s flexible engines.


---

---

### Question #564

A company is building an ecommerce application and needs to store sensitive customer information. The company needs to give customers the ability to complete purchase transactions on the website. The company also needs to ensure that sensitive customer data is protected, even from database administrators. Which solution meets these requirements?

- A. Store sensitive data in an Amazon Elastic Block Store (Amazon EBS) volume. Use EBS encryption to encrypt the data. Use an IAM instance role to restrict access.

- B. Store sensitive data in Amazon RDS for MySQL. Use AWS Key Management Service (AWS KMS) client-side encryption to encrypt the data.

- C. Store sensitive data in Amazon S3. Use AWS Key Management Service (AWS KMS) server-side encryption to encrypt the data. Use S3 bucket policies to restrict access.

- D. Store sensitive data in Amazon FSx for Windows Server. Mount the file share on application servers. Use Windows file permissions to restrict access.

**Correct:** B
**Why:** To prevent even DBAs from accessing sensitive data, encrypt at the application/client layer before storage (client-side KMS encryption) and store ciphertext in the database.

**Incorrect:**
- A: EBS encryption protects at the volume level; DBAs can still read decrypted data via the DB engine.
- C: S3 is not the right backend for transactional ecommerce data; SSE-KMS also does not prevent privileged DB access.
- D: FSx + Windows permissions doesn’t address app-level transactional storage nor protect from DBAs.


---

---

### Question #566

A company runs multiple Amazon EC2 Linux instances in a VPC across two Availability Zones. The instances host applications that use a hierarchical directory structure. The applications need to read and write rapidly and concurrently to shared storage. What should a solutions architect do to meet these requirements?

- A. Create an Amazon S3 bucket. Allow access from all the EC2 instances in the VPC.

- B. Create an Amazon Elastic File System (Amazon EFS) file system. Mount the EFS file system from each EC2 instance.

- C. Create a file system on a Provisioned IOPS SSD (io2) Amazon Elastic Block Store (Amazon EBS) volume. Attach the EBS volume to all the EC2 instances.

- D. Create file systems on Amazon Elastic Block Store (Amazon EBS) volumes that are attached to each EC2 instance. Synchronize the EBS volumes across the different EC2 instances.

**Correct:** B
**Why:** Amazon EFS provides shared POSIX file system semantics, high concurrency, and multi-AZ access for EC2 instances; ideal for hierarchical directory structures and concurrent read/write.

**Incorrect:**
- A: S3 is object storage, not a shared POSIX file system.
- C: EBS volumes cannot be concurrently attached to multiple instances across AZs for shared writes.
- D: EBS volumes cannot be concurrently attached to multiple instances across AZs for shared writes.


---

---

### Question #567

A solutions architect is designing a workload that will store hourly energy consumption by business tenants in a building. The sensors will feed a database through HTTP requests that will add up usage for each tenant. The solutions architect must use managed services when possible. The workload will receive more features in the future as the solutions architect adds independent components. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use Amazon API Gateway with AWS Lambda functions to receive the data from the sensors, process the data, and store the data in an Amazon DynamoDB table.

- B. Use an Elastic Load Balancer that is supported by an Auto Scaling group of Amazon EC2 instances to receive and process the data from the sensors. Use an Amazon S3 bucket to store the processed data.

- C. Use Amazon API Gateway with AWS Lambda functions to receive the data from the sensors, process the data, and store the data in a Microsoft SQL Server Express database on an Amazon EC2 instance.

- D. Use an Elastic Load Balancer that is supported by an Auto Scaling group of Amazon EC2 instances to receive and process the data from the sensors. Use an Amazon Elastic File System (Amazon EFS) shared file system to store the processed data.

**Correct:** A
**Why:** API Gateway + Lambda gives a fully managed, serverless, event-driven ingestion and processing path with low overhead and easy future extensibility; store results in DynamoDB.

**Incorrect:**
- B: ELB + EC2 adds operational burden and is not necessary for simple HTTP ingest.
- C: EC2-hosted SQL Server Express increases ops overhead and reduces elasticity.
- D: ELB + EC2 adds operational burden and is not necessary for simple HTTP ingest.


---

---

### Question #568

A solutions architect is designing the storage architecture for a new web application used for storing and viewing engineering drawings. All application components will be deployed on the AWS infrastructure. The application design must support caching to minimize the amount of time that users wait for the engineering drawings to load. The application must be able to store petabytes of data. Which combination of storage and caching should the solutions architect use?

- A. Amazon S3 with Amazon CloudFront

- B. Amazon S3 Glacier with Amazon ElastiCache

- C. Amazon Elastic Block Store (Amazon EBS) volumes with Amazon CloudFront

- D. AWS Storage Gateway with Amazon ElastiCache

**Correct:** A
**Why:** Amazon S3 scales to petabytes and serves as durable storage. CloudFront provides global edge caching to reduce latency loading large drawings.

**Incorrect:**
- B: Glacier is archival and not suited for frequent/interactive access.
- C: EBS is block storage tied to instances; not optimal for petabyte-scale/serving globally.
- D: Storage Gateway is for hybrid integrations; not needed when fully on AWS.


---

---

### Question #583

A company has 5 PB of archived data on physical tapes. The company needs to preserve the data on the tapes for another 10 years for compliance purposes. The company wants to migrate to AWS in the next 6 months. The data center that stores the tapes has a 1 Gbps uplink internet connectivity. Which solution will meet these requirements MOST cost-effectively?

- A. Read the data from the tapes on premises. Stage the data in a local NFS storage. Use AWS DataSync to migrate the data to Amazon S3 Glacier Flexible Retrieval.

- B. Use an on-premises backup application to read the data from the tapes and to write directly to Amazon S3 Glacier Deep Archive.

- C. Order multiple AWS Snowball devices that have Tape Gateway. Copy the physical tapes to virtual tapes in Snowball. Ship the Snowball devices to AWS. Create a lifecycle policy to move the tapes to Amazon S3 Glacier Deep Archive.

- D. Configure an on-premises Tape Gateway. Create virtual tapes in the AWS Cloud. Use backup software to copy the physical tape to the virtual tape.

**Correct:** C
**Why:** Use Snowball devices with Tape Gateway to migrate physical tapes to virtual tapes, then lifecycle to S3 Glacier Deep Archive for long-term retention and low cost.

**Incorrect:**
- A: 1 Gbps link and 5 PB over 6 months is impractical and costly.
- B: Direct write to Deep Archive over the network is too slow for 5 PB.
- D: On-premises Tape Gateway alone over 1 Gbps is time‑prohibitive for 5 PB.


---

---

### Question #587

A company is designing a solution to capture customer activity in different web applications to process analytics and make predictions. Customer activity in the web applications is unpredictable and can increase suddenly. The company requires a solution that integrates with other web applications. The solution must include an authorization step for security purposes. Which solution will meet these requirements?

- A. Configure a Gateway Load Balancer (GWLB) in front of an Amazon Elastic Container Service (Amazon ECS) container instance that stores the information that the company receives in an Amazon Elastic File System (Amazon EFS) file system. Authorization is resolved at the GWLB.

- B. Configure an Amazon API Gateway endpoint in front of an Amazon Kinesis data stream that stores the information that the company receives in an Amazon S3 bucket. Use an AWS Lambda function to resolve authorization.

- C. Configure an Amazon API Gateway endpoint in front of an Amazon Kinesis Data Firehose that stores the information that the company receives in an Amazon S3 bucket. Use an API Gateway Lambda authorizer to resolve authorization.

- D. Configure a Gateway Load Balancer (GWLB) in front of an Amazon Elastic Container Service (Amazon ECS) container instance that stores the information that the company receives on an Amazon Elastic File System (Amazon EFS) file system. Use an AWS Lambda function to resolve authorization.

**Correct:** C
**Why:** API Gateway with a Lambda authorizer provides auth. Kinesis Data Firehose scales ingestion and delivers to S3 with minimal ops overhead.

**Incorrect:**
- A: GWLB + ECS introduces heavy ops complexity for simple event ingestion.
- B: API Gateway to Kinesis Data Streams is viable but requires more scaling/consumer management than Firehose for S3 delivery.
- D: GWLB + ECS introduces heavy ops complexity for simple event ingestion.


---

---

### Question #588

An ecommerce company wants a disaster recovery solution for its Amazon RDS DB instances that run Microsoft SQL Server Enterprise Edition. The company's current recovery point objective (RPO) and recovery time objective (RTO) are 24 hours. Which solution will meet these requirements MOST cost-effectively?

- A. Create a cross-Region read replica and promote the read replica to the primary instance.

- B. Use AWS Database Migration Service (AWS DMS) to create RDS cross-Region replication.

- C. Use cross-Region replication every 24 hours to copy native backups to an Amazon S3 bucket.

- D. Copy automatic snapshots to another Region every 24 hours.

**Correct:** D
**Why:** Copy automatic snapshots cross‑Region every 24 hours to meet 24‑hour RPO/RTO at the lowest cost.

**Incorrect:**
- A: Cross‑Region read replica costs more and is overkill for 24‑hour objectives.
- B: DMS is for migration/replication at higher cost/complexity.
- C: Native backups to S3 and custom replication add ops overhead.


---

---

### Question #590

A company migrated a MySQL database from the company's on-premises data center to an Amazon RDS for MySQL DB instance. The company sized the RDS DB instance to meet the company's average daily workload. Once a month, the database performs slowly when the company runs queries for a report. The company wants to have the ability to run reports and maintain the performance of the daily workloads. Which solution will meet these requirements?

- A. Create a read replica of the database. Direct the queries to the read replica.

- B. Create a backup of the database. Restore the backup to another DB instance. Direct the queries to the new database.

- C. Export the data to Amazon S3. Use Amazon Athena to query the S3 bucket.

- D. Resize the DB instance to accommodate the additional workload.

**Correct:** A
**Why:** A read replica offloads reporting queries without impacting primary OLTP performance.

**Incorrect:**
- B: Restoring a backup is slower and manual.
- C: Athena on S3 requires exports and a different access pattern.
- D: Upsizing increases cost and still mixes workloads on one instance.


---

---

### Question #592

A company uses AWS and sells access to copyrighted images. The company’s global customer base needs to be able to access these images quickly. The company must deny access to users from specic countries. The company wants to minimize costs as much as possible. Which solution will meet these requirements?

- A. Use Amazon S3 to store the images. Turn on multi-factor authentication (MFA) and public bucket access. Provide customers with a link to the S3 bucket.

- B. Use Amazon S3 to store the images. Create an IAM user for each customer. Add the users to a group that has permission to access the S3 bucket.

- C. Use Amazon EC2 instances that are behind Application Load Balancers (ALBs) to store the images. Deploy the instances only in the countries the company services. Provide customers with links to the ALBs for their specic country's instances.

- D. Use Amazon S3 to store the images. Use Amazon CloudFront to distribute the images with geographic restrictions. Provide a signed URL for each customer to access the data in CloudFront.

**Correct:** D
**Why:** S3 with CloudFront provides low‑latency global delivery. Geo restrictions and signed URLs enforce country blocks and per‑customer access.

**Incorrect:**
- A: Public buckets or per‑user IAM are insecure or operationally heavy.
- B: Public buckets or per‑user IAM are insecure or operationally heavy.
- C: EC2 + ALB for serving files is costly and complex.


---

---

### Question #598

A research company uses on-premises devices to generate data for analysis. The company wants to use the AWS Cloud to analyze the data. The devices generate .csv files and support writing the data to an SMB file share. Company analysts must be able to use SQL commands to query the data. The analysts will run queries periodically throughout the day. Which combination of steps will meet these requirements MOST cost-effectively? (Choose three.)

- A. Deploy an AWS Storage Gateway on premises in Amazon S3 File Gateway mode.

- B. Deploy an AWS Storage Gateway on premises in Amazon FSx File Gateway made.

- C. Set up an AWS Glue crawler to create a table based on the data that is in Amazon S3.

- D. Set up an Amazon EMR cluster with EMR File System (EMRFS) to query the data that is in Amazon S3. Provide access to analysts.

E. Set up an Amazon Redshift cluster to query the data that is in Amazon S3. Provide access to analysts.

F. Setup Amazon Athena to query the data that is in Amazon S3. Provide access to analysts.

**Correct:** A, C, F
**Why:** Use S3 File Gateway to land CSVs in S3 over SMB, crawl with Glue to build schema, and query with Athena using SQL on demand.

**Incorrect:**
- B: FSx File Gateway presents FSx, not S3.
- D: EMR/Redshift add cost/ops for periodic ad‑hoc queries.
- E: EMR/Redshift add cost/ops for periodic ad‑hoc queries.


---

---

### Question #601

A company runs its critical database on an Amazon RDS for PostgreSQL DB instance. The company wants to migrate to Amazon Aurora PostgreSQL with minimal downtime and data loss. Which solution will meet these requirements with the LEAST operational overhead?

- A. Create a DB snapshot of the RDS for PostgreSQL DB instance to populate a new Aurora PostgreSQL DB cluster.

- B. Create an Aurora read replica of the RDS for PostgreSQL DB instance. Promote the Aurora read replicate to a new Aurora PostgreSQL DB cluster.

- C. Use data import from Amazon S3 to migrate the database to an Aurora PostgreSQL DB cluster.

- D. Use the pg_dump utility to back up the RDS for PostgreSQL database. Restore the backup to a new Aurora PostgreSQL DB cluster.

**Correct:** B
**Why:** Create an Aurora read replica of RDS for PostgreSQL, then promote. This minimizes downtime and operational effort.

**Incorrect:**
- A: Snapshot/restore incurs longer downtime.
- C: S3 import/pg_dump are manual and operationally heavy.
- D: S3 import/pg_dump are manual and operationally heavy.


---

---

### Question #603

A company recently migrated to the AWS Cloud. The company wants a serverless solution for large-scale parallel on-demand processing of a semistructured dataset. The data consists of logs, media files, sales transactions, and IoT sensor data that is stored in Amazon S3. The company wants the solution to process thousands of items in the dataset in parallel. Which solution will meet these requirements with the MOST operational eciency?

- A. Use the AWS Step Functions Map state in Inline mode to process the data in parallel.

- B. Use the AWS Step Functions Map state in Distributed mode to process the data in parallel.

- C. Use AWS Glue to process the data in parallel.

- D. Use several AWS Lambda functions to process the data in parallel.

**Correct:** B
**Why:** Step Functions Distributed Map processes thousands to millions of items in parallel serverlessly with high efficiency.

**Incorrect:**
- A: Inline Map is limited for large-scale fan‑out.
- C: Glue/Lambda alone are less scalable or require orchestration for very large parallelism.
- D: Glue/Lambda alone are less scalable or require orchestration for very large parallelism.


---

---

### Question #604

A company will migrate 10 PB of data to Amazon S3 in 6 weeks. The current data center has a 500 Mbps uplink to the internet. Other on-premises applications share the uplink. The company can use 80% of the internet bandwidth for this one-time migration task. Which solution will meet these requirements?

- A. Configure AWS DataSync to migrate the data to Amazon S3 and to automatically verify the data.

- B. Use rsync to transfer the data directly to Amazon S3.

- C. Use the AWS CLI and multiple copy processes to send the data directly to Amazon S3.

- D. Order multiple AWS Snowball devices. Copy the data to the devices. Send the devices to AWS to copy the data to Amazon S3.

**Correct:** D
**Why:** With 500 Mbps and shared bandwidth, 10 PB in 6 weeks is infeasible over network; Snowball provides the needed data transfer speed.

**Incorrect:**
- A: Network transfer would not meet the timeline and could disrupt other apps.
- B: Network transfer would not meet the timeline and could disrupt other apps.
- C: Network transfer would not meet the timeline and could disrupt other apps.


---

---

### Question #605

A company has several on-premises Internet Small Computer Systems Interface (ISCSI) network storage servers. The company wants to reduce the number of these servers by moving to the AWS Cloud. A solutions architect must provide low-latency access to frequently used data and reduce the dependency on on-premises servers with a minimal number of infrastructure changes. Which solution will meet these requirements?

- A. Deploy an Amazon S3 File Gateway.

- B. Deploy Amazon Elastic Block Store (Amazon EBS) storage with backups to Amazon S3.

- C. Deploy an AWS Storage Gateway volume gateway that is congured with stored volumes.

- D. Deploy an AWS Storage Gateway volume gateway that is congured with cached volumes.

**Correct:** D
**Why:** Volume Gateway cached volumes present iSCSI locally while storing primary data in S3, reducing on‑prem dependency and providing low‑latency cache access.

**Incorrect:**
- A: S3 File Gateway is for SMB/NFS files, not iSCSI block.
- B: EBS is in‑cloud only and not iSCSI to on‑prem.
- C: Stored volumes keep primary data on‑prem.


---

---

### Question #606

A solutions architect is designing an application that will allow business users to upload objects to Amazon S3. The solution needs to maximize object durability. Objects also must be readily available at any time and for any length of time. Users will access objects frequently within the first 30 days after the objects are uploaded, but users are much less likely to access objects that are older than 30 days. Which solution meets these requirements MOST cost-effectively?

- A. Store all the objects in S3 Standard with an S3 Lifecycle rule to transition the objects to S3 Glacier after 30 days.

- B. Store all the objects in S3 Standard with an S3 Lifecycle rule to transition the objects to S3 Standard-Infrequent Access (S3 Standard-IA) after 30 days.

- C. Store all the objects in S3 Standard with an S3 Lifecycle rule to transition the objects to S3 One Zone-Infrequent Access (S3 One Zone-IA) after 30 days.

- D. Store all the objects in S3 Intelligent-Tiering with an S3 Lifecycle rule to transition the objects to S3 Standard-Infrequent Access (S3 Standard-IA) after 30 days.

**Correct:** B
**Why:** S3 Standard for first 30 days, then transition to S3 Standard‑IA keeps data highly durable/available at lower cost with a known access drop.

**Incorrect:**
- A: Glacier retrieval is not "readily available at any time."
- C: One Zone‑IA reduces availability/durability compared to multi‑AZ.
- D: Intelligent‑Tiering + lifecycle to IA is redundant and unnecessary.


---

---

### Question #607

A company has migrated a two-tier application from its on-premises data center to the AWS Cloud. The data tier is a Multi-AZ deployment of Amazon RDS for Oracle with 12 TB of General Purpose SSD Amazon Elastic Block Store (Amazon EBS) storage. The application is designed to process and store documents in the database as binary large objects (blobs) with an average document size of 6 MB. The database size has grown over time, reducing the performance and increasing the cost of storage. The company must improve the database performance and needs a solution that is highly available and resilient. Which solution will meet these requirements MOST cost-effectively?

- A. Reduce the RDS DB instance size. Increase the storage capacity to 24 TiB. Change the storage type to Magnetic.

- B. Increase the RDS DB instance size. Increase the storage capacity to 24 TiChange the storage type to Provisioned IOPS.

- C. Create an Amazon S3 bucket. Update the application to store documents in the S3 bucket. Store the object metadata in the existing database.

- D. Create an Amazon DynamoDB table. Update the application to use DynamoDB. Use AWS Database Migration Service (AWS DMS) to migrate data from the Oracle database to DynamoDB.

**Correct:** C
**Why:** Offload large blobs to S3 and keep only metadata in RDS to reduce DB size/cost and improve performance.

**Incorrect:**
- A: Increasing size/IOPS increases cost and doesn’t address bloated storage from blobs.
- B: Increasing size/IOPS increases cost and doesn’t address bloated storage from blobs.
- D: DynamoDB migration is unnecessary and higher effort.


---

---

### Question #609

A company is building a data analysis platform on AWS by using AWS Lake Formation. The platform will ingest data from different sources such as Amazon S3 and Amazon RDS. The company needs a secure solution to prevent access to portions of the data that contain sensitive information. Which solution will meet these requirements with the LEAST operational overhead?

- A. Create an IAM role that includes permissions to access Lake Formation tables.

- B. Create data lters to implement row-level security and cell-level security.

- C. Create an AWS Lambda function that removes sensitive information before Lake Formation ingests the data.

- D. Create an AWS Lambda function that periodically queries and removes sensitive information from Lake Formation tables.

**Correct:** B
**Why:** Lake Formation row‑level and cell‑level filters natively enforce fine‑grained access to sensitive data with minimal ops.

**Incorrect:**
- A: IAM role alone cannot implement row/cell security at the table data level.
- C: Lambda preprocessing/postprocessing adds complexity and is brittle.
- D: Lambda preprocessing/postprocessing adds complexity and is brittle.


---

---

### Question #610

A company deploys Amazon EC2 instances that run in a VPC. The EC2 instances load source data into Amazon S3 buckets so that the data can be processed in the future. According to compliance laws, the data must not be transmitted over the public internet. Servers in the company's on- premises data center will consume the output from an application that runs on the EC2 instances. Which solution will meet these requirements?

- A. Deploy an interface VPC endpoint for Amazon EC2. Create an AWS Site-to-Site VPN connection between the company and the VPC.

- B. Deploy a gateway VPC endpoint for Amazon S3. Set up an AWS Direct Connect connection between the on-premises network and the VPC.

- C. Set up an AWS Transit Gateway connection from the VPC to the S3 buckets. Create an AWS Site-to-Site VPN connection between the company and the VPC.

- D. Set up proxy EC2 instances that have routes to NAT gateways. Configure the proxy EC2 instances to fetch S3 data and feed the application instances.

**Correct:** B
**Why:** Use an S3 gateway endpoint for private access from EC2 to S3 and Direct Connect for private on‑prem access to VPC‑hosted outputs.

**Incorrect:**
- A: Do not provide private S3 access end‑to‑end without traversing the internet.
- C: Do not provide private S3 access end‑to‑end without traversing the internet.
- D: Do not provide private S3 access end‑to‑end without traversing the internet.


---

---

### Question #612

A company has an application that runs on Amazon EC2 instances in a private subnet. The application needs to process sensitive information from an Amazon S3 bucket. The application must not use the internet to connect to the S3 bucket. Which solution will meet these requirements?

- A. Configure an internet gateway. Update the S3 bucket policy to allow access from the internet gateway. Update the application to use the new internet gateway.

- B. Configure a VPN connection. Update the S3 bucket policy to allow access from the VPN connection. Update the application to use the new VPN connection.

- C. Configure a NAT gateway. Update the S3 bucket policy to allow access from the NAT gateway. Update the application to use the new NAT gateway.

- D. Configure a VPC endpoint. Update the S3 bucket policy to allow access from the VPC endpoint. Update the application to use the new VPC endpoint.

**Correct:** D
**Why:** Use an S3 VPC endpoint and bucket policy to allow access only via the endpoint. No internet path is used.

**Incorrect:**
- A: These traverse the internet or are unnecessary.
- B: These traverse the internet or are unnecessary.
- C: These traverse the internet or are unnecessary.


---

---

### Question #616

A company has deployed its newest product on AWS. The product runs in an Auto Scaling group behind a Network Load Balancer. The company stores the product’s objects in an Amazon S3 bucket. The company recently experienced malicious attacks against its systems. The company needs a solution that continuously monitors for malicious activity in the AWS account, workloads, and access patterns to the S3 bucket. The solution must also report suspicious activity and display the information on a dashboard. Which solution will meet these requirements?

- A. Configure Amazon Macie to monitor and report ndings to AWS Cong.

- B. Configure Amazon Inspector to monitor and report ndings to AWS CloudTrail.

- C. Configure Amazon GuardDuty to monitor and report ndings to AWS Security Hub.

- D. Configure AWS Cong to monitor and report ndings to Amazon EventBridge.

**Correct:** C
**Why:** GuardDuty continuously monitors account, workload, and S3 access for threats; Security Hub aggregates and dashboards findings.

**Incorrect:**
- A: Macie focuses on sensitive data discovery, not threat detection.
- B: Inspector is for vulnerability assessment, not S3 access/threat patterns.
- D: Config tracks resource configuration, not threat activity.


---

---

### Question #617

A company wants to migrate an on-premises data center to AWS. The data center hosts a storage server that stores data in an NFS-based file system. The storage server holds 200 GB of data. The company needs to migrate the data without interruption to existing services. Multiple resources in AWS must be able to access the data by using the NFS protocol. Which combination of steps will meet these requirements MOST cost-effectively? (Choose two.)

- A. Create an Amazon FSx for Lustre file system.

- B. Create an Amazon Elastic File System (Amazon EFS) file system.

- C. Create an Amazon S3 bucket to receive the data.

- D. Manually use an operating system copy command to push the data into the AWS destination.

E. Install an AWS DataSync agent in the on-premises data center. Use a DataSync task between the on-premises location and AWS.

**Correct:** B, E
**Why:** Create an EFS file system for NFS access and use DataSync to copy data from on‑prem to EFS without downtime.

**Incorrect:**
- A: Lustre/S3/Manual copy do not meet NFS access and minimal‑ops goals together.
- C: Lustre/S3/Manual copy do not meet NFS access and minimal‑ops goals together.
- D: Lustre/S3/Manual copy do not meet NFS access and minimal‑ops goals together.


---

---

### Question #621

An online photo-sharing company stores its photos in an Amazon S3 bucket that exists in the us-west-1 Region. The company needs to store a copy of all new photos in the us-east-1 Region. Which solution will meet this requirement with the LEAST operational effort?

- A. Create a second S3 bucket in us-east-1. Use S3 Cross-Region Replication to copy photos from the existing S3 bucket to the second S3 bucket.

- B. Create a cross-origin resource sharing (CORS) configuration of the existing S3 bucket. Specify us-east-1 in the CORS rule's AllowedOrigin element.

- C. Create a second S3 bucket in us-east-1 across multiple Availability Zones. Create an S3 Lifecycle rule to save photos into the second S3 bucket.

- D. Create a second S3 bucket in us-east-1. Configure S3 event notications on object creation and update events to invoke an AWS Lambda function to copy photos from the existing S3 bucket to the second S3 bucket.

**Correct:** A
**Why:** S3 Cross‑Region Replication automatically replicates new objects from us‑west‑1 to us‑east‑1 with minimal ops.

**Incorrect:**
- B: CORS is unrelated to replication.
- C: Lifecycle rules do not copy between buckets/Regions.
- D: Lambda copy works but adds unnecessary ops and cost.


---

---

### Question #622

A company is creating a new web application for its subscribers. The application will consist of a static single page and a persistent database layer. The application will have millions of users for 4 hours in the morning, but the application will have only a few thousand users during the rest of the day. The company's data architects have requested the ability to rapidly evolve their schema. Which solutions will meet these requirements and provide the MOST scalability? (Choose two.)

- A. Deploy Amazon DynamoDB as the database solution. Provision on-demand capacity.

- B. Deploy Amazon Aurora as the database solution. Choose the serverless DB engine mode.

- C. Deploy Amazon DynamoDB as the database solution. Ensure that DynamoDB auto scaling is enabled.

- D. Deploy the static content into an Amazon S3 bucket. Provision an Amazon CloudFront distribution with the S3 bucket as the origin.

E. Deploy the web servers for static content across a eet of Amazon EC2 instances in Auto Scaling groups. Configure the instances to periodically refresh the content from an Amazon Elastic File System (Amazon EFS) volume.

**Correct:** A, D
**Why:** DynamoDB (on‑demand) offers massive, bursty scalability with schema flexibility. S3 + CloudFront serves static content at scale.

**Incorrect:**
- B: Aurora Serverless is more ops overhead and cost for brief heavy peaks compared to DynamoDB.
- C: Auto scaling on provisioned may lag and require tuning vs. on‑demand.
- E: EC2 fleet for static content is unnecessary.


---

---

### Question #626

A company stores its data on premises. The amount of data is growing beyond the company's available capacity. The company wants to migrate its data from the on-premises location to an Amazon S3 bucket. The company needs a solution that will automatically validate the integrity of the data after the transfer. Which solution will meet these requirements?

- A. Order an AWS Snowball Edge device. Configure the Snowball Edge device to perform the online data transfer to an S3 bucket

- B. Deploy an AWS DataSync agent on premises. Configure the DataSync agent to perform the online data transfer to an S3 bucket.

- C. Create an Amazon S3 File Gateway on premises Configure the S3 File Gateway to perform the online data transfer to an S3 bucket

- D. Configure an accelerator in Amazon S3 Transfer Acceleration on premises. Configure the accelerator to perform the online data transfer to an S3 bucket.

**Correct:** B
**Why:** AWS DataSync performs online transfers to S3 with built‑in integrity verification.

**Incorrect:**
- A: Snowball Edge is offline and not needed here.
- C: S3 File Gateway presents SMB/NFS, but DataSync better automates validation at scale.
- D: S3 Transfer Acceleration is for internet uploads, not integrity‑checked migrations.


---

---

### Question #628

A global company runs its applications in multiple AWS accounts in AWS Organizations. The company's applications use multipart uploads to upload data to multiple Amazon S3 buckets across AWS Regions. The company wants to report on incomplete multipart uploads for cost compliance purposes. Which solution will meet these requirements with the LEAST operational overhead?

- A. Configure AWS Cong with a rule to report the incomplete multipart upload object count.

- B. Create a service control policy (SCP) to report the incomplete multipart upload object count.

- C. Configure S3 Storage Lens to report the incomplete multipart upload object count.

- D. Create an S3 Multi-Region Access Point to report the incomplete multipart upload object count.

**Correct:** C
**Why:** S3 Storage Lens provides org‑wide visibility, including incomplete multipart upload metrics, with minimal ops.

**Incorrect:**
- A: Config/SCP/Multi‑Region Access Point do not report incomplete MPU counts.
- B: Config/SCP/Multi‑Region Access Point do not report incomplete MPU counts.
- D: Config/SCP/Multi‑Region Access Point do not report incomplete MPU counts.


---

---

### Question #632

A company is creating a new application that will store a large amount of data. The data will be analyzed hourly and will be modied by several Amazon EC2 Linux instances that are deployed across multiple Availability Zones. The needed amount of storage space will continue to grow for the next 6 months. Which storage solution should a solutions architect recommend to meet these requirements?

- A. Store the data in Amazon S3 Glacier. Update the S3 Glacier vault policy to allow access to the application instances.

- B. Store the data in an Amazon Elastic Block Store (Amazon EBS) volume. Mount the EBS volume on the application instances.

- C. Store the data in an Amazon Elastic File System (Amazon EFS) file system. Mount the file system on the application instances.

- D. Store the data in an Amazon Elastic Block Store (Amazon EBS) Provisioned IOPS volume shared between the application instances.

**Correct:** C
**Why:** Amazon EFS provides a shared, scalable file system across AZs, ideal for concurrent modification and hourly analytics.

**Incorrect:**
- A: Glacier is archival and slow.
- B: EBS can’t be shared across instances/AZs concurrently.
- D: EBS can’t be shared across instances/AZs concurrently.


---

---

### Question #633

A company manages an application that stores data on an Amazon RDS for PostgreSQL Multi-AZ DB instance. Increases in trac are causing performance problems. The company determines that database queries are the primary reason for the slow performance. What should a solutions architect do to improve the application's performance?

- A. Serve read trac from the Multi-AZ standby replica.

- B. Configure the DB instance to use Transfer Acceleration.

- C. Create a read replica from the source DB instance. Serve read trac from the read replica.

- D. Use Amazon Kinesis Data Firehose between the application and Amazon RDS to increase the concurrency of database requests.

**Correct:** C
**Why:** A read replica offloads read traffic from the primary RDS instance to improve performance.

**Incorrect:**
- A: Multi-AZ standby is not for reads.
- B: Transfer Acceleration is for S3, not RDS.
- D: Kinesis Data Firehose is irrelevant here.


---

---

### Question #634

A company collects 10 GB of telemetry data daily from various machines. The company stores the data in an Amazon S3 bucket in a source data account. The company has hired several consulting agencies to use this data for analysis. Each agency needs read access to the data for its analysts. The company must share the data from the source data account by choosing a solution that maximizes security and operational eciency. Which solution will meet these requirements?

- A. Configure S3 global tables to replicate data for each agency.

- B. Make the S3 bucket public for a limited time. Inform only the agencies.

- C. Configure cross-account access for the S3 bucket to the accounts that the agencies own.

- D. Set up an IAM user for each analyst in the source data account. Grant each user access to the S3 bucket.

**Correct:** C
**Why:** Configure cross‑account S3 bucket policies to grant read to agency accounts; it’s secure and low‑ops.

**Incorrect:**
- A: S3 global tables don’t exist; that’s DynamoDB.
- B: Public bucket is insecure.
- D: Per‑user IAM in source account is overhead and less secure.


---

---

### Question #635

A company uses Amazon FSx for NetApp ONTAP in its primary AWS Region for CIFS and NFS file shares. Applications that run on Amazon EC2 instances access the file shares. The company needs a storage disaster recovery (DR) solution in a secondary Region. The data that is replicated in the secondary Region needs to be accessed by using the same protocols as the primary Region. Which solution will meet these requirements with the LEAST operational overhead?

- A. Create an AWS Lambda function to copy the data to an Amazon S3 bucket. Replicate the S3 bucket to the secondary Region.

- B. Create a backup of the FSx for ONTAP volumes by using AWS Backup. Copy the volumes to the secondary Region. Create a new FSx for ONTAP instance from the backup.

- C. Create an FSx for ONTAP instance in the secondary Region. Use NetApp SnapMirror to replicate data from the primary Region to the secondary Region.

- D. Create an Amazon Elastic File System (Amazon EFS) volume. Migrate the current data to the volume. Replicate the volume to the secondary Region.

**Correct:** C
**Why:** FSx for NetApp ONTAP supports SMB/NFS; use SnapMirror for cross‑Region replication with the same protocols on failover.

**Incorrect:**
- A: Lambda + S3 is not a file service and loses protocol semantics.
- B: Backup/restore increases RTO and ops.
- D: EFS is NFS only, not SMB.


---

---

### Question #636

A development team is creating an event-based application that uses AWS Lambda functions. Events will be generated when files are added to an Amazon S3 bucket. The development team currently has Amazon Simple Notification Service (Amazon SNS) congured as the event target from Amazon S3. What should a solutions architect do to process the events from Amazon S3 in a scalable way?

- A. Create an SNS subscription that processes the event in Amazon Elastic Container Service (Amazon ECS) before the event runs in Lambda.

- B. Create an SNS subscription that processes the event in Amazon Elastic Kubernetes Service (Amazon EKS) before the event runs in Lambda

- C. Create an SNS subscription that sends the event to Amazon Simple Queue Service (Amazon SQS). Configure the SOS queue to trigger a Lambda function.

- D. Create an SNS subscription that sends the event to AWS Server Migration Service (AWS SMS). Configure the Lambda function to poll from the SMS event.

**Correct:** C
**Why:** Send SNS to SQS, then trigger Lambda from SQS for scalable, durable processing and smoothing spikes.

**Incorrect:**
- A: ECS/EKS add complexity; SNS->Lambda fanout directly may throttle; SQS adds buffering.
- B: ECS/EKS add complexity; SNS->Lambda fanout directly may throttle; SQS adds buffering.
- D: SMS is unrelated.


---

---

### Question #638

A company collects and shares research data with the company's employees all over the world. The company wants to collect and store the data in an Amazon S3 bucket and process the data in the AWS Cloud. The company will share the data with the company's employees. The company needs a secure solution in the AWS Cloud that minimizes operational overhead. Which solution will meet these requirements?

- A. Use an AWS Lambda function to create an S3 presigned URL. Instruct employees to use the URL.

- B. Create an IAM user for each employee. Create an IAM policy for each employee to allow S3 access. Instruct employees to use the AWS Management Console.

- C. Create an S3 File Gateway. Create a share for uploading and a share for downloading. Allow employees to mount shares on their local computers to use S3 File Gateway.

- D. Configure AWS Transfer Family SFTP endpoints. Select the custom identity provider options. Use AWS Secrets Manager to manage the user credentials Instruct employees to use Transfer Family.

**Correct:** A
**Why:** Presigned URLs from Lambda provide secure, minimal‑ops upload/download to S3 without managing user accounts or servers.

**Incorrect:**
- B: Per‑employee IAM users add heavy management.
- C: S3 File Gateway is for SMB/NFS; not needed for internet‑scale sharing.
- D: Transfer Family SFTP adds server management and user store overhead.


---

---

### Question #640

A company has an application workow that uses an AWS Lambda function to download and decrypt files from Amazon S3. These files are encrypted using AWS Key Management Service (AWS KMS) keys. A solutions architect needs to design a solution that will ensure the required permissions are set correctly. Which combination of actions accomplish this? (Choose two.)

- A. Attach the kms:decrypt permission to the Lambda function’s resource policy

- B. Grant the decrypt permission for the Lambda IAM role in the KMS key's policy

- C. Grant the decrypt permission for the Lambda resource policy in the KMS key's policy.

- D. Create a new IAM policy with the kms:decrypt permission and attach the policy to the Lambda function.

E. Create a new IAM role with the kms:decrypt permission and attach the execution role to the Lambda function.

**Correct:** B, E
**Why:** Allow the Lambda execution role in the KMS key policy and ensure the function uses an execution role with kms:Decrypt.

**Incorrect:**
- A: Lambda resource policies do not grant KMS decrypt permissions.
- C: Lambda resource policies do not grant KMS decrypt permissions.
- D: Policies attach to roles; attach to the function’s role, not the function object.


---

---

### Question #641

A company wants to monitor its AWS costs for nancial review. The cloud operations team is designing an architecture in the AWS Organizations management account to query AWS Cost and Usage Reports for all member accounts. The team must run this query once a month and provide a detailed analysis of the bill. Which solution is the MOST scalable and cost-effective way to meet these requirements?

- A. Enable Cost and Usage Reports in the management account. Deliver reports to Amazon Kinesis. Use Amazon EMR for analysis.

- B. Enable Cost and Usage Reports in the management account. Deliver the reports to Amazon S3 Use Amazon Athena for analysis.

- C. Enable Cost and Usage Reports for member accounts. Deliver the reports to Amazon S3 Use Amazon Redshift for analysis.

- D. Enable Cost and Usage Reports for member accounts. Deliver the reports to Amazon Kinesis. Use Amazon QuickSight tor analysis.

**Correct:** B
**Why:** CUR to S3 + Athena provides scalable, low‑cost monthly querying across member accounts from the management account.

**Incorrect:**
- A: Kinesis/QuickSight not needed; CUR+Athena is simpler/cheaper.
- C: Enabling CUR per member is unnecessary; centralize in management.
- D: Kinesis/QuickSight not needed; CUR+Athena is simpler/cheaper.


---

---

### Question #643

A company runs several websites on AWS for its different brands. Each website generates tens of gigabytes of web trac logs each day. A solutions architect needs to design a scalable solution to give the company's developers the ability to analyze trac patterns across all the company's websites. This analysis by the developers will occur on demand once a week over the course of several months. The solution must support queries with standard SQL. Which solution will meet these requirements MOST cost-effectively?

- A. Store the logs in Amazon S3. Use Amazon Athena tor analysis.

- B. Store the logs in Amazon RDS. Use a database client for analysis.

- C. Store the logs in Amazon OpenSearch Service. Use OpenSearch Service for analysis.

- D. Store the logs in an Amazon EMR cluster Use a supported open-source framework for SQL-based analysis.

**Correct:** A
**Why:** Store logs in S3 and query with Athena using SQL only when needed; minimal cost/ops.

**Incorrect:**
- B: RDS is expensive and not ideal for log analytics.
- C: OpenSearch is more costly for weekly ad‑hoc queries.
- D: EMR cluster management adds significant overhead.


---

---

### Question #646

A solutions architect needs to host a high performance computing (HPC) workload in the AWS Cloud. The workload will run on hundreds of Amazon EC2 instances and will require parallel access to a shared file system to enable distributed processing of large datasets. Datasets will be accessed across multiple instances simultaneously. The workload requires access latency within 1 ms. After processing has completed, engineers will need access to the dataset for manual postprocessing. Which solution will meet these requirements?

- A. Use Amazon Elastic File System (Amazon EFS) as a shared file system. Access the dataset from Amazon EFS.

- B. Mount an Amazon S3 bucket to serve as the shared file system. Perform postprocessing directly from the S3 bucket.

- C. Use Amazon FSx for Lustre as a shared file system. Link the file system to an Amazon S3 bucket for postprocessing.

- D. Configure AWS Resource Access Manager to share an Amazon S3 bucket so that it can be mounted to all instances for processing and postprocessing.

**Correct:** B
**Why:** FSx for Lustre persistent file systems provide sub‑millisecond latency, high throughput, and HA for HPC, with optional S3 integration for data lifecycle.

**Incorrect:**
- A: Scratch has no HA.
- C: Not explicit about persistence/HA; persistent FSx is preferred for availability.
- D: S3 is not a POSIX FS and cannot be "mounted" natively with required latency.


---

---

### Question #651

A company stores a large volume of image files in an Amazon S3 bucket. The images need to be readily available for the first 180 days. The images are infrequently accessed for the next 180 days. After 360 days, the images need to be archived but must be available instantly upon request. After 5 years, only auditors can access the images. The auditors must be able to retrieve the images within 12 hours. The images cannot be lost during this process. A developer will use S3 Standard storage for the first 180 days. The developer needs to configure an S3 Lifecycle rule. Which solution will meet these requirements MOST cost-effectively?

- A. Transition the objects to S3 One Zone-Infrequent Access (S3 One Zone-IA) after 180 days. S3 Glacier Instant Retrieval after 360 days, and S3 Glacier Deep Archive after 5 years.

- B. Transition the objects to S3 One Zone-Infrequent Access (S3 One Zone-IA) after 180 days. S3 Glacier Flexible Retrieval after 360 days, and S3 Glacier Deep Archive after 5 years.

- C. Transition the objects to S3 Standard-Infrequent Access (S3 Standard-IA) after 180 days, S3 Glacier Instant Retrieval after 360 days, and S3 Glacier Deep Archive after 5 years.

- D. Transition the objects to S3 Standard-Infrequent Access (S3 Standard-IA) after 180 days, S3 Glacier Flexible Retrieval after 360 days, and S3 Glacier Deep Archive after 5 years.

**Correct:** C
**Why:** Transition to S3 Standard‑IA after 180 days, then Glacier Instant Retrieval after 360 days (instant access), and Deep Archive after 5 years (12‑hour SLA sufficient).

**Incorrect:**
- A: Mismatch between retrieval speed requirements and storage class capabilities.
- B: Mismatch between retrieval speed requirements and storage class capabilities.
- D: Mismatch between retrieval speed requirements and storage class capabilities.


---

---

### Question #654

A company recently migrated its web application to the AWS Cloud. The company uses an Amazon EC2 instance to run multiple processes to host the application. The processes include an Apache web server that serves static content. The Apache web server makes requests to a PHP application that uses a local Redis server for user sessions. The company wants to redesign the architecture to be highly available and to use AWS managed solutions. Which solution will meet these requirements?

- A. Use AWS Elastic Beanstalk to host the static content and the PHP application. Configure Elastic Beanstalk to deploy its EC2 instance into a public subnet. Assign a public IP address.

- B. Use AWS Lambda to host the static content and the PHP application. Use an Amazon API Gateway REST API to proxy requests to the Lambda function. Set the API Gateway CORS configuration to respond to the domain name. Configure Amazon ElastiCache for Redis to handle session information.

- C. Keep the backend code on the EC2 instance. Create an Amazon ElastiCache for Redis cluster that has Multi-AZ enabled. Configure the ElastiCache for Redis cluster in cluster mode. Copy the frontend resources to Amazon S3. Configure the backend code to reference the EC2 instance.

- D. Configure an Amazon CloudFront distribution with an Amazon S3 endpoint to an S3 bucket that is congured to host the static content. Configure an Application Load Balancer that targets an Amazon Elastic Container Service (Amazon ECS) service that runs AWS Fargate tasks for the PHP application. Configure the PHP application to use an Amazon ElastiCache for Redis cluster that runs in multiple Availability Zones.

**Correct:** D
**Why:** S3 + CloudFront for static assets; ECS Fargate behind ALB for PHP app; Redis (Multi‑AZ) for sessions meets HA with managed services.

**Incorrect:**
- A: Single EC2 in public subnet is not HA.
- B: Lambda for PHP monolith adds complexity and cold‑start concerns.
- C: Keeping backend on EC2 is not fully managed/HA.


---

---

### Question #656

A company runs a website that stores images of historical events. Website users need the ability to search and view images based on the year that the event in the image occurred. On average, users request each image only once or twice a year. The company wants a highly available solution to store and deliver the images to users. Which solution will meet these requirements MOST cost-effectively?

- A. Store images in Amazon Elastic Block Store (Amazon EBS). Use a web server that runs on Amazon EC2.

- B. Store images in Amazon Elastic File System (Amazon EFS). Use a web server that runs on Amazon EC2.

- C. Store images in Amazon S3 Standard. Use S3 Standard to directly deliver images by using a static website.

- D. Store images in Amazon S3 Standard-Infrequent Access (S3 Standard-IA). Use S3 Standard-IA to directly deliver images by using a static website.

**Correct:** D
**Why:** S3 Standard‑IA stores infrequently accessed images cost‑effectively and can serve via static website hosting when requested.

**Incorrect:**
- A: EBS/EFS require EC2 and add ops.
- B: EBS/EFS require EC2 and add ops.
- C: S3 Standard costs more for rarely accessed objects.


---

---

### Question #663

A company is developing a new application on AWS. The application consists of an Amazon Elastic Container Service (Amazon ECS) cluster, an Amazon S3 bucket that contains assets for the application, and an Amazon RDS for MySQL database that contains the dataset for the application. The dataset contains sensitive information. The company wants to ensure that only the ECS cluster can access the data in the RDS for MySQL database and the data in the S3 bucket. Which solution will meet these requirements?

- A. Create a new AWS Key Management Service (AWS KMS) customer managed key to encrypt both the S3 bucket and the RDS for MySQL database. Ensure that the KMS key policy includes encrypt and decrypt permissions for the ECS task execution role.

- B. Create an AWS Key Management Service (AWS KMS) AWS managed key to encrypt both the S3 bucket and the RDS for MySQL database. Ensure that the S3 bucket policy species the ECS task execution role as a user.

- C. Create an S3 bucket policy that restricts bucket access to the ECS task execution role. Create a VPC endpoint for Amazon RDS for MySQL. Update the RDS for MySQL security group to allow access from only the subnets that the ECS cluster will generate tasks in.

- D. Create a VPC endpoint for Amazon RDS for MySQL. Update the RDS for MySQL security group to allow access from only the subnets that the ECS cluster will generate tasks in. Create a VPC endpoint for Amazon S3. Update the S3 bucket policy to allow access from only the S3 VPC endpoint.

**Correct:** C
**Why:** Restrict S3 bucket access to the ECS task execution role, and tighten RDS access via security groups to only the ECS task subnets; combined, only the ECS tasks can reach data.

**Incorrect:**
- A: KMS encryption alone doesn’t restrict principal network/data access.
- B: KMS encryption alone doesn’t restrict principal network/data access.
- D: There is no VPC endpoint for RDS database connections; S3 endpoint restriction is good, but RDS SG is the right control.


---

---

### Question #667

A company is moving its data and applications to AWS during a multiyear migration project. The company wants to securely access data on Amazon S3 from the company's AWS Region and from the company's on-premises location. The data must not traverse the internet. The company has established an AWS Direct Connect connection between its Region and its on-premises location. Which solution will meet these requirements?

- A. Create gateway endpoints for Amazon S3. Use the gateway endpoints to securely access the data from the Region and the on-premises location.

- B. Create a gateway in AWS Transit Gateway to access Amazon S3 securely from the Region and the on-premises location.

- C. Create interface endpoints for Amazon S3. Use the interface endpoints to securely access the data from the Region and the on-premises location.

- D. Use an AWS Key Management Service (AWS KMS) key to access the data securely from the Region and the on-premises location.

**Correct:** C
**Why:** S3 interface endpoints (PrivateLink) allow private S3 access inside a VPC. Over Direct Connect private VIF, on‑prem can reach those endpoints without internet.

**Incorrect:**
- A: Gateway endpoints are not reachable from on‑prem.
- B: Transit Gateway does not provide S3 service access.
- D: KMS keys don’t provide network‑private access.


---

---

### Question #672

A marketing company receives a large amount of new clickstream data in Amazon S3 from a marketing campaign. The company needs to analyze the clickstream data in Amazon S3 quickly. Then the company needs to determine whether to process the data further in the data pipeline. Which solution will meet these requirements with the LEAST operational overhead?

- A. Create external tables in a Spark catalog. Configure jobs in AWS Glue to query the data.

- B. Configure an AWS Glue crawler to crawl the data. Configure Amazon Athena to query the data.

- C. Create external tables in a Hive metastore. Configure Spark jobs in Amazon EMR to query the data.

- D. Configure an AWS Glue crawler to crawl the data. Configure Amazon Kinesis Data Analytics to use SQL to query the data.

**Correct:** B
**Why:** Run an AWS Glue crawler to catalog the S3 data, then use Amazon Athena to query immediately with SQL and minimal ops.

**Incorrect:**
- A: Spark catalog setup adds unnecessary overhead for a quick assessment.
- C: EMR + Hive metastore increases cost/ops for ad‑hoc queries.
- D: Kinesis Data Analytics is for streaming SQL, not batch S3 analysis.


---

---

### Question #673

A company runs an SMB file server in its data center. The file server stores large files that the company frequently accesses for up to 7 days after the file creation date. After 7 days, the company needs to be able to access the files with a maximum retrieval time of 24 hours. Which solution will meet these requirements?

- A. Use AWS DataSync to copy data that is older than 7 days from the SMB file server to AWS.

- B. Create an Amazon S3 File Gateway to increase the company's storage space. Create an S3 Lifecycle policy to transition the data to S3 Glacier Deep Archive after 7 days.

- C. Create an Amazon FSx File Gateway to increase the company's storage space. Create an Amazon S3 Lifecycle policy to transition the data after 7 days.

- D. Configure access to Amazon S3 for each user. Create an S3 Lifecycle policy to transition the data to S3 Glacier Flexible Retrieval after 7 days.

**Correct:** B
**Why:** S3 File Gateway provides SMB access with local cache; lifecycle to S3 Glacier Deep Archive after 7 days keeps costs low and meets 24‑hour retrieval SLA.

**Incorrect:**
- A: DataSync alone does not provide SMB access or caching and is not continuous storage.
- C: FSx File Gateway targets FSx for Windows, not S3; S3 lifecycle rules don’t apply to FSx.
- D: Direct S3 access removes SMB access and user workflow compatibility.


---

---

### Question #678

A company stores sensitive data in Amazon S3. A solutions architect needs to create an encryption solution. The company needs to fully control the ability of users to create, rotate, and disable encryption keys with minimal effort for any data that must be encrypted. Which solution will meet these requirements?

- A. Use default server-side encryption with Amazon S3 managed encryption keys (SSE-S3) to store the sensitive data.

- B. Create a customer managed key by using AWS Key Management Service (AWS KMS). Use the new key to encrypt the S3 objects by using server-side encryption with AWS KMS keys (SSE-KMS).

- C. Create an AWS managed key by using AWS Key Management Service (AWS KMS). Use the new key to encrypt the S3 objects by using server-side encryption with AWS KMS keys (SSE-KMS).

- D. Download S3 objects to an Amazon EC2 instance. Encrypt the objects by using customer managed keys. Upload the encrypted objects back into Amazon S3.

**Correct:** B
**Why:** Use a customer managed KMS key with SSE‑KMS for S3 to fully control key creation, rotation, and disabling.

**Incorrect:**
- A: SSE‑S3 uses AWS‑owned keys with no customer control.
- C: AWS managed keys limit control of rotation/disable.
- D: Client‑side EC2 encryption adds operational complexity.


---

---

### Question #679

A company wants to back up its on-premises virtual machines (VMs) to AWS. The company's backup solution exports on-premises backups to an Amazon S3 bucket as objects. The S3 backups must be retained for 30 days and must be automatically deleted after 30 days. Which combination of steps will meet these requirements? (Choose three.)

- A. Create an S3 bucket that has S3 Object Lock enabled.

- B. Create an S3 bucket that has object versioning enabled.

- C. Configure a default retention period of 30 days for the objects.

- D. Configure an S3 Lifecycle policy to protect the objects for 30 days.

E. Configure an S3 Lifecycle policy to expire the objects after 30 days.

F. Configure the backup solution to tag the objects with a 30-day retention period

**Correct:** B, E, F
**Why:** Enable versioning, tag backup objects, and use a lifecycle rule to expire after 30 days for automatic deletion and simple scoping.

**Incorrect:**
- A: Object Lock and default retention are for WORM compliance; not required here and add complexity.
- C: Object Lock and default retention are for WORM compliance; not required here and add complexity.
- D: Lifecycle does not "protect" objects; use expire action instead.


---

---

### Question #680

A solutions architect needs to copy files from an Amazon S3 bucket to an Amazon Elastic File System (Amazon EFS) file system and another S3 bucket. The files must be copied continuously. New files are added to the original S3 bucket consistently. The copied files should be overwritten only if the source file changes. Which solution will meet these requirements with the LEAST operational overhead?

- A. Create an AWS DataSync location for both the destination S3 bucket and the EFS file system. Create a task for the destination S3 bucket and the EFS file system. Set the transfer mode to transfer only data that has changed.

- B. Create an AWS Lambda function. Mount the file system to the function. Set up an S3 event notification to invoke the function when files are created and changed in Amazon S3. Configure the function to copy files to the file system and the destination S3 bucket.

- C. Create an AWS DataSync location for both the destination S3 bucket and the EFS file system. Create a task for the destination S3 bucket and the EFS file system. Set the transfer mode to transfer all data.

- D. Launch an Amazon EC2 instance in the same VPC as the file system. Mount the file system. Create a script to routinely synchronize all objects that changed in the origin S3 bucket to the destination S3 bucket and the mounted file system.

**Correct:** A
**Why:** AWS DataSync supports continuous copies S3→S3 and S3→EFS with change‑only transfers, minimizing overhead and avoiding unnecessary overwrites.

**Incorrect:**
- B: Lambda + mount is complex and not ideal for continuous, scalable sync.
- C: Transfer all data is inefficient and increases costs.
- D: EC2 + scripts adds ops and reliability risks.


---

## Amazon SNS

### Question #531

A company needs to integrate with a third-party data feed. The data feed sends a webhook to notify an external service when new data is ready for consumption. A developer wrote an AWS Lambda function to retrieve data when the company receives a webhook callback. The developer must make the Lambda function available for the third party to call. Which solution will meet these requirements with the MOST operational eciency?

- A. Create a function URL for the Lambda function. Provide the Lambda function URL to the third party for the webhook.

- B. Deploy an Application Load Balancer (ALB) in front of the Lambda function. Provide the ALB URL to the third party for the webhook.

- C. Create an Amazon Simple Notification Service (Amazon SNS) topic. Attach the topic to the Lambda function. Provide the public hostname of the SNS topic to the third party for the webhook.

- D. Create an Amazon Simple Queue Service (Amazon SQS) queue. Attach the queue to the Lambda function. Provide the public hostname of the SQS queue to the third party for the webhook.

**Correct:** A
**Why:** Lambda function URLs expose HTTPS endpoints directly for webhook callbacks with minimal ops.

**Incorrect:**
- B: ALB/SNS/SQS add unnecessary components for a simple webhook.
- C: ALB/SNS/SQS add unnecessary components for a simple webhook.
- D: ALB/SNS/SQS add unnecessary components for a simple webhook.


---

---

### Question #533

A company stores data in Amazon S3. According to regulations, the data must not contain personally identiable information (PII). The company recently discovered that S3 buckets have some objects that contain PII. The company needs to automatically detect PII in S3 buckets and to notify the company’s security team. Which solution will meet these requirements?

- A. Use Amazon Macie. Create an Amazon EventBridge rule to filter the SensitiveData event type from Macie ndings and to send an Amazon Simple Notification Service (Amazon SNS) notification to the security team.

- B. Use Amazon GuardDuty. Create an Amazon EventBridge rule to filter the CRITICAL event type from GuardDuty ndings and to send an Amazon Simple Notification Service (Amazon SNS) notification to the security team.

- C. Use Amazon Macie. Create an Amazon EventBridge rule to filter the SensitiveData:S3Object/Personal event type from Macie ndings and to send an Amazon Simple Queue Service (Amazon SQS) notification to the security team.

- D. Use Amazon GuardDuty. Create an Amazon EventBridge rule to filter the CRITICAL event type from GuardDuty ndings and to send an Amazon Simple Queue Service (Amazon SQS) notification to the security team.

**Correct:** A
**Why:** Macie detects PII in S3; route SensitiveData events to SNS via EventBridge to notify security.

**Incorrect:**
- B: GuardDuty is not for PII in S3.
- C: SQS is not ideal for notifications to humans.
- D: GuardDuty is not for PII in S3.


---

---

### Question #611

A company has an application with a REST-based interface that allows data to be received in near-real time from a third-party vendor. Once received, the application processes and stores the data for further analysis. The application is running on Amazon EC2 instances. The third-party vendor has received many 503 Service Unavailable Errors when sending data to the application. When the data volume spikes, the compute capacity reaches its maximum limit and the application is unable to process all requests. Which design should a solutions architect recommend to provide a more scalable solution?

- A. Use Amazon Kinesis Data Streams to ingest the data. Process the data using AWS Lambda functions.

- B. Use Amazon API Gateway on top of the existing application. Create a usage plan with a quota limit for the third-party vendor.

- C. Use Amazon Simple Notification Service (Amazon SNS) to ingest the data. Put the EC2 instances in an Auto Scaling group behind an Application Load Balancer.

- D. Repackage the application as a container. Deploy the application using Amazon Elastic Container Service (Amazon ECS) using the EC2 launch type with an Auto Scaling group.

**Correct:** A
**Why:** Kinesis Data Streams buffers spikes and decouples producers from consumers; Lambda scales to process without 503s.

**Incorrect:**
- B: API Gateway with quotas throttles the vendor rather than scaling.
- C: SNS is pub/sub and not ideal for high‑throughput buffering + ordering.
- D: ECS on EC2 still faces sudden capacity limits without a buffer.


---

---

### Question #636

A development team is creating an event-based application that uses AWS Lambda functions. Events will be generated when files are added to an Amazon S3 bucket. The development team currently has Amazon Simple Notification Service (Amazon SNS) congured as the event target from Amazon S3. What should a solutions architect do to process the events from Amazon S3 in a scalable way?

- A. Create an SNS subscription that processes the event in Amazon Elastic Container Service (Amazon ECS) before the event runs in Lambda.

- B. Create an SNS subscription that processes the event in Amazon Elastic Kubernetes Service (Amazon EKS) before the event runs in Lambda

- C. Create an SNS subscription that sends the event to Amazon Simple Queue Service (Amazon SQS). Configure the SOS queue to trigger a Lambda function.

- D. Create an SNS subscription that sends the event to AWS Server Migration Service (AWS SMS). Configure the Lambda function to poll from the SMS event.

**Correct:** C
**Why:** Send SNS to SQS, then trigger Lambda from SQS for scalable, durable processing and smoothing spikes.

**Incorrect:**
- A: ECS/EKS add complexity; SNS->Lambda fanout directly may throttle; SQS adds buffering.
- B: ECS/EKS add complexity; SNS->Lambda fanout directly may throttle; SQS adds buffering.
- D: SMS is unrelated.


---

## Amazon SQS

### Question #513

A social media company wants to allow its users to upload images in an application that is hosted in the AWS Cloud. The company needs a solution that automatically resizes the images so that the images can be displayed on multiple device types. The application experiences unpredictable trac patterns throughout the day. The company is seeking a highly available solution that maximizes scalability. What should a solutions architect do to meet these requirements?

- A. Create a static website hosted in Amazon S3 that invokes AWS Lambda functions to resize the images and store the images in an Amazon S3 bucket.

- B. Create a static website hosted in Amazon CloudFront that invokes AWS Step Functions to resize the images and store the images in an Amazon RDS database.

- C. Create a dynamic website hosted on a web server that runs on an Amazon EC2 instance. Configure a process that runs on the EC2 instance to resize the images and store the images in an Amazon S3 bucket.

- D. Create a dynamic website hosted on an automatically scaling Amazon Elastic Container Service (Amazon ECS) cluster that creates a resize job in Amazon Simple Queue Service (Amazon SQS). Set up an image-resizing program that runs on an Amazon EC2 instance to process the resize jobs.

**Correct:** A
**Why:** Static site front end in S3 with Lambda resizing on upload provides high availability and scalability with minimal ops; store results in S3.

**Incorrect:**
- B: CloudFront+Step Functions/EC2/ECS add complexity and are less serverless.
- C: CloudFront+Step Functions/EC2/ECS add complexity and are less serverless.
- D: CloudFront+Step Functions/EC2/ECS add complexity and are less serverless.


---

---

### Question #531

A company needs to integrate with a third-party data feed. The data feed sends a webhook to notify an external service when new data is ready for consumption. A developer wrote an AWS Lambda function to retrieve data when the company receives a webhook callback. The developer must make the Lambda function available for the third party to call. Which solution will meet these requirements with the MOST operational eciency?

- A. Create a function URL for the Lambda function. Provide the Lambda function URL to the third party for the webhook.

- B. Deploy an Application Load Balancer (ALB) in front of the Lambda function. Provide the ALB URL to the third party for the webhook.

- C. Create an Amazon Simple Notification Service (Amazon SNS) topic. Attach the topic to the Lambda function. Provide the public hostname of the SNS topic to the third party for the webhook.

- D. Create an Amazon Simple Queue Service (Amazon SQS) queue. Attach the queue to the Lambda function. Provide the public hostname of the SQS queue to the third party for the webhook.

**Correct:** A
**Why:** Lambda function URLs expose HTTPS endpoints directly for webhook callbacks with minimal ops.

**Incorrect:**
- B: ALB/SNS/SQS add unnecessary components for a simple webhook.
- C: ALB/SNS/SQS add unnecessary components for a simple webhook.
- D: ALB/SNS/SQS add unnecessary components for a simple webhook.


---

---

### Question #533

A company stores data in Amazon S3. According to regulations, the data must not contain personally identiable information (PII). The company recently discovered that S3 buckets have some objects that contain PII. The company needs to automatically detect PII in S3 buckets and to notify the company’s security team. Which solution will meet these requirements?

- A. Use Amazon Macie. Create an Amazon EventBridge rule to filter the SensitiveData event type from Macie ndings and to send an Amazon Simple Notification Service (Amazon SNS) notification to the security team.

- B. Use Amazon GuardDuty. Create an Amazon EventBridge rule to filter the CRITICAL event type from GuardDuty ndings and to send an Amazon Simple Notification Service (Amazon SNS) notification to the security team.

- C. Use Amazon Macie. Create an Amazon EventBridge rule to filter the SensitiveData:S3Object/Personal event type from Macie ndings and to send an Amazon Simple Queue Service (Amazon SQS) notification to the security team.

- D. Use Amazon GuardDuty. Create an Amazon EventBridge rule to filter the CRITICAL event type from GuardDuty ndings and to send an Amazon Simple Queue Service (Amazon SQS) notification to the security team.

**Correct:** A
**Why:** Macie detects PII in S3; route SensitiveData events to SNS via EventBridge to notify security.

**Incorrect:**
- B: GuardDuty is not for PII in S3.
- C: SQS is not ideal for notifications to humans.
- D: GuardDuty is not for PII in S3.


---

---

### Question #555

A company runs an application in a VPC with public and private subnets. The VPC extends across multiple Availability Zones. The application runs on Amazon EC2 instances in private subnets. The application uses an Amazon Simple Queue Service (Amazon SQS) queue. A solutions architect needs to design a secure solution to establish a connection between the EC2 instances and the SQS queue. Which solution will meet these requirements?

- A. Implement an interface VPC endpoint for Amazon SQS. Configure the endpoint to use the private subnets. Add to the endpoint a security group that has an inbound access rule that allows trac from the EC2 instances that are in the private subnets.

- B. Implement an interface VPC endpoint for Amazon SQS. Configure the endpoint to use the public subnets. Attach to the interface endpoint a VPC endpoint policy that allows access from the EC2 instances that are in the private subnets.

- C. Implement an interface VPC endpoint for Amazon SQS. Configure the endpoint to use the public subnets. Attach an Amazon SQS access policy to the interface VPC endpoint that allows requests from only a specied VPC endpoint.

- D. Implement a gateway endpoint for Amazon SQS. Add a NAT gateway to the private subnets. Attach an IAM role to the EC2 instances that allows access to the SQS queue.

**Correct:** A
**Why:** Use an interface VPC endpoint (AWS PrivateLink) for SQS in private subnets. Attach a security group allowing traffic from EC2 instances in those subnets for a private, secure path.

**Incorrect:**
- B: Public subnets are unnecessary; security groups apply to the endpoint, but placing it in public subnets doesn’t meet "secure private" requirement.
- C: SQS access policies attach to queues, not to interface endpoints. Also endpoint should be in private subnets.
- D: SQS does not support gateway endpoints. A NAT gateway would traverse the internet path, which is not desired.


---

---

### Question #569

An Amazon EventBridge rule targets a third-party API. The third-party API has not received any incoming trac. A solutions architect needs to determine whether the rule conditions are being met and if the rule's target is being invoked. Which solution will meet these requirements?

- A. Check for metrics in Amazon CloudWatch in the namespace for AWS/Events.

- B. Review events in the Amazon Simple Queue Service (Amazon SQS) dead-letter queue.

- C. Check for the events in Amazon CloudWatch Logs.

- D. Check the trails in AWS CloudTrail for the EventBridge events.

**Correct:** A
**Why:** CloudWatch provides AWS/Events metrics (e.g., Invocations, MatchedEvents, DeliveryToTargetFailures) to verify rule matching and target invocation.

**Incorrect:**
- B: DLQ is relevant if a target supports and you configured one; not inherent for third-party API targets.
- C: CloudWatch Logs may be used if target logs there, but the primary signal for EventBridge rule evaluation is CloudWatch metrics.
- D: CloudTrail logs API calls, not internal EventBridge rule evaluations and target invocations.


---

---

### Question #636

A development team is creating an event-based application that uses AWS Lambda functions. Events will be generated when files are added to an Amazon S3 bucket. The development team currently has Amazon Simple Notification Service (Amazon SNS) congured as the event target from Amazon S3. What should a solutions architect do to process the events from Amazon S3 in a scalable way?

- A. Create an SNS subscription that processes the event in Amazon Elastic Container Service (Amazon ECS) before the event runs in Lambda.

- B. Create an SNS subscription that processes the event in Amazon Elastic Kubernetes Service (Amazon EKS) before the event runs in Lambda

- C. Create an SNS subscription that sends the event to Amazon Simple Queue Service (Amazon SQS). Configure the SOS queue to trigger a Lambda function.

- D. Create an SNS subscription that sends the event to AWS Server Migration Service (AWS SMS). Configure the Lambda function to poll from the SMS event.

**Correct:** C
**Why:** Send SNS to SQS, then trigger Lambda from SQS for scalable, durable processing and smoothing spikes.

**Incorrect:**
- A: ECS/EKS add complexity; SNS->Lambda fanout directly may throttle; SQS adds buffering.
- B: ECS/EKS add complexity; SNS->Lambda fanout directly may throttle; SQS adds buffering.
- D: SMS is unrelated.


---

## Amazon VPC

### Question #504

A company needs to connect several VPCs in the us-east-1 Region that span hundreds of AWS accounts. The company's networking team has its own AWS account to manage the cloud network. What is the MOST operationally ecient solution to connect the VPCs?

- A. Set up VPC peering connections between each VPC. Update each associated subnet’s route table

- B. Configure a NAT gateway and an internet gateway in each VPC to connect each VPC through the internet

- C. Create an AWS Transit Gateway in the networking team’s AWS account. Configure static routes from each VPC.

- D. Deploy VPN gateways in each VPC. Create a transit VPC in the networking team’s AWS account to connect to each VPC.

**Correct:** C
**Why:** Transit Gateway in a central networking account scales to hundreds of VPCs with simple routing.

**Incorrect:**
- A: Peering/internet/VPN transit VPCs add heavy ops.
- B: Peering/internet/VPN transit VPCs add heavy ops.
- D: Peering/internet/VPN transit VPCs add heavy ops.


---

---

### Question #509

A company operates a two-tier application for image processing. The application uses two Availability Zones, each with one public subnet and one private subnet. An Application Load Balancer (ALB) for the web tier uses the public subnets. Amazon EC2 instances for the application tier use the private subnets. Users report that the application is running more slowly than expected. A security audit of the web server log files shows that the application is receiving millions of illegitimate requests from a small number of IP addresses. A solutions architect needs to resolve the immediate performance problem while the company investigates a more permanent solution. What should the solutions architect recommend to meet this requirement?

- A. Modify the inbound security group for the web tier. Add a deny rule for the IP addresses that are consuming resources.

- B. Modify the network ACL for the web tier subnets. Add an inbound deny rule for the IP addresses that are consuming resources.

- C. Modify the inbound security group for the application tier. Add a deny rule for the IP addresses that are consuming resources.

- D. Modify the network ACL for the application tier subnets. Add an inbound deny rule for the IP addresses that are consuming resources.

**Correct:** B
**Why:** NACLs support explicit deny rules by IP to immediately block abusive sources on the web subnets.

**Incorrect:**
- A: Security groups are allow‑only—no deny rules.
- C: Security groups are allow‑only—no deny rules.
- D: Block at the web tier first, not the app subnets.


---

---

### Question #510

A global marketing company has applications that run in the ap-southeast-2 Region and the eu-west-1 Region. Applications that run in a VPC in eu- west-1 need to communicate securely with databases that run in a VPC in ap-southeast-2. Which network design will meet these requirements?

- A. Create a VPC peering connection between the eu-west-1 VPC and the ap-southeast-2 VPC. Create an inbound rule in the eu-west-1 application security group that allows trac from the database server IP addresses in the ap-southeast-2 security group.

- B. Configure a VPC peering connection between the ap-southeast-2 VPC and the eu-west-1 VPC. Update the subnet route tables. Create an inbound rule in the ap-southeast-2 database security group that references the security group ID of the application servers in eu-west-1.

- C. Configure a VPC peering connection between the ap-southeast-2 VPC and the eu-west-1 VPUpdate the subnet route tables. Create an inbound rule in the ap-southeast-2 database security group that allows trac from the eu-west-1 application server IP addresses.

- D. Create a transit gateway with a peering attachment between the eu-west-1 VPC and the ap-southeast-2 VPC. After the transit gateways are properly peered and routing is congured, create an inbound rule in the database security group that references the security group ID of the application servers in eu-west-1.

**Correct:** C
**Why:** Cross‑Region VPC peering plus route updates and allowing the specific application server IPs in the DB SG meets the need securely.

**Incorrect:**
- A: SG references across Regions are not supported; TGW peering still doesn’t enable cross‑Region SG referencing.
- B: SG references across Regions are not supported; TGW peering still doesn’t enable cross‑Region SG referencing.
- D: SG references across Regions are not supported; TGW peering still doesn’t enable cross‑Region SG referencing.


---

---

### Question #514

A company is running a microservices application on Amazon EC2 instances. The company wants to migrate the application to an Amazon Elastic Kubernetes Service (Amazon EKS) cluster for scalability. The company must configure the Amazon EKS control plane with endpoint private access set to true and endpoint public access set to false to maintain security compliance. The company must also put the data plane in private subnets. However, the company has received error notications because the node cannot join the cluster. Which solution will allow the node to join the cluster?

- A. Grant the required permission in AWS Identity and Access Management (IAM) to the AmazonEKSNodeRole IAM role.

- B. Create interface VPC endpoints to allow nodes to access the control plane.

- C. Recreate nodes in the public subnet. Restrict security groups for EC2 nodes.

- D. Allow outbound trac in the security group of the nodes.

**Correct:** B
**Why:** With private EKS endpoint and private node subnets, create interface VPC endpoints so nodes can reach the control plane APIs.

**Incorrect:**
- A: IAM/placing nodes public/SG egress alone won’t fix private endpoint reachability.
- C: IAM/placing nodes public/SG egress alone won’t fix private endpoint reachability.
- D: IAM/placing nodes public/SG egress alone won’t fix private endpoint reachability.


---

---

### Question #534

A company wants to build a logging solution for its multiple AWS accounts. The company currently stores the logs from all accounts in a centralized account. The company has created an Amazon S3 bucket in the centralized account to store the VPC flow logs and AWS CloudTrail logs. All logs must be highly available for 30 days for frequent analysis, retained for an additional 60 days for backup purposes, and deleted 90 days after creation. Which solution will meet these requirements MOST cost-effectively?

- A. Transition objects to the S3 Standard storage class 30 days after creation. Write an expiration action that directs Amazon S3 to delete objects after 90 days.

- B. Transition objects to the S3 Standard-Infrequent Access (S3 Standard-IA) storage class 30 days after creation. Move all objects to the S3 Glacier Flexible Retrieval storage class after 90 days. Write an expiration action that directs Amazon S3 to delete objects after 90 days.

- C. Transition objects to the S3 Glacier Flexible Retrieval storage class 30 days after creation. Write an expiration action that directs Amazon S3 to delete objects after 90 days.

- D. Transition objects to the S3 One Zone-Infrequent Access (S3 One Zone-IA) storage class 30 days after creation. Move all objects to the S3 Glacier Flexible Retrieval storage class after 90 days. Write an expiration action that directs Amazon S3 to delete objects after 90 days.

**Correct:** C
**Why:** Keep logs in Standard for 30 days, then transition to Glacier Flexible Retrieval until day 90, then expire—lowest cost for retention/restore needs.

**Incorrect:**
- A: Other tiering mixes are less cost‑effective or contradict the 90‑day deletion.
- B: Other tiering mixes are less cost‑effective or contradict the 90‑day deletion.
- D: Other tiering mixes are less cost‑effective or contradict the 90‑day deletion.


---

---

### Question #549

A company has created a multi-tier application for its ecommerce website. The website uses an Application Load Balancer that resides in the public subnets, a web tier in the public subnets, and a MySQL cluster hosted on Amazon EC2 instances in the private subnets. The MySQL database needs to retrieve product catalog and pricing information that is hosted on the internet by a third-party provider. A solutions architect must devise a strategy that maximizes security without increasing operational overhead. What should the solutions architect do to meet these requirements?

- A. Deploy a NAT instance in the VPC. Route all the internet-based trac through the NAT instance.

- B. Deploy a NAT gateway in the public subnets. Modify the private subnet route table to direct all internet-bound trac to the NAT gateway.

- C. Configure an internet gateway and attach it to the VPModify the private subnet route table to direct internet-bound trac to the internet gateway.

- D. Configure a virtual private gateway and attach it to the VPC. Modify the private subnet route table to direct internet-bound trac to the virtual private gateway.

**Correct:** B
**Why:** A NAT gateway in a public subnet provides secure outbound internet from private subnets without exposing instances.

**Incorrect:**
- A: NAT instance adds ops.
- C: IGW/VGW are not for private outbound egress.
- D: IGW/VGW are not for private outbound egress.


---

---

### Question #555

A company runs an application in a VPC with public and private subnets. The VPC extends across multiple Availability Zones. The application runs on Amazon EC2 instances in private subnets. The application uses an Amazon Simple Queue Service (Amazon SQS) queue. A solutions architect needs to design a secure solution to establish a connection between the EC2 instances and the SQS queue. Which solution will meet these requirements?

- A. Implement an interface VPC endpoint for Amazon SQS. Configure the endpoint to use the private subnets. Add to the endpoint a security group that has an inbound access rule that allows trac from the EC2 instances that are in the private subnets.

- B. Implement an interface VPC endpoint for Amazon SQS. Configure the endpoint to use the public subnets. Attach to the interface endpoint a VPC endpoint policy that allows access from the EC2 instances that are in the private subnets.

- C. Implement an interface VPC endpoint for Amazon SQS. Configure the endpoint to use the public subnets. Attach an Amazon SQS access policy to the interface VPC endpoint that allows requests from only a specied VPC endpoint.

- D. Implement a gateway endpoint for Amazon SQS. Add a NAT gateway to the private subnets. Attach an IAM role to the EC2 instances that allows access to the SQS queue.

**Correct:** A
**Why:** Use an interface VPC endpoint (AWS PrivateLink) for SQS in private subnets. Attach a security group allowing traffic from EC2 instances in those subnets for a private, secure path.

**Incorrect:**
- B: Public subnets are unnecessary; security groups apply to the endpoint, but placing it in public subnets doesn’t meet "secure private" requirement.
- C: SQS access policies attach to queues, not to interface endpoints. Also endpoint should be in private subnets.
- D: SQS does not support gateway endpoints. A NAT gateway would traverse the internet path, which is not desired.


---

---

### Question #558

A company has two VPCs that are located in the us-west-2 Region within the same AWS account. The company needs to allow network trac between these VPCs. Approximately 500 GB of data transfer will occur between the VPCs each month. What is the MOST cost-effective solution to connect these VPCs?

- A. Implement AWS Transit Gateway to connect the VPCs. Update the route tables of each VPC to use the transit gateway for inter-VPC communication.

- B. Implement an AWS Site-to-Site VPN tunnel between the VPCs. Update the route tables of each VPC to use the VPN tunnel for inter-VPC communication.

- C. Set up a VPC peering connection between the VPCs. Update the route tables of each VPC to use the VPC peering connection for inter-VPC communication.

- D. Set up a 1 GB AWS Direct Connect connection between the VPCs. Update the route tables of each VPC to use the Direct Connect connection for inter-VPC communication.

**Correct:** C
**Why:** VPC peering within the same account/Region is simplest and most cost-effective for 500 GB/month, with low operational overhead.

**Incorrect:**
- A: Transit Gateway adds unnecessary cost/complexity for two VPCs.
- B: Site-to-Site VPN incurs data transfer charges and adds latency/overhead.
- D: Direct Connect is for on-prem to AWS, not VPC-to-VPC, and is cost-inefficient here.


---

---

### Question #562

A solutions architect needs to ensure that API calls to Amazon DynamoDB from Amazon EC2 instances in a VPC do not travel across the internet. Which combination of steps should the solutions architect take to meet this requirement? (Choose two.)

- A. Create a route table entry for the endpoint.

- B. Create a gateway endpoint for DynamoDB.

- C. Create an interface endpoint for Amazon EC2.

- D. Create an elastic network interface for the endpoint in each of the subnets of the VPC.

E. Create a security group entry in the endpoint's security group to provide access.

**Correct:** A, B
**Why:** Use a DynamoDB gateway VPC endpoint and update route tables to ensure DynamoDB API calls stay within the AWS network and not over the internet.

**Incorrect:**
- C: Interface endpoint for EC2 is unrelated.
- D: Gateway endpoints do not create ENIs; that’s for interface endpoints.
- E: Gateway endpoints don’t use security groups.


---

---

### Question #566

A company runs multiple Amazon EC2 Linux instances in a VPC across two Availability Zones. The instances host applications that use a hierarchical directory structure. The applications need to read and write rapidly and concurrently to shared storage. What should a solutions architect do to meet these requirements?

- A. Create an Amazon S3 bucket. Allow access from all the EC2 instances in the VPC.

- B. Create an Amazon Elastic File System (Amazon EFS) file system. Mount the EFS file system from each EC2 instance.

- C. Create a file system on a Provisioned IOPS SSD (io2) Amazon Elastic Block Store (Amazon EBS) volume. Attach the EBS volume to all the EC2 instances.

- D. Create file systems on Amazon Elastic Block Store (Amazon EBS) volumes that are attached to each EC2 instance. Synchronize the EBS volumes across the different EC2 instances.

**Correct:** B
**Why:** Amazon EFS provides shared POSIX file system semantics, high concurrency, and multi-AZ access for EC2 instances; ideal for hierarchical directory structures and concurrent read/write.

**Incorrect:**
- A: S3 is object storage, not a shared POSIX file system.
- C: EBS volumes cannot be concurrently attached to multiple instances across AZs for shared writes.
- D: EBS volumes cannot be concurrently attached to multiple instances across AZs for shared writes.


---

---

### Question #576

A company is building a RESTful serverless web application on AWS by using Amazon API Gateway and AWS Lambda. The users of this web application will be geographically distributed, and the company wants to reduce the latency of API requests to these users. Which type of endpoint should a solutions architect use to meet these requirements?

- A. Private endpoint

- B. Regional endpoint

- C. Interface VPC endpoint

- D. Edge-optimized endpoint

**Correct:** D
**Why:** Edge-optimized API Gateway endpoints use CloudFront to reduce latency for geographically distributed users.

**Incorrect:**
- A: Private endpoints are for VPC-only access.
- B: Regional endpoints don’t leverage global edge locations.
- C: Interface VPC endpoints are for private access within a VPC, not global latency reduction.


---

---

### Question #600

A company is planning to migrate a TCP-based application into the company's VPC. The application is publicly accessible on a nonstandard TCP port through a hardware appliance in the company's data center. This public endpoint can process up to 3 million requests per second with low latency. The company requires the same level of performance for the new public endpoint in AWS. What should a solutions architect recommend to meet this requirement?

- A. Deploy a Network Load Balancer (NLB). Configure the NLB to be publicly accessible over the TCP port that the application requires.

- B. Deploy an Application Load Balancer (ALB). Configure the ALB to be publicly accessible over the TCP port that the application requires.

- C. Deploy an Amazon CloudFront distribution that listens on the TCP port that the application requires. Use an Application Load Balancer as the origin.

- D. Deploy an Amazon API Gateway API that is congured with the TCP port that the application requires. Configure AWS Lambda functions with provisioned concurrency to process the requests.

**Correct:** A
**Why:** NLB supports millions of requests per second with low latency on arbitrary TCP ports.

**Incorrect:**
- B: ALB is HTTP/HTTPS (L7) and not optimized for raw TCP performance at this scale.
- C: CloudFront/API Gateway do not meet the raw TCP nonstandard port requirement.
- D: CloudFront/API Gateway do not meet the raw TCP nonstandard port requirement.


---

---

### Question #608

A company has an application that serves clients that are deployed in more than 20.000 retail storefront locations around the world. The application consists of backend web services that are exposed over HTTPS on port 443. The application is hosted on Amazon EC2 instances behind an Application Load Balancer (ALB). The retail locations communicate with the web application over the public internet. The company allows each retail location to register the IP address that the retail location has been allocated by its local ISP. The company's security team recommends to increase the security of the application endpoint by restricting access to only the IP addresses registered by the retail locations. What should a solutions architect do to meet these requirements?

- A. Associate an AWS WAF web ACL with the ALB. Use IP rule sets on the ALB to filter trac. Update the IP addresses in the rule to include the registered IP addresses.

- B. Deploy AWS Firewall Manager to manage the ALCongure firewall rules to restrict trac to the ALModify the firewall rules to include the registered IP addresses.

- C. Store the IP addresses in an Amazon DynamoDB table. Configure an AWS Lambda authorization function on the ALB to validate that incoming requests are from the registered IP addresses.

- D. Configure the network ACL on the subnet that contains the public interface of the ALB. Update the ingress rules on the network ACL with entries for each of the registered IP addresses.

**Correct:** A
**Why:** Attach an AWS WAF web ACL to the ALB with IP set rules; update the IP set with registered site IPs to restrict access.

**Incorrect:**
- B: Firewall Manager helps manage WAF across accounts but still relies on WAF/IP sets.
- C: ALB does not support Lambda authorizers; and DynamoDB storage is unnecessary.
- D: Network ACLs are coarse and hard to manage at scale.


---

---

### Question #610

A company deploys Amazon EC2 instances that run in a VPC. The EC2 instances load source data into Amazon S3 buckets so that the data can be processed in the future. According to compliance laws, the data must not be transmitted over the public internet. Servers in the company's on- premises data center will consume the output from an application that runs on the EC2 instances. Which solution will meet these requirements?

- A. Deploy an interface VPC endpoint for Amazon EC2. Create an AWS Site-to-Site VPN connection between the company and the VPC.

- B. Deploy a gateway VPC endpoint for Amazon S3. Set up an AWS Direct Connect connection between the on-premises network and the VPC.

- C. Set up an AWS Transit Gateway connection from the VPC to the S3 buckets. Create an AWS Site-to-Site VPN connection between the company and the VPC.

- D. Set up proxy EC2 instances that have routes to NAT gateways. Configure the proxy EC2 instances to fetch S3 data and feed the application instances.

**Correct:** B
**Why:** Use an S3 gateway endpoint for private access from EC2 to S3 and Direct Connect for private on‑prem access to VPC‑hosted outputs.

**Incorrect:**
- A: Do not provide private S3 access end‑to‑end without traversing the internet.
- C: Do not provide private S3 access end‑to‑end without traversing the internet.
- D: Do not provide private S3 access end‑to‑end without traversing the internet.


---

---

### Question #612

A company has an application that runs on Amazon EC2 instances in a private subnet. The application needs to process sensitive information from an Amazon S3 bucket. The application must not use the internet to connect to the S3 bucket. Which solution will meet these requirements?

- A. Configure an internet gateway. Update the S3 bucket policy to allow access from the internet gateway. Update the application to use the new internet gateway.

- B. Configure a VPN connection. Update the S3 bucket policy to allow access from the VPN connection. Update the application to use the new VPN connection.

- C. Configure a NAT gateway. Update the S3 bucket policy to allow access from the NAT gateway. Update the application to use the new NAT gateway.

- D. Configure a VPC endpoint. Update the S3 bucket policy to allow access from the VPC endpoint. Update the application to use the new VPC endpoint.

**Correct:** D
**Why:** Use an S3 VPC endpoint and bucket policy to allow access only via the endpoint. No internet path is used.

**Incorrect:**
- A: These traverse the internet or are unnecessary.
- B: These traverse the internet or are unnecessary.
- C: These traverse the internet or are unnecessary.


---

---

### Question #614

A company is designing a new multi-tier web application that consists of the following components: • Web and application servers that run on Amazon EC2 instances as part of Auto Scaling groups • An Amazon RDS DB instance for data storage A solutions architect needs to limit access to the application servers so that only the web servers can access them. Which solution will meet these requirements?

- A. Deploy AWS PrivateLink in front of the application servers. Configure the network ACL to allow only the web servers to access the application servers.

- B. Deploy a VPC endpoint in front of the application servers. Configure the security group to allow only the web servers to access the application servers.

- C. Deploy a Network Load Balancer with a target group that contains the application servers' Auto Scaling group. Configure the network ACL to allow only the web servers to access the application servers.

- D. Deploy an Application Load Balancer with a target group that contains the application servers' Auto Scaling group. Configure the security group to allow only the web servers to access the application servers.

**Correct:** D
**Why:** ALB for the app tier with security groups allowing only the web tier enforces tiered access cleanly.

**Incorrect:**
- A: PrivateLink/VPC endpoints don’t fit this intra‑VPC tiering model.
- B: PrivateLink/VPC endpoints don’t fit this intra‑VPC tiering model.
- C: NLB lacks L7 features; NACLs are coarse and stateless.


---

---

### Question #639

A company is building a new furniture inventory application. The company has deployed the application on a eet ofAmazon EC2 instances across multiple Availability Zones. The EC2 instances run behind an Application Load Balancer (ALB) in their VPC. A solutions architect has observed that incoming trac seems to favor one EC2 instance, resulting in latency for some requests. What should the solutions architect do to resolve this issue?

- A. Disable session anity (sticky sessions) on the ALB

- B. Replace the ALB with a Network Load Balancer

- C. Increase the number of EC2 instances in each Availability Zone

- D. Adjust the frequency of the health checks on the ALB's target group

**Correct:** A
**Why:** Sticky sessions (session affinity) can concentrate traffic; disabling distributes requests evenly among instances.

**Incorrect:**
- B: NLB doesn’t solve HTTP session stickiness issues.
- C: More instances treats symptoms but not root cause.
- D: Health check frequency isn’t the cause of imbalance.


---

---

### Question #654

A company recently migrated its web application to the AWS Cloud. The company uses an Amazon EC2 instance to run multiple processes to host the application. The processes include an Apache web server that serves static content. The Apache web server makes requests to a PHP application that uses a local Redis server for user sessions. The company wants to redesign the architecture to be highly available and to use AWS managed solutions. Which solution will meet these requirements?

- A. Use AWS Elastic Beanstalk to host the static content and the PHP application. Configure Elastic Beanstalk to deploy its EC2 instance into a public subnet. Assign a public IP address.

- B. Use AWS Lambda to host the static content and the PHP application. Use an Amazon API Gateway REST API to proxy requests to the Lambda function. Set the API Gateway CORS configuration to respond to the domain name. Configure Amazon ElastiCache for Redis to handle session information.

- C. Keep the backend code on the EC2 instance. Create an Amazon ElastiCache for Redis cluster that has Multi-AZ enabled. Configure the ElastiCache for Redis cluster in cluster mode. Copy the frontend resources to Amazon S3. Configure the backend code to reference the EC2 instance.

- D. Configure an Amazon CloudFront distribution with an Amazon S3 endpoint to an S3 bucket that is congured to host the static content. Configure an Application Load Balancer that targets an Amazon Elastic Container Service (Amazon ECS) service that runs AWS Fargate tasks for the PHP application. Configure the PHP application to use an Amazon ElastiCache for Redis cluster that runs in multiple Availability Zones.

**Correct:** D
**Why:** S3 + CloudFront for static assets; ECS Fargate behind ALB for PHP app; Redis (Multi‑AZ) for sessions meets HA with managed services.

**Incorrect:**
- A: Single EC2 in public subnet is not HA.
- B: Lambda for PHP monolith adds complexity and cold‑start concerns.
- C: Keeping backend on EC2 is not fully managed/HA.


---

---

### Question #657

A company has multiple AWS accounts in an organization in AWS Organizations that different business units use. The company has multiple oces around the world. The company needs to update security group rules to allow new oce CIDR ranges or to remove old CIDR ranges across the organization. The company wants to centralize the management of security group rules to minimize the administrative overhead that updating CIDR ranges requires. Which solution will meet these requirements MOST cost-effectively?

- A. Create VPC security groups in the organization's management account. Update the security groups when a CIDR range update is necessary.

- B. Create a VPC customer managed prex list that contains the list of CIDRs. Use AWS Resource Access Manager (AWS RAM) to share the prex list across the organization. Use the prex list in the security groups across the organization.

- C. Create an AWS managed prex list. Use an AWS Security Hub policy to enforce the security group update across the organization. Use an AWS Lambda function to update the prex list automatically when the CIDR ranges change.

- D. Create security groups in a central administrative AWS account. Create an AWS Firewall Manager common security group policy for the whole organization. Select the previously created security groups as primary groups in the policy.

**Correct:** B
**Why:** Create and share a VPC prefix list via RAM and reference it in security groups; update once to propagate across accounts.

**Incorrect:**
- A: Central SGs in one account don’t propagate automatically.
- C: No such AWS managed prefix list for office CIDRs with auto updates.
- D: Firewall Manager SG policies don’t centrally update IPs without a shared prefix list.


---

---

### Question #659

A company is relocating its data center and wants to securely transfer 50 TB of data to AWS within 2 weeks. The existing data center has a Site-to- Site VPN connection to AWS that is 90% utilized. Which AWS service should a solutions architect use to meet these requirements?

- A. AWS DataSync with a VPC endpoint

- B. AWS Direct Connect

- C. AWS Snowball Edge Storage Optimized

- D. AWS Storage Gateway

**Correct:** C
**Why:** Snowball Edge Storage Optimized transfers 50 TB securely within 2 weeks without saturating the VPN.

**Incorrect:**
- A: DataSync over congested VPN may miss the window.
- B: Direct Connect cannot be provisioned that quickly typically.
- D: Storage Gateway is not a bulk one‑time transfer solution.


---

---

### Question #663

A company is developing a new application on AWS. The application consists of an Amazon Elastic Container Service (Amazon ECS) cluster, an Amazon S3 bucket that contains assets for the application, and an Amazon RDS for MySQL database that contains the dataset for the application. The dataset contains sensitive information. The company wants to ensure that only the ECS cluster can access the data in the RDS for MySQL database and the data in the S3 bucket. Which solution will meet these requirements?

- A. Create a new AWS Key Management Service (AWS KMS) customer managed key to encrypt both the S3 bucket and the RDS for MySQL database. Ensure that the KMS key policy includes encrypt and decrypt permissions for the ECS task execution role.

- B. Create an AWS Key Management Service (AWS KMS) AWS managed key to encrypt both the S3 bucket and the RDS for MySQL database. Ensure that the S3 bucket policy species the ECS task execution role as a user.

- C. Create an S3 bucket policy that restricts bucket access to the ECS task execution role. Create a VPC endpoint for Amazon RDS for MySQL. Update the RDS for MySQL security group to allow access from only the subnets that the ECS cluster will generate tasks in.

- D. Create a VPC endpoint for Amazon RDS for MySQL. Update the RDS for MySQL security group to allow access from only the subnets that the ECS cluster will generate tasks in. Create a VPC endpoint for Amazon S3. Update the S3 bucket policy to allow access from only the S3 VPC endpoint.

**Correct:** C
**Why:** Restrict S3 bucket access to the ECS task execution role, and tighten RDS access via security groups to only the ECS task subnets; combined, only the ECS tasks can reach data.

**Incorrect:**
- A: KMS encryption alone doesn’t restrict principal network/data access.
- B: KMS encryption alone doesn’t restrict principal network/data access.
- D: There is no VPC endpoint for RDS database connections; S3 endpoint restriction is good, but RDS SG is the right control.


---

---

### Question #667

A company is moving its data and applications to AWS during a multiyear migration project. The company wants to securely access data on Amazon S3 from the company's AWS Region and from the company's on-premises location. The data must not traverse the internet. The company has established an AWS Direct Connect connection between its Region and its on-premises location. Which solution will meet these requirements?

- A. Create gateway endpoints for Amazon S3. Use the gateway endpoints to securely access the data from the Region and the on-premises location.

- B. Create a gateway in AWS Transit Gateway to access Amazon S3 securely from the Region and the on-premises location.

- C. Create interface endpoints for Amazon S3. Use the interface endpoints to securely access the data from the Region and the on-premises location.

- D. Use an AWS Key Management Service (AWS KMS) key to access the data securely from the Region and the on-premises location.

**Correct:** C
**Why:** S3 interface endpoints (PrivateLink) allow private S3 access inside a VPC. Over Direct Connect private VIF, on‑prem can reach those endpoints without internet.

**Incorrect:**
- A: Gateway endpoints are not reachable from on‑prem.
- B: Transit Gateway does not provide S3 service access.
- D: KMS keys don’t provide network‑private access.


---

---

### Question #674

A company runs a web application on Amazon EC2 instances in an Auto Scaling group. The application uses a database that runs on an Amazon RDS for PostgreSQL DB instance. The application performs slowly when trac increases. The database experiences a heavy read load during periods of high trac. Which actions should a solutions architect take to resolve these performance issues? (Choose two.)

- A. Turn on auto scaling for the DB instance.

- B. Create a read replica for the DB instance. Configure the application to send read trac to the read replica.

- C. Convert the DB instance to a Multi-AZ DB instance deployment. Configure the application to send read trac to the standby DB instance.

- D. Create an Amazon ElastiCache cluster. Configure the application to cache query results in the ElastiCache cluster.

E. Configure the Auto Scaling group subnets to ensure that the EC2 instances are provisioned in the same Availability Zone as the DB instance.

**Correct:** B, D
**Why:** Offload read traffic to an RDS read replica and/or cache frequent queries in ElastiCache to reduce DB load and improve response times.

**Incorrect:**
- A: RDS compute does not auto scale; this doesn’t solve read pressure.
- C: Multi‑AZ standby is not readable.


---

---

### Question #676

A company's application uses Network Load Balancers, Auto Scaling groups, Amazon EC2 instances, and databases that are deployed in an Amazon VPC. The company wants to capture information about trac to and from the network interfaces in near real time in its Amazon VPC. The company wants to send the information to Amazon OpenSearch Service for analysis. Which solution will meet these requirements?

- A. Create a log group in Amazon CloudWatch Logs. Configure VPC Flow Logs to send the log data to the log group. Use Amazon Kinesis Data Streams to stream the logs from the log group to OpenSearch Service.

- B. Create a log group in Amazon CloudWatch Logs. Configure VPC Flow Logs to send the log data to the log group. Use Amazon Kinesis Data Firehose to stream the logs from the log group to OpenSearch Service.

- C. Create a trail in AWS CloudTrail. Configure VPC Flow Logs to send the log data to the trail. Use Amazon Kinesis Data Streams to stream the logs from the trail to OpenSearch Service.

- D. Create a trail in AWS CloudTrail. Configure VPC Flow Logs to send the log data to the trail. Use Amazon Kinesis Data Firehose to stream the logs from the trail to OpenSearch Service.

**Correct:** B
**Why:** Send VPC Flow Logs to CloudWatch Logs, then stream to OpenSearch Service with Kinesis Data Firehose for near real‑time analysis.

**Incorrect:**
- A: Data Streams adds custom consumer management; Firehose is simpler.
- C: CloudTrail is not used for VPC Flow Logs delivery.
- D: CloudTrail is not used for VPC Flow Logs delivery.


---

---

### Question #680

A solutions architect needs to copy files from an Amazon S3 bucket to an Amazon Elastic File System (Amazon EFS) file system and another S3 bucket. The files must be copied continuously. New files are added to the original S3 bucket consistently. The copied files should be overwritten only if the source file changes. Which solution will meet these requirements with the LEAST operational overhead?

- A. Create an AWS DataSync location for both the destination S3 bucket and the EFS file system. Create a task for the destination S3 bucket and the EFS file system. Set the transfer mode to transfer only data that has changed.

- B. Create an AWS Lambda function. Mount the file system to the function. Set up an S3 event notification to invoke the function when files are created and changed in Amazon S3. Configure the function to copy files to the file system and the destination S3 bucket.

- C. Create an AWS DataSync location for both the destination S3 bucket and the EFS file system. Create a task for the destination S3 bucket and the EFS file system. Set the transfer mode to transfer all data.

- D. Launch an Amazon EC2 instance in the same VPC as the file system. Mount the file system. Create a script to routinely synchronize all objects that changed in the origin S3 bucket to the destination S3 bucket and the mounted file system.

**Correct:** A
**Why:** AWS DataSync supports continuous copies S3→S3 and S3→EFS with change‑only transfers, minimizing overhead and avoiding unnecessary overwrites.

**Incorrect:**
- B: Lambda + mount is complex and not ideal for continuous, scalable sync.
- C: Transfer all data is inefficient and increases costs.
- D: EC2 + scripts adds ops and reliability risks.


---

---

### Question #684

A company wants to migrate its web applications from on premises to AWS. The company is located close to the eu-central-1 Region. Because of regulations, the company cannot launch some of its applications in eu-central-1. The company wants to achieve single-digit millisecond latency. Which solution will meet these requirements?

- A. Deploy the applications in eu-central-1. Extend the company’s VPC from eu-central-1 to an edge location in Amazon CloudFront.

- B. Deploy the applications in AWS Local Zones by extending the company's VPC from eu-central-1 to the chosen Local Zone.

- C. Deploy the applications in eu-central-1. Extend the company’s VPC from eu-central-1 to the regional edge caches in Amazon CloudFront.

- D. Deploy the applications in AWS Wavelength Zones by extending the company’s VPC from eu-central-1 to the chosen Wavelength Zone.

**Correct:** B
**Why:** Deploy to AWS Local Zones to achieve single‑digit ms latency near the users while associating with eu‑central‑1 control plane; CloudFront/Wavelength do not host the applications.

**Incorrect:**
- A: CloudFront cannot host applications; only caches content.
- C: CloudFront cannot host applications; only caches content.
- D: Wavelength Zones target 5G/mobile edge and are not general app hosting replacements.


---

## Elastic Load Balancing (ALB/NLB/GWLB)

### Question #502

A company runs a website that uses a content management system (CMS) on Amazon EC2. The CMS runs on a single EC2 instance and uses an Amazon Aurora MySQL Multi-AZ DB instance for the data tier. Website images are stored on an Amazon Elastic Block Store (Amazon EBS) volume that is mounted inside the EC2 instance. Which combination of actions should a solutions architect take to improve the performance and resilience of the website? (Choose two.)

- A. Move the website images into an Amazon S3 bucket that is mounted on every EC2 instance

- B. Share the website images by using an NFS share from the primary EC2 instance. Mount this share on the other EC2 instances.

- C. Move the website images onto an Amazon Elastic File System (Amazon EFS) file system that is mounted on every EC2 instance.

- D. Create an Amazon Machine Image (AMI) from the existing EC2 instance. Use the AMI to provision new instances behind an Application Load Balancer as part of an Auto Scaling group. Configure the Auto Scaling group to maintain a minimum of two instances. Configure an accelerator in AWS Global Accelerator for the website

E. Create an Amazon Machine Image (AMI) from the existing EC2 instance. Use the AMI to provision new instances behind an Application Load Balancer as part of an Auto Scaling group. Configure the Auto Scaling group to maintain a minimum of two instances. Configure an Amazon CloudFront distribution for the website.

**Correct:** C, E
**Why:** Move images to EFS for shared, scalable storage; use ALB+Auto Scaling behind a CloudFront distribution for performance and resilience.

**Incorrect:**
- A: S3 mounted or EC2 NFS via a primary instance are not ideal.
- B: S3 mounted or EC2 NFS via a primary instance are not ideal.
- D: Global Accelerator is unnecessary for origin performance here.


---

---

### Question #509

A company operates a two-tier application for image processing. The application uses two Availability Zones, each with one public subnet and one private subnet. An Application Load Balancer (ALB) for the web tier uses the public subnets. Amazon EC2 instances for the application tier use the private subnets. Users report that the application is running more slowly than expected. A security audit of the web server log files shows that the application is receiving millions of illegitimate requests from a small number of IP addresses. A solutions architect needs to resolve the immediate performance problem while the company investigates a more permanent solution. What should the solutions architect recommend to meet this requirement?

- A. Modify the inbound security group for the web tier. Add a deny rule for the IP addresses that are consuming resources.

- B. Modify the network ACL for the web tier subnets. Add an inbound deny rule for the IP addresses that are consuming resources.

- C. Modify the inbound security group for the application tier. Add a deny rule for the IP addresses that are consuming resources.

- D. Modify the network ACL for the application tier subnets. Add an inbound deny rule for the IP addresses that are consuming resources.

**Correct:** B
**Why:** NACLs support explicit deny rules by IP to immediately block abusive sources on the web subnets.

**Incorrect:**
- A: Security groups are allow‑only—no deny rules.
- C: Security groups are allow‑only—no deny rules.
- D: Block at the web tier first, not the app subnets.


---

---

### Question #516

A company provides an API interface to customers so the customers can retrieve their nancial information. Е he company expects a larger number of requests during peak usage times of the year. The company requires the API to respond consistently with low latency to ensure customer satisfaction. The company needs to provide a compute host for the API. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use an Application Load Balancer and Amazon Elastic Container Service (Amazon ECS).

- B. Use Amazon API Gateway and AWS Lambda functions with provisioned concurrency.

- C. Use an Application Load Balancer and an Amazon Elastic Kubernetes Service (Amazon EKS) cluster.

- D. Use Amazon API Gateway and AWS Lambda functions with reserved concurrency.

**Correct:** B
**Why:** API Gateway + Lambda with provisioned concurrency delivers consistently low latency with minimal ops.

**Incorrect:**
- A: ALB+ECS/EKS add cluster ops.
- C: ALB+ECS/EKS add cluster ops.
- D: Reserved concurrency controls throughput but doesn’t remove cold starts.


---

---

### Question #527

A company has a regional subscription-based streaming service that runs in a single AWS Region. The architecture consists of web servers and application servers on Amazon EC2 instances. The EC2 instances are in Auto Scaling groups behind Elastic Load Balancers. The architecture includes an Amazon Aurora global database cluster that extends across multiple Availability Zones. The company wants to expand globally and to ensure that its application has minimal downtime. Which solution will provide the MOST fault tolerance?

- A. Extend the Auto Scaling groups for the web tier and the application tier to deploy instances in Availability Zones in a second Region. Use an Aurora global database to deploy the database in the primary Region and the second Region. Use Amazon Route 53 health checks with a failover routing policy to the second Region.

- B. Deploy the web tier and the application tier to a second Region. Add an Aurora PostgreSQL cross-Region Aurora Replica in the second Region. Use Amazon Route 53 health checks with a failover routing policy to the second Region. Promote the secondary to primary as needed.

- C. Deploy the web tier and the application tier to a second Region. Create an Aurora PostgreSQL database in the second Region. Use AWS Database Migration Service (AWS DMS) to replicate the primary database to the second Region. Use Amazon Route 53 health checks with a failover routing policy to the second Region.

- D. Deploy the web tier and the application tier to a second Region. Use an Amazon Aurora global database to deploy the database in the primary Region and the second Region. Use Amazon Route 53 health checks with a failover routing policy to the second Region. Promote the secondary to primary as needed.

**Correct:** D
**Why:** Deploy app tiers in a second Region and use Aurora Global Database plus Route 53 failover for maximal fault tolerance.

**Incorrect:**
- A: Less integrated or slower replication and more manual promotion.
- B: Less integrated or slower replication and more manual promotion.
- C: Less integrated or slower replication and more manual promotion.


---

---

### Question #530

A company has an online gaming application that has TCP and UDP multiplayer gaming capabilities. The company uses Amazon Route 53 to point the application trac to multiple Network Load Balancers (NLBs) in different AWS Regions. The company needs to improve application performance and decrease latency for the online game in preparation for user growth. Which solution will meet these requirements?

- A. Add an Amazon CloudFront distribution in front of the NLBs. Increase the Cache-Control max-age parameter.

- B. Replace the NLBs with Application Load Balancers (ALBs). Configure Route 53 to use latency-based routing.

- C. Add AWS Global Accelerator in front of the NLBs. Configure a Global Accelerator endpoint to use the correct listener ports.

- D. Add an Amazon API Gateway endpoint behind the NLBs. Enable API caching. Override method caching for the different stages.

**Correct:** C
**Why:** Global Accelerator improves global TCP/UDP performance with anycast IPs in front of NLBs.

**Incorrect:**
- A: CloudFront/ALB/API Gateway are not suited for arbitrary TCP/UDP improvements.
- B: CloudFront/ALB/API Gateway are not suited for arbitrary TCP/UDP improvements.
- D: CloudFront/ALB/API Gateway are not suited for arbitrary TCP/UDP improvements.


---

---

### Question #531

A company needs to integrate with a third-party data feed. The data feed sends a webhook to notify an external service when new data is ready for consumption. A developer wrote an AWS Lambda function to retrieve data when the company receives a webhook callback. The developer must make the Lambda function available for the third party to call. Which solution will meet these requirements with the MOST operational eciency?

- A. Create a function URL for the Lambda function. Provide the Lambda function URL to the third party for the webhook.

- B. Deploy an Application Load Balancer (ALB) in front of the Lambda function. Provide the ALB URL to the third party for the webhook.

- C. Create an Amazon Simple Notification Service (Amazon SNS) topic. Attach the topic to the Lambda function. Provide the public hostname of the SNS topic to the third party for the webhook.

- D. Create an Amazon Simple Queue Service (Amazon SQS) queue. Attach the queue to the Lambda function. Provide the public hostname of the SQS queue to the third party for the webhook.

**Correct:** A
**Why:** Lambda function URLs expose HTTPS endpoints directly for webhook callbacks with minimal ops.

**Incorrect:**
- B: ALB/SNS/SQS add unnecessary components for a simple webhook.
- C: ALB/SNS/SQS add unnecessary components for a simple webhook.
- D: ALB/SNS/SQS add unnecessary components for a simple webhook.


---

---

### Question #537

A company runs a three-tier web application in the AWS Cloud that operates across three Availability Zones. The application architecture has an Application Load Balancer, an Amazon EC2 web server that hosts user session states, and a MySQL database that runs on an EC2 instance. The company expects sudden increases in application trac. The company wants to be able to scale to meet future application capacity demands and to ensure high availability across all three Availability Zones. Which solution will meet these requirements?

- A. Migrate the MySQL database to Amazon RDS for MySQL with a Multi-AZ DB cluster deployment. Use Amazon ElastiCache for Redis with high availability to store session data and to cache reads. Migrate the web server to an Auto Scaling group that is in three Availability Zones.

- B. Migrate the MySQL database to Amazon RDS for MySQL with a Multi-AZ DB cluster deployment. Use Amazon ElastiCache for Memcached with high availability to store session data and to cache reads. Migrate the web server to an Auto Scaling group that is in three Availability Zones.

- C. Migrate the MySQL database to Amazon DynamoDB Use DynamoDB Accelerator (DAX) to cache reads. Store the session data in DynamoDB. Migrate the web server to an Auto Scaling group that is in three Availability Zones.

- D. Migrate the MySQL database to Amazon RDS for MySQL in a single Availability Zone. Use Amazon ElastiCache for Redis with high availability to store session data and to cache reads. Migrate the web server to an Auto Scaling group that is in three Availability Zones.

**Correct:** A
**Why:** RDS MySQL Multi‑AZ DB cluster for HA, ElastiCache Redis for sessions/cache, and an ASG across three AZs meets scale and HA goals.

**Incorrect:**
- B: Memcached lacks persistence/HA and is less preferred for sessions.
- C: Rewriting to DynamoDB is unnecessary.
- D: Single‑AZ DB is not highly available.


---

---

### Question #541

A company wants to build a web application on AWS. Client access requests to the website are not predictable and can be idle for a long time. Only customers who have paid a subscription fee can have the ability to sign in and use the web application. Which combination of steps will meet these requirements MOST cost-effectively? (Choose three.)

- A. Create an AWS Lambda function to retrieve user information from Amazon DynamoDB. Create an Amazon API Gateway endpoint to accept RESTful APIs. Send the API calls to the Lambda function.

- B. Create an Amazon Elastic Container Service (Amazon ECS) service behind an Application Load Balancer to retrieve user information from Amazon RDS. Create an Amazon API Gateway endpoint to accept RESTful APIs. Send the API calls to the Lambda function.

- C. Create an Amazon Cognito user pool to authenticate users.

- D. Create an Amazon Cognito identity pool to authenticate users.

E. Use AWS Amplify to serve the frontend web content with HTML, CSS, and JS. Use an integrated Amazon CloudFront configuration.

F. Use Amazon S3 static web hosting with PHP, CSS, and JS. Use Amazon CloudFront to serve the frontend web content.

**Correct:** A, C, E
**Why:** Serverless API (API Gateway → Lambda) is cost‑effective for spiky/idle loads; Cognito user pool handles subscription auth; Amplify hosts frontend with integrated CloudFront.

**Incorrect:**
- B: ECS/EC2 PHP or identity pools are unnecessary here.
- D: ECS/EC2 PHP or identity pools are unnecessary here.
- F: ECS/EC2 PHP or identity pools are unnecessary here.


---

---

### Question #545

A company wants to direct its users to a backup static error page if the company's primary website is unavailable. The primary website's DNS records are hosted in Amazon Route 53. The domain is pointing to an Application Load Balancer (ALB). The company needs a solution that minimizes changes and infrastructure overhead. Which solution will meet these requirements?

- A. Update the Route 53 records to use a latency routing policy. Add a static error page that is hosted in an Amazon S3 bucket to the records so that the trac is sent to the most responsive endpoints.

- B. Set up a Route 53 active-passive failover configuration. Direct trac to a static error page that is hosted in an Amazon S3 bucket when Route 53 health checks determine that the ALB endpoint is unhealthy.

- C. Set up a Route 53 active-active configuration with the ALB and an Amazon EC2 instance that hosts a static error page as endpoints. Configure Route 53 to send requests to the instance only if the health checks fail for the ALB.

- D. Update the Route 53 records to use a multivalue answer routing policy. Create a health check. Direct trac to the website if the health check passes. Direct trac to a static error page that is hosted in Amazon S3 if the health check does not pass.

**Correct:** B
**Why:** Route 53 active‑passive failover to an S3 static error page when ALB health checks fail—minimal infra/changes.

**Incorrect:**
- A: Latency/multivalue policies don’t provide ALB health‑based failover to S3.
- C: Maintaining EC2 for a static page adds ops.
- D: Latency/multivalue policies don’t provide ALB health‑based failover to S3.


---

---

### Question #549

A company has created a multi-tier application for its ecommerce website. The website uses an Application Load Balancer that resides in the public subnets, a web tier in the public subnets, and a MySQL cluster hosted on Amazon EC2 instances in the private subnets. The MySQL database needs to retrieve product catalog and pricing information that is hosted on the internet by a third-party provider. A solutions architect must devise a strategy that maximizes security without increasing operational overhead. What should the solutions architect do to meet these requirements?

- A. Deploy a NAT instance in the VPC. Route all the internet-based trac through the NAT instance.

- B. Deploy a NAT gateway in the public subnets. Modify the private subnet route table to direct all internet-bound trac to the NAT gateway.

- C. Configure an internet gateway and attach it to the VPModify the private subnet route table to direct internet-bound trac to the internet gateway.

- D. Configure a virtual private gateway and attach it to the VPC. Modify the private subnet route table to direct internet-bound trac to the virtual private gateway.

**Correct:** B
**Why:** A NAT gateway in a public subnet provides secure outbound internet from private subnets without exposing instances.

**Incorrect:**
- A: NAT instance adds ops.
- C: IGW/VGW are not for private outbound egress.
- D: IGW/VGW are not for private outbound egress.


---

---

### Question #559

A company hosts multiple applications on AWS for different product lines. The applications use different compute resources, including Amazon EC2 instances and Application Load Balancers. The applications run in different AWS accounts under the same organization in AWS Organizations across multiple AWS Regions. Teams for each product line have tagged each compute resource in the individual accounts. The company wants more details about the cost for each product line from the consolidated billing feature in Organizations. Which combination of steps will meet these requirements? (Choose two.)

- A. Select a specic AWS generated tag in the AWS Billing console.

- B. Select a specic user-dened tag in the AWS Billing console.

- C. Select a specic user-dened tag in the AWS Resource Groups console.

- D. Activate the selected tag from each AWS account.

E. Activate the selected tag from the Organizations management account.

**Correct:** B, E
**Why:** Use a specific user-defined cost allocation tag and activate it in the AWS Billing console of the Organizations management (payer) account to surface costs by tag across linked accounts.

**Incorrect:**
- A: AWS-generated tags are limited in usefulness and not aligned to product lines.
- C: Resource Groups is not where cost allocation tags are activated for billing.
- D: Tag activation for consolidated billing is performed in the management account, not individually in each member account.


---

---

### Question #567

A solutions architect is designing a workload that will store hourly energy consumption by business tenants in a building. The sensors will feed a database through HTTP requests that will add up usage for each tenant. The solutions architect must use managed services when possible. The workload will receive more features in the future as the solutions architect adds independent components. Which solution will meet these requirements with the LEAST operational overhead?

- A. Use Amazon API Gateway with AWS Lambda functions to receive the data from the sensors, process the data, and store the data in an Amazon DynamoDB table.

- B. Use an Elastic Load Balancer that is supported by an Auto Scaling group of Amazon EC2 instances to receive and process the data from the sensors. Use an Amazon S3 bucket to store the processed data.

- C. Use Amazon API Gateway with AWS Lambda functions to receive the data from the sensors, process the data, and store the data in a Microsoft SQL Server Express database on an Amazon EC2 instance.

- D. Use an Elastic Load Balancer that is supported by an Auto Scaling group of Amazon EC2 instances to receive and process the data from the sensors. Use an Amazon Elastic File System (Amazon EFS) shared file system to store the processed data.

**Correct:** A
**Why:** API Gateway + Lambda gives a fully managed, serverless, event-driven ingestion and processing path with low overhead and easy future extensibility; store results in DynamoDB.

**Incorrect:**
- B: ELB + EC2 adds operational burden and is not necessary for simple HTTP ingest.
- C: EC2-hosted SQL Server Express increases ops overhead and reduces elasticity.
- D: ELB + EC2 adds operational burden and is not necessary for simple HTTP ingest.


---

---

### Question #575

A company deploys its applications on Amazon Elastic Kubernetes Service (Amazon EKS) behind an Application Load Balancer in an AWS Region. The application needs to store data in a PostgreSQL database engine. The company wants the data in the database to be highly available. The company also needs increased capacity for read workloads. Which solution will meet these requirements with the MOST operational eciency?

- A. Create an Amazon DynamoDB database table congured with global tables.

- B. Create an Amazon RDS database with Multi-AZ deployments.

- C. Create an Amazon RDS database with Multi-AZ DB cluster deployment.

- D. Create an Amazon RDS database congured with cross-Region read replicas.

**Correct:** C
**Why:** RDS Multi-AZ DB cluster deployment provides high availability and additional reader capacity through readable standbys for read scaling.

**Incorrect:**
- A: DynamoDB is not a PostgreSQL engine.
- B: Traditional Multi-AZ (single-standby) does not provide increased read capacity.
- D: Cross-Region read replicas add latency/complexity and are for DR, not primary read scaling.


---

---

### Question #587

A company is designing a solution to capture customer activity in different web applications to process analytics and make predictions. Customer activity in the web applications is unpredictable and can increase suddenly. The company requires a solution that integrates with other web applications. The solution must include an authorization step for security purposes. Which solution will meet these requirements?

- A. Configure a Gateway Load Balancer (GWLB) in front of an Amazon Elastic Container Service (Amazon ECS) container instance that stores the information that the company receives in an Amazon Elastic File System (Amazon EFS) file system. Authorization is resolved at the GWLB.

- B. Configure an Amazon API Gateway endpoint in front of an Amazon Kinesis data stream that stores the information that the company receives in an Amazon S3 bucket. Use an AWS Lambda function to resolve authorization.

- C. Configure an Amazon API Gateway endpoint in front of an Amazon Kinesis Data Firehose that stores the information that the company receives in an Amazon S3 bucket. Use an API Gateway Lambda authorizer to resolve authorization.

- D. Configure a Gateway Load Balancer (GWLB) in front of an Amazon Elastic Container Service (Amazon ECS) container instance that stores the information that the company receives on an Amazon Elastic File System (Amazon EFS) file system. Use an AWS Lambda function to resolve authorization.

**Correct:** C
**Why:** API Gateway with a Lambda authorizer provides auth. Kinesis Data Firehose scales ingestion and delivers to S3 with minimal ops overhead.

**Incorrect:**
- A: GWLB + ECS introduces heavy ops complexity for simple event ingestion.
- B: API Gateway to Kinesis Data Streams is viable but requires more scaling/consumer management than Firehose for S3 delivery.
- D: GWLB + ECS introduces heavy ops complexity for simple event ingestion.


---

---

### Question #589

A company runs a web application on Amazon EC2 instances in an Auto Scaling group behind an Application Load Balancer that has sticky sessions enabled. The web server currently hosts the user session state. The company wants to ensure high availability and avoid user session state loss in the event of a web server outage. Which solution will meet these requirements?

- A. Use an Amazon ElastiCache for Memcached instance to store the session data. Update the application to use ElastiCache for Memcached to store the session state.

- B. Use Amazon ElastiCache for Redis to store the session state. Update the application to use ElastiCache for Redis to store the session state.

- C. Use an AWS Storage Gateway cached volume to store session data. Update the application to use AWS Storage Gateway cached volume to store the session state.

- D. Use Amazon RDS to store the session state. Update the application to use Amazon RDS to store the session state.

**Correct:** B
**Why:** ElastiCache for Redis supports durable, highly available session storage and eliminates dependency on individual web servers.

**Incorrect:**
- A: Memcached lacks persistence and robust HA.
- C: Storage Gateway is not for session storage.
- D: RDS adds latency/overhead vs. an in‑memory cache for sessions.


---

---

### Question #591

A company runs a container application by using Amazon Elastic Kubernetes Service (Amazon EKS). The application includes microservices that manage customers and place orders. The company needs to route incoming requests to the appropriate microservices. Which solution will meet this requirement MOST cost-effectively?

- A. Use the AWS Load Balancer Controller to provision a Network Load Balancer.

- B. Use the AWS Load Balancer Controller to provision an Application Load Balancer.

- C. Use an AWS Lambda function to connect the requests to Amazon EKS.

- D. Use Amazon API Gateway to connect the requests to Amazon EKS.

**Correct:** B
**Why:** The AWS Load Balancer Controller can provision an ALB for path/host routing to EKS microservices cost‑effectively.

**Incorrect:**
- A: NLB is L4 and not suited for HTTP routing across microservices.
- C: Lambda or API Gateway add unnecessary abstraction and cost.
- D: Lambda or API Gateway add unnecessary abstraction and cost.


---

---

### Question #592

A company uses AWS and sells access to copyrighted images. The company’s global customer base needs to be able to access these images quickly. The company must deny access to users from specic countries. The company wants to minimize costs as much as possible. Which solution will meet these requirements?

- A. Use Amazon S3 to store the images. Turn on multi-factor authentication (MFA) and public bucket access. Provide customers with a link to the S3 bucket.

- B. Use Amazon S3 to store the images. Create an IAM user for each customer. Add the users to a group that has permission to access the S3 bucket.

- C. Use Amazon EC2 instances that are behind Application Load Balancers (ALBs) to store the images. Deploy the instances only in the countries the company services. Provide customers with links to the ALBs for their specic country's instances.

- D. Use Amazon S3 to store the images. Use Amazon CloudFront to distribute the images with geographic restrictions. Provide a signed URL for each customer to access the data in CloudFront.

**Correct:** D
**Why:** S3 with CloudFront provides low‑latency global delivery. Geo restrictions and signed URLs enforce country blocks and per‑customer access.

**Incorrect:**
- A: Public buckets or per‑user IAM are insecure or operationally heavy.
- B: Public buckets or per‑user IAM are insecure or operationally heavy.
- C: EC2 + ALB for serving files is costly and complex.


---

---

### Question #600

A company is planning to migrate a TCP-based application into the company's VPC. The application is publicly accessible on a nonstandard TCP port through a hardware appliance in the company's data center. This public endpoint can process up to 3 million requests per second with low latency. The company requires the same level of performance for the new public endpoint in AWS. What should a solutions architect recommend to meet this requirement?

- A. Deploy a Network Load Balancer (NLB). Configure the NLB to be publicly accessible over the TCP port that the application requires.

- B. Deploy an Application Load Balancer (ALB). Configure the ALB to be publicly accessible over the TCP port that the application requires.

- C. Deploy an Amazon CloudFront distribution that listens on the TCP port that the application requires. Use an Application Load Balancer as the origin.

- D. Deploy an Amazon API Gateway API that is congured with the TCP port that the application requires. Configure AWS Lambda functions with provisioned concurrency to process the requests.

**Correct:** A
**Why:** NLB supports millions of requests per second with low latency on arbitrary TCP ports.

**Incorrect:**
- B: ALB is HTTP/HTTPS (L7) and not optimized for raw TCP performance at this scale.
- C: CloudFront/API Gateway do not meet the raw TCP nonstandard port requirement.
- D: CloudFront/API Gateway do not meet the raw TCP nonstandard port requirement.


---

---

### Question #608

A company has an application that serves clients that are deployed in more than 20.000 retail storefront locations around the world. The application consists of backend web services that are exposed over HTTPS on port 443. The application is hosted on Amazon EC2 instances behind an Application Load Balancer (ALB). The retail locations communicate with the web application over the public internet. The company allows each retail location to register the IP address that the retail location has been allocated by its local ISP. The company's security team recommends to increase the security of the application endpoint by restricting access to only the IP addresses registered by the retail locations. What should a solutions architect do to meet these requirements?

- A. Associate an AWS WAF web ACL with the ALB. Use IP rule sets on the ALB to filter trac. Update the IP addresses in the rule to include the registered IP addresses.

- B. Deploy AWS Firewall Manager to manage the ALCongure firewall rules to restrict trac to the ALModify the firewall rules to include the registered IP addresses.

- C. Store the IP addresses in an Amazon DynamoDB table. Configure an AWS Lambda authorization function on the ALB to validate that incoming requests are from the registered IP addresses.

- D. Configure the network ACL on the subnet that contains the public interface of the ALB. Update the ingress rules on the network ACL with entries for each of the registered IP addresses.

**Correct:** A
**Why:** Attach an AWS WAF web ACL to the ALB with IP set rules; update the IP set with registered site IPs to restrict access.

**Incorrect:**
- B: Firewall Manager helps manage WAF across accounts but still relies on WAF/IP sets.
- C: ALB does not support Lambda authorizers; and DynamoDB storage is unnecessary.
- D: Network ACLs are coarse and hard to manage at scale.


---

---

### Question #611

A company has an application with a REST-based interface that allows data to be received in near-real time from a third-party vendor. Once received, the application processes and stores the data for further analysis. The application is running on Amazon EC2 instances. The third-party vendor has received many 503 Service Unavailable Errors when sending data to the application. When the data volume spikes, the compute capacity reaches its maximum limit and the application is unable to process all requests. Which design should a solutions architect recommend to provide a more scalable solution?

- A. Use Amazon Kinesis Data Streams to ingest the data. Process the data using AWS Lambda functions.

- B. Use Amazon API Gateway on top of the existing application. Create a usage plan with a quota limit for the third-party vendor.

- C. Use Amazon Simple Notification Service (Amazon SNS) to ingest the data. Put the EC2 instances in an Auto Scaling group behind an Application Load Balancer.

- D. Repackage the application as a container. Deploy the application using Amazon Elastic Container Service (Amazon ECS) using the EC2 launch type with an Auto Scaling group.

**Correct:** A
**Why:** Kinesis Data Streams buffers spikes and decouples producers from consumers; Lambda scales to process without 503s.

**Incorrect:**
- B: API Gateway with quotas throttles the vendor rather than scaling.
- C: SNS is pub/sub and not ideal for high‑throughput buffering + ordering.
- D: ECS on EC2 still faces sudden capacity limits without a buffer.


---

---

### Question #614

A company is designing a new multi-tier web application that consists of the following components: • Web and application servers that run on Amazon EC2 instances as part of Auto Scaling groups • An Amazon RDS DB instance for data storage A solutions architect needs to limit access to the application servers so that only the web servers can access them. Which solution will meet these requirements?

- A. Deploy AWS PrivateLink in front of the application servers. Configure the network ACL to allow only the web servers to access the application servers.

- B. Deploy a VPC endpoint in front of the application servers. Configure the security group to allow only the web servers to access the application servers.

- C. Deploy a Network Load Balancer with a target group that contains the application servers' Auto Scaling group. Configure the network ACL to allow only the web servers to access the application servers.

- D. Deploy an Application Load Balancer with a target group that contains the application servers' Auto Scaling group. Configure the security group to allow only the web servers to access the application servers.

**Correct:** D
**Why:** ALB for the app tier with security groups allowing only the web tier enforces tiered access cleanly.

**Incorrect:**
- A: PrivateLink/VPC endpoints don’t fit this intra‑VPC tiering model.
- B: PrivateLink/VPC endpoints don’t fit this intra‑VPC tiering model.
- C: NLB lacks L7 features; NACLs are coarse and stateless.


---

---

### Question #616

A company has deployed its newest product on AWS. The product runs in an Auto Scaling group behind a Network Load Balancer. The company stores the product’s objects in an Amazon S3 bucket. The company recently experienced malicious attacks against its systems. The company needs a solution that continuously monitors for malicious activity in the AWS account, workloads, and access patterns to the S3 bucket. The solution must also report suspicious activity and display the information on a dashboard. Which solution will meet these requirements?

- A. Configure Amazon Macie to monitor and report ndings to AWS Cong.

- B. Configure Amazon Inspector to monitor and report ndings to AWS CloudTrail.

- C. Configure Amazon GuardDuty to monitor and report ndings to AWS Security Hub.

- D. Configure AWS Cong to monitor and report ndings to Amazon EventBridge.

**Correct:** C
**Why:** GuardDuty continuously monitors account, workload, and S3 access for threats; Security Hub aggregates and dashboards findings.

**Incorrect:**
- A: Macie focuses on sensitive data discovery, not threat detection.
- B: Inspector is for vulnerability assessment, not S3 access/threat patterns.
- D: Config tracks resource configuration, not threat activity.


---

---

### Question #625

A company is hosting a website behind multiple Application Load Balancers. The company has different distribution rights for its content around the world. A solutions architect needs to ensure that users are served the correct content without violating distribution rights. Which configuration should the solutions architect choose to meet these requirements?

- A. Configure Amazon CloudFront with AWS WAF.

- B. Configure Application Load Balancers with AWS WAF

- C. Configure Amazon Route 53 with a geolocation policy

- D. Configure Amazon Route 53 with a geoproximity routing policy

**Correct:** C
**Why:** Route 53 geolocation routing serves content based on user location across multiple ALB endpoints to respect distribution rights.

**Incorrect:**
- A: WAF doesn’t handle routing to different content by geography.
- B: WAF doesn’t handle routing to different content by geography.
- D: Geoproximity adjusts by distance/bias, not strict country mapping.


---

---

### Question #639

A company is building a new furniture inventory application. The company has deployed the application on a eet ofAmazon EC2 instances across multiple Availability Zones. The EC2 instances run behind an Application Load Balancer (ALB) in their VPC. A solutions architect has observed that incoming trac seems to favor one EC2 instance, resulting in latency for some requests. What should the solutions architect do to resolve this issue?

- A. Disable session anity (sticky sessions) on the ALB

- B. Replace the ALB with a Network Load Balancer

- C. Increase the number of EC2 instances in each Availability Zone

- D. Adjust the frequency of the health checks on the ALB's target group

**Correct:** A
**Why:** Sticky sessions (session affinity) can concentrate traffic; disabling distributes requests evenly among instances.

**Incorrect:**
- B: NLB doesn’t solve HTTP session stickiness issues.
- C: More instances treats symptoms but not root cause.
- D: Health check frequency isn’t the cause of imbalance.


---

---

### Question #642

A company wants to run a gaming application on Amazon EC2 instances that are part of an Auto Scaling group in the AWS Cloud. The application will transmit data by using UDP packets. The company wants to ensure that the application can scale out and in as trac increases and decreases. What should a solutions architect do to meet these requirements?

- A. Attach a Network Load Balancer to the Auto Scaling group.

- B. Attach an Application Load Balancer to the Auto Scaling group.

- C. Deploy an Amazon Route 53 record set with a weighted policy to route trac appropriately.

- D. Deploy a NAT instance that is congured with port forwarding to the EC2 instances in the Auto Scaling group.

**Correct:** A
**Why:** NLB supports UDP and scales out/in with the Auto Scaling group behind it.

**Incorrect:**
- B: ALB does not support UDP.
- C: Route 53/NAT instance do not provide scalable UDP load balancing.
- D: Route 53/NAT instance do not provide scalable UDP load balancing.


---

---

### Question #644

An international company has a subdomain for each country that the company operates in. The subdomains are formatted as example.com, country1.example.com, and country2.example.com. The company's workloads are behind an Application Load Balancer. The company wants to encrypt the website data that is in transit. Which combination of steps will meet these requirements? (Choose two.)

- A. Use the AWS Certicate Manager (ACM) console to request a public certicate for the apex top domain example com and a wildcard certicate for *.example.com.

- B. Use the AWS Certicate Manager (ACM) console to request a private certicate for the apex top domain example.com and a wildcard certicate for *.example.com.

- C. Use the AWS Certicate Manager (ACM) console to request a public and private certicate for the apex top domain example.com.

- D. Validate domain ownership by email address. Switch to DNS validation by adding the required DNS records to the DNS provider.

E. Validate domain ownership for the domain by adding the required DNS records to the DNS provider.

**Correct:** A, E
**Why:** Request a public cert for example.com and a wildcard for *.example.com in ACM; validate via DNS records.

**Incorrect:**
- B: Private certs or mixed public/private are not needed for public websites.
- C: Private certs or mixed public/private are not needed for public websites.
- D: Email validation is more manual vs. DNS validation.


---

---

### Question #647

A gaming company is building an application with Voice over IP capabilities. The application will serve trac to users across the world. The application needs to be highly available with an automated failover across AWS Regions. The company wants to minimize the latency of users without relying on IP address caching on user devices. What should a solutions architect do to meet these requirements?

- A. Use AWS Global Accelerator with health checks.

- B. Use Amazon Route 53 with a geolocation routing policy.

- C. Create an Amazon CloudFront distribution that includes multiple origins.

- D. Create an Application Load Balancer that uses path-based routing.

**Correct:** A
**Why:** Global Accelerator provides anycast IPs, health checks, and automatic multi‑Region failover without relying on DNS caching.

**Incorrect:**
- B: Route 53 relies on DNS caching/TTL.
- C: CloudFront is for HTTP(S), not generic VoIP/UDP or bi‑directional traffic patterns.
- D: ALB routes within a Region only.


---

---

### Question #654

A company recently migrated its web application to the AWS Cloud. The company uses an Amazon EC2 instance to run multiple processes to host the application. The processes include an Apache web server that serves static content. The Apache web server makes requests to a PHP application that uses a local Redis server for user sessions. The company wants to redesign the architecture to be highly available and to use AWS managed solutions. Which solution will meet these requirements?

- A. Use AWS Elastic Beanstalk to host the static content and the PHP application. Configure Elastic Beanstalk to deploy its EC2 instance into a public subnet. Assign a public IP address.

- B. Use AWS Lambda to host the static content and the PHP application. Use an Amazon API Gateway REST API to proxy requests to the Lambda function. Set the API Gateway CORS configuration to respond to the domain name. Configure Amazon ElastiCache for Redis to handle session information.

- C. Keep the backend code on the EC2 instance. Create an Amazon ElastiCache for Redis cluster that has Multi-AZ enabled. Configure the ElastiCache for Redis cluster in cluster mode. Copy the frontend resources to Amazon S3. Configure the backend code to reference the EC2 instance.

- D. Configure an Amazon CloudFront distribution with an Amazon S3 endpoint to an S3 bucket that is congured to host the static content. Configure an Application Load Balancer that targets an Amazon Elastic Container Service (Amazon ECS) service that runs AWS Fargate tasks for the PHP application. Configure the PHP application to use an Amazon ElastiCache for Redis cluster that runs in multiple Availability Zones.

**Correct:** D
**Why:** S3 + CloudFront for static assets; ECS Fargate behind ALB for PHP app; Redis (Multi‑AZ) for sessions meets HA with managed services.

**Incorrect:**
- A: Single EC2 in public subnet is not HA.
- B: Lambda for PHP monolith adds complexity and cold‑start concerns.
- C: Keeping backend on EC2 is not fully managed/HA.


---

---

### Question #655

A company runs a web application on Amazon EC2 instances in an Auto Scaling group that has a target group. The company designed the application to work with session anity (sticky sessions) for a better user experience. The application must be available publicly over the internet as an endpoint. A WAF must be applied to the endpoint for additional security. Session anity (sticky sessions) must be congured on the endpoint. Which combination of steps will meet these requirements? (Choose two.)

- A. Create a public Network Load Balancer. Specify the application target group.

- B. Create a Gateway Load Balancer. Specify the application target group.

- C. Create a public Application Load Balancer. Specify the application target group.

- D. Create a second target group. Add Elastic IP addresses to the EC2 instances.

E. Create a web ACL in AWS WAF. Associate the web ACL with the endpoint

**Correct:** C, E
**Why:** ALB supports sticky sessions and integrates with AWS WAF via a web ACL for security.

**Incorrect:**
- A: NLB/GWLB don’t provide sticky sessions for HTTP; Elastic IPs are not target group members.
- B: NLB/GWLB don’t provide sticky sessions for HTTP; Elastic IPs are not target group members.
- D: NLB/GWLB don’t provide sticky sessions for HTTP; Elastic IPs are not target group members.


---

---

### Question #660

A company hosts an application on Amazon EC2 On-Demand Instances in an Auto Scaling group. Application peak hours occur at the same time each day. Application users report slow application performance at the start of peak hours. The application performs normally 2-3 hours after peak hours begin. The company wants to ensure that the application works properly at the start of peak hours. Which solution will meet these requirements?

- A. Configure an Application Load Balancer to distribute trac properly to the instances.

- B. Configure a dynamic scaling policy for the Auto Scaling group to launch new instances based on memory utilization.

- C. Configure a dynamic scaling policy for the Auto Scaling group to launch new instances based on CPU utilization.

- D. Configure a scheduled scaling policy for the Auto Scaling group to launch new instances before peak hours.

**Correct:** D
**Why:** Scheduled scaling pre‑warms capacity before predictable peak hours to avoid slow start.

**Incorrect:**
- A: Load balancer alone won’t add capacity.
- B: Reactive scaling lags at the start of peaks.
- C: Reactive scaling lags at the start of peaks.


---

---

### Question #666

A startup company is hosting a website for its customers on an Amazon EC2 instance. The website consists of a stateless Python application and a MySQL database. The website serves only a small amount of trac. The company is concerned about the reliability of the instance and needs to migrate to a highly available architecture. The company cannot modify the application code. Which combination of actions should a solutions architect take to achieve high availability for the website? (Choose two.)

- A. Provision an internet gateway in each Availability Zone in use.

- B. Migrate the database to an Amazon RDS for MySQL Multi-AZ DB instance.

- C. Migrate the database to Amazon DynamoDB, and enable DynamoDB auto scaling.

- D. Use AWS DataSync to synchronize the database data across multiple EC2 instances.

E. Create an Application Load Balancer to distribute trac to an Auto Scaling group of EC2 instances that are distributed across two Availability Zones.

**Correct:** B, E
**Why:** RDS for MySQL Multi‑AZ provides HA for the DB. ALB + Auto Scaling across two AZs provides HA for the stateless app without code changes.

**Incorrect:**
- A: Internet gateways are per VPC, not per AZ.
- C: DynamoDB/DataSync are irrelevant here.
- D: DynamoDB/DataSync are irrelevant here.


---

---

### Question #676

A company's application uses Network Load Balancers, Auto Scaling groups, Amazon EC2 instances, and databases that are deployed in an Amazon VPC. The company wants to capture information about trac to and from the network interfaces in near real time in its Amazon VPC. The company wants to send the information to Amazon OpenSearch Service for analysis. Which solution will meet these requirements?

- A. Create a log group in Amazon CloudWatch Logs. Configure VPC Flow Logs to send the log data to the log group. Use Amazon Kinesis Data Streams to stream the logs from the log group to OpenSearch Service.

- B. Create a log group in Amazon CloudWatch Logs. Configure VPC Flow Logs to send the log data to the log group. Use Amazon Kinesis Data Firehose to stream the logs from the log group to OpenSearch Service.

- C. Create a trail in AWS CloudTrail. Configure VPC Flow Logs to send the log data to the trail. Use Amazon Kinesis Data Streams to stream the logs from the trail to OpenSearch Service.

- D. Create a trail in AWS CloudTrail. Configure VPC Flow Logs to send the log data to the trail. Use Amazon Kinesis Data Firehose to stream the logs from the trail to OpenSearch Service.

**Correct:** B
**Why:** Send VPC Flow Logs to CloudWatch Logs, then stream to OpenSearch Service with Kinesis Data Firehose for near real‑time analysis.

**Incorrect:**
- A: Data Streams adds custom consumer management; Firehose is simpler.
- C: CloudTrail is not used for VPC Flow Logs delivery.
- D: CloudTrail is not used for VPC Flow Logs delivery.


---

---

### Question #683

A company is migrating its multi-tier on-premises application to AWS. The application consists of a single-node MySQL database and a multi-node web tier. The company must minimize changes to the application during the migration. The company wants to improve application resiliency after the migration. Which combination of steps will meet these requirements? (Choose two.)

- A. Migrate the web tier to Amazon EC2 instances in an Auto Scaling group behind an Application Load Balancer.

- B. Migrate the database to Amazon EC2 instances in an Auto Scaling group behind a Network Load Balancer.

- C. Migrate the database to an Amazon RDS Multi-AZ deployment.

- D. Migrate the web tier to an AWS Lambda function.

E. Migrate the database to an Amazon DynamoDB table.

**Correct:** A, C
**Why:** Move the web tier behind an ALB with Auto Scaling for resiliency, and migrate the DB to RDS Multi‑AZ for high availability with minimal app changes.

**Incorrect:**
- B: EC2 DB on NLB is self‑managed and higher ops.
- D: Lambda/DynamoDB require major app changes.
- E: Lambda/DynamoDB require major app changes.


---

## General / Architecture

### Question #525

A company wants to add its existing AWS usage cost to its operation cost dashboard. A solutions architect needs to recommend a solution that will give the company access to its usage cost programmatically. The company must be able to access cost data for the current year and forecast costs for the next 12 months. Which solution will meet these requirements with the LEAST operational overhead?

- A. Access usage cost-related data by using the AWS Cost Explorer API with pagination.

- B. Access usage cost-related data by using downloadable AWS Cost Explorer report .csv files.

- C. Configure AWS Budgets actions to send usage cost data to the company through FTP.

- D. Create AWS Budgets reports for usage cost data. Send the data to the company through SMTP.

**Correct:** A
**Why:** The Cost Explorer API provides programmatic access to historical and forecasted costs with pagination.

**Incorrect:**
- B: CSV downloads or Budgets reports/actions are less programmatic and lack complete forecast APIs.
- C: CSV downloads or Budgets reports/actions are less programmatic and lack complete forecast APIs.
- D: CSV downloads or Budgets reports/actions are less programmatic and lack complete forecast APIs.


---

---

### Question #554

A company's SAP application has a backend SQL Server database in an on-premises environment. The company wants to migrate its on-premises application and database server to AWS. The company needs an instance type that meets the high demands of its SAP database. On-premises performance data shows that both the SAP application and the database have high memory utilization. Which solution will meet these requirements?

- A. Use the compute optimized instance family for the application. Use the memory optimized instance family for the database.

- B. Use the storage optimized instance family for both the application and the database.

- C. Use the memory optimized instance family for both the application and the database.

- D. Use the high performance computing (HPC) optimized instance family for the application. Use the memory optimized instance family for the database.

**Correct:** C
**Why:** Both the SAP application and the SQL Server database have high memory utilization; memory-optimized instances best meet performance needs for both tiers.

**Incorrect:**
- A: Mixing compute/memory families mismatches the observed utilization (both are memory-heavy).
- B: Storage-optimized is for high disk throughput/IOPS, not high memory needs.
- D: HPC-optimized targets tightly coupled compute workloads, not SAP app servers.


---

---

### Question #624

A company wants to provide users with access to AWS resources. The company has 1,500 users and manages their access to on-premises resources through Active Directory user groups on the corporate network. However, the company does not want users to have to maintain another identity to access the resources. A solutions architect must manage user access to the AWS resources while preserving access to the on- premises resources. What should the solutions architect do to meet these requirements?

- A. Create an IAM user for each user in the company. Attach the appropriate policies to each user.

- B. Use Amazon Cognito with an Active Directory user pool. Create roles with the appropriate policies attached.

- C. Dene cross-account roles with the appropriate policies attached. Map the roles to the Active Directory groups.

- D. Configure Security Assertion Markup Language (SAML) 2 0-based federation. Create roles with the appropriate policies attached Map the roles to the Active Directory groups.

**Correct:** D
**Why:** SAML 2.0 federation maps AD groups to IAM roles for access to AWS without new identities.

**Incorrect:**
- A: Creating IAM users duplicates identities.
- B: Cognito is for app identities, not enterprise AWS console/API access.
- C: Cross‑account roles don’t federate with AD by themselves.


---

---

### Question #652

A company has a large data workload that runs for 6 hours each day. The company cannot lose any data while the process is running. A solutions architect is designing an Amazon EMR cluster configuration to support this critical data workload. Which solution will meet these requirements MOST cost-effectively?

- A. Configure a long-running cluster that runs the primary node and core nodes on On-Demand Instances and the task nodes on Spot Instances.

- B. Configure a transient cluster that runs the primary node and core nodes on On-Demand Instances and the task nodes on Spot Instances.

- C. Configure a transient cluster that runs the primary node on an On-Demand Instance and the core nodes and task nodes on Spot Instances.

- D. Configure a long-running cluster that runs the primary node on an On-Demand Instance, the core nodes on Spot Instances, and the task nodes on Spot Instances.

**Correct:** B
**Why:** A transient EMR cluster with On‑Demand master/core (for durability) and Spot task nodes minimizes cost while protecting data.

**Incorrect:**
- A: Long‑running clusters accrue cost outside the 6‑hour window.
- C: Spot for core nodes risks data loss if reclaimed.
- D: Long‑running clusters accrue cost outside the 6‑hour window.


---

---

### Question #664

A company has a web application that runs on premises. The application experiences latency issues during peak hours. The latency issues occur twice each month. At the start of a latency issue, the application's CPU utilization immediately increases to 10 times its normal amount. The company wants to migrate the application to AWS to improve latency. The company also wants to scale the application automatically when application demand increases. The company will use AWS Elastic Beanstalk for application deployment. Which solution will meet these requirements?

- A. Configure an Elastic Beanstalk environment to use burstable performance instances in unlimited mode. Configure the environment to scale based on requests.

- B. Configure an Elastic Beanstalk environment to use compute optimized instances. Configure the environment to scale based on requests.

- C. Configure an Elastic Beanstalk environment to use compute optimized instances. Configure the environment to scale on a schedule.

- D. Configure an Elastic Beanstalk environment to use burstable performance instances in unlimited mode. Configure the environment to scale on predictive metrics.

**Correct:** A
**Why:** Burstable instances (unlimited) handle infrequent CPU spikes cost‑effectively; scale on request count for elasticity.

**Incorrect:**
- B: Compute‑optimized cost more continuously and schedule scaling misses irregular spikes.
- C: Compute‑optimized cost more continuously and schedule scaling misses irregular spikes.
- D: Predictive scaling is less useful for twice‑monthly irregular events.


---
