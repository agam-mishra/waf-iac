# Welcome to WAF IAC project🚀

# This project is to developed to help anyone who wants to create WAF resource through IAC(Infrastructure as Code) for the AWS Application to fight against DdOS attacks😃

# The project was developed on AWS CDK V2 in typescript language with help of AWS Documentation🤓
Refer here for AWS Documentation on WAF https://docs.aws.amazon.com/cdk/api/v2/docs/aws-cdk-lib.aws_wafv2-readme.html

# Steps to follow pre deployment👇🏻
1. Get the name of ALB you want to attach WAF resource to. The name help you to get ALB ARN which is how AWS identifies its resources.
Add the ALB name in /lib/waf-iac-stack.ts on line 16.
2. On line 27 & 42 add IPs which you want to permanently block (optional, also could be done via Console).
3. On line 55 add regular expression consisting of pattern of bot requests which you want to block permanently (optional, could be done via Console).
4. On line 71 add regular expressions consisting of URL patterns which you want to block permanently (optional, could be done via Console).
5. On line 338 & 339 change the description & name of web acl.
6. On line 535 & 564 change name of alarm (optional).
7. On line 553 & 582 chnage the threshold of alarm.

# Steps to follow for deployment👇🏻
1. Clone the repository
2. run npm install to install all the dependencies.
3. Configure your AWS account in CLI using aws configure (keep access key and secret key ready for this step).
4. run cdk deploy to deploy your changes.





## Useful commands😎

* `npm run build`   compile typescript to js
* `npm run watch`   watch for changes and compile
* `npm run test`    perform the jest unit tests
* `cdk deploy`      deploy this stack to your default AWS account/region
* `cdk diff`        compare deployed stack with current state
* `cdk synth`       emits the synthesized CloudFormation template
* `cdk destroy`     destroys the deployed stack from your AWS account
