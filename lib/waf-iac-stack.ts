import * as cdk from 'aws-cdk-lib';
import * as wafv2 from 'aws-cdk-lib/aws-wafv2';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as sns from 'aws-cdk-lib/aws-sns'
import { Construct } from 'constructs';


export class WafIacStack extends cdk.Stack {
  constructor(scope: cdk.App, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    //get name load balancer ARN
    const stageALB = elbv2.ApplicationLoadBalancer.fromLookup(this, 'ALB', {
      loadBalancerTags: {
        application: '',  //Name of ALB you want it to be attached to
      },
    });

    new cdk.CfnOutput(this, "stageLbArn", {
      value: stageALB.loadBalancerArn,
      description: "Stage LB ARN",
    });

    //IPv4 IP set 
    const ipV4IPSet = new wafv2.CfnIPSet(this, 'IPv4IPSet', {
      addresses: [],
      ipAddressVersion: 'IPV4',
      scope: 'REGIONAL',
      description: 'This IP set will be used to list permanently blocked IPv4 IPs.',
      name: 'blocked-IPv4-ip-list',
      tags: [{
        key: 'ipset',
        value: 'IPv4',
      }],
    });


    //IPv6 IP set
    const ipV6IPSet = new wafv2.CfnIPSet(this, 'IPv6IPSet', {
      addresses: [],
      ipAddressVersion: 'IPV6',
      scope: 'REGIONAL',
      description: 'This IP set will be used to list permanently blocked IPv6 IPs.',
      name: 'blocked-IPv6-ip-list',
      tags: [{
        key: 'ipset',
        value: 'IPv6',
      }],
    });


    // Bot Regex pattern
    const botRegexPatternSet = new wafv2.CfnRegexPatternSet(this, 'BotRegexPatternSet', {
      regularExpressionList: [
        "^foobar$",
      ],
      scope: 'REGIONAL',
      description: 'This regex rule is for requests which have bad User Agent on.',
      name: 'bot-requests',
      tags: [{
        key: 'regexPattern',
        value: 'bot-requests',
      }],
    });


    // URL Regex pattern
    const urlRegexPatternSet = new wafv2.CfnRegexPatternSet(this, 'UrlRegexPatternSet', {
      regularExpressionList: ["^foobar$", "^example$"],
      scope: 'REGIONAL',
      description: 'This regex group is to find false url requests on.',
      name: 'url-path',
      tags: [{
        key: 'regexPattern',
        value: 'url-path',
      }],
    });


    //rule group for bad url
    const badUrlRequestRG = new wafv2.CfnRuleGroup(this, 'badUrlRequestRG', {
      capacity: 100,
      scope: 'REGIONAL',
      visibilityConfig: {
        cloudWatchMetricsEnabled: true,
        metricName: 'badUrlRequestRG',
        sampledRequestsEnabled: true,
      },
      customResponseBodies: {
        badUrlResponse: {
          content: '<div>error: access denied by A team</div>',
          contentType: 'TEXT_HTML',
        },
      },
      description: 'This rule group will be used for requests with bad URL in.',
      name: 'bad-url-request-rg',
      rules: [{
        name: 'url-rule',
        priority: 0,
        statement: {
          regexPatternSetReferenceStatement: {
            arn: `${urlRegexPatternSet.attrArn}`,
            fieldToMatch: {
              uriPath: {},
            },
            textTransformations: [{
              priority: 0,
              type: 'NONE',
            }],
          }
        },
        visibilityConfig: {
          cloudWatchMetricsEnabled: true,
          metricName: 'url-rule',
          sampledRequestsEnabled: true,
        },
        action: {
          block:{
            customResponse: {
              responseCode: 403,
              customResponseBodyKey: 'badUrlResponse',
            },
          },
        },
        ruleLabels: [{
          name: 'badurlrequest',
        }],
      }],
      tags: [{
        key: 'rule-group',
        value: 'bad-url-request-rg',
      }],
    });

    new cdk.CfnOutput(this, "badUrlRequestRGArn", {
      value: badUrlRequestRG.attrArn,
      description: " Bad URL RG ARN",
    });

    //rule group for ip
    const blockIpRG = new wafv2.CfnRuleGroup(this, 'blockIpRG', {
      capacity: 25,
      scope: 'REGIONAL',
      visibilityConfig: {
        cloudWatchMetricsEnabled: true,
        metricName: 'blockIpRG',
        sampledRequestsEnabled: true,
      },
      customResponseBodies: {
        blockIpResponse: {
          content: '<div>error: access denied</div>',
          contentType: 'TEXT_HTML',
        },
      },
      description: 'This rule group will be used to block malicious IPs.',
      name: 'block-ip-rg',
      rules: [{
        name: 'blocked-ips',
        priority: 0,
        statement:{
          orStatement: {
            statements:[
              {
              ipSetReferenceStatement:{
                arn: `${ipV4IPSet.attrArn}`
              },
            },
            {
              ipSetReferenceStatement:{
                arn: `${ipV6IPSet.attrArn}`
              }
            }
          ]
          },
        },
        visibilityConfig: {
          cloudWatchMetricsEnabled: true,
          metricName: 'url-rule',
          sampledRequestsEnabled: true,
        },
        action: {
          block:{
            customResponse: {
              responseCode: 403,
              customResponseBodyKey: 'blockIpResponse',
            },
          },
        },
        ruleLabels: [{
          name: 'permanentlyblockedip',
        }],
      }],
      tags: [{
        key: 'rule-group',
        value: 'block-ip-rg',
      }],
    });

    new cdk.CfnOutput(this, "blockIpRGArn", {
      value: blockIpRG.attrArn,
      description: " Block IP RG ARN",
    });
    


    //rule group for blocking bots
    const botRequestRG = new wafv2.CfnRuleGroup(this, 'botRequestRG', {
      capacity: 75,
      scope: 'REGIONAL',
      visibilityConfig: {
        cloudWatchMetricsEnabled: true,
        metricName: 'botRequestRG',
        sampledRequestsEnabled: true,
      },
      customResponseBodies: {
        botRequestResponse: {
          content: '<div>error: access denied</div>',
          contentType: 'TEXT_HTML',
        },
      },
      description: 'This rule group will be used to block bot requests.',
      name: 'bot-requests-rg',
      rules: [{
        name: 'block-bot-rule',
        priority: 0,
        statement: {
          regexPatternSetReferenceStatement: {
            arn: `${botRegexPatternSet.attrArn}`,
            fieldToMatch: {
              singleHeader: {
                name:"User-Agent"
              },
            },
            textTransformations: [{
              priority: 0,
              type: 'NONE',
            }],
          },
        },
        visibilityConfig: {
          cloudWatchMetricsEnabled: true,
          metricName: 'block-bot-rule',
          sampledRequestsEnabled: true,
        },
        action: {
          block:{
            customResponse: {
              responseCode: 403,
              customResponseBodyKey: 'botRequestResponse',
            },
          },
        },
        ruleLabels: [{
          name: 'botrequests',
        }],
      }],
      tags: [{
        key: 'rule-group',
        value: 'bot-requests-rg',
      }],
    });

    new cdk.CfnOutput(this, "botRequestRGArn", {
      value: botRequestRG.attrArn,
      description: "Bot Request RG ARN",
    });


    // rule group for blocking IPs based on rate limit
    const limitIpRequestRG = new wafv2.CfnRuleGroup(this, 'limitIpRequestRG', {
      capacity: 50,
      scope: 'REGIONAL',
      visibilityConfig: {
        cloudWatchMetricsEnabled: true,
        metricName: 'limitIpRequestRG',
        sampledRequestsEnabled: true,
      },

      customResponseBodies: {
        limitIpResponse: {
          content: '<div>error: access denied</div>',
          contentType: 'TEXT_HTML',
        },
      },
      description: 'This rule group will be used to count and block requests from IP.',
      name: 'limit-ip-request-rg',
      rules: [{
        name: 'block-ip-rule',
        priority: 0,
        statement: {
          rateBasedStatement: {
            aggregateKeyType: 'IP',
            limit: 100,
          },
        },
        visibilityConfig: {
          cloudWatchMetricsEnabled: true,
          metricName: 'block-ip-rule',
          sampledRequestsEnabled: true,
        },
        action: {
          block:{
            customResponse: {
              responseCode: 403,
              customResponseBodyKey: 'limitIpResponse',
            },
          },
        },
        ruleLabels: [{
          name: 'limitIp',
        }],
      }],
      tags: [{
        key: 'rule-group',
        value: 'imit-ip-request-rg',
      }],
    });

    new cdk.CfnOutput(this, "limitIpRequestRGArn", {
      value: limitIpRequestRG.attrArn,
      description: "Limit IP Requests RG ARN",
    });


    //create webAcl
    const webACL = new wafv2.CfnWebACL(this, 'webACL', { 
      defaultAction: {
        allow: {}
      },
      scope: 'REGIONAL',
      visibilityConfig: {
        cloudWatchMetricsEnabled: true,
        metricName: 'webACL',
        sampledRequestsEnabled: true,
      },
    
      description: 'description of webACL goes here.', // change description
      name: 'demoAcl', //change name of ACL
      rules: [
        //limit IPs rule in ACL
        {
          name: 'limit-ip',
          priority: 0,
          statement: { 
            ruleGroupReferenceStatement: {
              arn: limitIpRequestRG.attrArn,
            },
          },
          overrideAction: {
            none: {},
          },
          visibilityConfig: {
            cloudWatchMetricsEnabled: true,
            metricName: 'limit-ip',
            sampledRequestsEnabled: true,
          },
        },

        //AWSManagedRulesAmazonIpReputationList rule in ACL
        {
          name: 'AWS-AWSManagedRulesAmazonIpReputationList',
          priority: 1,
          statement: {
            managedRuleGroupStatement: {
              name: 'AWSManagedRulesAmazonIpReputationList',
              vendorName: 'AWS',
              excludedRules: [],
            },   
          },
          overrideAction: {
            none: {},
          },
          visibilityConfig: {
            cloudWatchMetricsEnabled: true,
            metricName: 'AWSManagedRulesAmazonIpReputationList',
            sampledRequestsEnabled: true,
          },
        },

        // //blocked IPs rule in ACL
        {
          name: 'blocked-ip',
          priority: 2,
          statement: { 
            ruleGroupReferenceStatement: {
              arn: `${blockIpRG.attrArn}`,
            },
          },
          overrideAction: {
            none: {},
          },
          visibilityConfig: {
            cloudWatchMetricsEnabled: true,
            metricName: 'blocked-ip',
            sampledRequestsEnabled: true,
          },
        },

        // //blocked bot requests rule in ACL   
        {
          name: 'block-bot-requests',
          priority: 3,
          statement: { 
            ruleGroupReferenceStatement: {
              arn: `${botRequestRG.attrArn}`,
            },
          },
          overrideAction: {
            none: {},
          },
          visibilityConfig: {
            cloudWatchMetricsEnabled: true,
            metricName: 'blocked-bot-requests',
            sampledRequestsEnabled: true,
          },
        },
        
        // //blocked URLs rule in ACL
        {
          name: 'block-url-requests',
          priority: 4,
          statement: { 
            ruleGroupReferenceStatement: {
              arn: `${badUrlRequestRG.attrArn}`,
            },
          },
          overrideAction: {
            none: {},
          },
          visibilityConfig: {
            cloudWatchMetricsEnabled: true,
            metricName: 'blocked-url-requests',
            sampledRequestsEnabled: true,
          },
        },

        // //AWS-AWSManagedRulesAnonymousIpList rule in ACL
        {
          name: 'AWS-AWSManagedRulesAnonymousIpList',
          priority: 5,
          statement: {
            managedRuleGroupStatement: {
              name: 'AWSManagedRulesAnonymousIpList',
              vendorName: 'AWS',
              excludedRules: [],
            },   
          },
          visibilityConfig: {
            cloudWatchMetricsEnabled: true,
            metricName: 'AWSManagedRulesAnonymousIpList',
            sampledRequestsEnabled: true,
          },
          overrideAction: {
            none: {},
          },
        },

        // //AWS-AWSManagedRulesCommonRuleSet rule in ACL
        {
          name: 'AWS-AWSManagedRulesCommonRuleSet',
          priority: 6,
          statement: {
            managedRuleGroupStatement: {
              name: 'AWSManagedRulesCommonRuleSet',
              vendorName: 'AWS',
              excludedRules: [],
            },   
          },
          visibilityConfig: {
            cloudWatchMetricsEnabled: true,
            metricName: 'AWSManagedRulesCommonRuleSet',
            sampledRequestsEnabled: true,
          },
          overrideAction: {
            none: {},
          },
        },

      ],
      tags: [{
        key: 'webAcl',
        value: 'waf',
      }],
    });
   

    new cdk.CfnOutput(this, "wafAclRegionalArn", {
      value: webACL.attrArn,
      description: "Web ACL ARN",
    });
    

    //create an object for associating webAcl to load balancer
    new WebACLAssociation(this, 'Association',{
      //resourceArn: stageALB.loadBalancerArn,
      resourceArn: stageALB.loadBalancerArn,
      webAclArn: webACL.attrArn
    });
    
    // get existing sns topic
    //uncomment this only when you want to push notifications to existing SNS topic.
    /** 
      const existingTopic = sns.Topic.fromTopicArn(this, 'Waf_alarm', "arn:aws:sns:us-east-1:453155843072:Waf_alarm");
      console.log(existingTopic.topicArn)
    */
    
    // create new SNS topic
    const topic = new sns.Topic(this, 'Topic',{
      displayName :'WAF Monitoring',
      topicName: 'waf-monitoring'
    });

    // get newly created topic's ARN
    const newTopicARN = new cdk.CfnOutput(this, "SNS ARN", {
      value: topic.topicArn,
      description: "SNS ARN",
    });


    // create a new subscription and attach it to newly created SNS topic
    new sns.Subscription(this, 'wafSubscription', {
      topic,
      endpoint: "abc@example.com", // email on which you want to be notified
      protocol: sns.SubscriptionProtocol.EMAIL,
    }); 


    new cloudwatch.CfnAlarm(this, 'WAF Counted Requests Alarm', {
      comparisonOperator: 'GreaterThanOrEqualToThreshold',
      evaluationPeriods: 1,
      actionsEnabled: true,
      alarmActions: [newTopicARN.value],
      alarmDescription: 'This alarm will be triggered when counted requests are more than 500 in a minute.',
      alarmName: 'WAF Counted Requests Alarm Stack', // giving this alarm a name to be  ore generic because using stack gives a unique id which is confusing
      datapointsToAlarm: 1,
      dimensions: [{
        name: 'RuleGroup',
        value: limitIpRequestRG.name || "",
      },
      {
        name: 'Region',
        value: 'us-east-1',
      },
      {
        name: 'Rule',
        value: 'ALL',
      }],
      metricName: 'PassedRequests',
      namespace: 'AWS/WAFV2',
      period: 60,
      statistic: 'Sum',
      threshold: 10, //change threshold
      treatMissingData: 'missing',
    });

    //Blocked Request Alarm
    new cloudwatch.CfnAlarm(this, 'WAF Blocked Requests Alarm', {
      comparisonOperator: 'GreaterThanOrEqualToThreshold',
      evaluationPeriods: 1,
      actionsEnabled: true,
      alarmActions: [newTopicARN.value],
      alarmDescription: 'This alarm will be triggered when counted requests are more than 500 in a minute.',
      alarmName: 'WAF Blocked Requests Alarm Stack', // giving this alarm a name to be  ore generic because using stack gives a unique id which is confusing
      datapointsToAlarm: 1,
      dimensions: [{
        name: 'WebACL',
        value:  webACL.name|| "", // change name
      },
      {
        name: 'Region',
        value: 'us-east-1',
      },
      {
        name: 'Rule',
        value: 'ALL',
      }],
      metricName: 'BlockedRequests',
      namespace: 'AWS/WAFV2',
      period: 60,
      statistic: 'Sum',
      threshold: 2, // change threshold
      treatMissingData: 'missing',
    });
  }
}

export class WebACLAssociation extends wafv2.CfnWebACLAssociation {
  constructor(scope: Construct, id: string, props: wafv2.CfnWebACLAssociationProps) {
      super(scope, id,{
          resourceArn: props.resourceArn,
          webAclArn: props.webAclArn,
      });
  }
}
