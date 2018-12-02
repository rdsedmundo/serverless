'use strict';

const _ = require('lodash');

class AwsCompileCloudWatchLogEvents {
  constructor(serverless) {
    this.serverless = serverless;
    this.provider = this.serverless.getProvider('aws');

    this.hooks = {
      'package:compileEvents': this.compileCloudWatchLogEvents.bind(this),
    };
  }

  compileCloudWatchLogEvents() {
    const logGroupNames = [];

    const promises = this.serverless.service.getAllFunctions().map((functionName) => {
      const functionObj = this.serverless.service.getFunction(functionName);
      let cloudWatchLogNumberInFunction = 0;

      if (!functionObj.events) {
        return Promise.resolve();
      }

      const eventPromises = functionObj.events.map(event => {
        if (!event.cloudwatchLog) {
          return Promise.resolve();
        }

        cloudWatchLogNumberInFunction++;
        let LogGroupName;
        let FilterPattern;

        if (typeof event.cloudwatchLog === 'object') {
          if (!event.cloudwatchLog.logGroup) {
            const errorMessage = [
              'Missing "logGroup" property for cloudwatchLog event ',
              `in function ${functionName} Please check the docs for more info.`,
            ].join('');
            throw new this.serverless.classes
              .Error(errorMessage);
          }

          if (event.cloudwatchLog.filter && typeof event.cloudwatchLog.filter !== 'string') {
            const errorMessage = [
              `"filter" property for cloudwatchLog event in function ${functionName} `,
              'should be string. Please check the docs for more info.',
            ].join('');
            throw new this.serverless.classes
              .Error(errorMessage);
          }

          LogGroupName = event.cloudwatchLog.logGroup.replace(/\r?\n/g, '');
          FilterPattern = event.cloudwatchLog.filter ?
            event.cloudwatchLog.filter.replace(/\r?\n/g, '') : '';
        } else if (typeof event.cloudwatchLog === 'string') {
          LogGroupName = event.cloudwatchLog.replace(/\r?\n/g, '');
          FilterPattern = '';
        } else {
          const errorMessage = [
            `cloudwatchLog event of function "${functionName}" is not an object or a string`,
            ' Please check the docs for more info.',
          ].join('');
          throw new this.serverless.classes
            .Error(errorMessage);
        }

        if (_.indexOf(logGroupNames, LogGroupName) !== -1) {
          const errorMessage = [
            `"${LogGroupName}" logGroup for cloudwatchLog event is duplicated.`,
            ' This property can only be set once per CloudFormation stack.',
          ].join('');
          throw new this.serverless.classes
            .Error(errorMessage);
        }
        logGroupNames.push(LogGroupName);

        const lambdaLogicalId = this.provider.naming
          .getLambdaLogicalId(functionName);
        const cloudWatchLogLogicalId = this.provider.naming
          .getCloudWatchLogLogicalId(functionName, cloudWatchLogNumberInFunction);
        const lambdaPermissionLogicalId = this.provider.naming
          .getLambdaCloudWatchLogPermissionLogicalId(functionName,
          cloudWatchLogNumberInFunction);

        // unescape quotes once when the first quote is detected escaped
        const idxFirstSlash = FilterPattern.indexOf('\\');
        const idxFirstQuote = FilterPattern.indexOf('"');
        if (idxFirstSlash >= 0 && idxFirstQuote >= 0 && idxFirstQuote > idxFirstSlash) {
          FilterPattern = FilterPattern.replace(/\\("|\\|')/g, (match, g) => g);
        }

        const cloudWatchLogRuleTemplate = `
          {
            "Type": "AWS::Logs::SubscriptionFilter",
            "DependsOn": "${lambdaPermissionLogicalId}",
            "Properties": {
              "LogGroupName": "${LogGroupName}",
              "FilterPattern": ${JSON.stringify(FilterPattern)},
              "DestinationArn": { "Fn::GetAtt": ["${lambdaLogicalId}", "Arn"] }
            }
          }
        `;

        const permissionTemplate = `
        {
          "Type": "AWS::Lambda::Permission",
          "Properties": {
            "FunctionName": { "Fn::GetAtt": ["${
          lambdaLogicalId}", "Arn"] },
            "Action": "lambda:InvokeFunction",
            "Principal": {
              "Fn::Join": [ "", [
              "logs.",
              { "Ref": "AWS::Region" },
              ".",
              { "Ref": "AWS::URLSuffix" }
              ] ]
            },
            "SourceArn": {
              "Fn::Join": [ "", [
              "arn:",
              { "Ref": "AWS::Partition" },
              ":logs:",
              { "Ref": "AWS::Region" },
              ":",
              { "Ref": "AWS::AccountId" },
              ":log-group:",
              "${LogGroupName}",
              ":*"
              ] ]
            }
          }
        }
        `;

        const newCloudWatchLogRuleObject = {
          [cloudWatchLogLogicalId]: JSON.parse(cloudWatchLogRuleTemplate),
        };

        const newPermissionObject = {
          [lambdaPermissionLogicalId]: JSON.parse(permissionTemplate),
        };

        _.merge(this.serverless.service.provider.compiledCloudFormationTemplate.Resources,
          newCloudWatchLogRuleObject, newPermissionObject);

        // return a new promise that will check the resource limit exceeded against the function
        return this.checkAndFixLogGroupSubscriptionFilterResourceLimitExceeded({
          logGroupName: LogGroupName,
          functionName,
        });
      });

      return Promise.all(eventPromises);
    });

    return Promise.all(promises);
  }

  /**
   * @description Cloudwatch imposes a hard limit of 1 subscription filter per log group.
   * If we change a cloudwatchLog event entry to add a subscription filter to a log group
   * that already had one before, it will throw an error because CloudFormation firstly
   * tries to create and replace the new subscription filter (therefore hitting the limit)
   * before deleting the old one. This precompile process aims to delete existent
   * subscription filters of functions that a new filter was provided, by checking the
   * current ARN with the new one that will be generated.
   * See: https://git.io/fpKCM
  */
  checkAndFixLogGroupSubscriptionFilterResourceLimitExceeded({ logGroupName, functionName }) {
    return new Promise((resolve, reject) => {
      const region = this.provider.getRegion();
      const serviceName = this.serverless.service.getServiceName();
      const stage = this.provider.getStage();
      const cloudWatchLogs = new this.provider.sdk.CloudWatchLogs({ region });

      cloudWatchLogs
        .describeSubscriptionFilters({ logGroupName })
        .promise()
        .then(({ subscriptionFilters: [subscriptionFilter] }) => {
          // log group doesn't have any subscription filters currently
          if (!subscriptionFilter) {
            resolve();
            return;
          }

          this.provider.getAccountId()
            .then((accountId) => {
              const { destinationArn: oldDestinationArn, filterName } = subscriptionFilter;
              // eslint-disable-next-line max-len
              const newDestinationArn = `arn:aws:lambda:${region}:${accountId}:function:${serviceName}-${stage}-${functionName}`;

              // everything is fine, just resolve
              if (oldDestinationArn === newDestinationArn) {
                resolve();
                return;
              }

              /*
                if the destinations functions' arns doesn't matter, we need to delete the current
                subscription filter to prevent the resource limit exceeded error to happen
              */
              cloudWatchLogs.deleteSubscriptionFilter({ logGroupName, filterName })
                .promise()
                .then(resolve)
                .catch(reject);
            })
            .catch(reject);
        })
        /*
          it will throw when trying to get subscription filters of a log group that was just added
          to the serverless.yml (therefore not created in AWS yet), we can safely ignore this error
          and just resolve
        */
        .catch(resolve);
    });
  }
}

module.exports = AwsCompileCloudWatchLogEvents;
