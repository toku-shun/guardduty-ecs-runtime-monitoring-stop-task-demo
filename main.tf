# Stop Task for Amazon GuardDuty ECS Runtime Monitoring

## versdions
terraform {
  required_version = "~> 1.6.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.29.0"
    }
  }
}

## providers
provider "aws" {
  region = "ap-northeast-1"
  default_tags {
    tags = {
      ManagedBy   = "terraform"
      Environment = var.environment
      SystemName  = var.system_name
    }
  }
}

## Amazon EventBridge
resource "aws_cloudwatch_event_rule" "eventbridge_rule" {
  name           = "${var.system_name}-${var.environment}-rule"
  description    = "Detecting runtime security threats in Amazon ECS, this rule invokes Step Functions for stopping ECS Task"
  event_bus_name = "default"
  event_pattern = jsonencode({
    "source" : ["aws.guardduty"],
    "detail-type" : ["GuardDuty Finding"],
    "detail" : {
      "resource" : {
        "resourceType" : ["ECSCluster"]
      },
      "service" : {
        "featureName" : ["RuntimeMonitoring"]
      }
    }
  })
  tags = {
    Name = "${var.system_name}-${var.environment}-rule"
  }
}

resource "aws_cloudwatch_event_target" "eventbridge_target" {
  rule           = aws_cloudwatch_event_rule.eventbridge_rule.name
  role_arn       = aws_iam_role.eventbridge_target.arn
  event_bus_name = "default"
  arn            = aws_sfn_state_machine.sfn_state_machine.arn
  input_transformer {
    input_paths = {
      "EcsClusterArn" : "$.detail.resource.ecsClusterDetails.arn",
      "GuardDutyFindingTitle" : "$.detail.title",
      "TaskArn" : "$.detail.resource.ecsClusterDetails.taskDetails.arn",
      "TaskDefinitionArn" : "$.detail.resource.ecsClusterDetails.taskDetails.definitionArn"
    }
    input_template = <<-EOT
        {
          "EcsClusterArn": <EcsClusterArn>,
          "TaskDefinitionArn":  <TaskDefinitionArn>,
          "TaskArn":  <TaskArn>,
          "GuardDutyFindingTitle": <GuardDutyFindingTitle>
        }
    EOT
  }
}

resource "aws_iam_role" "eventbridge_target" {
  name               = "${var.system_name}-${var.environment}-eventbridge-target-role"
  assume_role_policy = data.aws_iam_policy_document.eventbridge_target_assume_role_policy.json
  tags = {
    Name = "${var.system_name}-${var.environment}-eventbridge-target-role"
  }
}

data "aws_iam_policy_document" "eventbridge_target_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}
resource "aws_iam_role_policy_attachment" "eventbridge_target" {
  policy_arn = aws_iam_policy.eventbridge_target.arn
  role       = aws_iam_role.eventbridge_target.id
}
resource "aws_iam_policy" "eventbridge_target" {
  name   = "${var.system_name}-${var.environment}-eventbridge-target-policy"
  policy = data.aws_iam_policy_document.eventbridge_target.json
}
data "aws_iam_policy_document" "eventbridge_target" {
  statement {
    effect    = "Allow"
    resources = [aws_sfn_state_machine.sfn_state_machine.arn]
    actions = [
      "states:StartExecution"
    ]
  }
}

## AWS Step Functions
resource "aws_sfn_state_machine" "sfn_state_machine" {
  definition = jsonencode(
    {
      Comment = "Stop Task with runtime security threats detected by Amazon GuardDuty"
      StartAt = "StopTask"
      States = {
        StopTask = {
          Catch = [
            {
              ErrorEquals = [
                "States.ALL",
              ]
              Next = "Notify Failure"
            },
          ]
          Next = "Notify Success"
          Parameters = {
            "Cluster.$" = "$.EcsClusterArn"
            "Reason.$"  = "$.GuardDutyFindingTitle"
            "Task.$"    = "$.TaskArn"
          }
          Resource = "arn:aws:states:::aws-sdk:ecs:stopTask"
          Type     = "Task"
        }
        "Notify Failure" = {
          End = true
          Parameters = {
            "Message.$" = <<-EOT
                            States.Format('Step Functions failed to stop ECS Task with runtime security threats detected by GuardDuty.
                            Detail:
                              Error: {}
                              Cause: {}',$.Error,$.Cause)
                        EOT
            Subject     = "Step Functions failed to stop ECS Task with runtime security threats detected by GuardDuty"
            TopicArn    = aws_sns_topic.topic.arn
          }
          Resource = "arn:aws:states:::aws-sdk:sns:publish"
          Type     = "Task"
        }
        "Notify Success" = {
          End = true
          Parameters = {
            "Message.$" = <<-EOT
                            States.Format('Step Functions succeeded in stopping ECS Task with runtime security threats detected by GuardDuty.
                            Detail:
                              Cluster: {}
                              TaskDefinition: {}
                              Group: {}
                              Task: {}
                              StoppedReason: {}',$.Task.ClusterArn, $.Task.TaskDefinitionArn, $.Task.Group, $.Task.TaskArn, $.Task.StoppedReason)
                        EOT
            Subject     = "Step Functions succeeded in stopping ECS Task with runtime security threats detected by GuardDuty"
            TopicArn    = aws_sns_topic.topic.arn
          }
          Resource = "arn:aws:states:::aws-sdk:sns:publish"
          Type     = "Task"
        }
      }
      TimeoutSeconds = 3600
    }
  )
  name     = "${var.system_name}-${var.environment}-state-machine"
  publish  = true
  role_arn = aws_iam_role.sfn_state_machine.arn
  type     = "STANDARD"
  logging_configuration {
    include_execution_data = true
    level                  = "ALL"
    log_destination        = "${aws_cloudwatch_log_group.sfn_state_machine.arn}:*"
  }
  tracing_configuration {
    enabled = false
  }
  tags = {
    Name = "${var.system_name}-${var.environment}-state-machine"
  }
}

resource "aws_iam_role" "sfn_state_machine" {
  name               = "${var.system_name}-${var.environment}-state-machine-role"
  assume_role_policy = data.aws_iam_policy_document.sfn_state_machine_assume_role_policy.json
  tags = {
    Name = "${var.system_name}-${var.environment}-state-machine-role"
  }
}

data "aws_iam_policy_document" "sfn_state_machine_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["states.amazonaws.com"]
    }
  }
}
resource "aws_iam_role_policy_attachment" "sfn_state_machine" {
  policy_arn = aws_iam_policy.sfn_state_machine.arn
  role       = aws_iam_role.sfn_state_machine.id
}
resource "aws_iam_policy" "sfn_state_machine" {
  name   = "${var.system_name}-${var.environment}-state-machine-policy"
  policy = data.aws_iam_policy_document.sfn_state_machine.json
}

data "aws_iam_policy_document" "sfn_state_machine" {
  statement {
    effect    = "Allow"
    resources = ["*"]
    actions = [
      "ecs:StopTask"
    ]
  }
  statement {
    effect    = "Allow"
    resources = ["${aws_cloudwatch_log_group.sfn_state_machine.arn}:*"]
    actions = [
      "logs:CreateLogDelivery",
      "logs:GetLogDelivery",
      "logs:UpdateLogDelivery",
      "logs:DeleteLogDelivery",
      "logs:ListLogDeliveries",
      "logs:PutResourcePolicy",
      "logs:DescribeResourcePolicies",
      "logs:DescribeLogGroups"
    ]
  }
  statement {
    effect    = "Allow"
    resources = [aws_sns_topic.topic.arn]
    actions = [
      "sns:Publish"
    ]
  }
}

## Amazon CloudWatch Logs
resource "aws_cloudwatch_log_group" "sfn_state_machine" {
  name              = "${var.system_name}-${var.environment}-state-machine-log-group"
  retention_in_days = 7
  tags = {
    Name = "${var.system_name}-${var.environment}-state-machine-log-group"
  }
}

## Amazon SNS
resource "aws_sns_topic" "topic" {
  name = "${var.system_name}-${var.environment}-topic"
}
