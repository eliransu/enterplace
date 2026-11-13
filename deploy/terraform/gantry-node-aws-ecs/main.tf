# A Gantry hybrid node on AWS Fargate: gantry-enterprise in node mode, pulling its policy and keys from the control
# plane. The node token and the provider keys come from Secrets Manager and never appear in the task definition.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 6.0" }
  }
}

data "aws_region" "current" {}

locals {
  cluster_arn = coalesce(var.cluster_arn, try(aws_ecs_cluster.this[0].arn, null))
  secret_arns = concat([var.node_token_secret_arn], values(var.provider_key_secret_arns))
}

resource "aws_ecs_cluster" "this" {
  count = var.cluster_arn == null ? 1 : 0
  name  = var.name
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/gantry/${var.name}"
  retention_in_days = var.log_retention_days
}

# The execution role reads the secrets when a task starts; the gateway itself needs no AWS permissions.
resource "aws_iam_role" "execution" {
  name = "${var.name}-execution"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Principal = { Service = "ecs-tasks.amazonaws.com" } }]
  })
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "secrets" {
  name = "read-gantry-secrets"
  role = aws_iam_role.execution.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "secretsmanager:GetSecretValue", Resource = local.secret_arns }]
  })
}

resource "aws_ecs_task_definition" "this" {
  family                   = var.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = aws_iam_role.execution.arn
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.cpu_architecture
  }
  container_definitions = jsonencode([{
    name         = "gantry"
    image        = var.image
    essential    = true
    command      = ["node", "--control-plane", var.control_plane_url, "--dir", "/var/lib/gantry", "--listen", "0.0.0.0:8080", "--interval", tostring(var.poll_interval)]
    portMappings = [{ containerPort = 8080, protocol = "tcp" }]
    secrets = concat(
      [{ name = "GANTRY_NODE_TOKEN", valueFrom = var.node_token_secret_arn }],
      [for env_name, arn in var.provider_key_secret_arns : { name = env_name, valueFrom = arn }],
    )
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.this.name
        awslogs-region        = data.aws_region.current.region
        awslogs-stream-prefix = "gantry"
      }
    }
  }])
}

resource "aws_ecs_service" "this" {
  name            = var.name
  cluster         = local.cluster_arn
  task_definition = aws_ecs_task_definition.this.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.subnets
    security_groups  = var.security_groups
    assign_public_ip = var.assign_public_ip
  }

  # Optional: put the gateways behind your load balancer (health check path /healthz, port 8080).
  dynamic "load_balancer" {
    for_each = var.target_group_arn == null ? [] : [var.target_group_arn]
    content {
      target_group_arn = load_balancer.value
      container_name   = "gantry"
      container_port   = 8080
    }
  }
}
