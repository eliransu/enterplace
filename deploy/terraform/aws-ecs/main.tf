# Gantry on AWS: ECS Fargate gateways behind an HTTPS load balancer, Postgres for keys, kill switches and budgets,
# and one EFS access point per gateway for its audit log. See README.md.

data "aws_region" "current" {}

locals {
  create_db               = var.database_url_secret_arn == null
  database_url_secret_arn = local.create_db ? aws_secretsmanager_secret.database_url[0].arn : var.database_url_secret_arn
  runtime_secret_arns = compact(concat(
    [local.database_url_secret_arn, var.license_secret_arn, var.image_pull_secret_arn],
    values(var.provider_key_secret_arns),
  ))
  replicas    = { for i in range(var.replicas) : tostring(i) => i }
  gateway_url = "https://${coalesce(var.domain_name, aws_lb.this.dns_name)}"
  command = concat(
    ["serve", "/etc/gantry/gantry.policy.yaml", "--listen", "0.0.0.0:8080"],
    var.metrics_port == null ? [] : ["--metrics", "0.0.0.0:${var.metrics_port}"],
  )
}

# Security groups: the load balancer reaches the tasks, the tasks reach the database (through the proxy) and EFS,
# and nothing else reaches any of them.

resource "aws_security_group" "alb" {
  name        = "${var.name}-alb"
  description = "Gantry load balancer"
  vpc_id      = var.vpc_id
  tags        = var.tags
}

resource "aws_security_group" "task" {
  name        = "${var.name}-task"
  description = "Gantry gateways"
  vpc_id      = var.vpc_id
  tags        = var.tags
}

resource "aws_security_group" "efs" {
  name        = "${var.name}-efs"
  description = "Gantry audit volumes"
  vpc_id      = var.vpc_id
  tags        = var.tags
}

resource "aws_vpc_security_group_ingress_rule" "alb" {
  for_each          = { for pair in setproduct(var.allowed_cidrs, [443, 80]) : "${pair[0]}:${pair[1]}" => pair }
  security_group_id = aws_security_group.alb.id
  cidr_ipv4         = each.value[0]
  from_port         = each.value[1]
  to_port           = each.value[1]
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "alb_to_task" {
  security_group_id            = aws_security_group.alb.id
  referenced_security_group_id = aws_security_group.task.id
  from_port                    = 8080
  to_port                      = 8080
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "task_from_alb" {
  security_group_id            = aws_security_group.task.id
  referenced_security_group_id = aws_security_group.alb.id
  from_port                    = 8080
  to_port                      = 8080
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "task_metrics" {
  for_each          = var.metrics_port == null ? toset([]) : toset(var.metrics_cidrs)
  security_group_id = aws_security_group.task.id
  cidr_ipv4         = each.value
  from_port         = var.metrics_port
  to_port           = var.metrics_port
  ip_protocol       = "tcp"
}

# Model providers are reached over the internet, so the tasks keep open egress.
resource "aws_vpc_security_group_egress_rule" "task" {
  security_group_id = aws_security_group.task.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

resource "aws_vpc_security_group_ingress_rule" "efs_from_task" {
  security_group_id            = aws_security_group.efs.id
  referenced_security_group_id = aws_security_group.task.id
  from_port                    = 2049
  to_port                      = 2049
  ip_protocol                  = "tcp"
}

# The policy, in Parameter Store. ECS cannot mount a parameter as a file, and the image has no shell, so a small
# init container writes it to a task-local volume the gateway reads.
# ponytail: an Advanced parameter holds 8 KB of policy; a larger policy needs S3 and an init container that fetches it.
resource "aws_ssm_parameter" "policy" {
  name  = "/${var.name}/gantry.policy.yaml"
  type  = "String"
  tier  = "Intelligent-Tiering"
  value = var.policy
  tags  = var.tags
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/gantry/${var.name}"
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

resource "aws_ecs_cluster" "this" {
  name = var.name
  tags = var.tags
}

# The execution role pulls the image and reads the secrets and policy when a task starts. The gateway itself needs
# no AWS permissions, so the tasks get no task role.
resource "aws_iam_role" "execution" {
  name = "${var.name}-execution"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Principal = { Service = "ecs-tasks.amazonaws.com" } }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "execution" {
  name = "read-gantry-config"
  role = aws_iam_role.execution.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = "secretsmanager:GetSecretValue", Resource = local.runtime_secret_arns },
      { Effect = "Allow", Action = "ssm:GetParameters", Resource = aws_ssm_parameter.policy.arn },
    ]
  })
}

# EFS for the audit logs. Each gateway gets its own access point, so its own directory: each writes its own hash
# chain, and two gateways on one chain would break it.
resource "aws_efs_file_system" "this" {
  creation_token   = var.name
  encrypted        = true
  throughput_mode  = "elastic"
  performance_mode = "generalPurpose"
  tags             = merge(var.tags, { Name = "${var.name}-audit" })
}

resource "aws_efs_backup_policy" "this" {
  file_system_id = aws_efs_file_system.this.id
  backup_policy {
    status = "ENABLED"
  }
}

resource "aws_efs_mount_target" "this" {
  count           = length(var.private_subnet_ids)
  file_system_id  = aws_efs_file_system.this.id
  subnet_id       = var.private_subnet_ids[count.index]
  security_groups = [aws_security_group.efs.id]
}

resource "aws_efs_access_point" "replica" {
  for_each       = local.replicas
  file_system_id = aws_efs_file_system.this.id
  # The image runs as 65532; the access point makes every file it writes belong to that user.
  posix_user {
    uid = 65532
    gid = 65532
  }
  root_directory {
    path = "/gantry-${each.key}"
    creation_info {
      owner_uid   = 65532
      owner_gid   = 65532
      permissions = "0700"
    }
  }
  tags = merge(var.tags, { Name = "${var.name}-${each.key}" })
}

resource "aws_ecs_task_definition" "replica" {
  for_each                 = local.replicas
  family                   = "${var.name}-${each.key}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = aws_iam_role.execution.arn
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.cpu_architecture
  }
  volume {
    name = "policy"
  }
  volume {
    name = "data"
    efs_volume_configuration {
      file_system_id     = aws_efs_file_system.this.id
      transit_encryption = "ENABLED"
      authorization_config {
        access_point_id = aws_efs_access_point.replica[each.key].id
      }
    }
  }
  container_definitions = jsonencode([
    {
      name        = "policy"
      image       = "public.ecr.aws/docker/library/busybox:1.36"
      essential   = false
      command     = ["sh", "-c", "printf '%s' \"$GANTRY_POLICY\" > /etc/gantry/gantry.policy.yaml"]
      secrets     = [{ name = "GANTRY_POLICY", valueFrom = aws_ssm_parameter.policy.arn }]
      mountPoints = [{ sourceVolume = "policy", containerPath = "/etc/gantry" }]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.this.name
          awslogs-region        = data.aws_region.current.region
          awslogs-stream-prefix = "policy-${each.key}"
        }
      }
    },
    merge(
      {
        name                   = "gantry"
        image                  = var.image
        essential              = true
        command                = local.command
        readonlyRootFilesystem = true
        # SIGTERM gives requests in flight 30 seconds; the margin lets the audit log sync before the kill.
        stopTimeout  = 40
        dependsOn    = [{ containerName = "policy", condition = "SUCCESS" }]
        portMappings = concat([{ containerPort = 8080, protocol = "tcp" }], var.metrics_port == null ? [] : [{ containerPort = var.metrics_port, protocol = "tcp" }])
        mountPoints = [
          { sourceVolume = "policy", containerPath = "/etc/gantry", readOnly = true },
          { sourceVolume = "data", containerPath = "/var/lib/gantry" },
        ]
        # The parameter's value is read at task start, so a new hash here is what rolls the tasks onto a new policy.
        environment = [{ name = "GANTRY_POLICY_SHA256", value = sha256(var.policy) }]
        secrets = concat(
          [{ name = "DATABASE_URL", valueFrom = local.database_url_secret_arn }],
          var.license_secret_arn == null ? [] : [{ name = "GANTRY_LICENSE", valueFrom = var.license_secret_arn }],
          [for env_name, arn in var.provider_key_secret_arns : { name = env_name, valueFrom = arn }],
        )
        logConfiguration = {
          logDriver = "awslogs"
          options = {
            awslogs-group         = aws_cloudwatch_log_group.this.name
            awslogs-region        = data.aws_region.current.region
            awslogs-stream-prefix = "gantry-${each.key}"
          }
        }
      },
      var.image_pull_secret_arn == null ? {} : { repositoryCredentials = { credentialsParameter = var.image_pull_secret_arn } },
    ),
  ])
  tags = var.tags
}

resource "aws_ecs_service" "replica" {
  for_each                          = local.replicas
  name                              = "${var.name}-${each.key}"
  cluster                           = aws_ecs_cluster.this.arn
  task_definition                   = aws_ecs_task_definition.replica[each.key].arn
  desired_count                     = 1
  launch_type                       = "FARGATE"
  health_check_grace_period_seconds = 60
  # Stop the old task before starting the new one: two tasks on one access point would write one chain twice.
  deployment_minimum_healthy_percent = 0
  deployment_maximum_percent         = 100
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }
  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.task.id]
    assign_public_ip = false
  }
  load_balancer {
    target_group_arn = aws_lb_target_group.this.arn
    container_name   = "gantry"
    container_port   = 8080
  }
  propagate_tags = "SERVICE"
  tags           = var.tags
  depends_on     = [aws_lb_listener.https, aws_efs_mount_target.this]
}

resource "aws_lb" "this" {
  name                       = var.name
  load_balancer_type         = "application"
  internal                   = var.internal
  subnets                    = var.public_subnet_ids
  security_groups            = [aws_security_group.alb.id]
  drop_invalid_header_fields = true
  enable_deletion_protection = var.deletion_protection
  # A provider may take up to 120 seconds to start answering, and a stream can pause between tokens.
  idle_timeout = 300
  tags         = var.tags
}

resource "aws_lb_target_group" "this" {
  name                 = var.name
  port                 = 8080
  protocol             = "HTTP"
  target_type          = "ip"
  vpc_id               = var.vpc_id
  deregistration_delay = 35
  health_check {
    path                = "/healthz"
    matcher             = "200"
    interval            = 10
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
  # Console sessions live in the memory of the gateway that made them.
  stickiness {
    type    = "lb_cookie"
    enabled = true
  }
  tags = var.tags
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }
  tags = var.tags
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
  tags = var.tags
}
