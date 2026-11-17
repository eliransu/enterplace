# Postgres for the store: RDS Postgres 16 behind an RDS Proxy, created unless database_url_secret_arn names an
# existing database.
#
# Why the proxy: Enterplace checks the database's certificate against the Mozilla roots built into it. RDS instances
# present certificates from the RDS certificate authorities, which are not among them; RDS Proxy presents an
# ACM certificate that chains to Amazon's public roots, which are. The proxy also pools connections across gateways.

resource "random_password" "db" {
  count = local.create_db ? 1 : 0
  # Letters and digits only: the password goes into a connection string unescaped.
  length  = 32
  special = false
}

resource "aws_security_group" "db" {
  count       = local.create_db ? 1 : 0
  name        = "${var.name}-db"
  description = "Enterplace Postgres"
  vpc_id      = var.vpc_id
  tags        = var.tags
}

resource "aws_security_group" "db_proxy" {
  count       = local.create_db ? 1 : 0
  name        = "${var.name}-db-proxy"
  description = "Enterplace Postgres proxy"
  vpc_id      = var.vpc_id
  tags        = var.tags
}

resource "aws_vpc_security_group_ingress_rule" "db_proxy_from_task" {
  count                        = local.create_db ? 1 : 0
  security_group_id            = aws_security_group.db_proxy[0].id
  referenced_security_group_id = aws_security_group.task.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "db_proxy_to_db" {
  count                        = local.create_db ? 1 : 0
  security_group_id            = aws_security_group.db_proxy[0].id
  referenced_security_group_id = aws_security_group.db[0].id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "db_from_proxy" {
  count                        = local.create_db ? 1 : 0
  security_group_id            = aws_security_group.db[0].id
  referenced_security_group_id = aws_security_group.db_proxy[0].id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

resource "aws_db_subnet_group" "this" {
  count      = local.create_db ? 1 : 0
  name       = var.name
  subnet_ids = var.private_subnet_ids
  tags       = var.tags
}

resource "aws_db_instance" "this" {
  count                     = local.create_db ? 1 : 0
  identifier                = var.name
  engine                    = "postgres"
  engine_version            = "16"
  instance_class            = var.db_instance_class
  allocated_storage         = var.db_allocated_storage
  max_allocated_storage     = var.db_allocated_storage * 5
  storage_encrypted         = true
  db_name                   = "enterplace"
  username                  = "enterplace"
  password                  = random_password.db[0].result
  multi_az                  = var.db_multi_az
  db_subnet_group_name      = aws_db_subnet_group.this[0].name
  vpc_security_group_ids    = [aws_security_group.db[0].id]
  publicly_accessible       = false
  backup_retention_period   = 7
  copy_tags_to_snapshot     = true
  deletion_protection       = var.deletion_protection
  skip_final_snapshot       = false
  final_snapshot_identifier = "${var.name}-final"
  tags                      = var.tags
}

# The proxy signs in to the database with these; the gateways sign in to the proxy with the same pair.
resource "aws_secretsmanager_secret" "db_credentials" {
  count = local.create_db ? 1 : 0
  name  = "${var.name}/db-credentials"
  tags  = var.tags
}

resource "aws_secretsmanager_secret_version" "db_credentials" {
  count         = local.create_db ? 1 : 0
  secret_id     = aws_secretsmanager_secret.db_credentials[0].id
  secret_string = jsonencode({ username = "enterplace", password = random_password.db[0].result })
}

resource "aws_iam_role" "db_proxy" {
  count = local.create_db ? 1 : 0
  name  = "${var.name}-db-proxy"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Principal = { Service = "rds.amazonaws.com" } }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy" "db_proxy" {
  count = local.create_db ? 1 : 0
  name  = "read-db-credentials"
  role  = aws_iam_role.db_proxy[0].id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "secretsmanager:GetSecretValue", Resource = aws_secretsmanager_secret.db_credentials[0].arn }]
  })
}

resource "aws_db_proxy" "this" {
  count                  = local.create_db ? 1 : 0
  name                   = var.name
  engine_family          = "POSTGRESQL"
  require_tls            = true
  role_arn               = aws_iam_role.db_proxy[0].arn
  vpc_subnet_ids         = var.private_subnet_ids
  vpc_security_group_ids = [aws_security_group.db_proxy[0].id]
  auth {
    auth_scheme               = "SECRETS"
    secret_arn                = aws_secretsmanager_secret.db_credentials[0].arn
    iam_auth                  = "DISABLED"
    client_password_auth_type = "POSTGRES_SCRAM_SHA_256"
  }
  tags = var.tags
}

resource "aws_db_proxy_default_target_group" "this" {
  count         = local.create_db ? 1 : 0
  db_proxy_name = aws_db_proxy.this[0].name
}

resource "aws_db_proxy_target" "this" {
  count                  = local.create_db ? 1 : 0
  db_proxy_name          = aws_db_proxy.this[0].name
  target_group_name      = aws_db_proxy_default_target_group.this[0].name
  db_instance_identifier = aws_db_instance.this[0].identifier
}

# The whole connection string in one secret, because Enterplace reads it from one variable.
resource "aws_secretsmanager_secret" "database_url" {
  count = local.create_db ? 1 : 0
  name  = "${var.name}/database-url"
  tags  = var.tags
}

resource "aws_secretsmanager_secret_version" "database_url" {
  count         = local.create_db ? 1 : 0
  secret_id     = aws_secretsmanager_secret.database_url[0].id
  secret_string = "postgres://enterplace:${random_password.db[0].result}@${aws_db_proxy.this[0].endpoint}:5432/enterplace?sslmode=verify-full"
}
