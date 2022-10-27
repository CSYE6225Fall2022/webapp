#variables{
#aws_access_key = ""
#aws_secret_key = ""
#aws_region = "us-east-1"
#}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "aws_access_key" {
  type    = string
  default = ""
}

variable "aws_secret_key" {
  type    = string
  default = ""
}
variable "subnet_id" {
  type    = string
  default = ""
}


source "amazon-ebs" "my_ubuntu_ami" {
  access_key      = "${var.aws_access_key}"
  secret_key      = "${var.aws_secret_key}"
  region          = "${var.aws_region}"
  ami_name        = "custom-ami_${formatdate("YYYY_MM_DD_hh_mm_ss", timestamp())}"
  ami_description = "AMI for CSYE 6225"
  instance_type   = "t2.micro"
  source_ami      = "ami-08c40ec9ead489470"
  ami_users       = ["155671310944", "094363902806"]
  profile         = "dev"

  ssh_username = "ubuntu"
  ssh_timeout  = "10m"
  subnet_id    = "${var.subnet_id}"
  associate_public_ip_address= true
  ssh_interface = "public_ip"
  launch_block_device_mappings {
    delete_on_termination = true
    device_name           = "/dev/sda1"
    volume_size           = 50
    volume_type           = "gp2"
  }
}

build {
  sources = ["source.amazon-ebs.my_ubuntu_ami"]

  provisioner "file" {
    source      = "release.zip"
    destination = "release.zip"

  }

  provisioner "shell" {
    environment_vars = [
      "DEBIAN_FRONTEND=noninteractive",
      "CHECKPOINT_DISABLE=1"
    ]
    inline = [
      "sleep 10",
      "echo '############################################## inline script started##########################################################'",
      "sudo apt-get -y update",
      "echo '############################################## upgrade completed ##########################################################'",
      "sudo apt-get install build-essential -y",
      "echo '############################################## installed build essentials ##########################################################'",
      "sudo apt install openssl  libpq-dev libffi-dev bzip2 wget -y",
      "sudo apt install software-properties-common -y",
      "sudo add-apt-repository ppa:deadsnakes/ppa -y",
      "sudo apt install python3.9 -y",
      "echo  $python3 --version",
      "echo '****************************************************************************Python is installed ****************************************************************************'",
      "echo '****************************************************************************PIP is installed ****************************************************************************'",
      //"sudo apt-get install postgresql-14 -y",

      //"chmod +x postgres.sh",
      //"echo '****************************************************************************Postgres is installed ****************************************************************************'",
      "sudo apt-get install unzip -y",
      //"unzip release.zip",
      "unzip release.zip -d /home/ubuntu/",
      "echo '****************************************************************************first shell completed ****************************************************************************'",
      "sleep 10"

    ]
  }

  provisioner "shell" {
    script       = "postgres.sh"
    pause_before = "10s"
    timeout      = "10s"
  }

  provisioner "shell" {
    environment_vars = [
      "DEBIAN_FRONTEND=noninteractive",
      "CHECKPOINT_DISABLE=1"
    ]
    inline = [
      #      "sleep 10",
      "sudo apt-get install python3-pip -y",
      "sudo pip install -r requirements.txt",
      "sudo pip install uwsgi",

      #"sudo python3 manage.py makemigrations",
      #"sudo python3 manage.py migrate",
      #"sudo python3 manage.py makemigrations && python3 manage.py migrate",
      #"echo migration completed",
      "sudo cp webapp.service /etc/systemd/system/",
      "echo copied webapp.service",
      #"sudo systemctl --system enable webapp.service",
      #"sudo systemctl start webapp.service",
      "echo deployment complete",
      #      "sudo systemctl daemon-reload",
      "sudo lsof -PiTCP -sTCP:LISTEN"

    ]
  }
}


