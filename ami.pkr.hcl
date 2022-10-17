variables{
"aws_access_key" = "AKIASIPV3WJQG6ISHYI6"
"aws_secret_key" = "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"
"aws_region" = "us-east-1"
}

source "amazon_ebs" "my_ubuntu_ami"{
access_key = "AKIASIPV3WJQG6ISHYI6"
secret_key = "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"
region         = "us-east-1"
"ami_name" : "custom-ami_${formatdate("YYYY_MM_DD_hh_mm_ss",timestamp())}"
ami_description = "AMI for CSYE 6225"
instance_type = "t2.micro"
source_ami    = " ami-08c40ec9ead489470"
"ssh_username" : "ec2-user",
launch_block_device_mappings {
    delete_on_termination = true
    device_name           = "/dev/sda1"
    volume_size           = 8
    volume_type           = "gp2"
    }}

build {
  sources = ["source.amazon-ebs.my_ubuntu_ami"]

  provisioner "shell" {
    environment_vars = [
      "DEBIAN_FRONTEND=noninteractive",
      "CHECKPOINT_DISABLE=1"
    ]
