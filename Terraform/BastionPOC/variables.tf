variable "rgname" {
  description = "Resource Group to deploy vNet into"
  default = "BastionDemoInfraRG"
}
variable "rglocation" {
  description = "Resource Group location to deploy to"
  default = "West Europe"
}
variable "vNetName" {
  description = "Name of the vNet"
  default = "AzureBastionvNet"
}
variable "vNetAddressSpace" {
  description = "Address space for the vNet"
  default = "10.0.0.0/16"
}
variable "BastionSubnetRange" {
  description = "subnet Range for the bastion subnet"
  default = "10.0.2.0/27"
}
variable "vmsubnetRange" {
  description = "Subnet range for the VM subnet"
  default = "10.0.1.0/24"
}
variable "windowsvmname" {
  description = "Name of test windows VM"
  default = "Targetwinvm"
}
variable "linuxvmname" {
  description = "Name of the test linux VM"
  default = "Targetlinuxvm"
}
variable "bastionhostname" {
  description = "Name of the bastion"
  default = "Mybastion"
}