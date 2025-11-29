group "default" {
  targets = [
    "debian",
    "rhel",
    "ubuntu"
  ]
}

group "debian" {
  targets = ["debian12", "debian13"]
}

group "rhel" {
  targets = ["rhel8", "rhel9"]
}

group "ubuntu" {
  targets = ["ubuntu22", "ubuntu24"]
}

target "debian12" {
  dockerfile = "Dockerfile.debian12"
  tags = ["calico/host-native-build:debian12"]
}

target "debian13" {
  dockerfile = "Dockerfile.debian13"
  tags = ["calico/host-native-build:debian13"]
}

target "rhel8" {
  dockerfile = "Dockerfile.rhel8"
  tags = ["calico/host-native-build:rhel8"]
}

target "rhel9" {
  dockerfile = "Dockerfile.rhel9"
  tags = ["calico/host-native-build:rhel9"]
}

target "ubuntu22" {
  dockerfile = "Dockerfile.ubuntu22"
  tags = ["calico/host-native-build:ubuntu22"]
}

target "ubuntu24" {
  dockerfile = "Dockerfile.ubuntu24"
  tags = ["calico/host-native-build:ubuntu24"]
}
