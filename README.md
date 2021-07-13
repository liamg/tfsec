<p align="center">
  <img width="500" src="./tfsec.png">
</p>

[![GoReportCard](https://goreportcard.com/badge/github.com/aquasecurity/tfsec)](https://goreportcard.com/report/github.com/aquasecurity/tfsec)
[![GitHub All Releases](https://img.shields.io/github/downloads/aquasecurity/tfsec/total)](https://github.com/aquasecurity/tfsec/releases)
[![Join Our Slack](https://img.shields.io/badge/Slack-Join-green)](https://join.slack.com/t/tfsec/shared_invite/zt-o6c7mgoj-eJ1sLDv595sKiP5OPoHJww)
[![Docker Build](https://img.shields.io/docker/v/tfsec/tfsec?label=docker)](https://hub.docker.com/r/tfsec/tfsec)
[![Homebrew](https://img.shields.io/badge/dynamic/json.svg?url=https://formulae.brew.sh/api/formula/tfsec.json&query=$.versions.stable&label=homebrew)](https://formulae.brew.sh/formula/tfsec)
[![Chocolatey](https://img.shields.io/chocolatey/v/tfsec)](https://chocolatey.org/packages/tfsec)
[![AUR version](https://img.shields.io/aur/version/tfsec)](https://aur.archlinux.org/packages/tfsec)
[![VScode Extension](https://img.shields.io/visual-studio-marketplace/v/tfsec.tfsec?label=vscode)](https://marketplace.visualstudio.com/items?itemName=tfsec.tfsec)

tfsec uses static analysis of your terraform templates to spot potential
security issues. Now with terraform CDK support.

## Aqua and tfsec

Great news - tfsec has [now joined Aqua Security](https://www.aquasec.com/news/aqua-security-acquires-tfsec/). Not only will the project remain open source, it now has a lot more resource and expertise behind it. Expect great new features and many more checks very soon...

## Example Output

![Example screenshot](screenshot.png)

## Installation

Install with [brew/linuxbrew](https://brew.sh)

```bash
brew install tfsec
```

Install with [Chocolatey](https://chocolatey.org/)

```cmd
choco install tfsec
```

Install with [Scoop](https://scoop.sh/)

```cmd
scoop install tfsec
```

You can also grab the binary for your system from the [releases page](https://github.com/aquasecurity/tfsec/releases).

Alternatively, install with Go:

```bash
go install github.com/aquasecurity/tfsec/cmd/tfsec@latest
```

Please note that using `go install` will install directly from the `master` branch and version numbers will not be reported via `tfsec --version`.

### Signing

The binaries on the [releases page](https://github.com/aquasecurity/tfsec/releases) are signed with the tfsec signing key `D66B222A3EA4C25D5D1A097FC34ACEFB46EC39CE` 

Form more information check the [signing page](SIGNING.md) for instructions on verification.

## Usage

tfsec will scan the specified directory. If no directory is specified, the current working directory will be used.

The exit status will be non-zero if tfsec finds problems, otherwise the exit status will be zero.

```bash
tfsec .
```

## Use with Docker

As an alternative to installing and running tfsec on your system, you may run tfsec in a Docker container.

There are a number of Docker options available

| Image Name | Base | Comment |
|------------|------|---------|
|[tfsec/tfsec](https://hub.docker.com/repository/docker/tfsec/tfsec)|alpine|Normal tfsec image|
|[tfsec/tfsec-alpine](https://hub.docker.com/repository/docker/tfsec/tfsec-alpine)|alpine|Exactly the same as tfsec/tfsec, but for those whole like to be explicit|
|[tfsec/tfsec-ci](https://hub.docker.com/repository/docker/tfsec/tfsec-ci)|alpine|tfsec with no entrypoint - useful for CI builds where you want to override the command|
|[tfsec/tfsec-scratch](https://hub.docker.com/repository/docker/tfsec/tfsec-scratch)|scratch|An image built on scratch - nothing frilly, just runs tfsec|

To run:

```bash
docker run --rm -it -v "$(pwd):/src" tfsec/tfsec /src
```

## Use with Visual Studio Code

A Visual Studio Code extension is being developed to integrate with tfsec results. More information can be found on the [tfsec Marketplace page](https://marketplace.visualstudio.com/items?itemName=tfsec.tfsec)

## Use as GitHub Action

If you want to run tfsec on your repository as a GitHub Action, you can use [https://github.com/aquasecurity/tfsec-pr-commenter-action](https://github.com/aquasecurity/tfsec-pr-commenter-action).

## Features

- Checks for sensitive data inclusion across all providers
- Checks for violations of AWS, Azure and GCP security best practice recommendations
- Scans modules (currently only local modules are supported)
- Evaluates expressions as well as literal values
- Evaluates Terraform functions e.g. `concat()`

## Ignoring Warnings

You may wish to ignore some warnings. If you'd like to do so, you can
simply add a comment containing `tfsec:ignore:<RULE>` to the offending
line in your templates. If the problem refers to a block of code, such
as a multiline string, you can add the comment on the line above the
block, by itself.

For example, to ignore an open security group rule:

```hcl
resource "aws_security_group_rule" "my-rule" {
    type = "ingress"
    cidr_blocks = ["0.0.0.0/0"] #tfsec:ignore:AWS006
}
```

...or...

```hcl
resource "aws_security_group_rule" "my-rule" {
    type = "ingress"
    #tfsec:ignore:AWS006
    cidr_blocks = ["0.0.0.0/0"]
}
```

If you're not sure which line to add the comment on, just check the
tfsec output for the line number of the discovered problem.

You can ignore multiple rules by concatenating the rules on a single line:

```hcl
#tfsec:ignore:AWS017 tfsec:ignore:AWS002
resource "aws_s3_bucket" "my-bucket" {
  bucket = "foobar"
  acl    = "private"
}
```

### Expiration Date
You can set expiration date for `ignore` with `yyyy-mm-dd` format. This is a useful feature when you want to ensure ignored issue won't be forgotten and should be revisited in the future.
```
#tfsec:ignore:AWS017:exp:2022-01-02
```
Ignore like this will be active only till `2022-01-02`, after this date it will be deactivated.

## Disable checks

You may wish to exclude some checks from running. If you'd like to do so, you can
simply add new argument `-e CHECK1,CHECK2,etc` to your cmd command

```bash
tfsec . -e GEN001,GCP001,GCP002
```

## Including values from .tfvars

You can include values from a tfvars file in the scan,  using, for example: `--tfvars-file terraform.tfvars`.

## Included Checks

Checks are currently limited to AWS/Azure/GCP resources, but
there are also checks which are provider agnostic.

| Checks |
|:---|
|[AWS Checks](https://www.tfsec.dev/docs/aws/home/)|
|[Azure Checks](https://www.tfsec.dev/docs/azure/home/)|
|[GCP Checks](https://www.tfsec.dev/docs/google/home/)|
|[General Checks](https://www.tfsec.dev/docs/general/home/)|

## Running in CI

tfsec is designed for running in a CI pipeline. For this reason it will
exit with a non-zero exit code if a potential problem is detected.
You may wish to run tfsec as part of your build without coloured
output. You can do this using `--no-colour` (or `--no-color` for our
American friends).

## Output options

You can output tfsec results as JSON, CSV, Checkstyle, Sarif, JUnit or just plain old human readable format. Use the `--format` flag
to specify your desired format.

## Github Security Alerts
If you want to integrate with Github Security alerts and include the output of your tfsec checks you can use the [tfsec-sarif-action](https://github.com/marketplace/actions/run-tfsec-with-sarif-upload) Github action to run the static analysis then upload the results to the security alerts tab.

The alerts generated for [tfsec-example-project](https://github.com/tfsec/tfsec-example-project) look like this.

![github security alerts](codescanning.png)

When you click through the alerts for the branch, you get more information about the actual issue. 

![github security alerts](scanningalert.png)

For more information about adding security alerts, check 

## Support for older terraform versions

If you need to support versions of terraform which use HCL v1
(terraform <0.12), you can use `v0.1.3` of tfsec, though support is
very limited and has fewer checks.
