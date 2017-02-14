# AWS Inventory

Simple script to poll for inventory resource counts from aws and ultimately generate csv

## Installation

Make local clone of repository, configure aws credentials to consume, enable execution of module.

```sh
# aws configure #commented out as most will have this completed
git clone git@git.apparatus.net:golf/aws-inventory.git
chmod +x aws-inventory/inventory-aws-to-csv.py
```

## Usage

Execute the script:

```sh
cd aws-inventory/
./inventory-aws-to-csv.py --profile YOUR_AWS_PROFILE
```

The following options are available in the script passed as arguments:

* Profile = The aws profile to consume from your `~/.aws/credentials`
* --compute = True enables counting compute resources
* --network = True enables counting network resources
* --paas = True enables counting paas resources
* --security = True enables counting security resources
* --storage = True enables counting storage resources
* --s3objects = True enables counting s3 objects in buckets (separate because of high api cost)

The script defaults to disabling all of the above

## Support

Please [open an issue](https://git.apparatus.net/golf/aws-inventory/issues/new) for support.

## Contributing

Please contribute using [Github Flow](https://guides.github.com/introduction/flow/). Create a branch, add commits, and [open a pull request](https://git.apparatus.net/golf/aws-inventory/merge_requests/new).
