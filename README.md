# ARTIPHISHELL

# Offical Deployment

The following is the offical way to deploy ARTIPHISHELL for the AFC

### Game Network Configuration

```bash
# Tailscale Configuration
export TS_CLIENT_SECRET='tskey-XXXXXXXXX'
export TS_CLIENT_ID='XXXXXXXXX'
export TS_OP_TAG='tag:crs-binary-blade'

export CRS_API_HOSTNAME='binary-blade-final.tail7e9b4c.ts.net'
export CRS_API_URL="https://$CRS_API_HOSTNAME"
export CRS_KEY_ID='xxxxxxxxxxxxx'
export CRS_KEY_TOKEN='XXXXXXXXXXX'

export COMPETITION_API_URL='https://api.tail7e9b4c.ts.net'
export COMPETITION_API_KEY_ID='xxxxxxxxxxxx'
export COMPETITION_API_KEY_TOKEN='XXXXXXXXXXXX'
```

### Configure LLM Secrets

```bash
export OPENAI_API_KEY='sk-XXXXXXXXXXX'
export ANTHROPIC_API_KEY='sk-ant-XXXXXXXXXXX'
export GEMINI_API_KEY='XXXXXXXXXXXXX'
```

### Azure Configuration

```bash
export AZURE_USER='finalafc'
export TF_VAR_ARM_TENANT_ID='xxxxxxx'
export TF_VAR_ARM_SUBSCRIPTION_ID='xxxxxxxxx'

# You will need to change these to a globally unique name
export TF_VAR_ARM_RESOURCE_GROUP='ARTIPHISHELL-PROD-AFC'
export TF_VAR_ARM_STORAGE_ACCOUNT='artiphishellprodafc'

# Either be logged into azcli, or provide the following envs
export TF_VAR_ARM_CLIENT_ID='xxxxxxxxxx'
export export TF_VAR_ARM_CLIENT_SECRET='xxxxxxxxx'
```

### Telemetry Configuration
```bash
export OTEL_EXPORTER_OTLP_ENDPOINT="https://otel.binary-blade.aixcc.tech:443"
export OTEL_EXPORTER_OTLP_PROTOCOL=grpc
export OTEL_EXPORTER_OTLP_HEADERS='XXXXXXXXXXX'
```

### CRS Configuration

There are many env vars which control how the CRS is deployed

To use the configuration we submitted with during the AFC, use the provided `final.env` file

```bash
source ./infra/final.env
```

### Build and Bring Up CRS Cluster

Now that we are configured, we need to:
1. Bring up the CRS Azure Container Registry via Terraform
2. Build the docker images for the CRS
3. Push the docker images to the registry
4. Deploy the Azure Terraform config
5. Install the ARTIPHISHELL Helm Application

These steps can be done all at once command using the `./infra/Makefile`:

```bash

# This will both build and bring up the entire CRS into the Azure Subscription
pushd infra
make clean # clean stale azure credentials
make up
```

---

# Development

For internal development information, check out the private [Wiki](https://github.com/shellphish-support-syndicate/artiphishell/wiki)

Private CI Results Can Be Found Here: [https://ci.internal.artiphishell.com/](https://ci.internal.artiphishell.com/)
