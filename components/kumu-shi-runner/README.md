# Kumu Shi
## Install
To install Kumu Shi (KS), you can just use the setup script in the root of this repository:
```
./setup.sh
```

You must also have [CodeQL](https://codeql.github.com/) installed on your system and in your PATH. 
You can download CodeQL from [here](https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.18.4/codeql-bundle-linux64.tar.gz).

## Verify installation
While we wait for backups, we have this:
```bash
kumu-shi --target-root /Users/mahaloz/github/challenge-004-nginx-source \ 
  --crash-input ./crashing_seeds/0b92b138c40e495cd9500b2be36616fc \
  --report-yaml ./poi.yaml --function-json-dir ./function_out_dir/ \
  --function-indices ./function_indices.json \
  --codeql-db /Users/mahaloz/github/artiphishell-tests-data/backups/kumushi/codeql_db/nginx-codeql-db \
  --codeql-executable /Users/mahaloz/github/artiphishell-tests-data/codeql/codeql
```