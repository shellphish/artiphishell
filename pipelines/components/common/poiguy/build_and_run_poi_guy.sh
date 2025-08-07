#!/usr/bin/bash
docker build . --tag="poi-guy-container"
pydatatask-lock local

pydatatask inject poi_guy_run_for_codeql.joern_db 1 < /home/ravindu/poiguy/hamlin.joern.tar.gz
pydatatask inject poi_guy_run_for_codeql.codeql_report_dir 1 < /home/ravindu/poiguy/temp/report.codeql.sarif

pydatatask inject poi_guy_run_for_semgrep.joern_db 2 < /home/ravindu/poiguy/hamlin.joern.tar.gz
pydatatask inject poi_guy_run_for_semgrep.semgrep_report_dir 2 < /home/ravindu/poiguy/temp/report.semgrep.sarif

pydatatask inject poi_guy_run_for_joern.joern_report_dir 3 < /home/ravindu/poiguy/temp/report.joern.dump

pydatatask inject poi_guy_run_for_mango.mango_report_dir 4 < /home/ravindu/poiguy/temp/mango_output.json

pydatatask run --v
