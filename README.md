# OWASP Benchmark with TESTABLE Enhancements
This is a fork of the OWASP Benchmark project, which aims to discover testability patterns in web application code which make it hard for dynamic testing tools to detect vulnerabilities.

## Running
Here are some steps to build and run the benchmark.

### Building and Benchmarking
Everything is run within docker containers:
```bash
cd VMs
docker compose up --build
```
This will build and start the benchmark, including testing using OWASP ZAP.

### Create Scorecards
To create scorecards, copy the results where benchmark can find them:

```bash
cp VMs/zap/wrk/results/2023-09-21-ZAP-Report-benchmark.xml results/
```

Then run the scorecard script:

```bash
bash createScorecards.sh
```

You will find the results in the ```scorecard``` directory.

### Evaluate patterns
Currently just a simple python script that looks for strings and tries to correlate them to false negatives:

```bash
python3 scripts/simplePattern.py
```

## ZAP
To configure ZAP, here are some useful links:
 * Configuring scripts: https://www.zaproxy.org/docs/desktop/addons/automation-framework
 * Scanner codes: https://www.zaproxy.org/docs/alerts/

# OWASP Benchmark
The OWASP Benchmark Project is a Java test suite designed to verify the speed and accuracy of vulnerability detection tools. It is a fully runnable open source web application that can be analyzed by any type of Application Security Testing (AST) tool, including SAST, DAST (like <a href="https://owasp.org/www-project-zap">OWASP ZAP</a>), and IAST tools. The intent is that all the vulnerabilities deliberately included in and scored by the Benchmark are actually exploitable so its a fair test for any kind of application vulnerability detection tool. The Benchmark also includes scorecard generators for numerous open source and commercial AST tools, and the set of supported tools is growing all the time.

The project documentation is all on the OWASP site at the <a href="https://owasp.org/www-project-benchmark">OWASP Benchmark</a> project pages. Please refer to that site for all the project details.

The current latest release is v1.2. Note that all the releases that are available here: https://github.com/OWASP/Benchmark/releases are historical. The latest release is always available live by simply cloning or pulling the head of this repository (i.e., git pull).
