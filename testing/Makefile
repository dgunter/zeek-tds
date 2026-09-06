
test:
	@mkdir -p .tmp/script-coverage
	@btest -c btest.cfg

# Everything CI hands to SonarCloud: results, script coverage, formatter findings.
sonar-reports:
	@mkdir -p .tmp/script-coverage
	-btest -c btest.cfg -x .tmp/btest.xml
	@./Scripts/btest-to-sonar .tmp/btest.xml tests .tmp/sonar-tests.xml
	@./Scripts/coverage-to-sonar .tmp/script-coverage .. .tmp/sonar-coverage.xml
	-./Scripts/format-check .. .tmp/sonar-issues.json
