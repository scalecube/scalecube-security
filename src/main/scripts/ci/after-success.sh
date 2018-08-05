#!/usr/bin/env bash

if [ -z "$CODACY_PROJECT_TOKEN" ]; then
	find -name jacoco.xml -exec java -jar ~/codacy-coverage-reporter-assembly.jar report -l Java -r {} \;
	java -jar ~/codacy-coverage-reporter final
fi;
