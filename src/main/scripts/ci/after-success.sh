#!/bin/bash

if [ -z "$CODACY_PROJECT_TOKEN" ]; then
	echo [WARNING] Please go to https://app.codacy.com/app/$TRAVIS_REPO_SLUG/settings/coverage and add CODACY_PROJECT_TOKEN to travis settings
else 
	find -name jacoco.xml -exec java -jar ~/codacy-coverage-reporter-assembly.jar report -l Java -r {} \;
	java -jar ~/codacy-coverage-reporter-assembly.jar final
fi;