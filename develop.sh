#!/bin/bash

docker run -it --rm -v ${PWD}:/cpp --workdir=/cpp gmssl:v0.0.3 bash