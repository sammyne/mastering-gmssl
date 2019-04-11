#!/bin/bash

docker run -it --name gmssl --rm -v ${PWD}:/cpp --workdir=/cpp gmssl:v0.0.4 bash