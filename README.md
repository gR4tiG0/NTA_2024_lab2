# NTA_2024_lab2

download docker from remote: `docker pull gratigo/nta_lab2:latest`
run docker from remote: `docker run --rm -it gratigo/nta_lab2:latest`
build from git repo: `docker build -t 'gratigo/nta_lab2' .`
run cli: `docker run --rm -it 'gratigo/nta_lab2'`
stop container: `docker stop $(docker ps | grep "gratigo/nta_lab2" | cut -d " " -f1)`
remove image: `docker image rm 'gratigo/nta_lab2'`


P.S To test application script `solver.py` can be used. It works along with `oracle.py` class-file to create connection between lab enviroment that generates DLP and developed solver.
With default settings it iterates from 3 to 12 dec-len and solves both steps using SPH
