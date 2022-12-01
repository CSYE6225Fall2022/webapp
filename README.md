# webapp
#####    Created an endpoint "healthz/"  that gives a status code 200 with a GET request

## In order to run the web app

##### cd webapp
##### python3 venv venv 
##### Install required dependencies


## To run the webapp 


##### python3 manage.py runserver

## To check if the end point functions

##### Install POSTMAN
##### Runserver using python3 manage.py runserver
##### Copy the localhost IP and paste it in POSTMAN 
##### Change the method to GET and click send
##### Would respond with status code 200 
#### Added workflow, added Git branch protection
##### End
#### Creating an ssl document 
#### aws acm import-certificate --certificate fileb://demo_jayanth-adithya_me.crt  --certificate-chain fileb://demo_jayanth-adithya_me.ca-bundle  --private-key fileb://private.key --region us-east-1 --profile Demo

#### Jmeter command - jmeter -n -t health-ltest.jmx -f -l health-ltest.jtl -e -o health-ltest -Jthreads=1000 -Jloops=1000 -Jhost=demo.jayanth-adithya.me -Jport=443
### checking build artifact


