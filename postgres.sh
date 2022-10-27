#!/bin/bash
echo "Script Execution Started"
#sleep 10
echo $(pwd)
sudo apt-get update -y
#echo "update completed"
sudo apt-get install postgresql-14  -y
sudo psql --version
#sudo -u postgres psql -U postgres -c "CREATE ROLE jayanthadithya1 SUPERUSER CREATEDB CREATEROLE LOGIN PASSWORD 'postgres';"
#sudo -u postgres createuser jayanthadithya
#sudo -u postgres createdb
#sudo -u postgres psql
#ALTER USER postgres with encrypted password '';
#Grant all privileges on database postgres to jayanthadithya
#ALTER USER postgres PASSWORD '';
#CREATE ROLE jayanthadithya SUPERUSER CREATEDB CREATEROLE LOGIN PASSWORD '';
#sudo systemctl restart postgresql@14-main.service
#sleep 10
echo "****************************************************************************Postgres is installed ****************************************************************************"
exit
