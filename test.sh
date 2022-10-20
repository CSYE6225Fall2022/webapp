#!/bin/bash
echo "Test Script Execution Started"
$(ls)
#cd ~
#source bin/activate
python3 manage.py makemigrations
python3 manage.py migrate
python3 manage.py runserver 8000 &
#echo "Test complete"
exit 0

