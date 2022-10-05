from .models import AccountCustom
from rest_framework import serializers


class AccountCustomSerializer(serializers.ModelSerializer):
    class Meta:
        model = AccountCustom
        fields = ('id',
            'first_name',
                  'last_name',
                  'username',
                  'password')
        #read_only_fields = ('username',)
