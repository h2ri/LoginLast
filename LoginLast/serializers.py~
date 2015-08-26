from django.contrib.auth.models import User, Group
from rest_framework import serializers
from .models import MyUser
from oauth2_provider.models import Application, AccessToken, RefreshToken
# first we define the serializers
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User


class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group

class SignUpSerializer(serializers.ModelSerializer):
	client_id = serializers.SerializerMethodField()
	client_secret = serializers.SerializerMethodField()

	class Meta:
		model = User
		fields = ('username','password','client_id','client_secret')
		#write_only_fields = ('password',)
	def get_client_id(self, obj):
		return Application.objects.get(user=obj).client_id
	def get_client_secret(self, obj):
		return Application.objects.get(user=obj).client_secret


	def create(self, validated_data):
        	password = validated_data.pop('password', None)
        	instance = self.Meta.model(**validated_data)
        	if password is not None:
			instance.set_password(password)
        	instance.save()
        	return instance

    	def update(self, instance, validated_data):
        	for attr, value in validated_data.items():
            		if attr == 'password':
                		instance.set_password(value)
            		else:
        			setattr(instance, attr, value)
        	instance.save()
        	return instance

class LoginSerializer(SignUpSerializer):
        access_token = serializers.SerializerMethodField()
	referesh_token = serializers.SerializerMethodField()
	expires = serializers.SerializerMethodField()
	class Meta:
		model = User
		fields = ('client_id','client_secret','access_token','referesh_token','expires')
	
	def get_access_token(self,obj):
		return AccessToken.objects.get(user=obj).token

	def get_referesh_token(self,obj):
		return RefreshToken.objects.get(user=obj).token
		
	def get_expires(self,obj):
		return AccessToken.objects.get(user=obj).expires
