from django.contrib.auth.models import User, Group
from rest_framework import permissions, viewsets, generics
from oauth2_provider.ext.rest_framework import TokenHasReadWriteScope, TokenHasScope
from .serializers import UserSerializer, GroupSerializer, SignUpSerializer, LoginSerializer
from oauth2_provider.decorators import protected_resource
from .permissions import IsAuthenticatedOrCreate
from rest_framework.authentication import BasicAuthentication
from rest_framework.response import Response
from rest_framework.generics import CreateAPIView
from rest_framework import status
from oauth2_provider.models import Application, AccessToken, RefreshToken
import httplib
import base64
import urllib
import json

class UserViewSet(viewsets.ModelViewSet):

    #permission_classes = [permissions.IsAuthenticated, TokenHasReadWriteScope]
    queryset = User.objects.all()
    permission_classes = (permissions.AllowAny,)
    serializer_class = UserSerializer
    '''   def get_queryset(self):
	if self.request.user.is_superuser:
		return User.objects.all()
	else:
		return User.objects.filter(id=self.request.user.id)
    '''
		
	

def getAuthToken(creds,password):
	conn = httplib.HTTPConnection("127.0.0.1:8000")
	print conn
    	url =  "/o/token/"
    	headersMap = {
	"Content-Type": "application/x-www-form-urlencoded",
	};
	data = {'username':str(creds["username"]),'password':str(password),'grant_type':str('password'),'client_id':str(creds["client_id"]),'client_secret':str(creds["client_secret"])
	}
	requestUrl = url + "?" + urllib.urlencode(data)
    	conn.request("POST", requestUrl, headers=headersMap)
    	response = conn.getresponse()
    	if response.status == 200:
		
		#print AccessToken.objects.get(user=110).token
        	data = response.read()
        	result = json.loads( data )
        	return result["access_token"]
	else:
		print response.status

class GroupViewSet(viewsets.ModelViewSet):
    permission_classes = [permissions.IsAuthenticated, TokenHasScope]
    required_scopes = ['groups']
    queryset = Group.objects.all()
    serializer_class = GroupSerializer

class SignUp(generics.CreateAPIView):
	queryset = User.objects.all()
	serializer_class = SignUpSerializer
	permission_classes = (IsAuthenticatedOrCreate,)
	
	
	def create(self,request, *args, **kwargs):
		password = request.POST.get('password','')
		serializer = self.get_serializer(data=request.DATA)
		
		if serializer.is_valid():
            		self.object = serializer.save()
            		headers = self.get_success_headers(serializer.data)
			creds = serializer.data
			#calling for accesstoken
			token =  getAuthToken(creds,password)
			q = User.objects.get(username = creds["username"])
			p = AccessToken.objects.get(user=q.id)
			print p.token
			print p.expires
			print RefreshToken.objects.get(user=q.id).token
			return Response(token ,status=status.HTTP_201_CREATED,
                            headers=headers)

        	return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class Login(generics.ListAPIView):
    #queryset = User.objects.all()
    serializer_class = LoginSerializer
    authentication_classes = (BasicAuthentication,)
    def get_queryset(self):
        return [self.request.user]



#To get access token

