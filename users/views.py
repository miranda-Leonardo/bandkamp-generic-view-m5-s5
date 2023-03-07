from rest_framework.views import APIView, Request, Response, status
from rest_framework.generics import CreateAPIView, RetrieveUpdateAPIView, RetrieveDestroyAPIView
from .models import User
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.authentication import JWTAuthentication
from .serializers import UserSerializer, CustomJWTSerializer
from django.shortcuts import get_object_or_404
from .permissions import IsAccountOwner


class SignInView(TokenObtainPairView):
    serializer_class = CustomJWTSerializer


class UserView(CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def post(self, request: Request) -> Response:
        """
        Registro de usuários
        """
        serializer = UserSerializer(data=request.data)
        
        serializer.is_valid(raise_exception=True)

        serializer.save()

        return Response(serializer.data, status.HTTP_201_CREATED)


class UserDetailView(RetrieveUpdateAPIView, RetrieveDestroyAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAccountOwner]

    queryset = User.objects.all()
    serializer_class = UserSerializer

    lookup_url_kwarg = "pk"

    def get(self, request: Request, *args, **kwargs) -> Response:
        """
        Obtençao de usuário
        """
        user = get_object_or_404(User, *args, **kwargs)

        self.check_object_permissions(request, user)

        serializer = UserSerializer(user)

        return Response(serializer.data)

    def patch(self, request: Request, *args, **kwargs) -> Response:
        """
        Atualização de usuário
        """
        user = get_object_or_404(User, *args, **kwargs)

        self.check_object_permissions(request, user)

        serializer = UserSerializer(user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(serializer.data)

    def delete(self, request: Request, *args, **kwargs) -> Response:
        """
        Deleçao de usuário
        """
        user = get_object_or_404(User, *args, **kwargs)

        self.check_object_permissions(request, user)

        user.delete()

        return Response(status=status.HTTP_204_NO_CONTENT)
