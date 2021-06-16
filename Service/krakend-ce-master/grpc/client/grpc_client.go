package client

import (
	pb "github.com/devopsfaith/krakend-ce/grpc/authentication_service/service"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func NewauthenticationClient(address string) (pb.AuthenticationClient, error) {
	creds, err := credentials.NewClientTLSFromFile("certificate/cert.pem", "")
	if err != nil {
		return nil, err
	}
	conn, err := grpc.Dial(address, grpc.WithTransportCredentials(creds))

	if err != nil {
		return nil, err
	}

	client := pb.NewAuthenticationClient(conn)
	return client, nil
}
